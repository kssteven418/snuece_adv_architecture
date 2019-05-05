/*
 * Copyright (c) 2007 The Hewlett-Packard Development Company
 * All rights reserved.
 *
 * The license below extends only to copyright in the software and shall
 * not be construed as granting a license to any other intellectual
 * property including but not limited to intellectual property relating
 * to a hardware implementation of the functionality of the software
 * licensed hereunder.  You may use the software subject to the license
 * terms below provided that you ensure that this notice is replicated
 * unmodified and in its entirety in all distributions of the software,
 * modified or unmodified, in source code or in binary form.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors: Gabe Black
 */

#include "arch/x86/linux/process.hh"

#include "arch/x86/isa_traits.hh"
#include "arch/x86/linux/linux.hh"
#include "arch/x86/registers.hh"
#include "base/trace.hh"
#include "cpu/thread_context.hh"
#include "kern/linux/linux.hh"
#include "sim/process.hh"
#include "sim/syscall_desc.hh"
#include "sim/syscall_emul.hh"

using namespace std;
using namespace X86ISA;

/// Target uname() handler.
static SyscallReturn
unameFunc(SyscallDesc *desc, int callnum, Process *process,
          ThreadContext *tc)
{
    int index = 0;
    TypedBufferArg<Linux::utsname> name(process->getSyscallArg(tc, index));

    strcpy(name->sysname, "Linux");
    strcpy(name->nodename, "sim.gem5.org");
    strcpy(name->release, "3.0.0");
    strcpy(name->version, "#1 Mon Aug 18 11:32:15 EDT 2003");
    strcpy(name->machine, "x86_64");

    name.copyOut(tc->getMemProxy());

    return 0;
}

static SyscallReturn
archPrctlFunc(SyscallDesc *desc, int callnum, Process *process,
              ThreadContext *tc)
{
    enum ArchPrctlCodes
    {
        SetFS = 0x1002,
        GetFS = 0x1003,
        SetGS = 0x1001,
        GetGS = 0x1004
    };

    // First argument is the code, second is the address
    int index = 0;
    int code = process->getSyscallArg(tc, index);
    uint64_t addr = process->getSyscallArg(tc, index);
    uint64_t fsBase, gsBase;
    SETranslatingPortProxy &p = tc->getMemProxy();
    switch(code)
    {
      // Each of these valid options should actually check addr.
      case SetFS:
        tc->setMiscRegNoEffect(MISCREG_FS_BASE, addr);
        tc->setMiscRegNoEffect(MISCREG_FS_EFF_BASE, addr);
        return 0;
      case GetFS:
        fsBase = tc->readMiscRegNoEffect(MISCREG_FS_BASE);
        p.write(addr, fsBase);
        return 0;
      case SetGS:
        tc->setMiscRegNoEffect(MISCREG_GS_BASE, addr);
        tc->setMiscRegNoEffect(MISCREG_GS_EFF_BASE, addr);
        return 0;
      case GetGS:
        gsBase = tc->readMiscRegNoEffect(MISCREG_GS_BASE);
        p.write(addr, gsBase);
        return 0;
      default:
        return -EINVAL;
    }
}

BitUnion32(UserDescFlags)
    Bitfield<0> seg_32bit;
    Bitfield<2, 1> contents;
    Bitfield<3> read_exec_only;
    Bitfield<4> limit_in_pages;
    Bitfield<5> seg_not_present;
    Bitfield<6> useable;
EndBitUnion(UserDescFlags)

struct UserDesc32 {
    uint32_t entry_number;
    uint32_t base_addr;
    uint32_t limit;
    uint32_t flags;
};

struct UserDesc64 {
    uint32_t entry_number;
    uint32_t __padding1;
    uint64_t base_addr;
    uint32_t limit;
    uint32_t flags;
};

static SyscallReturn
setThreadArea32Func(SyscallDesc *desc, int callnum,
                    Process *process, ThreadContext *tc)
{
    const int minTLSEntry = 6;
    const int numTLSEntries = 3;
    const int maxTLSEntry = minTLSEntry + numTLSEntries - 1;

    X86Process *x86p = dynamic_cast<X86Process *>(process);
    assert(x86p);

    assert((maxTLSEntry + 1) * sizeof(uint64_t) <= x86p->gdtSize());

    int argIndex = 0;
    TypedBufferArg<UserDesc32> userDesc(process->getSyscallArg(tc, argIndex));
    TypedBufferArg<uint64_t>
        gdt(x86p->gdtStart() + minTLSEntry * sizeof(uint64_t),
            numTLSEntries * sizeof(uint64_t));

    if (!userDesc.copyIn(tc->getMemProxy()))
        return -EFAULT;

    if (!gdt.copyIn(tc->getMemProxy()))
        panic("Failed to copy in GDT for %s.\n", desc->name());

    if (userDesc->entry_number == (uint32_t)(-1)) {
        // Find a free TLS entry.
        for (int i = 0; i < numTLSEntries; i++) {
            if (gdt[i] == 0) {
                userDesc->entry_number = i + minTLSEntry;
                break;
            }
        }
        // We failed to find one.
        if (userDesc->entry_number == (uint32_t)(-1))
            return -ESRCH;
    }

    int index = userDesc->entry_number;

    if (index < minTLSEntry || index > maxTLSEntry)
        return -EINVAL;

    index -= minTLSEntry;

    // Build the entry we're going to add.
    SegDescriptor segDesc = 0;
    UserDescFlags flags = userDesc->flags;

    segDesc.limitLow = bits(userDesc->limit, 15, 0);
    segDesc.baseLow = bits(userDesc->base_addr, 23, 0);
    segDesc.type.a = 1;
    if (!flags.read_exec_only)
        segDesc.type.w = 1;
    if (bits((uint8_t)flags.contents, 0))
        segDesc.type.e = 1;
    if (bits((uint8_t)flags.contents, 1))
        segDesc.type.codeOrData = 1;
    segDesc.s = 1;
    segDesc.dpl = 3;
    if (!flags.seg_not_present)
        segDesc.p = 1;
    segDesc.limitHigh = bits(userDesc->limit, 19, 16);
    if (flags.useable)
        segDesc.avl = 1;
    segDesc.l = 0;
    if (flags.seg_32bit)
        segDesc.d = 1;
    if (flags.limit_in_pages)
        segDesc.g = 1;
    segDesc.baseHigh = bits(userDesc->base_addr, 31, 24);

    gdt[index] = (uint64_t)segDesc;

    if (!userDesc.copyOut(tc->getMemProxy()))
        return -EFAULT;
    if (!gdt.copyOut(tc->getMemProxy()))
        panic("Failed to copy out GDT for %s.\n", desc->name());

    return 0;
}

static SyscallDesc syscallDescs64[] = {
    /*   0 */ SyscallDesc("read", readFunc),
    /*   1 */ SyscallDesc("write", writeFunc),
    /*   2 */ SyscallDesc("open", openFunc<X86Linux64>),
    /*   3 */ SyscallDesc("close", closeFunc),
    /*   4 */ SyscallDesc("stat", stat64Func<X86Linux64>),
    /*   5 */ SyscallDesc("fstat", fstat64Func<X86Linux64>),
    /*   6 */ SyscallDesc("lstat", lstat64Func<X86Linux64>),
    /*   7 */ SyscallDesc("poll", ignoreFunc),
    /*   8 */ SyscallDesc("lseek", lseekFunc),
    /*   9 */ SyscallDesc("mmap", mmapFunc<X86Linux64>),
    /*  10 */ SyscallDesc("mprotect", ignoreFunc),
    /*  11 */ SyscallDesc("munmap", munmapFunc),
    /*  12 */ SyscallDesc("brk", brkFunc),
    /*  13 */ SyscallDesc("rt_sigaction", ignoreFunc, SyscallDesc::WarnOnce),
    /*  14 */ SyscallDesc("rt_sigprocmask", ignoreFunc, SyscallDesc::WarnOnce),
    /*  15 */ SyscallDesc("rt_sigreturn", ignoreFunc),
    /*  16 */ SyscallDesc("ioctl", ioctlFunc<X86Linux64>),
    /*  17 */ SyscallDesc("pread64", ignoreFunc),
    /*  18 */ SyscallDesc("pwrite64", pwrite64Func<X86Linux64>),
    /*  19 */ SyscallDesc("readv", ignoreFunc),
    /*  20 */ SyscallDesc("writev", writevFunc<X86Linux64>),
    /*  21 */ SyscallDesc("access", ignoreFunc),
    /*  22 */ SyscallDesc("pipe", pipeFunc),
    /*  23 */ SyscallDesc("select", ignoreFunc),
    /*  24 */ SyscallDesc("sched_yield", ignoreFunc),
    /*  25 */ SyscallDesc("mremap", mremapFunc<X86Linux64>),
    /*  26 */ SyscallDesc("msync", ignoreFunc),
    /*  27 */ SyscallDesc("mincore", ignoreFunc),
    /*  28 */ SyscallDesc("madvise", ignoreFunc),
    /*  29 */ SyscallDesc("shmget", ignoreFunc),
    /*  30 */ SyscallDesc("shmat", ignoreFunc),
    /*  31 */ SyscallDesc("shmctl", ignoreFunc),
    /*  32 */ SyscallDesc("dup", dupFunc),
    /*  33 */ SyscallDesc("dup2", dup2Func),
    /*  34 */ SyscallDesc("pause", ignoreFunc),
    /*  35 */ SyscallDesc("nanosleep", ignoreFunc, SyscallDesc::WarnOnce),
    /*  36 */ SyscallDesc("getitimer", ignoreFunc),
    /*  37 */ SyscallDesc("alarm", ignoreFunc),
    /*  38 */ SyscallDesc("setitimer", ignoreFunc),
    /*  39 */ SyscallDesc("getpid", getpidFunc),
    /*  40 */ SyscallDesc("sendfile", ignoreFunc),
    /*  41 */ SyscallDesc("socket", ignoreFunc),
    /*  42 */ SyscallDesc("connect", ignoreFunc),
    /*  43 */ SyscallDesc("accept", ignoreFunc),
    /*  44 */ SyscallDesc("sendto", ignoreFunc),
    /*  45 */ SyscallDesc("recvfrom", ignoreFunc),
    /*  46 */ SyscallDesc("sendmsg", ignoreFunc),
    /*  47 */ SyscallDesc("recvmsg", ignoreFunc),
    /*  48 */ SyscallDesc("shutdown", ignoreFunc),
    /*  49 */ SyscallDesc("bind", ignoreFunc),
    /*  50 */ SyscallDesc("listen", ignoreFunc),
    /*  51 */ SyscallDesc("getsockname", ignoreFunc),
    /*  52 */ SyscallDesc("getpeername", ignoreFunc),
    /*  53 */ SyscallDesc("socketpair", ignoreFunc),
    /*  54 */ SyscallDesc("setsockopt", ignoreFunc),
    /*  55 */ SyscallDesc("getsockopt", ignoreFunc),
    /*  56 */ SyscallDesc("clone", cloneFunc<X86Linux64>),
    /*  57 */ SyscallDesc("fork", ignoreFunc),
    /*  58 */ SyscallDesc("vfork", ignoreFunc),
    /*  59 */ SyscallDesc("execve", execveFunc<X86Linux64>),
    /*  60 */ SyscallDesc("exit", exitFunc),
    /*  61 */ SyscallDesc("wait4", ignoreFunc),
    /*  62 */ SyscallDesc("kill", ignoreFunc),
    /*  63 */ SyscallDesc("uname", unameFunc),
    /*  64 */ SyscallDesc("semget", ignoreFunc),
    /*  65 */ SyscallDesc("semop", ignoreFunc),
    /*  66 */ SyscallDesc("semctl", ignoreFunc),
    /*  67 */ SyscallDesc("shmdt", ignoreFunc),
    /*  68 */ SyscallDesc("msgget", ignoreFunc),
    /*  69 */ SyscallDesc("msgsnd", ignoreFunc),
    /*  70 */ SyscallDesc("msgrcv", ignoreFunc),
    /*  71 */ SyscallDesc("msgctl", ignoreFunc),
    /*  72 */ SyscallDesc("fcntl", fcntlFunc),
    /*  73 */ SyscallDesc("flock", ignoreFunc),
    /*  74 */ SyscallDesc("fsync", ignoreFunc),
    /*  75 */ SyscallDesc("fdatasync", ignoreFunc),
    /*  76 */ SyscallDesc("truncate", truncateFunc),
    /*  77 */ SyscallDesc("ftruncate", ftruncateFunc),
    /*  78 */ SyscallDesc("getdents", ignoreFunc),
    /*  79 */ SyscallDesc("getcwd", getcwdFunc),
    /*  80 */ SyscallDesc("chdir", ignoreFunc),
    /*  81 */ SyscallDesc("fchdir", ignoreFunc),
    /*  82 */ SyscallDesc("rename", renameFunc),
    /*  83 */ SyscallDesc("mkdir", ignoreFunc),
    /*  84 */ SyscallDesc("rmdir", ignoreFunc),
    /*  85 */ SyscallDesc("creat", ignoreFunc),
    /*  86 */ SyscallDesc("link", ignoreFunc),
    /*  87 */ SyscallDesc("unlink", unlinkFunc),
    /*  88 */ SyscallDesc("symlink", ignoreFunc),
    /*  89 */ SyscallDesc("readlink", readlinkFunc),
    /*  90 */ SyscallDesc("chmod", ignoreFunc),
    /*  91 */ SyscallDesc("fchmod", ignoreFunc),
    /*  92 */ SyscallDesc("chown", ignoreFunc),
    /*  93 */ SyscallDesc("fchown", ignoreFunc),
    /*  94 */ SyscallDesc("lchown", ignoreFunc),
    /*  95 */ SyscallDesc("umask", ignoreFunc),
    /*  96 */ SyscallDesc("gettimeofday", gettimeofdayFunc<X86Linux64>),
    /*  97 */ SyscallDesc("getrlimit", getrlimitFunc<X86Linux64>),
    /*  98 */ SyscallDesc("getrusage", getrusageFunc<X86Linux64>),
    /*  99 */ SyscallDesc("sysinfo", sysinfoFunc<X86Linux64>),
    /* 100 */ SyscallDesc("times", timesFunc<X86Linux64>),
    /* 101 */ SyscallDesc("ptrace", ignoreFunc),
    /* 102 */ SyscallDesc("getuid", getuidFunc),
    /* 103 */ SyscallDesc("syslog", ignoreFunc),
    /* 104 */ SyscallDesc("getgid", getgidFunc),
    /* 105 */ SyscallDesc("setuid", ignoreFunc),
    /* 106 */ SyscallDesc("setgid", ignoreFunc),
    /* 107 */ SyscallDesc("geteuid", geteuidFunc),
    /* 108 */ SyscallDesc("getegid", getegidFunc),
    /* 109 */ SyscallDesc("setpgid", setpgidFunc),
    /* 110 */ SyscallDesc("getppid", getppidFunc),
    /* 111 */ SyscallDesc("getpgrp", ignoreFunc),
    /* 112 */ SyscallDesc("setsid", ignoreFunc),
    /* 113 */ SyscallDesc("setreuid", ignoreFunc),
    /* 114 */ SyscallDesc("setregid", ignoreFunc),
    /* 115 */ SyscallDesc("getgroups", ignoreFunc),
    /* 116 */ SyscallDesc("setgroups", ignoreFunc),
    /* 117 */ SyscallDesc("setresuid", ignoreFunc),
    /* 118 */ SyscallDesc("getresuid", ignoreFunc),
    /* 119 */ SyscallDesc("setresgid", ignoreFunc),
    /* 120 */ SyscallDesc("getresgid", ignoreFunc),
    /* 121 */ SyscallDesc("getpgid", ignoreFunc),
    /* 122 */ SyscallDesc("setfsuid", ignoreFunc),
    /* 123 */ SyscallDesc("setfsgid", ignoreFunc),
    /* 124 */ SyscallDesc("getsid", ignoreFunc),
    /* 125 */ SyscallDesc("capget", ignoreFunc),
    /* 126 */ SyscallDesc("capset", ignoreFunc),
    /* 127 */ SyscallDesc("rt_sigpending", ignoreFunc),
    /* 128 */ SyscallDesc("rt_sigtimedwait", ignoreFunc),
    /* 129 */ SyscallDesc("rt_sigqueueinfo", ignoreFunc),
    /* 130 */ SyscallDesc("rt_sigsuspend", ignoreFunc),
    /* 131 */ SyscallDesc("sigaltstack", ignoreFunc),
    /* 132 */ SyscallDesc("utime", ignoreFunc),
    /* 133 */ SyscallDesc("mknod", ignoreFunc),
    /* 134 */ SyscallDesc("uselib", ignoreFunc),
    /* 135 */ SyscallDesc("personality", ignoreFunc),
    /* 136 */ SyscallDesc("ustat", ignoreFunc),
    /* 137 */ SyscallDesc("statfs", statfsFunc<X86Linux64>),
    /* 138 */ SyscallDesc("fstatfs", ignoreFunc),
    /* 139 */ SyscallDesc("sysfs", ignoreFunc),
    /* 140 */ SyscallDesc("getpriority", ignoreFunc),
    /* 141 */ SyscallDesc("setpriority", ignoreFunc),
    /* 142 */ SyscallDesc("sched_setparam", ignoreFunc),
    /* 143 */ SyscallDesc("sched_getparam", ignoreFunc),
    /* 144 */ SyscallDesc("sched_setscheduler", ignoreFunc),
    /* 145 */ SyscallDesc("sched_getscheduler", ignoreFunc),
    /* 146 */ SyscallDesc("sched_get_priority_max", ignoreFunc),
    /* 147 */ SyscallDesc("sched_get_priority_min", ignoreFunc),
    /* 148 */ SyscallDesc("sched_rr_get_interval", ignoreFunc),
    /* 149 */ SyscallDesc("mlock", ignoreFunc),
    /* 150 */ SyscallDesc("munlock", ignoreFunc),
    /* 151 */ SyscallDesc("mlockall", ignoreFunc),
    /* 152 */ SyscallDesc("munlockall", ignoreFunc),
    /* 153 */ SyscallDesc("vhangup", ignoreFunc),
    /* 154 */ SyscallDesc("modify_ldt", ignoreFunc),
    /* 155 */ SyscallDesc("pivot_root", ignoreFunc),
    /* 156 */ SyscallDesc("_sysctl", ignoreFunc),
    /* 157 */ SyscallDesc("prctl", ignoreFunc),
    /* 158 */ SyscallDesc("arch_prctl", archPrctlFunc),
    /* 159 */ SyscallDesc("adjtimex", ignoreFunc),
    /* 160 */ SyscallDesc("setrlimit", ignoreFunc),
    /* 161 */ SyscallDesc("chroot", ignoreFunc),
    /* 162 */ SyscallDesc("sync", ignoreFunc),
    /* 163 */ SyscallDesc("acct", ignoreFunc),
    /* 164 */ SyscallDesc("settimeofday", ignoreFunc),
    /* 165 */ SyscallDesc("mount", ignoreFunc),
    /* 166 */ SyscallDesc("umount2", ignoreFunc),
    /* 167 */ SyscallDesc("swapon", ignoreFunc),
    /* 168 */ SyscallDesc("swapoff", ignoreFunc),
    /* 169 */ SyscallDesc("reboot", ignoreFunc),
    /* 170 */ SyscallDesc("sethostname", ignoreFunc),
    /* 171 */ SyscallDesc("setdomainname", ignoreFunc),
    /* 172 */ SyscallDesc("iopl", ignoreFunc),
    /* 173 */ SyscallDesc("ioperm", ignoreFunc),
    /* 174 */ SyscallDesc("create_module", ignoreFunc),
    /* 175 */ SyscallDesc("init_module", ignoreFunc),
    /* 176 */ SyscallDesc("delete_module", ignoreFunc),
    /* 177 */ SyscallDesc("get_kernel_syms", ignoreFunc),
    /* 178 */ SyscallDesc("query_module", ignoreFunc),
    /* 179 */ SyscallDesc("quotactl", ignoreFunc),
    /* 180 */ SyscallDesc("nfsservctl", ignoreFunc),
    /* 181 */ SyscallDesc("getpmsg", ignoreFunc),
    /* 182 */ SyscallDesc("putpmsg", ignoreFunc),
    /* 183 */ SyscallDesc("afs_syscall", ignoreFunc),
    /* 184 */ SyscallDesc("tuxcall", ignoreFunc),
    /* 185 */ SyscallDesc("security", ignoreFunc),
    /* 186 */ SyscallDesc("gettid", gettidFunc),
    /* 187 */ SyscallDesc("readahead", ignoreFunc),
    /* 188 */ SyscallDesc("setxattr", ignoreFunc),
    /* 189 */ SyscallDesc("lsetxattr", ignoreFunc),
    /* 190 */ SyscallDesc("fsetxattr", ignoreFunc),
    /* 191 */ SyscallDesc("getxattr", ignoreFunc),
    /* 192 */ SyscallDesc("lgetxattr", ignoreFunc),
    /* 193 */ SyscallDesc("fgetxattr", ignoreFunc),
    /* 194 */ SyscallDesc("listxattr", ignoreFunc),
    /* 195 */ SyscallDesc("llistxattr", ignoreFunc),
    /* 196 */ SyscallDesc("flistxattr", ignoreFunc),
    /* 197 */ SyscallDesc("removexattr", ignoreFunc),
    /* 198 */ SyscallDesc("lremovexattr", ignoreFunc),
    /* 199 */ SyscallDesc("fremovexattr", ignoreFunc),
    /* 200 */ SyscallDesc("tkill", ignoreFunc),
    /* 201 */ SyscallDesc("time", timeFunc<X86Linux64>),
    /* 202 */ SyscallDesc("futex", futexFunc<X86Linux64>),
    /* 203 */ SyscallDesc("sched_setaffinity", ignoreFunc),
    /* 204 */ SyscallDesc("sched_getaffinity", ignoreFunc),
    /* 205 */ SyscallDesc("set_thread_area", ignoreFunc),
    /* 206 */ SyscallDesc("io_setup", ignoreFunc),
    /* 207 */ SyscallDesc("io_destroy", ignoreFunc),
    /* 208 */ SyscallDesc("io_getevents", ignoreFunc),
    /* 209 */ SyscallDesc("io_submit", ignoreFunc),
    /* 210 */ SyscallDesc("io_cancel", ignoreFunc),
    /* 211 */ SyscallDesc("get_thread_area", ignoreFunc),
    /* 212 */ SyscallDesc("lookup_dcookie", ignoreFunc),
    /* 213 */ SyscallDesc("epoll_create", ignoreFunc),
    /* 214 */ SyscallDesc("epoll_ctl_old", ignoreFunc),
    /* 215 */ SyscallDesc("epoll_wait_old", ignoreFunc),
    /* 216 */ SyscallDesc("remap_file_pages", ignoreFunc),
    /* 217 */ SyscallDesc("getdents64", ignoreFunc),
    /* 218 */ SyscallDesc("set_tid_address", setTidAddressFunc),
    /* 219 */ SyscallDesc("restart_syscall", ignoreFunc),
    /* 220 */ SyscallDesc("semtimedop", ignoreFunc),
    /* 221 */ SyscallDesc("fadvise64", ignoreFunc),
    /* 222 */ SyscallDesc("timer_create", ignoreFunc),
    /* 223 */ SyscallDesc("timer_settime", ignoreFunc),
    /* 224 */ SyscallDesc("timer_gettime", ignoreFunc),
    /* 225 */ SyscallDesc("timer_getoverrun", ignoreFunc),
    /* 226 */ SyscallDesc("timer_delete", ignoreFunc),
    /* 227 */ SyscallDesc("clock_settime", ignoreFunc),
    /* 228 */ SyscallDesc("clock_gettime", clock_gettimeFunc<X86Linux64>),
    /* 229 */ SyscallDesc("clock_getres", clock_getresFunc<X86Linux64>),
    /* 230 */ SyscallDesc("clock_nanosleep", ignoreFunc),
    /* 231 */ SyscallDesc("exit_group", exitGroupFunc),
    /* 232 */ SyscallDesc("epoll_wait", ignoreFunc),
    /* 233 */ SyscallDesc("epoll_ctl", ignoreFunc),
    /* 234 */ SyscallDesc("tgkill", tgkillFunc<X86Linux64>),
    /* 235 */ SyscallDesc("utimes", ignoreFunc),
    /* 236 */ SyscallDesc("vserver", ignoreFunc),
    /* 237 */ SyscallDesc("mbind", ignoreFunc),
    /* 238 */ SyscallDesc("set_mempolicy", ignoreFunc),
    /* 239 */ SyscallDesc("get_mempolicy", ignoreFunc),
    /* 240 */ SyscallDesc("mq_open", ignoreFunc),
    /* 241 */ SyscallDesc("mq_unlink", ignoreFunc),
    /* 242 */ SyscallDesc("mq_timedsend", ignoreFunc),
    /* 243 */ SyscallDesc("mq_timedreceive", ignoreFunc),
    /* 244 */ SyscallDesc("mq_notify", ignoreFunc),
    /* 245 */ SyscallDesc("mq_getsetattr", ignoreFunc),
    /* 246 */ SyscallDesc("kexec_load", ignoreFunc),
    /* 247 */ SyscallDesc("waitid", ignoreFunc),
    /* 248 */ SyscallDesc("add_key", ignoreFunc),
    /* 249 */ SyscallDesc("request_key", ignoreFunc),
    /* 250 */ SyscallDesc("keyctl", ignoreFunc),
    /* 251 */ SyscallDesc("ioprio_set", ignoreFunc),
    /* 252 */ SyscallDesc("ioprio_get", ignoreFunc),
    /* 253 */ SyscallDesc("inotify_init", ignoreFunc),
    /* 254 */ SyscallDesc("inotify_add_watch", ignoreFunc),
    /* 255 */ SyscallDesc("inotify_rm_watch", ignoreFunc),
    /* 256 */ SyscallDesc("migrate_pages", ignoreFunc),
    /* 257 */ SyscallDesc("openat", openatFunc<X86Linux64>),
    /* 258 */ SyscallDesc("mkdirat", ignoreFunc),
    /* 259 */ SyscallDesc("mknodat", ignoreFunc),
    /* 260 */ SyscallDesc("fchownat", ignoreFunc),
    /* 261 */ SyscallDesc("futimesat", ignoreFunc),
    /* 262 */ SyscallDesc("newfstatat", ignoreFunc),
    /* 263 */ SyscallDesc("unlinkat", ignoreFunc),
    /* 264 */ SyscallDesc("renameat", ignoreFunc),
    /* 265 */ SyscallDesc("linkat", ignoreFunc),
    /* 266 */ SyscallDesc("symlinkat", ignoreFunc),
    /* 267 */ SyscallDesc("readlinkat", readlinkFunc),
    /* 268 */ SyscallDesc("fchmodat", ignoreFunc),
    /* 269 */ SyscallDesc("faccessat", ignoreFunc),
    /* 270 */ SyscallDesc("pselect6", ignoreFunc),
    /* 271 */ SyscallDesc("ppoll", ignoreFunc),
    /* 272 */ SyscallDesc("unshare", ignoreFunc),
    /* 273 */ SyscallDesc("set_robust_list", ignoreFunc),
    /* 274 */ SyscallDesc("get_robust_list", ignoreFunc),
    /* 275 */ SyscallDesc("splice", ignoreFunc),
    /* 276 */ SyscallDesc("tee", ignoreFunc),
    /* 277 */ SyscallDesc("sync_file_range", ignoreFunc),
    /* 278 */ SyscallDesc("vmsplice", ignoreFunc),
    /* 279 */ SyscallDesc("move_pages", ignoreFunc),
    /* 280 */ SyscallDesc("utimensat", ignoreFunc),
    /* 281 */ SyscallDesc("epoll_pwait", ignoreFunc),
    /* 282 */ SyscallDesc("signalfd", ignoreFunc),
    /* 283 */ SyscallDesc("timerfd_create", ignoreFunc),
    /* 284 */ SyscallDesc("eventfd", ignoreFunc),
    /* 285 */ SyscallDesc("fallocate", fallocateFunc),
    /* 286 */ SyscallDesc("timerfd_settime", ignoreFunc),
    /* 287 */ SyscallDesc("timerfd_gettime", ignoreFunc),
    /* 288 */ SyscallDesc("accept4", ignoreFunc),
    /* 289 */ SyscallDesc("signalfd4", ignoreFunc),
    /* 290 */ SyscallDesc("eventfd2", ignoreFunc),
    /* 291 */ SyscallDesc("epoll_create1", ignoreFunc),
    /* 292 */ SyscallDesc("dup3", ignoreFunc),
    /* 293 */ SyscallDesc("pipe2", ignoreFunc),
    /* 294 */ SyscallDesc("inotify_init1", ignoreFunc),
    /* 295 */ SyscallDesc("preadv", ignoreFunc),
    /* 296 */ SyscallDesc("pwritev", ignoreFunc),
    /* 297 */ SyscallDesc("rt_tgsigqueueinfo", ignoreFunc),
    /* 298 */ SyscallDesc("perf_event_open", ignoreFunc),
    /* 299 */ SyscallDesc("recvmmsg", ignoreFunc),
    /* 300 */ SyscallDesc("fanotify_init", ignoreFunc),
    /* 301 */ SyscallDesc("fanotify_mark", ignoreFunc),
    /* 302 */ SyscallDesc("prlimit64", ignoreFunc),
    /* 303 */ SyscallDesc("name_to_handle_at", ignoreFunc),
    /* 304 */ SyscallDesc("open_by_handle_at", ignoreFunc),
    /* 305 */ SyscallDesc("clock_adjtime", ignoreFunc),
    /* 306 */ SyscallDesc("syncfs", ignoreFunc),
    /* 307 */ SyscallDesc("sendmmsg", ignoreFunc),
    /* 308 */ SyscallDesc("setns", ignoreFunc),
    /* 309 */ SyscallDesc("getcpu", ignoreFunc),
    /* 310 */ SyscallDesc("proess_vm_readv", ignoreFunc),
    /* 311 */ SyscallDesc("proess_vm_writev", ignoreFunc),
    /* 312 */ SyscallDesc("kcmp", ignoreFunc),
    /* 313 */ SyscallDesc("finit_module", ignoreFunc),
};

X86_64LinuxProcess::X86_64LinuxProcess(ProcessParams * params,
                                       ObjectFile *objFile)
    : X86_64Process(params, objFile, syscallDescs64,
                    sizeof(syscallDescs64) / sizeof(SyscallDesc))
{}

void X86_64LinuxProcess::clone(ThreadContext *old_tc, ThreadContext *new_tc,
                               Process *process, TheISA::IntReg flags)
{
    X86_64Process::clone(old_tc, new_tc, (X86_64Process*)process, flags);
}

static SyscallDesc syscallDescs32[] = {
    /*   0 */ SyscallDesc("restart_syscall", ignoreFunc),
    /*   1 */ SyscallDesc("exit", exitFunc),
    /*   2 */ SyscallDesc("fork", ignoreFunc),
    /*   3 */ SyscallDesc("read", readFunc),
    /*   4 */ SyscallDesc("write", writeFunc),
    /*   5 */ SyscallDesc("open", openFunc<X86Linux32>),
    /*   6 */ SyscallDesc("close", closeFunc),
    /*   7 */ SyscallDesc("waitpid", ignoreFunc),
    /*   8 */ SyscallDesc("creat", ignoreFunc),
    /*   9 */ SyscallDesc("link", ignoreFunc),
    /*  10 */ SyscallDesc("unlink", ignoreFunc),
    /*  11 */ SyscallDesc("execve", execveFunc<X86Linux32>),
    /*  12 */ SyscallDesc("chdir", ignoreFunc),
    /*  13 */ SyscallDesc("time", timeFunc<X86Linux32>),
    /*  14 */ SyscallDesc("mknod", ignoreFunc),
    /*  15 */ SyscallDesc("chmod", ignoreFunc),
    /*  16 */ SyscallDesc("lchown", ignoreFunc),
    /*  17 */ SyscallDesc("break", ignoreFunc),
    /*  18 */ SyscallDesc("oldstat", ignoreFunc),
    /*  19 */ SyscallDesc("lseek", ignoreFunc),
    /*  20 */ SyscallDesc("getpid", getpidFunc),
    /*  21 */ SyscallDesc("mount", ignoreFunc),
    /*  22 */ SyscallDesc("umount", ignoreFunc),
    /*  23 */ SyscallDesc("setuid", ignoreFunc),
    /*  24 */ SyscallDesc("getuid", getuidFunc),
    /*  25 */ SyscallDesc("stime", ignoreFunc),
    /*  26 */ SyscallDesc("ptrace", ignoreFunc),
    /*  27 */ SyscallDesc("alarm", ignoreFunc),
    /*  28 */ SyscallDesc("oldfstat", ignoreFunc),
    /*  29 */ SyscallDesc("pause", ignoreFunc),
    /*  30 */ SyscallDesc("utime", ignoreFunc),
    /*  31 */ SyscallDesc("stty", ignoreFunc),
    /*  32 */ SyscallDesc("gtty", ignoreFunc),
    /*  33 */ SyscallDesc("access", ignoreFunc),
    /*  34 */ SyscallDesc("nice", ignoreFunc),
    /*  35 */ SyscallDesc("ftime", ignoreFunc),
    /*  36 */ SyscallDesc("sync", ignoreFunc),
    /*  37 */ SyscallDesc("kill", ignoreFunc),
    /*  38 */ SyscallDesc("rename", ignoreFunc),
    /*  39 */ SyscallDesc("mkdir", ignoreFunc),
    /*  40 */ SyscallDesc("rmdir", ignoreFunc),
    /*  41 */ SyscallDesc("dup", dupFunc),
    /*  42 */ SyscallDesc("pipe", pipeFunc),
    /*  43 */ SyscallDesc("times", timesFunc<X86Linux32>),
    /*  44 */ SyscallDesc("prof", ignoreFunc),
    /*  45 */ SyscallDesc("brk", brkFunc),
    /*  46 */ SyscallDesc("setgid", ignoreFunc),
    /*  47 */ SyscallDesc("getgid", getgidFunc),
    /*  48 */ SyscallDesc("signal", ignoreFunc),
    /*  49 */ SyscallDesc("geteuid", geteuidFunc),
    /*  50 */ SyscallDesc("getegid", getegidFunc),
    /*  51 */ SyscallDesc("acct", ignoreFunc),
    /*  52 */ SyscallDesc("umount2", ignoreFunc),
    /*  53 */ SyscallDesc("lock", ignoreFunc),
    /*  54 */ SyscallDesc("ioctl", ioctlFunc<X86Linux32>),
    /*  55 */ SyscallDesc("fcntl", fcntlFunc),
    /*  56 */ SyscallDesc("mpx", ignoreFunc),
    /*  57 */ SyscallDesc("setpgid", setpgidFunc),
    /*  58 */ SyscallDesc("ulimit", ignoreFunc),
    /*  59 */ SyscallDesc("oldolduname", ignoreFunc),
    /*  60 */ SyscallDesc("umask", ignoreFunc),
    /*  61 */ SyscallDesc("chroot", ignoreFunc),
    /*  62 */ SyscallDesc("ustat", ignoreFunc),
    /*  63 */ SyscallDesc("dup2", dup2Func),
    /*  64 */ SyscallDesc("getppid", ignoreFunc),
    /*  65 */ SyscallDesc("getpgrp", ignoreFunc),
    /*  66 */ SyscallDesc("setsid", ignoreFunc),
    /*  67 */ SyscallDesc("sigaction", ignoreFunc),
    /*  68 */ SyscallDesc("sgetmask", ignoreFunc),
    /*  69 */ SyscallDesc("ssetmask", ignoreFunc),
    /*  70 */ SyscallDesc("setreuid", ignoreFunc),
    /*  71 */ SyscallDesc("setregid", ignoreFunc),
    /*  72 */ SyscallDesc("sigsuspend", ignoreFunc),
    /*  73 */ SyscallDesc("sigpending", ignoreFunc),
    /*  74 */ SyscallDesc("sethostname", ignoreFunc),
    /*  75 */ SyscallDesc("setrlimit", ignoreFunc),
    /*  76 */ SyscallDesc("getrlimit", getrlimitFunc<X86Linux32>),
    /*  77 */ SyscallDesc("getrusage", getrusageFunc<X86Linux32>),
    /*  78 */ SyscallDesc("gettimeofday", ignoreFunc),
    /*  79 */ SyscallDesc("settimeofday", ignoreFunc),
    /*  80 */ SyscallDesc("getgroups", ignoreFunc),
    /*  81 */ SyscallDesc("setgroups", ignoreFunc),
    /*  82 */ SyscallDesc("select", ignoreFunc),
    /*  83 */ SyscallDesc("symlink", ignoreFunc),
    /*  84 */ SyscallDesc("oldlstat", ignoreFunc),
    /*  85 */ SyscallDesc("readlink", readlinkFunc),
    /*  86 */ SyscallDesc("uselib", ignoreFunc),
    /*  87 */ SyscallDesc("swapon", ignoreFunc),
    /*  88 */ SyscallDesc("reboot", ignoreFunc),
    /*  89 */ SyscallDesc("readdir", ignoreFunc),
    /*  90 */ SyscallDesc("mmap", ignoreFunc),
    /*  91 */ SyscallDesc("munmap", munmapFunc),
    /*  92 */ SyscallDesc("truncate", truncateFunc),
    /*  93 */ SyscallDesc("ftruncate", ftruncateFunc),
    /*  94 */ SyscallDesc("fchmod", ignoreFunc),
    /*  95 */ SyscallDesc("fchown", ignoreFunc),
    /*  96 */ SyscallDesc("getpriority", ignoreFunc),
    /*  97 */ SyscallDesc("setpriority", ignoreFunc),
    /*  98 */ SyscallDesc("profil", ignoreFunc),
    /*  99 */ SyscallDesc("statfs", ignoreFunc),
    /* 100 */ SyscallDesc("fstatfs", ignoreFunc),
    /* 101 */ SyscallDesc("ioperm", ignoreFunc),
    /* 102 */ SyscallDesc("socketcall", ignoreFunc),
    /* 103 */ SyscallDesc("syslog", ignoreFunc),
    /* 104 */ SyscallDesc("setitimer", ignoreFunc),
    /* 105 */ SyscallDesc("getitimer", ignoreFunc),
    /* 106 */ SyscallDesc("stat", ignoreFunc),
    /* 107 */ SyscallDesc("lstat", ignoreFunc),
    /* 108 */ SyscallDesc("fstat", ignoreFunc),
    /* 109 */ SyscallDesc("olduname", ignoreFunc),
    /* 110 */ SyscallDesc("iopl", ignoreFunc),
    /* 111 */ SyscallDesc("vhangup", ignoreFunc),
    /* 112 */ SyscallDesc("idle", ignoreFunc),
    /* 113 */ SyscallDesc("vm86old", ignoreFunc),
    /* 114 */ SyscallDesc("wait4", ignoreFunc),
    /* 115 */ SyscallDesc("swapoff", ignoreFunc),
    /* 116 */ SyscallDesc("sysinfo", sysinfoFunc<X86Linux32>),
    /* 117 */ SyscallDesc("ipc", ignoreFunc),
    /* 118 */ SyscallDesc("fsync", ignoreFunc),
    /* 119 */ SyscallDesc("sigreturn", ignoreFunc),
    /* 120 */ SyscallDesc("clone", cloneFunc<X86Linux32>),
    /* 121 */ SyscallDesc("setdomainname", ignoreFunc),
    /* 122 */ SyscallDesc("uname", unameFunc),
    /* 123 */ SyscallDesc("modify_ldt", ignoreFunc),
    /* 124 */ SyscallDesc("adjtimex", ignoreFunc),
    /* 125 */ SyscallDesc("mprotect", ignoreFunc),
    /* 126 */ SyscallDesc("sigprocmask", ignoreFunc),
    /* 127 */ SyscallDesc("create_module", ignoreFunc),
    /* 128 */ SyscallDesc("init_module", ignoreFunc),
    /* 129 */ SyscallDesc("delete_module", ignoreFunc),
    /* 130 */ SyscallDesc("get_kernel_syms", ignoreFunc),
    /* 131 */ SyscallDesc("quotactl", ignoreFunc),
    /* 132 */ SyscallDesc("getpgid", ignoreFunc),
    /* 133 */ SyscallDesc("fchdir", ignoreFunc),
    /* 134 */ SyscallDesc("bdflush", ignoreFunc),
    /* 135 */ SyscallDesc("sysfs", ignoreFunc),
    /* 136 */ SyscallDesc("personality", ignoreFunc),
    /* 137 */ SyscallDesc("afs_syscall", ignoreFunc),
    /* 138 */ SyscallDesc("setfsuid", ignoreFunc),
    /* 139 */ SyscallDesc("setfsgid", ignoreFunc),
    /* 140 */ SyscallDesc("_llseek", _llseekFunc),
    /* 141 */ SyscallDesc("getdents", ignoreFunc),
    /* 142 */ SyscallDesc("_newselect", ignoreFunc),
    /* 143 */ SyscallDesc("flock", ignoreFunc),
    /* 144 */ SyscallDesc("msync", ignoreFunc),
    /* 145 */ SyscallDesc("readv", ignoreFunc),
    /* 146 */ SyscallDesc("writev", writevFunc<X86Linux32>),
    /* 147 */ SyscallDesc("getsid", ignoreFunc),
    /* 148 */ SyscallDesc("fdatasync", ignoreFunc),
    /* 149 */ SyscallDesc("_sysctl", ignoreFunc),
    /* 150 */ SyscallDesc("mlock", ignoreFunc),
    /* 151 */ SyscallDesc("munlock", ignoreFunc),
    /* 152 */ SyscallDesc("mlockall", ignoreFunc),
    /* 153 */ SyscallDesc("munlockall", ignoreFunc),
    /* 154 */ SyscallDesc("sched_setparam", ignoreFunc),
    /* 155 */ SyscallDesc("sched_getparam", ignoreFunc),
    /* 156 */ SyscallDesc("sched_setscheduler", ignoreFunc),
    /* 157 */ SyscallDesc("sched_getscheduler", ignoreFunc),
    /* 158 */ SyscallDesc("sched_yield", ignoreFunc),
    /* 159 */ SyscallDesc("sched_get_priority_max", ignoreFunc),
    /* 160 */ SyscallDesc("sched_get_priority_min", ignoreFunc),
    /* 161 */ SyscallDesc("sched_rr_get_interval", ignoreFunc),
    /* 162 */ SyscallDesc("nanosleep", ignoreFunc),
    /* 163 */ SyscallDesc("mremap", ignoreFunc),
    /* 164 */ SyscallDesc("setresuid", ignoreFunc),
    /* 165 */ SyscallDesc("getresuid", ignoreFunc),
    /* 166 */ SyscallDesc("vm86", ignoreFunc),
    /* 167 */ SyscallDesc("query_module", ignoreFunc),
    /* 168 */ SyscallDesc("poll", ignoreFunc),
    /* 169 */ SyscallDesc("nfsservctl", ignoreFunc),
    /* 170 */ SyscallDesc("setresgid", ignoreFunc),
    /* 171 */ SyscallDesc("getresgid", ignoreFunc),
    /* 172 */ SyscallDesc("prctl", ignoreFunc),
    /* 173 */ SyscallDesc("rt_sigreturn", ignoreFunc),
    /* 174 */ SyscallDesc("rt_sigaction", ignoreFunc),
    /* 175 */ SyscallDesc("rt_sigprocmask", ignoreFunc),
    /* 176 */ SyscallDesc("rt_sigpending", ignoreFunc),
    /* 177 */ SyscallDesc("rt_sigtimedwait", ignoreFunc),
    /* 178 */ SyscallDesc("rt_sigqueueinfo", ignoreFunc),
    /* 179 */ SyscallDesc("rt_sigsuspend", ignoreFunc),
    /* 180 */ SyscallDesc("pread64", ignoreFunc),
    /* 181 */ SyscallDesc("pwrite64", ignoreFunc),
    /* 182 */ SyscallDesc("chown", ignoreFunc),
    /* 183 */ SyscallDesc("getcwd", getcwdFunc),
    /* 184 */ SyscallDesc("capget", ignoreFunc),
    /* 185 */ SyscallDesc("capset", ignoreFunc),
    /* 186 */ SyscallDesc("sigaltstack", ignoreFunc),
    /* 187 */ SyscallDesc("sendfile", ignoreFunc),
    /* 188 */ SyscallDesc("getpmsg", ignoreFunc),
    /* 189 */ SyscallDesc("putpmsg", ignoreFunc),
    /* 190 */ SyscallDesc("vfork", ignoreFunc),
    /* 191 */ SyscallDesc("ugetrlimit", ignoreFunc),
    /* 192 */ SyscallDesc("mmap2", mmap2Func<X86Linux32>),
    /* 193 */ SyscallDesc("truncate64", truncate64Func),
    /* 194 */ SyscallDesc("ftruncate64", ftruncate64Func),
    /* 195 */ SyscallDesc("stat64", stat64Func<X86Linux32>),
    /* 196 */ SyscallDesc("lstat64", ignoreFunc),
    /* 197 */ SyscallDesc("fstat64", fstat64Func<X86Linux32>),
    /* 198 */ SyscallDesc("lchown32", ignoreFunc),
    /* 199 */ SyscallDesc("getuid32", getuidFunc),
    /* 200 */ SyscallDesc("getgid32", getgidFunc),
    /* 201 */ SyscallDesc("geteuid32", geteuidFunc),
    /* 202 */ SyscallDesc("getegid32", getegidFunc),
    /* 203 */ SyscallDesc("setreuid32", ignoreFunc),
    /* 204 */ SyscallDesc("setregid32", ignoreFunc),
    /* 205 */ SyscallDesc("getgroups32", ignoreFunc),
    /* 206 */ SyscallDesc("setgroups32", ignoreFunc),
    /* 207 */ SyscallDesc("fchown32", ignoreFunc),
    /* 208 */ SyscallDesc("setresuid32", ignoreFunc),
    /* 209 */ SyscallDesc("getresuid32", ignoreFunc),
    /* 210 */ SyscallDesc("setresgid32", ignoreFunc),
    /* 211 */ SyscallDesc("getresgid32", ignoreFunc),
    /* 212 */ SyscallDesc("chown32", ignoreFunc),
    /* 213 */ SyscallDesc("setuid32", ignoreFunc),
    /* 214 */ SyscallDesc("setgid32", ignoreFunc),
    /* 215 */ SyscallDesc("setfsuid32", ignoreFunc),
    /* 216 */ SyscallDesc("setfsgid32", ignoreFunc),
    /* 217 */ SyscallDesc("pivot_root", ignoreFunc),
    /* 218 */ SyscallDesc("mincore", ignoreFunc),
    /* 219 */ SyscallDesc("madvise", ignoreFunc),
    /* 220 */ SyscallDesc("madvise1", ignoreFunc),
    /* 221 */ SyscallDesc("getdents64", ignoreFunc),
    /* 222 */ SyscallDesc("fcntl64", ignoreFunc),
    /* 223 */ SyscallDesc("unused", ignoreFunc),
    /* 224 */ SyscallDesc("gettid", gettidFunc),
    /* 225 */ SyscallDesc("readahead", ignoreFunc),
    /* 226 */ SyscallDesc("setxattr", ignoreFunc),
    /* 227 */ SyscallDesc("lsetxattr", ignoreFunc),
    /* 228 */ SyscallDesc("fsetxattr", ignoreFunc),
    /* 229 */ SyscallDesc("getxattr", ignoreFunc),
    /* 230 */ SyscallDesc("lgetxattr", ignoreFunc),
    /* 231 */ SyscallDesc("fgetxattr", ignoreFunc),
    /* 232 */ SyscallDesc("listxattr", ignoreFunc),
    /* 233 */ SyscallDesc("llistxattr", ignoreFunc),
    /* 234 */ SyscallDesc("flistxattr", ignoreFunc),
    /* 235 */ SyscallDesc("removexattr", ignoreFunc),
    /* 236 */ SyscallDesc("lremovexattr", ignoreFunc),
    /* 237 */ SyscallDesc("fremovexattr", ignoreFunc),
    /* 238 */ SyscallDesc("tkill", ignoreFunc),
    /* 239 */ SyscallDesc("sendfile64", ignoreFunc),
    /* 240 */ SyscallDesc("futex", ignoreFunc),
    /* 241 */ SyscallDesc("sched_setaffinity", ignoreFunc),
    /* 242 */ SyscallDesc("sched_getaffinity", ignoreFunc),
    /* 243 */ SyscallDesc("set_thread_area", setThreadArea32Func),
    /* 244 */ SyscallDesc("get_thread_area", ignoreFunc),
    /* 245 */ SyscallDesc("io_setup", ignoreFunc),
    /* 246 */ SyscallDesc("io_destroy", ignoreFunc),
    /* 247 */ SyscallDesc("io_getevents", ignoreFunc),
    /* 248 */ SyscallDesc("io_submit", ignoreFunc),
    /* 249 */ SyscallDesc("io_cancel", ignoreFunc),
    /* 250 */ SyscallDesc("fadvise64", ignoreFunc),
    /* 251 */ SyscallDesc("unused", ignoreFunc),
    /* 252 */ SyscallDesc("exit_group", exitFunc),
    /* 253 */ SyscallDesc("lookup_dcookie", ignoreFunc),
    /* 254 */ SyscallDesc("epoll_create", ignoreFunc),
    /* 255 */ SyscallDesc("epoll_ctl", ignoreFunc),
    /* 256 */ SyscallDesc("epoll_wait", ignoreFunc),
    /* 257 */ SyscallDesc("remap_file_pages", ignoreFunc),
    /* 258 */ SyscallDesc("set_tid_address", setTidAddressFunc),
    /* 259 */ SyscallDesc("timer_create", ignoreFunc),
    /* 260 */ SyscallDesc("timer_settime", ignoreFunc),
    /* 261 */ SyscallDesc("timer_gettime", ignoreFunc),
    /* 262 */ SyscallDesc("timer_getoverrun", ignoreFunc),
    /* 263 */ SyscallDesc("timer_delete", ignoreFunc),
    /* 264 */ SyscallDesc("clock_settime", ignoreFunc),
    /* 265 */ SyscallDesc("clock_gettime", clock_gettimeFunc<X86Linux32>),
    /* 266 */ SyscallDesc("clock_getres", ignoreFunc),
    /* 267 */ SyscallDesc("clock_nanosleep", ignoreFunc),
    /* 268 */ SyscallDesc("statfs64", ignoreFunc),
    /* 269 */ SyscallDesc("fstatfs64", ignoreFunc),
    /* 270 */ SyscallDesc("tgkill", tgkillFunc<X86Linux32>),
    /* 271 */ SyscallDesc("utimes", ignoreFunc),
    /* 272 */ SyscallDesc("fadvise64_64", ignoreFunc),
    /* 273 */ SyscallDesc("vserver", ignoreFunc),
    /* 274 */ SyscallDesc("mbind", ignoreFunc),
    /* 275 */ SyscallDesc("get_mempolicy", ignoreFunc),
    /* 276 */ SyscallDesc("set_mempolicy", ignoreFunc),
    /* 277 */ SyscallDesc("mq_open", ignoreFunc),
    /* 278 */ SyscallDesc("mq_unlink", ignoreFunc),
    /* 279 */ SyscallDesc("mq_timedsend", ignoreFunc),
    /* 280 */ SyscallDesc("mq_timedreceive", ignoreFunc),
    /* 281 */ SyscallDesc("mq_notify", ignoreFunc),
    /* 282 */ SyscallDesc("mq_getsetattr", ignoreFunc),
    /* 283 */ SyscallDesc("kexec_load", ignoreFunc),
    /* 284 */ SyscallDesc("waitid", ignoreFunc),
    /* 285 */ SyscallDesc("sys_setaltroot", ignoreFunc),
    /* 286 */ SyscallDesc("add_key", ignoreFunc),
    /* 287 */ SyscallDesc("request_key", ignoreFunc),
    /* 288 */ SyscallDesc("keyctl", ignoreFunc),
    /* 289 */ SyscallDesc("ioprio_set", ignoreFunc),
    /* 290 */ SyscallDesc("ioprio_get", ignoreFunc),
    /* 291 */ SyscallDesc("inotify_init", ignoreFunc),
    /* 292 */ SyscallDesc("inotify_add_watch", ignoreFunc),
    /* 293 */ SyscallDesc("inotify_rm_watch", ignoreFunc),
    /* 294 */ SyscallDesc("migrate_pages", ignoreFunc),
    /* 295 */ SyscallDesc("openat", openatFunc<X86Linux32>),
    /* 296 */ SyscallDesc("mkdirat", ignoreFunc),
    /* 297 */ SyscallDesc("mknodat", ignoreFunc),
    /* 298 */ SyscallDesc("fchownat", ignoreFunc),
    /* 299 */ SyscallDesc("futimesat", ignoreFunc),
    /* 300 */ SyscallDesc("fstatat64", ignoreFunc),
    /* 301 */ SyscallDesc("unlinkat", ignoreFunc),
    /* 302 */ SyscallDesc("renameat", ignoreFunc),
    /* 303 */ SyscallDesc("linkat", ignoreFunc),
    /* 304 */ SyscallDesc("symlinkat", ignoreFunc),
    /* 305 */ SyscallDesc("readlinkat", readlinkFunc),
    /* 306 */ SyscallDesc("fchmodat", ignoreFunc),
    /* 307 */ SyscallDesc("faccessat", ignoreFunc),
    /* 308 */ SyscallDesc("pselect6", ignoreFunc),
    /* 309 */ SyscallDesc("ppoll", ignoreFunc),
    /* 310 */ SyscallDesc("unshare", ignoreFunc),
    /* 311 */ SyscallDesc("set_robust_list", ignoreFunc),
    /* 312 */ SyscallDesc("get_robust_list", ignoreFunc),
    /* 313 */ SyscallDesc("splice", ignoreFunc),
    /* 314 */ SyscallDesc("sync_file_range", ignoreFunc),
    /* 315 */ SyscallDesc("tee", ignoreFunc),
    /* 316 */ SyscallDesc("vmsplice", ignoreFunc),
    /* 317 */ SyscallDesc("move_pages", ignoreFunc),
    /* 318 */ SyscallDesc("getcpu", ignoreFunc),
    /* 319 */ SyscallDesc("epoll_pwait", ignoreFunc),
    /* 320 */ SyscallDesc("utimensat", ignoreFunc),
    /* 321 */ SyscallDesc("signalfd", ignoreFunc),
    /* 322 */ SyscallDesc("timerfd", ignoreFunc),
    /* 323 */ SyscallDesc("eventfd", ignoreFunc)
};

I386LinuxProcess::I386LinuxProcess(ProcessParams * params, ObjectFile *objFile)
    : I386Process(params, objFile, syscallDescs32,
                  sizeof(syscallDescs32) / sizeof(SyscallDesc))
{}

void I386LinuxProcess::clone(ThreadContext *old_tc, ThreadContext *new_tc,
                             Process *process, TheISA::IntReg flags)
{
    I386Process::clone(old_tc, new_tc, (I386Process*)process, flags);
}
