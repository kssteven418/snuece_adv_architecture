/*
 * Copyright (c) 2003-2005 The Regents of The University of Michigan
 * All rights reserved.
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
 * Authors: Steve Reinhardt
 *          Ali Saidi
 */

#include "arch/alpha/linux/process.hh"

#include "arch/alpha/isa_traits.hh"
#include "arch/alpha/linux/linux.hh"
#include "base/trace.hh"
#include "cpu/thread_context.hh"
#include "debug/SyscallVerbose.hh"
#include "kern/linux/linux.hh"
#include "sim/process.hh"
#include "sim/syscall_desc.hh"
#include "sim/syscall_emul.hh"

using namespace std;
using namespace AlphaISA;

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
    strcpy(name->machine, "alpha");

    name.copyOut(tc->getMemProxy());
    return 0;
}

/// Target osf_getsysyinfo() handler.  Even though this call is
/// borrowed from Tru64, the subcases that get used appear to be
/// different in practice from those used by Tru64 processes.
static SyscallReturn
osf_getsysinfoFunc(SyscallDesc *desc, int callnum, Process *process,
                   ThreadContext *tc)
{
    int index = 0;
    unsigned op = process->getSyscallArg(tc, index);
    Addr bufPtr = process->getSyscallArg(tc, index);
    // unsigned nbytes = process->getSyscallArg(tc, 2);

    switch (op) {

      case 45: { // GSI_IEEE_FP_CONTROL
          TypedBufferArg<uint64_t> fpcr(bufPtr);
          // I don't think this exactly matches the HW FPCR
          *fpcr = 0;
          fpcr.copyOut(tc->getMemProxy());
          return 0;
      }

      default:
        cerr << "osf_getsysinfo: unknown op " << op << endl;
        abort();
        break;
    }

    return 1;
}

/// Target osf_setsysinfo() handler.
static SyscallReturn
osf_setsysinfoFunc(SyscallDesc *desc, int callnum, Process *process,
                   ThreadContext *tc)
{
    int index = 0;
    unsigned op = process->getSyscallArg(tc, index);
    Addr bufPtr = process->getSyscallArg(tc, index);
    // unsigned nbytes = process->getSyscallArg(tc, 2);

    switch (op) {

      case 14: { // SSI_IEEE_FP_CONTROL
          TypedBufferArg<uint64_t> fpcr(bufPtr);
          // I don't think this exactly matches the HW FPCR
          fpcr.copyIn(tc->getMemProxy());
          DPRINTFR(SyscallVerbose, "osf_setsysinfo(SSI_IEEE_FP_CONTROL): "
                   " setting FPCR to 0x%x\n", gtoh(*(uint64_t*)fpcr));
          return 0;
      }

      default:
        cerr << "osf_setsysinfo: unknown op " << op << endl;
        abort();
        break;
    }

    return 1;
}


SyscallDesc AlphaLinuxProcess::syscallDescs[] = {
    /*  0 */ SyscallDesc("osf_syscall", ignoreFunc),
    /*  1 */ SyscallDesc("exit", exitFunc),
    /*  2 */ SyscallDesc("fork", ignoreFunc),
    /*  3 */ SyscallDesc("read", readFunc),
    /*  4 */ SyscallDesc("write", writeFunc),
    /*  5 */ SyscallDesc("osf_old_open", ignoreFunc),
    /*  6 */ SyscallDesc("close", closeFunc),
    /*  7 */ SyscallDesc("osf_wait4", ignoreFunc),
    /*  8 */ SyscallDesc("osf_old_creat", ignoreFunc),
    /*  9 */ SyscallDesc("link", ignoreFunc),
    /* 10 */ SyscallDesc("unlink", unlinkFunc),
    /* 11 */ SyscallDesc("osf_execve", ignoreFunc),
    /* 12 */ SyscallDesc("chdir", ignoreFunc),
    /* 13 */ SyscallDesc("fchdir", ignoreFunc),
    /* 14 */ SyscallDesc("mknod", ignoreFunc),
    /* 15 */ SyscallDesc("chmod", chmodFunc<AlphaLinux>),
    /* 16 */ SyscallDesc("chown", chownFunc),
    /* 17 */ SyscallDesc("brk", brkFunc),
    /* 18 */ SyscallDesc("osf_getfsstat", ignoreFunc),
    /* 19 */ SyscallDesc("lseek", lseekFunc),
    /* 20 */ SyscallDesc("getxpid", getpidPseudoFunc),
    /* 21 */ SyscallDesc("osf_mount", ignoreFunc),
    /* 22 */ SyscallDesc("umount", ignoreFunc),
    /* 23 */ SyscallDesc("setuid", setuidFunc),
    /* 24 */ SyscallDesc("getxuid", getuidPseudoFunc),
    /* 25 */ SyscallDesc("exec_with_loader", ignoreFunc),
    /* 26 */ SyscallDesc("osf_ptrace", ignoreFunc),
    /* 27 */ SyscallDesc("osf_nrecvmsg", ignoreFunc),
    /* 28 */ SyscallDesc("osf_nsendmsg", ignoreFunc),
    /* 29 */ SyscallDesc("osf_nrecvfrom", ignoreFunc),
    /* 30 */ SyscallDesc("osf_naccept", ignoreFunc),
    /* 31 */ SyscallDesc("osf_ngetpeername", ignoreFunc),
    /* 32 */ SyscallDesc("osf_ngetsockname", ignoreFunc),
    /* 33 */ SyscallDesc("access", ignoreFunc),
    /* 34 */ SyscallDesc("osf_chflags", ignoreFunc),
    /* 35 */ SyscallDesc("osf_fchflags", ignoreFunc),
    /* 36 */ SyscallDesc("sync", ignoreFunc),
    /* 37 */ SyscallDesc("kill", ignoreFunc),
    /* 38 */ SyscallDesc("osf_old_stat", ignoreFunc),
    /* 39 */ SyscallDesc("setpgid", ignoreFunc),
    /* 40 */ SyscallDesc("osf_old_lstat", ignoreFunc),
    /* 41 */ SyscallDesc("dup", dupFunc),
    /* 42 */ SyscallDesc("pipe", pipePseudoFunc),
    /* 43 */ SyscallDesc("osf_set_program_attributes", ignoreFunc),
    /* 44 */ SyscallDesc("osf_profil", ignoreFunc),
    /* 45 */ SyscallDesc("open", openFunc<AlphaLinux>),
    /* 46 */ SyscallDesc("osf_old_sigaction", ignoreFunc),
    /* 47 */ SyscallDesc("getxgid", getgidPseudoFunc),
    /* 48 */ SyscallDesc("osf_sigprocmask", ignoreFunc),
    /* 49 */ SyscallDesc("osf_getlogin", ignoreFunc),
    /* 50 */ SyscallDesc("osf_setlogin", ignoreFunc),
    /* 51 */ SyscallDesc("acct", ignoreFunc),
    /* 52 */ SyscallDesc("sigpending", ignoreFunc),
    /* 53 */ SyscallDesc("osf_classcntl", ignoreFunc),
    /* 54 */ SyscallDesc("ioctl", ioctlFunc<AlphaLinux>),
    /* 55 */ SyscallDesc("osf_reboot", ignoreFunc),
    /* 56 */ SyscallDesc("osf_revoke", ignoreFunc),
    /* 57 */ SyscallDesc("symlink", ignoreFunc),
    /* 58 */ SyscallDesc("readlink", readlinkFunc),
    /* 59 */ SyscallDesc("execve", ignoreFunc),
    /* 60 */ SyscallDesc("umask", umaskFunc),
    /* 61 */ SyscallDesc("chroot", ignoreFunc),
    /* 62 */ SyscallDesc("osf_old_fstat", ignoreFunc),
    /* 63 */ SyscallDesc("getpgrp", ignoreFunc),
    /* 64 */ SyscallDesc("getpagesize", getpagesizeFunc),
    /* 65 */ SyscallDesc("osf_mremap", ignoreFunc),
    /* 66 */ SyscallDesc("vfork", ignoreFunc),
    /* 67 */ SyscallDesc("stat", statFunc<AlphaLinux>),
    /* 68 */ SyscallDesc("lstat", lstatFunc<AlphaLinux>),
    /* 69 */ SyscallDesc("osf_sbrk", ignoreFunc),
    /* 70 */ SyscallDesc("osf_sstk", ignoreFunc),
    /* 71 */ SyscallDesc("mmap", mmapFunc<AlphaLinux>),
    /* 72 */ SyscallDesc("osf_old_vadvise", ignoreFunc),
    /* 73 */ SyscallDesc("munmap", munmapFunc),
    /* 74 */ SyscallDesc("mprotect", ignoreFunc),
    /* 75 */ SyscallDesc("madvise", ignoreFunc),
    /* 76 */ SyscallDesc("vhangup", ignoreFunc),
    /* 77 */ SyscallDesc("osf_kmodcall", ignoreFunc),
    /* 78 */ SyscallDesc("osf_mincore", ignoreFunc),
    /* 79 */ SyscallDesc("getgroups", ignoreFunc),
    /* 80 */ SyscallDesc("setgroups", ignoreFunc),
    /* 81 */ SyscallDesc("osf_old_getpgrp", ignoreFunc),
    /* 82 */ SyscallDesc("setpgrp", ignoreFunc),
    /* 83 */ SyscallDesc("osf_setitimer", ignoreFunc),
    /* 84 */ SyscallDesc("osf_old_wait", ignoreFunc),
    /* 85 */ SyscallDesc("osf_table", ignoreFunc),
    /* 86 */ SyscallDesc("osf_getitimer", ignoreFunc),
    /* 87 */ SyscallDesc("gethostname", gethostnameFunc),
    /* 88 */ SyscallDesc("sethostname", ignoreFunc),
    /* 89 */ SyscallDesc("getdtablesize", ignoreFunc),
    /* 90 */ SyscallDesc("dup2", ignoreFunc),
    /* 91 */ SyscallDesc("fstat", fstatFunc<AlphaLinux>),
    /* 92 */ SyscallDesc("fcntl", fcntlFunc),
    /* 93 */ SyscallDesc("osf_select", ignoreFunc),
    /* 94 */ SyscallDesc("poll", ignoreFunc),
    /* 95 */ SyscallDesc("fsync", ignoreFunc),
    /* 96 */ SyscallDesc("setpriority", ignoreFunc),
    /* 97 */ SyscallDesc("socket", ignoreFunc),
    /* 98 */ SyscallDesc("connect", ignoreFunc),
    /* 99 */ SyscallDesc("accept", ignoreFunc),
    /* 100 */ SyscallDesc("getpriority", ignoreFunc),
    /* 101 */ SyscallDesc("send", ignoreFunc),
    /* 102 */ SyscallDesc("recv", ignoreFunc),
    /* 103 */ SyscallDesc("sigreturn", ignoreFunc),
    /* 104 */ SyscallDesc("bind", ignoreFunc),
    /* 105 */ SyscallDesc("setsockopt", ignoreFunc),
    /* 106 */ SyscallDesc("listen", ignoreFunc),
    /* 107 */ SyscallDesc("osf_plock", ignoreFunc),
    /* 108 */ SyscallDesc("osf_old_sigvec", ignoreFunc),
    /* 109 */ SyscallDesc("osf_old_sigblock", ignoreFunc),
    /* 110 */ SyscallDesc("osf_old_sigsetmask", ignoreFunc),
    /* 111 */ SyscallDesc("sigsuspend", ignoreFunc),
    /* 112 */ SyscallDesc("osf_sigstack", ignoreFunc),
    /* 113 */ SyscallDesc("recvmsg", ignoreFunc),
    /* 114 */ SyscallDesc("sendmsg", ignoreFunc),
    /* 115 */ SyscallDesc("osf_old_vtrace", ignoreFunc),
    /* 116 */ SyscallDesc("osf_gettimeofday", ignoreFunc),
    /* 117 */ SyscallDesc("osf_getrusage", ignoreFunc),
    /* 118 */ SyscallDesc("getsockopt", ignoreFunc),
    /* 119 */ SyscallDesc("numa_syscalls", ignoreFunc),
    /* 120 */ SyscallDesc("readv", ignoreFunc),
    /* 121 */ SyscallDesc("writev", writevFunc<AlphaLinux>),
    /* 122 */ SyscallDesc("osf_settimeofday", ignoreFunc),
    /* 123 */ SyscallDesc("fchown", fchownFunc),
    /* 124 */ SyscallDesc("fchmod", fchmodFunc<AlphaLinux>),
    /* 125 */ SyscallDesc("recvfrom", ignoreFunc),
    /* 126 */ SyscallDesc("setreuid", ignoreFunc),
    /* 127 */ SyscallDesc("setregid", ignoreFunc),
    /* 128 */ SyscallDesc("rename", renameFunc),
    /* 129 */ SyscallDesc("truncate", truncateFunc),
    /* 130 */ SyscallDesc("ftruncate", ftruncateFunc),
    /* 131 */ SyscallDesc("flock", ignoreFunc),
    /* 132 */ SyscallDesc("setgid", ignoreFunc),
    /* 133 */ SyscallDesc("sendto", ignoreFunc),
    /* 134 */ SyscallDesc("shutdown", ignoreFunc),
    /* 135 */ SyscallDesc("socketpair", ignoreFunc),
    /* 136 */ SyscallDesc("mkdir", mkdirFunc),
    /* 137 */ SyscallDesc("rmdir", ignoreFunc),
    /* 138 */ SyscallDesc("osf_utimes", ignoreFunc),
    /* 139 */ SyscallDesc("osf_old_sigreturn", ignoreFunc),
    /* 140 */ SyscallDesc("osf_adjtime", ignoreFunc),
    /* 141 */ SyscallDesc("getpeername", ignoreFunc),
    /* 142 */ SyscallDesc("osf_gethostid", ignoreFunc),
    /* 143 */ SyscallDesc("osf_sethostid", ignoreFunc),
    /* 144 */ SyscallDesc("getrlimit", getrlimitFunc<AlphaLinux>),
    /* 145 */ SyscallDesc("setrlimit", ignoreFunc),
    /* 146 */ SyscallDesc("osf_old_killpg", ignoreFunc),
    /* 147 */ SyscallDesc("setsid", ignoreFunc),
    /* 148 */ SyscallDesc("quotactl", ignoreFunc),
    /* 149 */ SyscallDesc("osf_oldquota", ignoreFunc),
    /* 150 */ SyscallDesc("getsockname", ignoreFunc),
    /* 151 */ SyscallDesc("osf_pread", ignoreFunc),
    /* 152 */ SyscallDesc("osf_pwrite", ignoreFunc),
    /* 153 */ SyscallDesc("osf_pid_block", ignoreFunc),
    /* 154 */ SyscallDesc("osf_pid_unblock", ignoreFunc),
    /* 155 */ SyscallDesc("osf_signal_urti", ignoreFunc),
    /* 156 */ SyscallDesc("sigaction", ignoreFunc),
    /* 157 */ SyscallDesc("osf_sigwaitprim", ignoreFunc),
    /* 158 */ SyscallDesc("osf_nfssvc", ignoreFunc),
    /* 159 */ SyscallDesc("osf_getdirentries", ignoreFunc),
    /* 160 */ SyscallDesc("osf_statfs", ignoreFunc),
    /* 161 */ SyscallDesc("osf_fstatfs", ignoreFunc),
    /* 162 */ SyscallDesc("unknown #162", ignoreFunc),
    /* 163 */ SyscallDesc("osf_async_daemon", ignoreFunc),
    /* 164 */ SyscallDesc("osf_getfh", ignoreFunc),
    /* 165 */ SyscallDesc("osf_getdomainname", ignoreFunc),
    /* 166 */ SyscallDesc("setdomainname", ignoreFunc),
    /* 167 */ SyscallDesc("unknown #167", ignoreFunc),
    /* 168 */ SyscallDesc("unknown #168", ignoreFunc),
    /* 169 */ SyscallDesc("osf_exportfs", ignoreFunc),
    /* 170 */ SyscallDesc("unknown #170", ignoreFunc),
    /* 171 */ SyscallDesc("unknown #171", ignoreFunc),
    /* 172 */ SyscallDesc("unknown #172", ignoreFunc),
    /* 173 */ SyscallDesc("unknown #173", ignoreFunc),
    /* 174 */ SyscallDesc("unknown #174", ignoreFunc),
    /* 175 */ SyscallDesc("unknown #175", ignoreFunc),
    /* 176 */ SyscallDesc("unknown #176", ignoreFunc),
    /* 177 */ SyscallDesc("unknown #177", ignoreFunc),
    /* 178 */ SyscallDesc("unknown #178", ignoreFunc),
    /* 179 */ SyscallDesc("unknown #179", ignoreFunc),
    /* 180 */ SyscallDesc("unknown #180", ignoreFunc),
    /* 181 */ SyscallDesc("osf_alt_plock", ignoreFunc),
    /* 182 */ SyscallDesc("unknown #182", ignoreFunc),
    /* 183 */ SyscallDesc("unknown #183", ignoreFunc),
    /* 184 */ SyscallDesc("osf_getmnt", ignoreFunc),
    /* 185 */ SyscallDesc("unknown #185", ignoreFunc),
    /* 186 */ SyscallDesc("unknown #186", ignoreFunc),
    /* 187 */ SyscallDesc("osf_alt_sigpending", ignoreFunc),
    /* 188 */ SyscallDesc("osf_alt_setsid", ignoreFunc),
    /* 189 */ SyscallDesc("unknown #189", ignoreFunc),
    /* 190 */ SyscallDesc("unknown #190", ignoreFunc),
    /* 191 */ SyscallDesc("unknown #191", ignoreFunc),
    /* 192 */ SyscallDesc("unknown #192", ignoreFunc),
    /* 193 */ SyscallDesc("unknown #193", ignoreFunc),
    /* 194 */ SyscallDesc("unknown #194", ignoreFunc),
    /* 195 */ SyscallDesc("unknown #195", ignoreFunc),
    /* 196 */ SyscallDesc("unknown #196", ignoreFunc),
    /* 197 */ SyscallDesc("unknown #197", ignoreFunc),
    /* 198 */ SyscallDesc("unknown #198", ignoreFunc),
    /* 199 */ SyscallDesc("osf_swapon", ignoreFunc),
    /* 200 */ SyscallDesc("msgctl", ignoreFunc),
    /* 201 */ SyscallDesc("msgget", ignoreFunc),
    /* 202 */ SyscallDesc("msgrcv", ignoreFunc),
    /* 203 */ SyscallDesc("msgsnd", ignoreFunc),
    /* 204 */ SyscallDesc("semctl", ignoreFunc),
    /* 205 */ SyscallDesc("semget", ignoreFunc),
    /* 206 */ SyscallDesc("semop", ignoreFunc),
    /* 207 */ SyscallDesc("osf_utsname", ignoreFunc),
    /* 208 */ SyscallDesc("lchown", ignoreFunc),
    /* 209 */ SyscallDesc("osf_shmat", ignoreFunc),
    /* 210 */ SyscallDesc("shmctl", ignoreFunc),
    /* 211 */ SyscallDesc("shmdt", ignoreFunc),
    /* 212 */ SyscallDesc("shmget", ignoreFunc),
    /* 213 */ SyscallDesc("osf_mvalid", ignoreFunc),
    /* 214 */ SyscallDesc("osf_getaddressconf", ignoreFunc),
    /* 215 */ SyscallDesc("osf_msleep", ignoreFunc),
    /* 216 */ SyscallDesc("osf_mwakeup", ignoreFunc),
    /* 217 */ SyscallDesc("msync", ignoreFunc),
    /* 218 */ SyscallDesc("osf_signal", ignoreFunc),
    /* 219 */ SyscallDesc("osf_utc_gettime", ignoreFunc),
    /* 220 */ SyscallDesc("osf_utc_adjtime", ignoreFunc),
    /* 221 */ SyscallDesc("unknown #221", ignoreFunc),
    /* 222 */ SyscallDesc("osf_security", ignoreFunc),
    /* 223 */ SyscallDesc("osf_kloadcall", ignoreFunc),
    /* 224 */ SyscallDesc("unknown #224", ignoreFunc),
    /* 225 */ SyscallDesc("unknown #225", ignoreFunc),
    /* 226 */ SyscallDesc("unknown #226", ignoreFunc),
    /* 227 */ SyscallDesc("unknown #227", ignoreFunc),
    /* 228 */ SyscallDesc("unknown #228", ignoreFunc),
    /* 229 */ SyscallDesc("unknown #229", ignoreFunc),
    /* 230 */ SyscallDesc("unknown #230", ignoreFunc),
    /* 231 */ SyscallDesc("unknown #231", ignoreFunc),
    /* 232 */ SyscallDesc("unknown #232", ignoreFunc),
    /* 233 */ SyscallDesc("getpgid", ignoreFunc),
    /* 234 */ SyscallDesc("getsid", ignoreFunc),
    /* 235 */ SyscallDesc("sigaltstack", ignoreFunc),
    /* 236 */ SyscallDesc("osf_waitid", ignoreFunc),
    /* 237 */ SyscallDesc("osf_priocntlset", ignoreFunc),
    /* 238 */ SyscallDesc("osf_sigsendset", ignoreFunc),
    /* 239 */ SyscallDesc("osf_set_speculative", ignoreFunc),
    /* 240 */ SyscallDesc("osf_msfs_syscall", ignoreFunc),
    /* 241 */ SyscallDesc("osf_sysinfo", ignoreFunc),
    /* 242 */ SyscallDesc("osf_uadmin", ignoreFunc),
    /* 243 */ SyscallDesc("osf_fuser", ignoreFunc),
    /* 244 */ SyscallDesc("osf_proplist_syscall", ignoreFunc),
    /* 245 */ SyscallDesc("osf_ntp_adjtime", ignoreFunc),
    /* 246 */ SyscallDesc("osf_ntp_gettime", ignoreFunc),
    /* 247 */ SyscallDesc("osf_pathconf", ignoreFunc),
    /* 248 */ SyscallDesc("osf_fpathconf", ignoreFunc),
    /* 249 */ SyscallDesc("unknown #249", ignoreFunc),
    /* 250 */ SyscallDesc("osf_uswitch", ignoreFunc),
    /* 251 */ SyscallDesc("osf_usleep_thread", ignoreFunc),
    /* 252 */ SyscallDesc("osf_audcntl", ignoreFunc),
    /* 253 */ SyscallDesc("osf_audgen", ignoreFunc),
    /* 254 */ SyscallDesc("sysfs", ignoreFunc),
    /* 255 */ SyscallDesc("osf_subsys_info", ignoreFunc),
    /* 256 */ SyscallDesc("osf_getsysinfo", osf_getsysinfoFunc),
    /* 257 */ SyscallDesc("osf_setsysinfo", osf_setsysinfoFunc),
    /* 258 */ SyscallDesc("osf_afs_syscall", ignoreFunc),
    /* 259 */ SyscallDesc("osf_swapctl", ignoreFunc),
    /* 260 */ SyscallDesc("osf_memcntl", ignoreFunc),
    /* 261 */ SyscallDesc("osf_fdatasync", ignoreFunc),
    /* 262 */ SyscallDesc("unknown #262", ignoreFunc),
    /* 263 */ SyscallDesc("unknown #263", ignoreFunc),
    /* 264 */ SyscallDesc("unknown #264", ignoreFunc),
    /* 265 */ SyscallDesc("unknown #265", ignoreFunc),
    /* 266 */ SyscallDesc("unknown #266", ignoreFunc),
    /* 267 */ SyscallDesc("unknown #267", ignoreFunc),
    /* 268 */ SyscallDesc("unknown #268", ignoreFunc),
    /* 269 */ SyscallDesc("unknown #269", ignoreFunc),
    /* 270 */ SyscallDesc("unknown #270", ignoreFunc),
    /* 271 */ SyscallDesc("unknown #271", ignoreFunc),
    /* 272 */ SyscallDesc("unknown #272", ignoreFunc),
    /* 273 */ SyscallDesc("unknown #273", ignoreFunc),
    /* 274 */ SyscallDesc("unknown #274", ignoreFunc),
    /* 275 */ SyscallDesc("unknown #275", ignoreFunc),
    /* 276 */ SyscallDesc("unknown #276", ignoreFunc),
    /* 277 */ SyscallDesc("unknown #277", ignoreFunc),
    /* 278 */ SyscallDesc("unknown #278", ignoreFunc),
    /* 279 */ SyscallDesc("unknown #279", ignoreFunc),
    /* 280 */ SyscallDesc("unknown #280", ignoreFunc),
    /* 281 */ SyscallDesc("unknown #281", ignoreFunc),
    /* 282 */ SyscallDesc("unknown #282", ignoreFunc),
    /* 283 */ SyscallDesc("unknown #283", ignoreFunc),
    /* 284 */ SyscallDesc("unknown #284", ignoreFunc),
    /* 285 */ SyscallDesc("unknown #285", ignoreFunc),
    /* 286 */ SyscallDesc("unknown #286", ignoreFunc),
    /* 287 */ SyscallDesc("unknown #287", ignoreFunc),
    /* 288 */ SyscallDesc("unknown #288", ignoreFunc),
    /* 289 */ SyscallDesc("unknown #289", ignoreFunc),
    /* 290 */ SyscallDesc("unknown #290", ignoreFunc),
    /* 291 */ SyscallDesc("unknown #291", ignoreFunc),
    /* 292 */ SyscallDesc("unknown #292", ignoreFunc),
    /* 293 */ SyscallDesc("unknown #293", ignoreFunc),
    /* 294 */ SyscallDesc("unknown #294", ignoreFunc),
    /* 295 */ SyscallDesc("unknown #295", ignoreFunc),
    /* 296 */ SyscallDesc("unknown #296", ignoreFunc),
    /* 297 */ SyscallDesc("unknown #297", ignoreFunc),
    /* 298 */ SyscallDesc("unknown #298", ignoreFunc),
    /* 299 */ SyscallDesc("unknown #299", ignoreFunc),
/*
 * Linux-specific system calls begin at 300
 */
    /* 300 */ SyscallDesc("bdflush", ignoreFunc),
    /* 301 */ SyscallDesc("sethae", ignoreFunc),
    /* 302 */ SyscallDesc("mount", ignoreFunc),
    /* 303 */ SyscallDesc("old_adjtimex", ignoreFunc),
    /* 304 */ SyscallDesc("swapoff", ignoreFunc),
    /* 305 */ SyscallDesc("getdents", ignoreFunc),
    /* 306 */ SyscallDesc("create_module", ignoreFunc),
    /* 307 */ SyscallDesc("init_module", ignoreFunc),
    /* 308 */ SyscallDesc("delete_module", ignoreFunc),
    /* 309 */ SyscallDesc("get_kernel_syms", ignoreFunc),
    /* 310 */ SyscallDesc("syslog", ignoreFunc),
    /* 311 */ SyscallDesc("reboot", ignoreFunc),
    /* 312 */ SyscallDesc("clone", cloneFunc<AlphaLinux>),
    /* 313 */ SyscallDesc("uselib", ignoreFunc),
    /* 314 */ SyscallDesc("mlock", ignoreFunc),
    /* 315 */ SyscallDesc("munlock", ignoreFunc),
    /* 316 */ SyscallDesc("mlockall", ignoreFunc),
    /* 317 */ SyscallDesc("munlockall", ignoreFunc),
    /* 318 */ SyscallDesc("sysinfo", sysinfoFunc<AlphaLinux>),
    /* 319 */ SyscallDesc("_sysctl", ignoreFunc),
    /* 320 */ SyscallDesc("was sys_idle", ignoreFunc),
    /* 321 */ SyscallDesc("oldumount", ignoreFunc),
    /* 322 */ SyscallDesc("swapon", ignoreFunc),
    /* 323 */ SyscallDesc("times", ignoreFunc),
    /* 324 */ SyscallDesc("personality", ignoreFunc),
    /* 325 */ SyscallDesc("setfsuid", ignoreFunc),
    /* 326 */ SyscallDesc("setfsgid", ignoreFunc),
    /* 327 */ SyscallDesc("ustat", ignoreFunc),
    /* 328 */ SyscallDesc("statfs", ignoreFunc),
    /* 329 */ SyscallDesc("fstatfs", ignoreFunc),
    /* 330 */ SyscallDesc("sched_setparam", ignoreFunc),
    /* 331 */ SyscallDesc("sched_getparam", ignoreFunc),
    /* 332 */ SyscallDesc("sched_setscheduler", ignoreFunc),
    /* 333 */ SyscallDesc("sched_getscheduler", ignoreFunc),
    /* 334 */ SyscallDesc("sched_yield", ignoreFunc),
    /* 335 */ SyscallDesc("sched_get_priority_max", ignoreFunc),
    /* 336 */ SyscallDesc("sched_get_priority_min", ignoreFunc),
    /* 337 */ SyscallDesc("sched_rr_get_interval", ignoreFunc),
    /* 338 */ SyscallDesc("afs_syscall", ignoreFunc),
    /* 339 */ SyscallDesc("uname", unameFunc),
    /* 340 */ SyscallDesc("nanosleep", ignoreFunc),
    /* 341 */ SyscallDesc("mremap", mremapFunc<AlphaLinux>),
    /* 342 */ SyscallDesc("nfsservctl", ignoreFunc),
    /* 343 */ SyscallDesc("setresuid", ignoreFunc),
    /* 344 */ SyscallDesc("getresuid", ignoreFunc),
    /* 345 */ SyscallDesc("pciconfig_read", ignoreFunc),
    /* 346 */ SyscallDesc("pciconfig_write", ignoreFunc),
    /* 347 */ SyscallDesc("query_module", ignoreFunc),
    /* 348 */ SyscallDesc("prctl", ignoreFunc),
    /* 349 */ SyscallDesc("pread", ignoreFunc),
    /* 350 */ SyscallDesc("pwrite", ignoreFunc),
    /* 351 */ SyscallDesc("rt_sigreturn", ignoreFunc),
    /* 352 */ SyscallDesc("rt_sigaction", ignoreFunc),
    /* 353 */ SyscallDesc("rt_sigprocmask", ignoreFunc),
    /* 354 */ SyscallDesc("rt_sigpending", ignoreFunc),
    /* 355 */ SyscallDesc("rt_sigtimedwait", ignoreFunc),
    /* 356 */ SyscallDesc("rt_sigqueueinfo", ignoreFunc),
    /* 357 */ SyscallDesc("rt_sigsuspend", ignoreFunc),
    /* 358 */ SyscallDesc("select", ignoreFunc),
    /* 359 */ SyscallDesc("gettimeofday", gettimeofdayFunc<AlphaLinux>),
    /* 360 */ SyscallDesc("settimeofday", ignoreFunc),
    /* 361 */ SyscallDesc("getitimer", ignoreFunc),
    /* 362 */ SyscallDesc("setitimer", ignoreFunc),
    /* 363 */ SyscallDesc("utimes", utimesFunc<AlphaLinux>),
    /* 364 */ SyscallDesc("getrusage", getrusageFunc<AlphaLinux>),
    /* 365 */ SyscallDesc("wait4", ignoreFunc),
    /* 366 */ SyscallDesc("adjtimex", ignoreFunc),
    /* 367 */ SyscallDesc("getcwd", getcwdFunc),
    /* 368 */ SyscallDesc("capget", ignoreFunc),
    /* 369 */ SyscallDesc("capset", ignoreFunc),
    /* 370 */ SyscallDesc("sendfile", ignoreFunc),
    /* 371 */ SyscallDesc("setresgid", ignoreFunc),
    /* 372 */ SyscallDesc("getresgid", ignoreFunc),
    /* 373 */ SyscallDesc("dipc", ignoreFunc),
    /* 374 */ SyscallDesc("pivot_root", ignoreFunc),
    /* 375 */ SyscallDesc("mincore", ignoreFunc),
    /* 376 */ SyscallDesc("pciconfig_iobase", ignoreFunc),
    /* 377 */ SyscallDesc("getdents64", ignoreFunc),
    /* 378 */ SyscallDesc("gettid", ignoreFunc),
    /* 379 */ SyscallDesc("readahead", ignoreFunc),
    /* 380 */ SyscallDesc("security", ignoreFunc),
    /* 381 */ SyscallDesc("tkill", ignoreFunc),
    /* 382 */ SyscallDesc("setxattr", ignoreFunc),
    /* 383 */ SyscallDesc("lsetxattr", ignoreFunc),
    /* 384 */ SyscallDesc("fsetxattr", ignoreFunc),
    /* 385 */ SyscallDesc("getxattr", ignoreFunc),
    /* 386 */ SyscallDesc("lgetxattr", ignoreFunc),
    /* 387 */ SyscallDesc("fgetxattr", ignoreFunc),
    /* 388 */ SyscallDesc("listxattr", ignoreFunc),
    /* 389 */ SyscallDesc("llistxattr", ignoreFunc),
    /* 390 */ SyscallDesc("flistxattr", ignoreFunc),
    /* 391 */ SyscallDesc("removexattr", ignoreFunc),
    /* 392 */ SyscallDesc("lremovexattr", ignoreFunc),
    /* 393 */ SyscallDesc("fremovexattr", ignoreFunc),
    /* 394 */ SyscallDesc("futex", ignoreFunc),
    /* 395 */ SyscallDesc("sched_setaffinity", ignoreFunc),
    /* 396 */ SyscallDesc("sched_getaffinity", ignoreFunc),
    /* 397 */ SyscallDesc("tuxcall", ignoreFunc),
    /* 398 */ SyscallDesc("io_setup", ignoreFunc),
    /* 399 */ SyscallDesc("io_destroy", ignoreFunc),
    /* 400 */ SyscallDesc("io_getevents", ignoreFunc),
    /* 401 */ SyscallDesc("io_submit", ignoreFunc),
    /* 402 */ SyscallDesc("io_cancel", ignoreFunc),
    /* 403 */ SyscallDesc("unknown #403", ignoreFunc),
    /* 404 */ SyscallDesc("unknown #404", ignoreFunc),
    /* 405 */ SyscallDesc("exit_group", exitGroupFunc), // exit all threads...
    /* 406 */ SyscallDesc("lookup_dcookie", ignoreFunc),
    /* 407 */ SyscallDesc("sys_epoll_create", ignoreFunc),
    /* 408 */ SyscallDesc("sys_epoll_ctl", ignoreFunc),
    /* 409 */ SyscallDesc("sys_epoll_wait", ignoreFunc),
    /* 410 */ SyscallDesc("remap_file_pages", ignoreFunc),
    /* 411 */ SyscallDesc("set_tid_address", ignoreFunc),
    /* 412 */ SyscallDesc("restart_syscall", ignoreFunc),
    /* 413 */ SyscallDesc("fadvise64", ignoreFunc),
    /* 414 */ SyscallDesc("timer_create", ignoreFunc),
    /* 415 */ SyscallDesc("timer_settime", ignoreFunc),
    /* 416 */ SyscallDesc("timer_gettime", ignoreFunc),
    /* 417 */ SyscallDesc("timer_getoverrun", ignoreFunc),
    /* 418 */ SyscallDesc("timer_delete", ignoreFunc),
    /* 419 */ SyscallDesc("clock_settime", ignoreFunc),
    /* 420 */ SyscallDesc("clock_gettime", ignoreFunc),
    /* 421 */ SyscallDesc("clock_getres", ignoreFunc),
    /* 422 */ SyscallDesc("clock_nanosleep", ignoreFunc),
    /* 423 */ SyscallDesc("semtimedop", ignoreFunc),
    /* 424 */ SyscallDesc("tgkill", ignoreFunc),
    /* 425 */ SyscallDesc("stat64", stat64Func<AlphaLinux>),
    /* 426 */ SyscallDesc("lstat64", lstat64Func<AlphaLinux>),
    /* 427 */ SyscallDesc("fstat64", fstat64Func<AlphaLinux>),
    /* 428 */ SyscallDesc("vserver", ignoreFunc),
    /* 429 */ SyscallDesc("mbind", ignoreFunc),
    /* 430 */ SyscallDesc("get_mempolicy", ignoreFunc),
    /* 431 */ SyscallDesc("set_mempolicy", ignoreFunc),
    /* 432 */ SyscallDesc("mq_open", ignoreFunc),
    /* 433 */ SyscallDesc("mq_unlink", ignoreFunc),
    /* 434 */ SyscallDesc("mq_timedsend", ignoreFunc),
    /* 435 */ SyscallDesc("mq_timedreceive", ignoreFunc),
    /* 436 */ SyscallDesc("mq_notify", ignoreFunc),
    /* 437 */ SyscallDesc("mq_getsetattr", ignoreFunc),
    /* 438 */ SyscallDesc("waitid", ignoreFunc),
    /* 439 */ SyscallDesc("add_key", ignoreFunc),
    /* 440 */ SyscallDesc("request_key", ignoreFunc),
    /* 441 */ SyscallDesc("keyctl", ignoreFunc)
};

AlphaLinuxProcess::AlphaLinuxProcess(ProcessParams * params,
                                     ObjectFile *objFile)
    : AlphaProcess(params, objFile),
     Num_Syscall_Descs(sizeof(syscallDescs) / sizeof(SyscallDesc))
{
    //init_regs->intRegFile[0] = 0;
}



SyscallDesc*
AlphaLinuxProcess::getDesc(int callnum)
{
    if (callnum < 0 || callnum >= Num_Syscall_Descs)
        return NULL;
    return &syscallDescs[callnum];
}
