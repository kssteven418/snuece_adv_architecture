/* Author: Sehoon Kim */

#ifndef __FMT__
#define __FMT__

#include "cpu/inst_seq.hh"
#include "debug/FMT.hh"

#define SIZE 50
typedef
struct _FMTentry{
	InstSeqNum instSeq;
	bool mispredBit;
	int branch;
	int L1;
	int L2;
	int tlb;

	//for smt
	int base;
	int wait;
	int misc;

} FMTentry;


class FMT{
	private:
		int size = SIZE;
		FMTentry FMTtable[SIZE];

	public:
		/*pointer variables*/
		int dispatch_head;
		int dispatch_tail;
		int fetch;
		
		bool correct_way_fetching;

	
		/* functions*/
		FMT();
		void ResetEntry(int i);
		void ResetAll();
	
		void SetCorrectWayFetching(bool b);
		bool GetCorrectWayFetching(){ return correct_way_fetching;}
		
		//forwarding pointer functions
		int ForwardFetchPtr(InstSeqNum seq);	
		void ForwardFetchPtr(int i);	
		bool ForwardDispTailPtr();
		void ForwardDispTailPtr(int i);	
		FMTentry *ForwardDispHeadPtr();
		FMTentry *ForwardDispHeadPtr(int i);

		int FindInst(InstSeqNum seq);

		void BranchUpdate(bool isROBblocked);
		void BranchUpdate(bool isROBblocked, int num);
		void SetMispredBitOnTail();

		bool NoPendingBranch();
		bool CheckHeadSeq(InstSeqNum seq);
		bool IsInPipeline(int entry);
		bool IsPipelineEmpty();
		bool IsROBEmpty();

		//L1, L2, TLB entry update
		void CountL1();
		void CountL2();
		void CountTLB();
		void CountBase();
		void CountWait();

		void CountL1(int n);
		void CountL2(int n);
		void CountTLB(int n);
		void CountBase(int n);
		void CountWait(int n);

		void CountL1Disp(int n);
		void CountL2Disp(int n);
		void CountTLBDisp(int n);
		void CountBaseDisp(int n);
		void CountWaitDisp(int n);
		void CountMiscDisp(int n);
		//Debug
		void PrintEntry();
		void DebugPrint();
};

#endif
