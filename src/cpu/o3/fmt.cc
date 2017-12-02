#include "fmt.hh"
#include "debug/FMT.hh"
#include <iostream>

#define FMTDEBUG 0
#define FMTDEBUG_SMT 0

FMT::FMT(){
	ResetAll();
}

void FMT::ResetAll(){
	
	for(int i=0; i<size; i++)
		ResetEntry(i);
	dispatch_head = 0;
	dispatch_tail = 0;
	fetch = 0;
}

void FMT::ResetEntry(int i){

		FMTtable[i].instSeq = 0;
		FMTtable[i].mispredBit = false;
		FMTtable[i].branch = 0;
		FMTtable[i].L1 = 0;
		FMTtable[i].L2 = 0;
		FMTtable[i].tlb = 0;
		FMTtable[i].base = 0;
		FMTtable[i].wait = 0;
}


void FMT::PrintEntry(){
#if FMTDEBUG_SMT
	std::cout<<"Fetch Ptr : " << fetch
		<<" ::: Base : " << FMTtable[fetch].base
		<<", Wait : " << FMTtable[fetch].wait
		<<", L1miss : "<<FMTtable[fetch].L1<<std::endl;
#endif
}


void FMT::SetCorrectWayFetching(bool b){
	correct_way_fetching = b;
}


//forward fetch pointer by one entry
int FMT::ForwardFetchPtr(InstSeqNum seq){
	++fetch;
	fetch = fetch % size;
	
	//for debugging purpose, return # of L1 miss
	int temp = FMTtable[fetch].L1;
	ResetEntry(fetch);

	//set instruction sequence entry
	FMTtable[fetch].instSeq = seq;

#if FMTDEBUG_SMT
	// std::cout<<"Fetch Ptr at "<<fetch<<std::endl;
#endif

	return temp;
}

//forward fetch pointer to ith entry
//this function is called @ branch mispred
//so do not reset entry
void FMT::ForwardFetchPtr(int i){
	fetch = i;
	//ResetEntry(fetch);
}

//forward dispatch tail pointer by one entry
bool FMT::ForwardDispTailPtr(){
	if(dispatch_tail == fetch){ //cannot advance ahead the fetch pointer
		return false;
	}
	++dispatch_tail;
	dispatch_tail = dispatch_tail % size;
	return true;
}

//forward dispatch tail pointer to ith entry
void FMT::ForwardDispTailPtr(int i){
	dispatch_tail = i;
}

//forward dispatch head pointer by one entry
//return the entry info for update
FMTentry *FMT::ForwardDispHeadPtr(){
	++dispatch_head;
	dispatch_head = dispatch_head % size;
	return &(FMTtable[dispatch_head]);
}

//forward dispatch tail pointer to ith entry
void FMT::ForwardDispHeadPtr(int i){
	dispatch_head = i;
}

//add 1 for every pending branched
//in between dispatch head and tail
void FMT::BranchUpdate(bool isROBblocked){
	
	//avoid duplication count when ROB is blocked
	//due to Load miss or Store miss
	if(isROBblocked){
		// std::cout<<"Mispred on D miss\n";
		return;
	}

	if(dispatch_head==dispatch_tail){ // no branches in backend
		return;
	}

	//count increase 1 per cycle

	int _head = (dispatch_head+1)%size;
	while(true){
		if(!FMTtable[_head].mispredBit){
			++FMTtable[_head].branch;
		}
		else{
			if(correct_way_fetching){// fetching correct way
									 // add up penalty until next dispatch
				++FMTtable[_head].branch;
			}
		}
		if(_head==dispatch_tail) break;
		_head = (_head+1)%size;
	}
}

void FMT::BranchUpdate(bool isROBblocked, int num){
	
	//avoid duplication count when ROB is blocked
	//due to Load miss or Store miss
	if(isROBblocked){
		// std::cout<<"Mispred on D miss\n";
		return;
	}

	if(dispatch_head==dispatch_tail){ // no branches in backend
		return;
	}

	//count increase 'dispatchWidth number' per cycle

	int _head = (dispatch_head+1)%size;
	while(true){
		if(!FMTtable[_head].mispredBit){
			FMTtable[_head].branch += num;
		}
		else{
			if(correct_way_fetching){// fetching correct way
									 // add up penalty until next dispatch
				FMTtable[_head].branch += num;
			}
		}
		if(_head==dispatch_tail) break;
		_head = (_head+1)%size;
	}
}



//set MispredBit on the disp tail pointer
void FMT::SetMispredBitOnTail(){
	FMTtable[dispatch_tail].mispredBit = true;
}


//True if there are no branches in the pipeline
bool FMT::NoPendingBranch(){
	return (fetch==dispatch_head);
}

//True if sequence number matches
bool FMT::CheckHeadSeq(InstSeqNum seq){
	
	// std::cout<<"compare : " << (dispatch_head+1)%size <<" head : " << FMTtable[(dispatch_head+1)%size].instSeq <<" squahsed : "<< seq << std::endl;
	if(dispatch_head==fetch){ // nothing in the pipeline
		return false;
	}
	return FMTtable[(dispatch_head+1)%size].instSeq == seq;
}

//True if the entry is in the pipeline
bool FMT::IsInPipeline(int entry){
	if(dispatch_head == fetch){ // nothing in the pipeline
		return false;
	}
	
	int _dispatch_head = (dispatch_head + 1)%size;
	if(fetch >= _dispatch_head){
		if(entry <= _dispatch_head || entry >= fetch) return true;
	}
	else{
		if(entry <= fetch || entry >= _dispatch_head) return true;
	}

	return true;
}

//True if the pipeline is empty
bool FMT::IsPipelineEmpty(){

#if FMTDEBUG_SMT
	std::cout<<fetch<<" "<<dispatch_head<<std::endl;
#endif

	return dispatch_head==fetch;
}

//find entry of the given inst seqnuence number
int FMT::FindInst(InstSeqNum seq){
	//TODO : range b/w disp tail and disp head

	if(dispatch_head==fetch) 
		return -1; // pipeline is empty
	
	int _head = (dispatch_head+1)%size;

	if(_head <= fetch){
		for(int i=_head; i<=fetch; i++){
			if(FMTtable[i].instSeq == seq){
				return i;
			}
		}
	}
	else{ // _head > fetch
		for(int i=_head; i<size; i++){
			if(FMTtable[i].instSeq == seq){
				return i;
			}
		}
		for(int i=0; i<=fetch; i++){
			if(FMTtable[i].instSeq == seq){
				return i;
			}
		}
	}
	return -1;
}


//update L1 miss entry
void FMT::CountL1(){
	FMTtable[fetch].L1++;
}

void FMT::CountL1(int n){
	FMTtable[fetch].L1 += n;
}

//update L2 miss entry
void FMT::CountL2(){
	FMTtable[fetch].L2++;
}

void FMT::CountL2(int n){
	FMTtable[fetch].L2 += n;
}

//update TLB miss entry
void FMT::CountTLB(){
	FMTtable[fetch].tlb++;
}

void FMT::CountTLB(int n){
	FMTtable[fetch].tlb += n;
}

//update Base entry
void FMT::CountBase(){
	FMTtable[fetch].base++;
}

void FMT::CountBase(int n){
	FMTtable[fetch].base += n;
}

//update Wait entry
void FMT::CountWait(){
	FMTtable[fetch].wait++;
}

void FMT::CountWait(int n){
	FMTtable[fetch].wait += n;
}





/* DEBUGGING FUNCTIONS*/

//print L1+L2 cahce miss and TLB miss
void FMT::DebugPrint(){
	
	/*DPRINTF(FMT, "(DEBUG FMT) Fetch : %d, Disp Tail : %d, Disp Head : %d \n",
			fetch, dispatch_tail, dispatch_head);
	*/

#if FMTDEBUG
	std::cout<<"( DEBUG FMT ) Fetch : "<< fetch <<
		", Disp Tail : "<< dispatch_tail <<
		", Disp Head : "<< dispatch_head;
	std::cout << std::endl;
#endif
}



