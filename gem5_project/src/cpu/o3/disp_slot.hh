#ifndef _DISP_SLOT_
#define _DISP_SLOT_

class Disp_slot {

public:
	int base;
	int I_miss;
	int D_miss;
	int wait;
	int total;
	int misc;

	Disp_slot();
	
	void print();
	void reset();
};

#endif
