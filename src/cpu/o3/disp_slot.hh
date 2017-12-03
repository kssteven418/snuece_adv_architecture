class Disp_slot{

public:
	int base;
	int L_miss;
	int D_miss;
	int wait;
	int total;

	Disp_slot(){
		base = 0;
		L_miss = 0;
		D_miss = 0;
		wait = 0;
		total = 0;
	}
};
