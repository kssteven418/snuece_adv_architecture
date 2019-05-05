#include "disp_slot.hh"
#include "debug/SMT_Rename.hh"
#include <iostream>

Disp_slot::Disp_slot(){
	base = 0;
	I_miss = 0;
	D_miss = 0;
	wait = 0;
	total = 0;
	misc = 0;
}

void Disp_slot::print(){
//	std::cout<< "Base: "<<base<<", L miss :"<< L_miss << ", D miss :" << D_miss 
//		<<", Wait:" << wait << ", Total:" << total << std::endl;
}

void Disp_slot::reset(){
	base = 0;
	I_miss = 0;
	D_miss = 0;
	wait = 0;
	total = 0;
	misc = 0;
}
