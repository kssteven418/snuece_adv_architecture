 #!/bin/bash
  
 ./build/ALPHA/gem5.debug \
	 --debug-flag=Progress \
         configs/example/se.py -n 1\
 		--smt \
         --cpu-type=DerivO3CPU -c "../../spec_alpha/gcc/gcc.alpha;../../spec_alpha/gcc/gcc.alpha" \
         --options="../../spec_alpha/gcc/gcc_input/s04.i -o ../../spec_alpha/gcc/gcc_input/s04.s;../../spec_alpha/gcc/gcc_input/s04.i -o ../../spec_alpha/gcc/gcc_input/s04.s" --caches --l1d_size=32kB --l1i_size=32kB --l2_size=256kB --l3_size=8MB --mem-size=8GB\

