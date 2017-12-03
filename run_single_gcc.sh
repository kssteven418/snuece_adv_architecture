 #!/bin/bash
  
 ./build/ALPHA/gem5.debug \
	 --debug-flag=Progress \
         configs/example/se.py -n 1\
 		--smt \
         --cpu-type=DerivO3CPU -c "../spec_alpha/bzip_test/t1/bzip2_base.alpha" \
		 --options="../spec_alpha/bzip_test/t1/input.combined" --caches --l1d_size=256kB --l1i_size=256kB --l2_size=512kB --l3_size=1024kB --mem-size=8GB\

