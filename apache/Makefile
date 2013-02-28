ae_module.so : ae_module.c
	apxs -i -a -c -I ../include -L ../lib -lacache ae_module.c 

clean :
	@rm -f *.o *.so 2>/dev/null
