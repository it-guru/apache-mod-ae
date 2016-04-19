authn_acache_module.so : authn_acache_module.c
	apxs2 -i -a -c -I ../include -I /usr/include/apache2-prefork -L ../lib -lacache authn_acache_module.c 

clean :
	@rm -Rf .libs *.o *.so *.lo *.la *.slo 2>/dev/null
