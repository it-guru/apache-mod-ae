P1:=$(shell cat debian/1.3/DEBIAN/control|egrep '^Package:'|awk 'BEGIN{FS=":"}{print $$2 }'|sed -e 's/ //g')
V1:=$(shell cat debian/1.3/DEBIAN/control|egrep '^Version:'|awk 'BEGIN{FS=":"}{print $$2}'|sed -e 's/ //g')
P2:=$(shell cat debian/2.0/DEBIAN/control|egrep '^Package:'|awk 'BEGIN{FS=":"}{print $$2 }'|sed -e 's/ //g')
V2:=$(shell cat debian/2.0/DEBIAN/control|egrep '^Version:'|awk 'BEGIN{FS=":"}{print $$2}'|sed -e 's/ //g')


all:

debapache: 
	@cd src && make && cd ..
	@cd apache &&  apxs -c -I ../include -L ../lib -lacache ae_module.c && cd ..
	@test -d debian/1.3/usr/lib/apache || mkdir -p debian/1.3/usr/lib/apache
	@test -d debian/1.3/etc/init.d || mkdir -p debian/1.3/etc/init.d
	@test -d debian/1.3/usr/sbin   || mkdir -p debian/1.3/usr/sbin
	@test -d debian/1.3/usr/share/lib/acache  \
	|| mkdir -p debian/1.3/usr/share/lib/acache
	@cp apache/ae_module.so debian/1.3/usr/lib/apache
	@cp contrib/etc/acache.conf debian/1.3/etc/
	@cp contrib/etc/aetools.conf debian/1.3/etc/
	@make -C src clean 
	@make -C src
	@cp src/acache debian/1.3/usr/sbin
	@cp src/client debian/1.3/usr/sbin/acache-client
	@cp contrib/authscripts/dummy.sh debian/1.3/usr/share/lib/acache
	echo -e "\n\nUsing Version from debian/1.3/DEBIAN/control and build $(P1)-$(V1).deb"
	@chmod 755 debian/1.3/DEBIAN
	@dpkg-deb --build debian/1.3
	@mv debian/1.3.deb $(P1)-$(V1).deb
	
debapache2: 
	@cd src && make && cd ..
	@cd apache2 &&  apxs2 -a -c -I ../include -L ../lib -lacache ae_module.c && cd ..
	@test -d debian/2.0/usr/lib/apache2/modules || \
         mkdir -p debian/2.0/usr/lib/apache2/modules
	@test -d debian/2.0/etc/init.d || mkdir -p debian/2.0/etc/init.d
	@test -d debian/2.0/usr/sbin   || mkdir -p debian/2.0/usr/sbin
	@test -d debian/2.0/usr/share/lib/acache  \
	 || mkdir -p debian/2.0/usr/share/lib/acache
	@cp apache2/.libs/ae_module.so debian/2.0/usr/lib/apache2/modules/
	@cp contrib/etc/acache.conf debian/2.0/etc/
	@cp contrib/etc/aetools.conf debian/2.0/etc/
	@make -C src clean 
	@make -C src
	@cp contrib/etc/init.d.debian/acache /etc/init.d 
	@cp src/acache debian/2.0/usr/sbin
	@cp src/client debian/2.0/usr/sbin/acache-client
	@cp contrib/authscripts/dummy.sh debian/2.0/usr/share/lib/acache
	 echo -e "\n\nUsing Version from debian/2.0/DEBIAN/control and build $(P2)-$(V2).deb"
	@chmod 755 debian/2.0/DEBIAN
	@dpkg-deb --build debian/2.0 
	@mv debian/2.0.deb $(P2)-$(V2).deb
	@echo "LoadModule ae_auth_module /usr/lib/apache2/modules/ae_module.so" \
	 > /etc/apache2/mods-available/mod_ae_auth.load
	@test -L /etc/apache2/mods-enabled/mod_ae_auth.load || \
         ln -s ../mods-available/mod_ae_auth.load /etc/apache2/mods-enabled/mod_ae_auth.load
	
