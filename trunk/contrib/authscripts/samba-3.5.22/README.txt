The directory structure of samba 3.5.22 is a little bit confused. Soo i have
build a script, witch do all patch jobs for you.

Step 1: unpack stock samba package
=======
  tar -xzvf ~/samba-3.5.22.tar.gz

Step 2: apply patch
=======
  patch -p0 < ~/samba-3.5.22-smb3passchk-01.diff

Step 3: run configure and make
=======
  cd samba-3.5.22/source3
  ./configure --prefix=/usr --sysconfdir=/etc --libdir=/etc/samba
  make -j 4
  make
  cd ../..

After these steps, you should find the executable at ...

  ./samba-3.5.22/source3/smb3passchk/smb3passchk

... have some fun with it!
