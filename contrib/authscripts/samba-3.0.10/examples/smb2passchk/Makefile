#
CC = gcc


CFLAGS = -I../../source/popt -I/usr/include -I../../source/include -I../../source/ubiqx -I../../source -I../../source/smbwrapper

LDFLAGS = -L../../source/bin -L/usr/lib

all: smb2passchk

smb2passchk: smb2passchk.o 
	@echo Linking smb2passchk
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lsmbclient

smb2passchk-static: smb2passchk.o 
	@echo Linking smb2passchk
	@$(CC) $(CFLAGS) -static $(LDFLAGS) -o $@ $< -lsmbclient -ldl -lnsl

clean:
	@rm -f *.o *~ smb2passchk smb2passchk-static
