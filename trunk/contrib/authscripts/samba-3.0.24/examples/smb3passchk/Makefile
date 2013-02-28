#
CC = gcc


CFLAGS = -I../../source/popt -I/usr/include -I../../source/include -I../../source/ubiqx -I../../source -I../../source/smbwrapper

LDFLAGS = -L../../source/bin -L/usr/lib

all: smb3passchk

smb3passchk: smb3passchk.o 
	@echo Linking smb3passchk
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lsmbclient

smb3passchk-static: smb3passchk.o 
	@echo Linking smb3passchk
	@$(CC) $(CFLAGS) -static $(LDFLAGS) -o $@ $< -lsmbclient -ldl -lnsl

clean:
	@rm -f *.o *~ smb3passchk smb3passchk-static
