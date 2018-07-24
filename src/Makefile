CFLAGS= -I ../include

# for Soraris remove hash at the following line
# LFLAGS=-lsocket -lnsl

CC=gcc

all       : acache client

acache    : acache.o common.o config.o 
	    $(CC) -fPIC -o acache acache.o common.o config.o $(LFLAGS)
	    cp acache ../bin

client    : client.o common.o cliapi.o 
	    $(CC) -fPIC -o client client.o common.o  cliapi.o $(LFLAGS)
	    cp client ../bin

%.o       : %.c ../include/acache.h Makefile
	    $(CC) -fPIC -c $(CFLAGS) -o $@ $<
	    (mkdir -p ../lib 2>/dev/null)
	    ar cr ../lib/libacache.a $@ 

clean     : 
	rm -f *.o ../lib/*.a ../bin/* acache client
