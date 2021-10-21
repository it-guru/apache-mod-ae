#ifndef _ACACHE_H_
#define _ACACHE_H_
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <syslog.h>



#define AEMAXCACHE 1000
#define AEMAXHELPER 200
#define AEMAXCTIME 900
#define ACACHEID  "acache V0.35 by hartmut.vogler@t-systems.com (c) 2021"

#define AEMAXPASSLEN 80
#define AEMAXNAMELEN 50

typedef struct _HelperEntry
{
   char domain[20];
   char cmd[255];
   int    maxautotime;
   int    minautotime;
} HelperEntry;

typedef struct _Helper
{
   HelperEntry entry[AEMAXHELPER];
   int         n;
} Helper;

typedef struct _CacheEntry
{
   char   name[AEMAXNAMELEN];
   char   pass[AEMAXPASSLEN];
   time_t cdate;
   time_t mdate;
   time_t adate;
   int    status;
   int    lock;
} CacheEntry;

typedef struct _Cache
{
   Helper     helper;
   CacheEntry entry[AEMAXCACHE];
   int        n;
   int        maxused;
   int        cachehits;
   int        accesscount;
   int        loginfail;
   int        loginok;
} Cache;

typedef struct _ServerConfig
{
   int    sSocket;
   int    cSocket;
   int    sRun;
   struct sockaddr_in sSockAddr;
   struct sockaddr_in cSockAddr;
   Cache  *c;
   int    CacheSem;
   int    semid;
   int    shmid;
} ServerConfig;

typedef struct _ClientConfig
{
   int    cSocket;
   struct sockaddr_in cSockAddr;
} ClientConfig;

extern int h_errno;
extern int errno;

int   CleanUpServer(ServerConfig *);
char *strgetnextcmd(char *,char *,char *,int);
int   ReadLine(int,char *,int);
int   ReadConfig(ServerConfig *);
char *trim(char *);
char *strlwr(char *);
char *strchange(char *,char *,char *);

int CliCachelogin(char *,char *);
int CliCloseSession(ClientConfig *);
int CliDoLogin(ClientConfig *,char *,char *);
int CliOpenSession(ClientConfig *);

#endif
