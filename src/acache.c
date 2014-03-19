#include <acache.h>
#include <unistd.h>
#include <fcntl.h>

#define LOCKTIME 3600
int runserver;
int starttime;
int maxctime;
int debug;
int nofork;
int slevel;
int sfactor;
ServerConfig *curcfg;

int InitServer(ServerConfig *,char *);

void help()
{
   fprintf(stderr,"Usage: acache [-h] [-c t] [-s l] [-d]\n");
   fprintf(stderr,"       -h     shows this help\n");
   fprintf(stderr,"       -d     debug mode\n");
   fprintf(stderr,"       -f     no fork\n");
   fprintf(stderr,"       -S f   sfactor (default=2)\n");
   fprintf(stderr,"       -s l   secure level (default=0)\n");
   fprintf(stderr,"              l=0 LOW\n");
   fprintf(stderr,"                  - no special handling\n");
   fprintf(stderr,"              l=1 MINIMAL\n");
   fprintf(stderr,"                  - after 2 fails sleep= 1*sfactor sec\n");
   fprintf(stderr,"                  - after 4 fails sleep= 4*sfactor sec\n");
   fprintf(stderr,"              l=2 MIDDLE\n");
   fprintf(stderr,"                  - after 4 fails sleep= 2*sfactor sec\n");
   fprintf(stderr,"                  - after 6 fails sleep=30*sfactor sec\n");
   fprintf(stderr,"              l=3 HEIGHT\n");
   fprintf(stderr,"                  - after 2 fails sleep= 1*sfactor sec\n");
   fprintf(stderr,"                  - after 5 fails account lock %d*sfactor secs\n",LOCKTIME);
   fprintf(stderr,"       -c t   sets the cache live time to t in seconds\n");
   fprintf(stderr,"\n");
   fprintf(stderr,"       Sending a HUP signal to acache server resets\n");
   fprintf(stderr,"       the cache state.\n\n");
   fprintf(stderr,"       Sending a USR1 signal to acache server dumps\n");
   fprintf(stderr,"       status to syslog.\n\n");
   fprintf(stderr,"       Sending a USR2 signal to acache server switches\n");
   fprintf(stderr,"       the debug mode to syslog.\n");
   fprintf(stderr,"       Sending a CONT signal resets all internal "
                  "counters\n");
}


int main(int argn,char **argv)
{
   int          backcode;
   int          c;
   int          v;
   ServerConfig cfg;

   maxctime=MAXCTIME;
   debug=0;
   nofork=0;
   slevel=0;
   sfactor=2;
   while(1){
      c=getopt(argn,argv,"fdhc:s:S:");
      if (c==-1) break;
      switch(c){
          case 'f':nofork=1;
                   break;
          case 'd':debug=1;
                   break;
          case '?':
          case 'h':help();
                   exit(1);
                   break;
          case 's':if (optarg!=NULL){
                      sscanf(optarg,"%d",&v);
                   }
                   else{
                      fprintf(stderr,"ERROR: can't parse -s option\n");
                      exit(1);
                   }
                   if (v<0 || v>3){
                      fprintf(stderr,"ERROR: invalid level at -s\n");
                      exit(1);
                   }
                   slevel=v;
                   break;
          case 'S':if (optarg!=NULL){
                      sscanf(optarg,"%d",&v);
                   }
                   else{
                      fprintf(stderr,"ERROR: can't parse -S option\n");
                      exit(1);
                   }
                   sfactor=v;
                   break;
          case 'c':if (optarg!=NULL){
                      sscanf(optarg,"%d",&v);
                   }
                   else{
                      fprintf(stderr,"ERROR: can't parse -c option\n");
                      exit(1);
                   }
                   if (v<10 || v>3600){
                      fprintf(stderr,"ERROR: maxctime not in range "
                                     "between 10-3600\n");
                      exit(2);
                   }
                   maxctime=v;
                   break;
      }


   }

   openlog("acache",LOG_NDELAY|LOG_PID,LOG_AUTH);
   syslog(LOG_INFO,"%s",ACACHEID);

   if ((backcode=InitServer(&cfg,"800"))){
      if (backcode==4){
         fprintf(stderr,"ERROR: IP-Port already in use.\n");
      }
      else{
         fprintf(stderr,"Init Error %4d\n",backcode);
      }
      exit(-1);
   }
   starttime=time(NULL);
   ReadConfig(&cfg);
   if ((backcode=RunServer(&cfg))){
      fprintf(stderr,"Run Error %4d\n",backcode);
   }
}



int GetCacheStatus(ServerConfig *cfg,char *loginname,char *password)
{
   int c;
   int status;

   LockCacheWrite(cfg);
   for(c=0;c<cfg->c->n;c++){
      if (!strcmp(loginname,cfg->c->entry[c].name) &&
           slevel==3 &&
           cfg->c->entry[c].lock){
         if (debug){
            fprintf(stderr,"account '%s' is locked\n",loginname);
         }
         UnLockCacheWrite(cfg);
         return(8192);
      }
      if (!strcmp(loginname,cfg->c->entry[c].name) &&
          !strcmp(password,cfg->c->entry[c].pass) ){
         if (debug){
            fprintf(stderr,"Cache found %s at cache pos %d with status %d\n",
                   loginname,c,cfg->c->entry[c].status);
         }
         cfg->c->cachehits++;
         cfg->c->entry[c].adate=time(NULL);
         status=cfg->c->entry[c].status;
         UnLockCacheWrite(cfg);
         return(status);
      }
   }
   UnLockCacheWrite(cfg);
   return(-1);
}

int SetCacheStatus(ServerConfig *cfg,char *loginname,char *password,int st)
{
   int c,set=0;
   int nfail=0;
   int sleeptime=0;
   int newcdate;

   LockCacheWrite(cfg);
   for(c=0;c<cfg->c->n;c++){
      if (!strcmp(loginname,cfg->c->entry[c].name) &&
          !strcmp(password,cfg->c->entry[c].pass) ){
         cfg->c->entry[c].status=st;
         cfg->c->entry[c].mdate=time(NULL);
         set=1;
         if (debug){
            fprintf( stderr, "SetCacheStatus: %d\n",c );
         }
      }
      if (st!=0 &&
          cfg->c->entry[c].status!=0 &&
          !strcmp(loginname,cfg->c->entry[c].name)){
         nfail++;
      }
   }
   if (debug){
      fprintf(stderr,"found %d failed logins on '%s'\n",nfail,loginname);
   }
   if (nfail>=5 && slevel==3){
      if (sfactor>0){
         newcdate=time(NULL)+(LOCKTIME*sfactor)-maxctime;
      }
      else{
         newcdate=time(NULL)+300;
      }
      #ifdef LOG_WARNING
      syslog(LOG_WARNING,"WARN: account '%s' will now be locked",loginname);
      #endif
      for(c=0;c<cfg->c->n;c++){
         if (!strcmp(loginname,cfg->c->entry[c].name)){
            cfg->c->entry[c].lock=1;
            cfg->c->entry[c].cdate=newcdate;
            cfg->c->entry[c].mdate=newcdate;
            newcdate=0; // set all following cacheentry to 0 for cleanup
         }
      }
      syslog(LOG_INFO,"account '%s' is now locked for min. %d sec",
             loginname,LOCKTIME);
      UnLockCacheWrite(cfg);
      return(1024);
   }
   if (!set){
      if (debug){
         fprintf( stderr, "cfg->c->n: %d\n",cfg->c->n );
      }
      if (cfg->c->n>MAXCACHE-2){
         #ifdef LOG_WARNING
         syslog(LOG_WARNING,"WARN: out of cache space!!!");
         #endif
      }
      else{
         if (debug){
            syslog(LOG_INFO,"Append \"%s\" at cache pos %d",
                   loginname,cfg->c->n);
         }
         strcpy(cfg->c->entry[cfg->c->n].name,loginname);
         strcpy(cfg->c->entry[cfg->c->n].pass,password);
         cfg->c->entry[cfg->c->n].lock=0;
         cfg->c->entry[cfg->c->n].status=st;
         cfg->c->entry[cfg->c->n].cdate=time(NULL);
         cfg->c->n++;
         if (cfg->c->maxused<cfg->c->n) cfg->c->maxused=cfg->c->n;
      }
   }
   UnLockCacheWrite(cfg);

   if (slevel==1){
      if (nfail>=2){
         sleep(1*sfactor);
      }
      if (nfail>=4){
         #ifdef LOG_WARNING
         syslog(LOG_WARNING,"WARN: posible hacking try at account '%s'",
                            loginname);
         #endif
         sleep(2*sfactor);
      }
   }

   if (slevel==2){
      if (nfail>=4){
         sleep(2*sfactor);
      }
      if (nfail>=6){
         #ifdef LOG_WARNING
         syslog(LOG_WARNING,"WARN: posible hacking try at account '%s'",
                            loginname);
         #endif
         sleep(30*sfactor);
      }
   }

   if (slevel==3){
      if (nfail>=2){
         sleep(1*sfactor);
      }
   }

   return(0);
}




int CleanCacheStatus(ServerConfig *cfg)
{
   int  c,n,found;
   FILE *f;
   char Buffer[1024];

   if (cfg->c->n==0){
      return(0);
   }
   LockCacheWrite(cfg);
   if (debug){
      fprintf(stderr,"Cleaner Start for '%d' entries\n",cfg->c->n);
   }
   for(c=0;c<cfg->c->n;c++){
      if ( (cfg->c->entry[c].mdate<time(NULL)-maxctime) &&
           (cfg->c->entry[c].cdate<time(NULL)-maxctime) ){
         if (debug){
            fprintf(stderr,"Remove ID=%d User=%s:cdate=%d mdate=%d adate=%d\n",
                           c,cfg->c->entry[c].name,
                           cfg->c->entry[c].cdate,cfg->c->entry[c].mdate,
                           cfg->c->entry[c].adate);
         }
         memmove(&cfg->c->entry[c],
                 &cfg->c->entry[c+1],
                 (cfg->c->n-c)*sizeof(CacheEntry));
         cfg->c->n--;
      }
   }
   if (debug){
      fprintf(stderr,"Cleaner End\n");
   }
   UnLockCacheWrite(cfg); 
   return(0);
}




int CheckAccount(ServerConfig *cfg,char *loginname,char *password)
{
   int  status,c,pid,found=0;
   char Buffer[255],*p,Domain[255],User[255],cmd[512];
   int  pi[2],pos,exitstate=50;
   char *commandargs[40];
   FILE *f;

   cfg->c->accesscount++;
   if ((status=GetCacheStatus(cfg,loginname,password))>=0){
      exitstate=status;
   }
   else{
      if (debug){
         syslog(LOG_INFO,"no cache entry found for user '%s'\n",loginname); 
      }
      strcpy(Buffer,loginname);
      p=Buffer;
      while(*p!='/' && *p!=0) p++;
      if (*p=='/'){
         strcpy(User,p+1);
         *p=0;
         strcpy(Domain,Buffer);
      }
      else{
         strcpy(User,Buffer);
         strcpy(Domain,"");
      }
      c=0;
      while(c<cfg->c->helper.n){
         if (!strcmp(Domain,cfg->c->helper.entry[c].domain) ||
             !strcmp("*",cfg->c->helper.entry[c].domain) ||
             (!strcmp(Domain,"") && 
              !strcmp("none",cfg->c->helper.entry[c].domain))){
            if (debug){
               syslog(LOG_INFO,"Domain found at pos %d in config\n",c); 
            }
            exitstate=GetAuthState(cfg,loginname,Domain,User,password,c);
            if (exitstate==0){
               if (found==1){
                  syslog(LOG_INFO,"WARN: sucessfuly auth at alternate path "
                                  "on  \"%s\" Domain: \"%s\"",loginname,Domain);
               }
               printf("Auth OK\n"); 
               return(exitstate);
            }
            found=1;
         }
         c++;
      }
      if (!found){
         syslog(LOG_INFO,"Domain not found Login: \"%s\" Domain: \"%s\"",loginname,Domain);
      }
   }
   return(exitstate);
}

int GetAuthState(ServerConfig *cfg,char *loginname,char *Domain,
                 char *User,char *password,int c)
{
   char Buffer[255],*p,cmd[512];
   int  status,pid,found=0;
   int  pi[2],pos,exitstate=50;
   char *commandargs[40];
   FILE *f;

   if (strlen(loginname)>sizeof(cfg->c->entry[c].name)-1){
      return(100);
   }
   if (strlen(password)>sizeof(cfg->c->entry[c].pass)-1){
      return(101);
   }

   strcpy(cmd,cfg->c->helper.entry[c].cmd);
   strchange(cmd,"%U",User);
   strchange(cmd,"%D",Domain);
   strchange(cmd,"%F",loginname);
   pos=0;
   p=NULL;
   do{
     commandargs[pos]=NULL;
     if (p=strgetnextcmd(cmd,p,Buffer,255)){
        commandargs[pos]=(char *)malloc(strlen(Buffer)+1);
        strcpy(commandargs[pos],Buffer);
        pos++;
     }
   }while(p);
   pos=0;
   while(commandargs[pos]){
      printf("%3d \"%s\"\n",pos,commandargs[pos]);
      pos++;
   }
   signal(SIGCHLD,SIG_DFL);   
   pipe(pi);
   switch(pid=fork()){
      case 0 : /* Client Prozess */
               close(STDIN_FILENO);
               dup(pi[0]);
               close(pi[1]);
               close(pi[0]);
               execv(commandargs[0],commandargs);
               printf("ERROR %04d\n",errno);
               exit(-1);
               break;

      case -1: /* Fehler */
               break;

      default: /* Server */
               close(pi[0]);
               write(pi[1],password,strlen(password));
               write(pi[1],"\n",1);
               waitpid(pid,&exitstate,0);
               close(pi[1]);
               break;
   }
   printf("Process %d ExitState=%d\n",pid,exitstate);
   if (exitstate==0){
      SetCacheStatus(cfg,loginname,password,exitstate);
      cfg->c->loginok++;
   }
   else{
      // SetCacheStatus(cfg,loginname,password,1); # Cache of invalid logins
      //                                           # is not a good idea, because
      //                                           # invalid responses in 
      //                                           # backends are also cached
      //                                           # (f.e. connect problems)
      cfg->c->loginfail++;
   }
   while(commandargs[pos]){
      free(commandargs[pos]);
      pos++;
   }
   return(exitstate);
}







void semoperation(ServerConfig *cfg,int op,int option)
{
   struct sembuf sb;
   int    val,back,c=0;


   sb.sem_num=0;
   sb.sem_op=op;
   sb.sem_flg=option;
   do{
      if ((back=semop(cfg->semid,&sb,1))==-1){
          if (errno!=EAGAIN){
             fprintf(stderr,"semop errno=%d\n",errno);
             exit(-1);
          }
          else{
            fprintf(stderr,"semop errno=%d sleeping 1 sec\n",errno);
            sleep(1);
            c++;
         }
         if (c>10){
            fprintf(stderr,"semop errno=%d c=%d\n",errno,c);
            exit(-1);
         }
      }
   }while(back==-1);
}



int LockCacheWrite(ServerConfig *cfg)
{
   if (debug){
      syslog(LOG_DEBUG,"DEBUG: LockCacheWrite pre semop");
   }
   semoperation(cfg,-1,SEM_UNDO|IPC_NOWAIT);
   if (debug){
      syslog(LOG_DEBUG,"DEBUG: LockCacheWrite post semop");
   }
}



int UnLockCacheWrite(ServerConfig *cfg)
{
   if (debug){
      syslog(LOG_DEBUG,"DEBUG: UnLockCacheWrite pre semop");
   }
   semoperation(cfg,1,IPC_NOWAIT|SEM_UNDO);
   if (debug){
      syslog(LOG_DEBUG,"DEBUG: UnLockCacheWrite post semop");
   }
}



int ReturnCode(ServerConfig *cfg,int id,char *info)
{
   char Buffer[1024];

   switch(id){
       case 0 :    sprintf(Buffer,"%06d OK\n",id);
                   break;
       case 10:    sprintf(Buffer,"%06d Fehlende Logininformatioen\n",id);
                   break;
       case 20:    sprintf(Buffer,"%06d Komando Fehler\n",id);
                   break;
       case 65280: sprintf(Buffer,"%06d Komando Fehler\n",id);
                   break;
       default   : sprintf(Buffer,"%06d exitcode\n",id);
                   break;

   }
   write(cfg->cSocket,Buffer,strlen(Buffer));
}



int HandleConnection(ServerConfig *cfg)
{
   char Buffer[255];
   char cmd[255],loginname[255],password[255];
   char *p;
   int  exitcode,runok=1;
   FILE *f;

   while(runok && (!ReadLine(cfg->cSocket,Buffer,255))){
      trim(Buffer);
      p=NULL;
      if (p=strgetnextcmd(Buffer,p,cmd,255)){
         /*
          *  Login Commando
          */
         if (!strcmp(cmd,"login")){
            loginname[0]=0;
            password[0]=0;
            if (p=strgetnextcmd(Buffer,p,loginname,255)){
               p=strgetnextcmd(Buffer,p,password,255);
            }
            if (strlen(loginname) && strlen(password)){
               if (debug){
                  fprintf( stderr, "login: '%s' '%s'\n",loginname,password );
               }
               exitcode=CheckAccount(cfg,loginname,password);
               if (debug){
                  fprintf( stderr, "exitcode of CheckAccount for '%s': %d\n",
                           loginname,exitcode );
               }
               ReturnCode(cfg,exitcode,NULL);
            }
            else{
               ReturnCode(cfg,10,NULL);
            }
         }
         /*
          *  quit Commando
          */
         else if (!strcmp(cmd,"quit")){
            runok=0;
         }
         else {
            ReturnCode(cfg,20,NULL);
         }
      }
   }
   return(0);
}




int MainServer(ServerConfig *cfg)
{
   int    cSockAddrSize;
   int    pid,back,waitfd;
   struct timeval tm;
   fd_set msk;
   time_t lastclean;

  
   cSockAddrSize=sizeof(cfg->cSockAddr);
   lastclean=time(NULL);
   do{
      tm.tv_sec=maxctime/2;
      tm.tv_usec=0;
      FD_ZERO( &msk );
      FD_SET( cfg->sSocket , &msk );
      if ((waitfd=select( cfg->sSocket+1,&msk,NULL,NULL,&tm))< 0 ) {
         if (errno==EINTR){
            if (debug) fprintf( stderr, "\nacache.select(): break select\n");
         //   break;
         }
         if (debug){
            fprintf( stderr, "\nMainServer(): select() error %d\n\r",errno );
         }
      }
      else{
         if (waitfd==1){
            if ((cfg->cSocket=accept(cfg->sSocket,
                (struct sockaddr *) &cfg->cSockAddr,&cSockAddrSize))==-1){
               fprintf(stderr,"accept() errno=%d\n",errno);
               if (errno==EINTR){
                  break;
               }
               exit(1);
            }
            if (debug){
               syslog(LOG_DEBUG,"DEBUG: starting fork of new prozess");
            }
            write(cfg->cSocket,ACACHEID,strlen(ACACHEID));
            write(cfg->cSocket,"\n",1);
            if ((pid=fork())<0) {
              return(6);
            }
            if (pid) close(cfg->cSocket);
            if (pid==0){
               signal(SIGPIPE,SIG_DFL);
               back=HandleConnection(cfg);
               /*sleep(1); */
               close(cfg->cSocket);
               return(back);
            }
         }
      }
      if ((lastclean+(maxctime/2)<time(NULL))){
         lastclean=time(NULL);
         pid=fork();
         if (pid==0){
            CleanCacheStatus(cfg);
            exit(0); 
         }
         if (pid<0){
            exit(-1);
         }
         lastclean=time(NULL);
      }
   }while(runserver);
   if (debug){
      fprintf(stderr,"server normal shutdown\n");
   }
   syslog(LOG_INFO,"Shutdown");
   CleanUpServer(cfg);
   unlink("/var/run/acache.pid");

   return(0);
}



int RunServer(ServerConfig *cfg)
{
   int pid,c;
   FILE *f;

   if (debug && nofork){
      curcfg=cfg;
      return(MainServer(cfg));
   }
   if ((pid=fork())<0){
      return(6);
   }
   else{
     if (pid!=0){
        syslog(LOG_INFO,"Server PID       : %d",pid);
        if (f=fopen("/var/run/acache.pid","w+")){
           fprintf(f,"%d\n",pid);
           fclose(f);
        }
        if (debug){
           fprintf(stderr,"PID=%d\n",pid);
        }
        return(0);
     }
     else{
        fclose(stdout);
        fclose(stdin);
        fclose(stderr);
        open("/dev/null",O_RDWR);
        open("/dev/null",O_RDWR);
        open("/dev/null",O_RDWR);
        curcfg=cfg;
        return(MainServer(cfg));
     }
   }
   return(0);
}


void ShutdownServer(int sig)
{
   if (debug){
      fprintf(stderr,"ShutdownServer by signal %d\n",sig);
   }
   syslog(LOG_INFO,"get shutdown signal %d",sig);
   runserver=0;
}


void DumpStatus(int sig)
{
   int c;
   ServerConfig *cfg=curcfg;

   syslog(LOG_INFO,"------------- Dump start -------------------");
   syslog(LOG_INFO," uptime                 : %d sec",time(NULL)-starttime);
   syslog(LOG_INFO," current cache entrys   : %d",curcfg->c->n);
   syslog(LOG_INFO," max uesed cache entrys : %d of max %d",
          curcfg->c->maxused,MAXCACHE);
   syslog(LOG_INFO," querys                 : %d",curcfg->c->accesscount);
   syslog(LOG_INFO," cache hits             : %d",curcfg->c->cachehits);
   syslog(LOG_INFO," domain configurations  : %d von max %d",
          curcfg->c->helper.n,MAXHELPER);
   syslog(LOG_INFO," failed logins          : %d",curcfg->c->loginfail);
   syslog(LOG_INFO," valid logins           : %d",curcfg->c->loginok);
   syslog(LOG_INFO,"------------ Cache Entrys ------------------");
   for(c=0;c<cfg->c->n;c++){
      syslog(LOG_INFO," Status='%d' lock='%d' deltactime=%ld Account='%s'",
                      cfg->c->entry[c].status,
                      cfg->c->entry[c].lock,
                      cfg->c->entry[c].cdate-time(NULL),
                      cfg->c->entry[c].name);
   }
   syslog(LOG_INFO,"-------------- Dump end --------------------");
   signal(SIGUSR1,DumpStatus);
}


void ResetCache(int sig)
{
   int c;
   ServerConfig *cfg=curcfg;

   syslog(LOG_INFO,"------------- acache reset -----------------");
   LockCacheWrite(cfg);
   cfg->c->n=0;
   UnLockCacheWrite(cfg);
   signal(SIGHUP,ResetCache);
}


void SwitchDebug(int sig)
{
   debug=!debug;
   syslog(LOG_INFO,"Debug is set to %d",debug);
   signal(SIGUSR2,SwitchDebug);
}

void ResetCounter(int sig)
{
   debug=!debug;
   syslog(LOG_INFO,"Reset counter signal recived");
   signal(SIGCONT,ResetCounter);
   curcfg->c->cachehits=0;
   curcfg->c->accesscount=0;
   curcfg->c->loginfail=0;
   curcfg->c->loginok=0;
   starttime=time(NULL);
}





int InitServer(ServerConfig *cfg,char *service)
{
   int c,key,shmid,semid;
   int yes=1;    // char yes='1' on solaris
              

   signal(SIGKILL,ShutdownServer);
   signal(SIGTERM,ShutdownServer);
   signal(SIGUSR1,DumpStatus);
   signal(SIGHUP,ResetCache);
   signal(SIGUSR2,SwitchDebug);
   signal(SIGCONT,ResetCounter);
   signal(SIGPIPE,SIG_IGN);
   signal(SIGCHLD, SIG_IGN);

   memset((void *)&cfg->sSockAddr,0,sizeof(cfg->sSockAddr));
   runserver=1;
   cfg->sSockAddr.sin_family=AF_INET;
   if (service){
      if ((c=atoi(service))>0){
         cfg->sSockAddr.sin_port = htons(c);
      }
      else return(3);
   }
   else{
      return(2);
   }
   if ((cfg->sSocket=socket(AF_INET,SOCK_STREAM,0))==-1) return(1);
   //
   // test to preserve address already in use
   //
   if (setsockopt(cfg->sSocket,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int))==-1){
      perror("setsockopt");
      exit(1);
   } 
   if (bind(cfg->sSocket,(struct sockaddr *)&cfg->sSockAddr,
       sizeof(cfg->sSockAddr))){
       if (debug){
          fprintf(stderr,"ERROR: can't bind Socket at Port %s (errno=%d)\n",
                         service,errno);
          fprintf(stderr,"ERROR: %s\n",strerror(errno));
       }
       return(4);
   }
   if (listen(cfg->sSocket,100)) return(5);

   key=ftok("/etc/acache.conf",0);
   if (key==-1){
      fprintf(stderr,"ERROR: can't access file /etc/acache.conf errno=%d\n",
              errno);
      exit(-1);
   }
   syslog(LOG_INFO,"IPC Key          : %d",key);
   cfg->shmid=shmget(key,sizeof(Cache),0770);
   if (cfg->shmid==-1){
      cfg->shmid=shmget(key,sizeof(Cache),IPC_CREAT|0770);
      if (cfg->shmid==-1){
         fprintf(stderr,"ERROR: Can't Creat Shared Memory. errno=%d\n",
                 errno);
         exit(-1);
      }
   }
   syslog(LOG_INFO,"Shared Memory ID : %d",cfg->shmid);
   cfg->c=(Cache *)shmat(cfg->shmid,NULL,0);
   if (cfg->c==(void *)-1){
      fprintf(stderr,"ERROR: Can't attach Shared Memory. errno=%d\n",
              errno);
      exit(-1);
   }
   cfg->c->n=0;
   cfg->c->cachehits=0;
   cfg->c->accesscount=0;
   cfg->c->loginfail=0;
   cfg->c->loginok=0;
   cfg->c->helper.n=0;
   semid=semget(key,1,IPC_CREAT|0770);
   if (semid==-1){
      fprintf(stderr,"ERROR: Can't Create Semaphore. errno=%d\n",
              errno);
      exit(-1);
   }
   syslog(LOG_INFO,"Semaphore ID     : %d",semid);
   cfg->semid=semid;
   semoperation(cfg,1,IPC_NOWAIT);

   return(0);
}


int CleanUpServer(ServerConfig *cfg)
{
   close(cfg->sSocket);
   close(cfg->cSocket);
   shmdt((char *)cfg->c);
   shmctl(cfg->shmid,IPC_RMID,NULL);
   semctl(cfg->semid,0,IPC_RMID,NULL);
}
