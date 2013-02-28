#include <acache.h>


int CliOpenSession(ClientConfig *cfg)
{
   char *service="800";
   int  c;
   char Buffer[1024];

   memset((void *)&cfg->cSockAddr,0,sizeof(cfg->cSockAddr));
   cfg->cSockAddr.sin_family=AF_INET;
   if (service){
      if ((c=atoi(service))>0){
         cfg->cSockAddr.sin_port = htons(c);
      }
      else return(3);
   }
   else{
      return(2);
   }
   if ((cfg->cSocket=socket(AF_INET,SOCK_STREAM,0))==-1) return(1);
   if (connect(cfg->cSocket,(struct sockaddr *)&cfg->cSockAddr,
       sizeof(cfg->cSockAddr))){
       printf("errno=%d\n",errno);
       return(4);
   }
   if (!ReadLine(cfg->cSocket,Buffer,255)){
/*
      printf("Init=%s\n",Buffer);
*/
   }
   return(0);
}

int CliDoLogin(ClientConfig *cfg,char *login,char *password)
{
   char Buffer[1024];
   int  Back=-1;

   sprintf(Buffer,"login %s %s\n",login,password);
   write(cfg->cSocket,Buffer,strlen(Buffer));
   if (!ReadLine(cfg->cSocket,Buffer,255)){
       sscanf(Buffer,"%d",&Back);
/*
       printf("Read=%s\n",Buffer);
*/
   }
   else{
       printf("No Line !!!\n");
   }
   return(Back);

}

int CliCloseSession(ClientConfig *cfg)
{
   char *closecmd="quit\n";
   write(cfg->cSocket,closecmd,strlen(closecmd));
   close(cfg->cSocket);
   return(0);
}


int CliCachelogin(char *login,char *password)
{
   ClientConfig cfg;
   int          c,result;

   c=CliOpenSession(&cfg);
   if (!c){
      result=CliDoLogin(&cfg,login,password);
      CliCloseSession(&cfg);
   }
   else{
      result=-1;
   }
   return(result); 
}

