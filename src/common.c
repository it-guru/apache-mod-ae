#include <acache.h>

char *strgetnextcmd(char *comline,char *lastpos,char *buffer,int max)
{
   int pos=0;
   int incmd=1;

   if (!lastpos) lastpos=comline;
   if (lastpos[pos]==0 || lastpos[pos]==10 || lastpos[pos]==13) return(NULL);
   while(lastpos[pos]==32 || lastpos[pos]==9) pos++;
   if (lastpos[pos]==0 || lastpos[pos]==10 || lastpos[pos]==13) return(NULL);
   lastpos=lastpos+pos;
   pos=0;
   while(lastpos[pos]!=32 && // space
         lastpos[pos]!=9 &&  // Tab
         lastpos[pos]!=10 && 
         lastpos[pos]!=13 && 
         lastpos[pos]!=0){
      buffer[pos]=lastpos[pos];
      pos++;
      if (pos>max-2) break;
   }
   buffer[pos]=0;
   return(lastpos+pos);
}


int ReadLine(int Socket,char *buffer,int max)
{
   char   c;
   int    pos=0,n;
   int    waitfd;
   struct timeval tm;
   fd_set msk;

   do{
      tm.tv_sec=60;
      tm.tv_usec=0;
      FD_ZERO( &msk );
      FD_SET( Socket , &msk );
      if ((waitfd=select( Socket+1,&msk,NULL,NULL,&tm))<= 0 ) {
         fprintf(stderr,"acache: unexpected result from select '%d'\n",errno);
         fprintf(stderr,"acache: hard termination in ReadLine pid=%d\n",getpid());
         return(-1);
         exit(errno);
      }
      n=read(Socket,&c,1);
      if (n==1){
         buffer[pos]=c;
         pos++;
      }
      else{
         return(-1);
      }
      if (c==10 || c==13) break;
   }while(pos<max-1);
   buffer[pos]=0;

   return(0);
}

char *trim(char *s)
{
   char *p;
 
   p=s; 
   while(*p==32 || *p==13 || *p==9 || *p==10) p++;
   if (p!=s) memmove(s,p,strlen(p)+1);
   p=s+strlen(s);
   while(p>s+1){
      if (*(p-1)==13 ||
          *(p-1)==10 ||
          *(p-1)==9  ||
          *(p-1)==32 ){
         *(p-1)=0;
      }
      else{
         break;
      }
      p--;
   }
   return(s);
}

char *strlwr(char *s)
{
   char *p;

   p=s;
   while(*p){
      *p=tolower(*p);
      p++;
   }
   return(s);
}

char *strchange(char *work,char *search,char *replace)
{
   char *pwork;

   pwork=work;


   while(*pwork){
      if (!strncmp(pwork,search,strlen(search))){
         memmove(pwork+(strlen(replace)-strlen(search)),pwork,strlen(pwork)+1);
         memcpy(pwork,replace,strlen(replace));
         pwork=pwork+strlen(replace);
      }
      else{
         pwork++;
      }
   }
}

