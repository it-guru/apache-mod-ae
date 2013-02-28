#include <acache.h>


int ReadHelpers(ServerConfig *cfg,char *helpersfile)
{
   FILE *f;
   char Buffer[1024];
   char *p;
   HelperEntry e;

   if ((f=fopen(helpersfile,"r"))!=NULL){
      while(fgets(Buffer,1024,f)){
         memset(&e,0,sizeof(HelperEntry));
         trim(Buffer);
         p=Buffer;
         while(*p!=' ' && *p!=9 && *p!=0) p++;
         *p=0;
         p++;
         trim(Buffer);
         trim(p);
         strcpy(e.domain,Buffer);
         strcpy(e.cmd,p);
/*         printf("domain=\"%s\" cmd=\"%s\"\n",e.domain,e.cmd); */
         memcpy(&(cfg->c->helper.entry[cfg->c->helper.n]),
                &e,sizeof(HelperEntry));
         cfg->c->helper.n++;
      }
      fclose(f);
   }
}


int HandleParam(ServerConfig *cfg,char *vari,char *value)
{
/*   printf("\"%s\"=\"%s\"\n",vari,value); */
   if (!strcmp(vari,"helpers")){
      ReadHelpers(cfg,value);
   }
}

int ReadConfig(ServerConfig *cfg)
{
   FILE *f;
   char Buffer[1024];
   char *p;

/*   printf("ReadConfig\n"); */
   if ((f=fopen("/etc/acache.conf","r"))!=NULL){
      memset(Buffer,0,1024);
      while(fgets(Buffer,1024,f)){
         trim(Buffer);
/*         printf("Z=\"%s\"\n",Buffer); */
         p=Buffer;
         while(*p!='=' && *p!=0) p++;
         *p=0;
         p++;
         trim(Buffer);
         strlwr(Buffer);
         trim(p);
         HandleParam(cfg,Buffer,p);
      }
      fclose(f);
   }
}
