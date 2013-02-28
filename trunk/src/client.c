#include <acache.h>

int main(int argn,char **argv)
{
   char login[255],password[255];

   login[0]=0;
   password[0]=0;
   if (argn<2){
      printf("usage: client Anmeldename [passwort]\n");
      exit(-1);
   }
   if (argn==2){
      strcpy(login,argv[1]);
      printf("Password:");
      scanf("%s",password);
   }
   if (argn==3){
      strcpy(login,argv[1]);
      strcpy(password,argv[2]);
   }
   printf("Login: %s   Passsword: %s\n",login,password);
   if (!CliCachelogin(login,password)){
      printf("OK\n");
      exit(0);
   }
   else{
      printf("failed\n");
      exit(1);
   }
      
}
