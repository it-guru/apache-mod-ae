#include "includes.h"
#include "debug.h"
#include "pstring.h"
#include "safe_string.h"
#include "proto.h"
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <libsmbclient.h>
#include <syslog.h>

#define MAXBUF 512
#define MAXHOSTS 20
#define NO_SYSLOG
#define CONFIGFILE "/root/.smb/smb.conf"

extern BOOL AllowDebugChange;
static BOOL give_flags = False;
static BOOL use_bcast = True;
static BOOL got_bcast = False;
static struct in_addr bcast_addr;
static BOOL recursion_desired = False;
static BOOL translate_addresses = True;
static int ServerFD= -1;
static int RootPort = False;
static BOOL find_status=True;


fstring cur_password;
fstring cur_workgroup;
fstring cur_username;
fstring cur_wins;
fstring hosts[MAXHOSTS];
fstring firsttry;
int maxhost=0;

int debug;
int global_id = 0;

void help()
{
   fprintf(stderr,"Usage: smb2passchk [-h] [-d] [-u username]\n"
                  "                   [-D domain] [-p password]\n"
                  "                   [-B bcast address]|[-U unicast address]\n"
                  "                   [-F first try domain controller]\n"
                  "                   \n\n");
   fprintf(stderr,"       -h   shows this help\n");
   fprintf(stderr,"       -u   sets the username\n");
   fprintf(stderr,"       -D   sets the domainname\n");
   fprintf(stderr,"       -p   sets the password\n");
   fprintf(stderr,"       -F   first try domain controller\n");
   fprintf(stderr,"       -d   debug mode\n\n");
}

/****************************************************************************
  open the socket communication
  **************************************************************************/
static BOOL open_sockets(void)
{
  ServerFD = open_socket_in( SOCK_DGRAM,
                             (RootPort ? 137 : 0),
                             (RootPort ?   0 : 3),
                             interpret_addr(lp_socket_address()), True );

  if (ServerFD == -1)
    return(False);

  set_socket_options( ServerFD, "SO_BROADCAST" );

  DEBUG(3, ("Socket opened.\n"));
  return True;
}


/****************************************************************************
usage on the program
****************************************************************************/
static void usage(void)
{
  printf("Usage: nmblookup [-M] [-B bcast address] [-d debuglevel] name\n");
  printf("Version %s\n",SAMBA_VERSION_STRING);
  printf("\t-d debuglevel         set the debuglevel\n");
  printf("\t-B broadcast address  the address to use for broadcasts\n");
  printf("\t-f                    lists flags returned from a name query\n");
  printf("\t-U unicast   address  the address to use for unicast\n");
  printf("\t-M                    searches for a master browser\n");
  printf("\t-R                    set recursion desired in packet\n");
  printf("\t-S                    lookup node status as well\n");
  printf("\t-T                    translate IP addresses into names\n");
  printf("\t-r                    Use root port 137 (Win95 only replies to this)\n");
  printf("\t-A                    Do a node status on <name> as an IP Address\n");
  printf("\t-i NetBIOS scope      Use the given NetBIOS scope for name queries\n");
  printf("\t-s smb.conf file      Use the given path to the smb.conf file\n");
  printf("\t-h                    Print this help message.\n");
  printf("\n  If you specify -M and name is \"-\", nmblookup looks up __MSBROWSE__<01>\n");
  printf("\n");
}

/****************************************************************************
turn a node status flags field into a string
****************************************************************************/
static char *node_status_flags(unsigned char flags)
{
	static fstring ret;
	fstrcpy(ret,"");
	
	fstrcat(ret, (flags & 0x80) ? "<GROUP> " : "        ");
	if ((flags & 0x60) == 0x00) fstrcat(ret,"B ");
	if ((flags & 0x60) == 0x20) fstrcat(ret,"P ");
	if ((flags & 0x60) == 0x40) fstrcat(ret,"M ");
	if ((flags & 0x60) == 0x60) fstrcat(ret,"H ");
	if (flags & 0x10) fstrcat(ret,"<DEREGISTERING> ");
	if (flags & 0x08) fstrcat(ret,"<CONFLICT> ");
	if (flags & 0x04) fstrcat(ret,"<ACTIVE> ");
	if (flags & 0x02) fstrcat(ret,"<PERMANENT> ");
	
	return ret;
}

/****************************************************************************
turn the NMB Query flags into a string
****************************************************************************/
static char *query_flags(int flags)
{
	static fstring ret1;
	fstrcpy(ret1, "");

	if (flags & NM_FLAGS_RS) fstrcat(ret1, "Response ");
	if (flags & NM_FLAGS_AA) fstrcat(ret1, "Authoritative ");
	if (flags & NM_FLAGS_TC) fstrcat(ret1, "Truncated ");
	if (flags & NM_FLAGS_RD) fstrcat(ret1, "Recursion_Desired ");
	if (flags & NM_FLAGS_RA) fstrcat(ret1, "Recursion_Available ");
	if (flags & NM_FLAGS_B)  fstrcat(ret1, "Broadcast ");

	return ret1;
}

/****************************************************************************
do a node status query
****************************************************************************/
static void do_node_status(int fd, char *name, int type, struct in_addr ip)
{
	struct nmb_name nname;
	int count, i, j;
	NODE_STATUS_STRUCT *status;
	fstring cleanname;

	printf("Looking up status of %s\n",inet_ntoa(ip));
	make_nmb_name(&nname, name, type);
	status = node_status_query(fd,&nname,ip, &count,NULL);
	if (status) {
		for (i=0;i<count;i++) {
			fstrcpy(cleanname, status[i].name);
			for (j=0;cleanname[j];j++) {
				if (!isprint((int)cleanname[j])) cleanname[j] = '.';
			}
			printf("\t%-15s <%02x> - %s\n",
			       cleanname,status[i].type,
			       node_status_flags(status[i].flags));
		}
		SAFE_FREE(status);
	}
	printf("\n");
}


/****************************************************************************
send out one query
****************************************************************************/
static BOOL query_one(char *lookup, unsigned int lookup_type)
{
	int j, count, flags;
	struct in_addr *ip_list=NULL;

	if (got_bcast) {
                if (debug){
	           printf("DEBUG:  querying %s on %s\n", lookup, inet_ntoa(bcast_addr));
                }
		ip_list = name_query(ServerFD,lookup,lookup_type,use_bcast,
				     use_bcast?True:recursion_desired,
				     bcast_addr,&count, &flags,NULL);
	} else {
		struct in_addr *bcast;
		for (j=iface_count() - 1;
		     !ip_list && j >= 0;
		     j--) {
			bcast = iface_n_bcast(j);
                        if (debug){
	            	   fprintf(stderr,"querying %s on %s\n", 
			   lookup, inet_ntoa(*bcast));
                        }
			ip_list = name_query(ServerFD,lookup,lookup_type,
					     use_bcast,
					     use_bcast?True:recursion_desired,
					     *bcast,&count, &flags,NULL);
		}
	}

	if (give_flags)
		printf("Flags: %s\n", query_flags(flags));

	if (!ip_list) return False;
        if (count>MAXHOSTS){
           count=MAXHOSTS;
        }

	for (j=0;j<count;j++) {
		if (translate_addresses) {
			struct hostent *host = gethostbyaddr((char *)&ip_list[j], sizeof(ip_list[j]), AF_INET);
			if (host) {
                                fstrcpy(hosts[maxhost], host -> h_name);
                                maxhost++;
			}
		}
                if (debug){
		   printf("DEBUG:  %s %s<%02x>\n",inet_ntoa(ip_list[j]),
                          lookup, lookup_type);
                }
	}

	/* We can only do find_status if the ip address returned
	   was valid - ie. name_query returned true.
	*/
	if (find_status) {
		do_node_status(ServerFD, lookup, lookup_type, ip_list[0]);
	}

	safe_free(ip_list);

	return (ip_list != NULL);
}


void auth_fn(const char *server, const char *share,
	     char *workgroup, int wgmaxlen, char *username, int unmaxlen,
	     char *password, int pwmaxlen)
{
  if (debug){
     fprintf(stderr, "DEBUG:  need password for //%s/%s\n", server, share);
     fprintf(stderr, "DEBUG:  workgroup: [%s]\n", cur_workgroup);
     fprintf(stderr, "DEBUG:  username: [%s]\n", cur_username);
     fprintf(stderr, "DEBUG:  password: [%s]\n", cur_password);
  }

  if (cur_workgroup[0]) strncpy(workgroup, cur_workgroup, wgmaxlen - 1);
  if (cur_username[0])  strncpy(username, cur_username, unmaxlen - 1);


  if (cur_password[0]) strncpy(password, cur_password, pwmaxlen - 1);

}



int dosmblogin(char *host)
{
   int err;
   int dh1;
   fstring buff;

   err = smbc_init(auth_fn,  0); /* Initialize things */
   if (err < 0) {
     fprintf(stderr, "ERROR:  Initializing the smbclient library ...: %s\n", 
             strerror(errno));
   }
   fstrcpy(buff,"smb://");
   fstrcat(buff,host);
   if (debug){
      fprintf(stderr, "DEBUG:  try to login at '%s'\n",buff);
   }

   if ((dh1 = smbc_opendir(buff))<1) {
      if (debug){
         fprintf(stderr, "DEBUG:  smb login error: %s: %s\n",buff,
                 strerror(errno));
      }
      return(errno);
   }
   if (debug){
      fprintf(stderr, "DEBUG:  smb login sucessfuly\n");
   }
   return(0);
}

int main(int argc, char *argv[])
{
   int err, fd, c,i, dirc;
   fstring dirbuf;
   unsigned int lookup_type = 0x0;
   char *dirp;
   struct stat st;
   char *home=getenv("HOME");
   FILE *F;
   fstring lookup;
   BOOL lookup_by_ip = False;
   BOOL find_master=False;
   char *p;
   struct in_addr ip;
   static fstring servicesf;

   DEBUGLEVEL = 1;
   /* Prevent smb.conf setting from overridding */
   AllowDebugChange = False;
   memset(hosts,sizeof(hosts),0);
   fstrcpy(cur_password,"");
   fstrcpy(cur_workgroup,"WORKGROUP");
   fstrcpy(firsttry,"");
   fstrcpy(cur_username,"nobody");
   fstrcpy(cur_wins,"");
   debug=0;
   while(1){
      c=getopt(argc,argv,"dhu:p:D:B:U:F:");
      if (c==-1) break;
      switch(c){
         case 'd':debug=255;
                  break;
         case '?':
         case 'h':help();
                  exit(1);
                  break;
         case 'u':fstrcpy(cur_username,optarg);
                  break;
         case 'F':fstrcpy(firsttry,optarg);
                  break;
         case 'D':fstrcpy(cur_workgroup,optarg);
                  break;
         case 'p':fstrcpy(cur_password,optarg);
                  break;
         case 'B':fstrcpy(cur_wins,optarg);
                  got_bcast = True;
                  use_bcast = True;
                  recursion_desired = True;
                  //translate_addresses =True;
                  break;
         case 'U':fstrcpy(cur_wins,optarg);
                  got_bcast = True;
                  use_bcast = False;
                  recursion_desired = True;
                 // translate_addresses =True;
                  break;
      }
   }
   if (home==NULL){
      putenv("HOME=/root");
      home=getenv("HOME");
   }
   fstrcpy(dirbuf,home);
   fstrcat(dirbuf,"/.smb");
   err=stat(dirbuf,&st);
   if (err || !(st.st_mode && S_IFDIR)){
      if (debug){
         fprintf(stderr,"DEBUG:  directory '%s' does not exists\n",dirbuf);
      }
      if (mkdir(dirbuf,0700)){
         fprintf(stderr,"ERROR:  can't create directory '%s'\n",dirbuf);
         exit(1);
      }
   }
   fstrcat(dirbuf,"/smb.conf");
   err=stat(dirbuf,&st);
   if (err || !(st.st_mode && (S_IFREG||S_IFLNK))){
      if (debug){
         fprintf(stderr,"DEBUG:  config '%s' does not exists\n",dirbuf);
      }
      if (F=fopen(dirbuf,"w+")){
         fclose(F);
      }
      else{
         fprintf(stderr,"ERROR:  can't create directory '%s'\n",dirbuf);
         exit(1);
      }
   }
   if (!strlen(cur_password)){
      if (debug) system("stty -echo");
      fprintf(stdout, "Enter password: [%s] ", cur_password);
      fgets(cur_password, sizeof(cur_password), stdin);
      fprintf(stdout,"\n");
      if (debug) system("stty echo");
   }
   if (cur_password[strlen(cur_password) - 1] == 0x0a) /* A new line? */
      cur_password[strlen(cur_password) - 1] = 0x00;
   if (cur_password[strlen(cur_password) - 1] == 0x0d) /* A new line? */
      cur_password[strlen(cur_password) - 1] = 0x00;
   if (cur_password[strlen(cur_password) - 1] == 0x0a) /* A new line? */
      cur_password[strlen(cur_password) - 1] = 0x00;
   if (cur_password[strlen(cur_password) - 1] == 0x0d) /* A new line? */
      cur_password[strlen(cur_password) - 1] = 0x00;

   TimeInit();
   setup_logging(argv[0],True);
   DEBUGLEVEL_CLASS[DBGC_ALL] = 1;

//   charset_initialise();
   bcast_addr = *interpret_addr2(cur_wins);
   got_bcast = True;
   use_bcast = False;
   translate_addresses = True;
   recursion_desired = True;
   load_case_tables();
   set_global_myworkgroup( "" );
   set_global_myname( "" );
   setup_logging( "smbclient", True );
   if (!lp_load(dyn_CONFIGFILE,True,False,False,True)) {
      fprintf(stderr,"Can't load '%s' - run testparm to debug it\n",
                      dyn_CONFIGFILE);
   }
   load_interfaces();
   if (!open_sockets()) return(1);

   fstrcpy(lookup,cur_workgroup);
   lookup_type=0x1c;
   if (!query_one(lookup, lookup_type)) {
     printf( "name_query failed to find name %s", lookup );
     if( 0 != lookup_type )
       printf( "#%02x", lookup_type );
     printf( "\n" );
   }
   if (strlen(firsttry)) fstrcpy(hosts[0],firsttry);
   for(c=0;c<MAXHOSTS;c++){
      if (!strlen(hosts[c])) exit(1);
      if (debug){
         fprintf(stderr,"DEBUG:  Check Host %s ...\n",hosts[c]);
      }
      
      err=dosmblogin(hosts[c]);
      // if (c<2) err=10;   keine Ahnung, warum ich das mal rein gemacht habe
      if (debug){
         fprintf(stderr,"DEBUG:  ... exitcode=%d on host %s\n",err,hosts[c]);
      }
      if (err==0){
         if (debug){
            fprintf(stderr,"DEBUG:  OK\n");
         }
         exit(0);
      }
      if (err==13){
         if (debug){
            fprintf(stderr,"ERROR:  %s on host %s\n",strerror(err),hosts[c]);
         }
         exit(err);
      }
   }
   if (debug){
      fprintf(stderr,"ERROR:  can't find any useable auth host (255)\n");
   }
   exit(255);
}

///////////////////////////////////////////////////////////////
