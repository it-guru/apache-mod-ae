/* ====================================================================
 */

/*
 * http_auth: authentication
 */

#include <linux/stat.h>
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_conf_globals.h"
#include "acache.h"


typedef struct aeauth_config_struct {
    char *auth_pwfile;
    char *user_file;
    char *seplist;
    int   auth_authoritative;
    int   user_file_chk;
    int   acctolower;
} aeauth_config_rec;

static void *ae_create_auth_dir_config(pool *p, char *d)
{
    aeauth_config_rec *sec =
    (aeauth_config_rec *) ap_pcalloc(p, sizeof(aeauth_config_rec));
    sec->auth_pwfile = NULL;    /* just to illustrate the default really */
    sec->user_file = NULL;      /* User file */
    sec->seplist = "/_\\";      /* List of Seperators */
    sec->auth_authoritative=1;
    sec->user_file_chk=0;
    sec->acctolower=0;
    return sec;
}



static const command_rec aeauth_cmds[] =
{
    {"aeDomainSeperator", ap_set_string_slot,
     (void *) XtOffsetOf(aeauth_config_rec, seplist), OR_AUTHCFG, TAKE1,
     "List of valid Seperators between domain and account"},
    {"aeUserFile", ap_set_string_slot,
     (void *) XtOffsetOf(aeauth_config_rec, user_file), OR_AUTHCFG, TAKE1,
     "text file containing user IDs"},
    {"aeAccountToLower", ap_set_flag_slot,
     (void *) XtOffsetOf(aeauth_config_rec, acctolower),
     OR_AUTHCFG, FLAG,
     "Set to 'yes' if the the typed in Account should convert to lower"},
    {"aeUserFileCheck", ap_set_flag_slot,
     (void *) XtOffsetOf(aeauth_config_rec, user_file_chk),
     OR_AUTHCFG, FLAG,
     "Set to 'yes' if the user.txt file should be checked"},
    {"aeAuthoritative", ap_set_flag_slot,
     (void *) XtOffsetOf(aeauth_config_rec, auth_authoritative),
     OR_AUTHCFG, FLAG,
     "Set to 'no' to allow access control to be passed along to lower modules if the UserID is not known to this module"},
    {NULL}
};

module MODULE_VAR_EXPORT ae_module;

static void ae_parse_seperator(request_rec *r,char *user)
{
   //conn_rec   *con = r->connection;
   aeauth_config_rec *curcfg =
   (aeauth_config_rec *) ap_get_module_config(r->per_dir_config, &ae_module);
   int  c,s;

   if (curcfg->acctolower){ 
      if (user){
         for(c=0;c<strlen(user);c++){
            user[c]=tolower((int)user[c]);
         }
      }
   }
   if (curcfg->seplist && strlen(curcfg->seplist)){
      if (user){
         for(c=0;c<strlen(user);c++){
            for(s=0;s<strlen(curcfg->seplist);s++){
               if (curcfg->seplist[s]==user[c]){
                  user[c]='/';
                  break;
               }
            }
            if (user[c]=='/') break;
         }
      }
   }
}

static int ae_find_chkfile(request_rec *r,char **chkfilename)
{
   aeauth_config_rec *curcfg =
   (aeauth_config_rec *) ap_get_module_config(r->per_dir_config, &ae_module);
   char   *tmpname,*chkname,*p,*lev1name;
   int    psize;
   struct stat s;

   if (!curcfg->user_file){
      lev1name=ap_pstrdup(r->pool,"user.txt");
   }
   else{
      lev1name=ap_pstrdup(r->pool,curcfg->user_file);
   }
   if (lev1name[0]!='/'){
      tmpname=ap_pstrdup(r->pool,r->filename);
      psize=strlen(tmpname);
      do{
         if (stat(tmpname,&s)!=-1){
            if (S_ISDIR(s.st_mode)){
               chkname=ap_pstrcat(r->pool,tmpname,"/",lev1name,NULL);
               if (!access(chkname,R_OK)){
                  *chkfilename=ap_pstrdup(r->pool,chkname);
                  break;
               }
               chkname=ap_pstrcat(r->pool,tmpname,"/",".htaccess",NULL);
               if (!access(chkname,R_OK)){
                  break;
               }
            }
         }
         if (!(p=strrchr(tmpname,'/'))){
            break;
         }
         else{
            *p=0;
         }
      }while(strlen(tmpname));
   }
   else{
      *chkfilename=ap_pstrdup(r->pool,lev1name);
   }

   return(0);
}


static int ae_is_user_ok(request_rec *r,char *user,char *chkfile)
{
   configfile_t *f;
   int          found=0,c=0;
   char         l[MAX_STRING_LEN],*p;

   if (chkfile){
      if (!(f = ap_pcfg_openfile(r->pool, chkfile))) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                       "ae:Could not open user file: %s for href=%s", 
                        chkfile,r->filename);
         return(1);
         }
         else{
            while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
               c++;
               p=l;
               while(*p!='#' && *p!=' ' && *p!=13 && *p!=10 && *p!=9 && *p!=0) p++;
               *p=0;
               if (!strcmp(user,l)){
                  found=1;
               }
               if (!strcmp("*",l)){
                  found=1;
               }
            }
            ap_cfg_closefile(f);
            if (!found){
               errno=0;
               ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                          "ae:NoAccess \"%s\" not in %s for href=%s",user,chkfile,r->filename);
               return(2);
            }
         }
      }
      else{
         errno=0;
         ap_log_rerror(APLOG_MARK, APLOG_ERR, r,
                       "ae:no falid user file %s for %s",chkfile,r->filename);
         return(3);
      }

   return(0);
}


static int ae_check_access(request_rec *r)
{
   aeauth_config_rec *sec =
   (aeauth_config_rec *) ap_get_module_config(r->per_dir_config, &ae_module);
   char *user = r->connection->user;
   char *chkfilename=NULL;
  
   if (sec->auth_authoritative){
      if (sec->user_file_chk){
         if (!user || !r->filename) return DECLINED;
         ae_find_chkfile(r,&chkfilename);
         if (user){
            if (!ae_is_user_ok(r,user,chkfilename)){
               return(OK);
            }
            else{
               return AUTH_REQUIRED;
            }
         }
      }
      else{
         if (user){
            return(OK);
         }
      }
   }

   return DECLINED;
}




static int ae_auth_user(request_rec *r)
{
    const char *sent_pw;
    aeauth_config_rec *sec =
      (aeauth_config_rec *) ap_get_module_config(r->per_dir_config, &ae_module);
    conn_rec   *c = r->connection;
    int        res,code;
    char       password[255];
    char       username[255];

    if (!sec->auth_authoritative) return(DECLINED);
    if ((res = ap_get_basic_auth_pw(r, &sent_pw)))
        return res;
    ae_parse_seperator(r,c->user);
    /*
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                      "ae_auth_user user='%s'",c->user);
    */
    if (sent_pw && c->user && strlen(sent_pw) && strlen(c->user)){
       strcpy(password,sent_pw);
       strcpy(username,c->user);
       if ((code=CliCachelogin(username,password))!=0){
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r,
                             "external user %s: password mismatch: %s (%d)", 
                        c->user, r->uri,code);
          ap_note_basic_auth_failure(r);
          res=AUTH_REQUIRED;
       }
       else{
          /*res=OK;*/
          res=ae_check_access(r);
       }
    }
    else{
       res=AUTH_REQUIRED;
    }
    return(res);
}






module MODULE_VAR_EXPORT ae_module =
{
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    ae_create_auth_dir_config,	/* dir config creater */
    NULL,			/* dir merger --- default is to override */
    NULL,			/* server config */
    NULL,			/* merge server config */
    aeauth_cmds,			/* command table */
    NULL,			/* handlers */
    NULL,			/* filename translation */
    ae_auth_user,	        /* check_user_id */
    ae_check_access,        	/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    NULL,			/* child_init */
    NULL,			/* child_exit */
    NULL			/* post read-request */
};
