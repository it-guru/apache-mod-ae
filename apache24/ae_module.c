/* ====================================================================
 */

/*
 * http_auth: authentication
 */

#include <linux/stat.h>
#include "apr_strings.h"
#include "apr_md5.h"
#include "ap_config.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "acache.h"


typedef struct aeauth_config_struct {
    char *auth_pwfile;
    char *user_file;
    char *seplist;
    int   auth_authoritative;
    int   user_file_chk;
    int   acctolower;
} aeauth_config_rec;

module AP_MODULE_DECLARE_DATA authn_acache_module;

static void *ae_create_auth_dir_config(apr_pool_t *p, char *d)
{
   aeauth_config_rec *sec =apr_pcalloc(p, sizeof(*sec));

   sec->auth_pwfile = NULL;    /* just to illustrate the default really */
   sec->user_file = NULL;      /* User file */
   sec->seplist = NULL;        /* List of Seperators */
   sec->auth_authoritative=1;
   sec->user_file_chk=0;
   sec->acctolower=0;

   return sec;
}

static const command_rec aeauth_cmds[] =
{
    AP_INIT_TAKE1("aeDomainSeperator", ap_set_string_slot,
                   (void *)APR_OFFSETOF(aeauth_config_rec, seplist),
                   OR_AUTHCFG,
                   "List of valid Seperators between domain and account "),

    AP_INIT_TAKE1("aeUserFile", ap_set_string_slot,
                   (void *)APR_OFFSETOF(aeauth_config_rec, user_file),
                   OR_AUTHCFG,
                   "text file containing user IDs"),
         
    AP_INIT_FLAG("aeAccountToLower", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(aeauth_config_rec, acctolower),
                 OR_AUTHCFG,
                 "Set to 'yes' if the the typed in Account should convert "
                 "to lower"),

    AP_INIT_FLAG("aeUserFileCheck", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(aeauth_config_rec, user_file_chk),
                 OR_AUTHCFG,
                 "Set to 'yes' if the user.txt file should be checked"),

    AP_INIT_FLAG("aeAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(aeauth_config_rec, auth_authoritative),
                 OR_AUTHCFG,
                 "Set to 'no' to allow access control to be passed along "
                 "to lower modules if the UserID is not known to this module"),

    {NULL}
};




static void ae_parse_seperator(request_rec *r,char *user)
{
   //conn_rec   *con = r->connection;
   aeauth_config_rec *sec=ap_get_module_config(r->per_dir_config, &authn_acache_module);
   int  c,s;
   char *seplist=sec->seplist;

   ap_log_rerror(APLOG_MARK, APLOG_DEBUG,APR_SUCCESS, r,
                       "DEBUG:ae_parse_seperator()");
   if (!seplist){
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG,APR_SUCCESS, r,
                       "DEBUG: set default seplist");
      seplist="/_\\";
   }
   else{
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG,APR_SUCCESS, r,
                       "DEBUG: use sep list '%s'",seplist);
   }

   if (sec->acctolower){ 
      if (user){
         for(c=0;c<strlen(user);c++){
            user[c]=tolower((int)user[c]);
         }
      }
   }
   ap_log_rerror(APLOG_MARK, APLOG_DEBUG,APR_SUCCESS, r,
                       "DEBUG:acctolower done");
   if (seplist && strlen(seplist)){
      if (user){
         for(c=0;c<strlen(user);c++){
            for(s=0;s<strlen(seplist);s++){
               if (seplist[s]==user[c]){
                  user[c]='/';
                  break;
               }
            }
            if (user[c]=='/') break;
         }
      }
   }
   ap_log_rerror(APLOG_MARK, APLOG_DEBUG,APR_SUCCESS, r,
                       "DEBUG:ae_parse_seperator() done");
}


static int ae_find_chkfile(request_rec *r,char **chkfilename)
{
   aeauth_config_rec *curcfg =
   (aeauth_config_rec *) ap_get_module_config(r->per_dir_config, &authn_acache_module);
   char   *tmpname,*chkname,*p,*lev1name;
   int    psize;
   struct stat s;
   int    found=0;

   ap_log_rerror(APLOG_MARK, APLOG_DEBUG,APR_SUCCESS, r,
                       "DEBUG:ae_find_chkfile()");
   if (!curcfg->user_file){
      lev1name=apr_pstrdup(r->pool,"user.txt");
   }
   else{
      lev1name=apr_pstrdup(r->pool,curcfg->user_file);
   }
   ap_log_rerror(APLOG_MARK, APLOG_DEBUG,APR_SUCCESS, r,
                       "DEBUG: start find at '%s'",lev1name);
   if (lev1name[0]!='/'){
      tmpname=apr_pstrdup(r->pool,r->filename);
      psize=strlen(tmpname);
      do{
         if (stat(tmpname,&s)!=-1){
            if (S_ISDIR(s.st_mode)){
               chkname=apr_pstrcat(r->pool,tmpname,"/",lev1name,NULL);
               ap_log_rerror(APLOG_MARK, APLOG_DEBUG,APR_SUCCESS, r,
                                   "DEBUG:  try '%s'",chkname);
               if (!access(chkname,R_OK)){
                  *chkfilename=apr_pstrdup(r->pool,chkname);
                  found=1;
                  break;
               }
               chkname=apr_pstrcat(r->pool,tmpname,"/",".htaccess",NULL);
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
      if (!found){
         *chkfilename=apr_pstrdup(r->pool,lev1name);
      }
   }
   else{
      *chkfilename=apr_pstrdup(r->pool,lev1name);
   }

   return(0);
}



static int ae_is_user_ok(request_rec *r,char *user,char *chkfile)
{
   ap_configfile_t *f;
   int             found=0,c=0;
   char            l[MAX_STRING_LEN],*p;
   apr_status_t status;

   ap_log_rerror(APLOG_MARK, APLOG_DEBUG,APR_SUCCESS, r,
                       "DEBUG:ae_is_user_ok()");
   if (chkfile){
      if ((status=ap_pcfg_openfile(&f,r->pool, chkfile))!=APR_SUCCESS) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR,APR_SUCCESS, r,
                       "ae:Could not open user file: %s for href=%s", 
                        chkfile,r->filename);
         return(1);
         }
         else{
            while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
               c++;
               p=l;
               while(*p!='#' && *p!=' ' && *p!=13 && *p!=10 && 
                     *p!=9 && *p!=0) p++;
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
               ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                             "ae:NoAccess \"%s\" not in %s for href=%s",
                             user,chkfile,r->filename);
               return(2);
            }
         }
      }
      else{
         errno=0;
         ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_SUCCESS, r,
                       "ae:no valid user file %s for %s",chkfile,r->filename);
         return(3);
      }

   return(0);
}



static int ae_check_access(request_rec *r)
{
   aeauth_config_rec *sec=ap_get_module_config(r->per_dir_config, &authn_acache_module);
   char *user = r->user;
   char *chkfilename=NULL;
  
   ap_log_rerror(APLOG_MARK, APLOG_DEBUG,APR_SUCCESS, r,
                       "DEBUG:ae_check_access()" );
   if (sec->auth_authoritative){
      if (sec->user_file_chk==1){
         ap_log_rerror(APLOG_MARK, APLOG_DEBUG,APR_SUCCESS, r,
                       "DEBUG:do user file check" );
         if (!user || !r->filename) return DECLINED;
         ae_find_chkfile(r,&chkfilename);
         if (user){
            if (!ae_is_user_ok(r,user,chkfilename)){
               return(OK);
            }
            else{
               return HTTP_UNAUTHORIZED;
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
   int        res,code;
   char       password[255];
   char       username[255];

   ap_log_rerror(APLOG_MARK,APLOG_DEBUG,APR_SUCCESS,r,"DEBUG:ae_auth_user(%d)",getpid());

   if ((res = ap_get_basic_auth_pw(r, &sent_pw)))
       return res;
   ae_parse_seperator(r,r->user);

   if (sent_pw && r->user && strlen(sent_pw) && strlen(r->user)){
      strcpy(password,sent_pw);
      strcpy(username,r->user);
      code=CliCachelogin(username,password);
      if (code>0){
         ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,APR_SUCCESS, r,
                            "external user %s: password mismatch: %s (%d)", 
                       r->user, r->uri,code);
         ap_note_basic_auth_failure(r);
         res=HTTP_UNAUTHORIZED;
      }
      else{
         /*res=OK;*/
         res=ae_check_access(r);
      }
   }
   else{
      res=HTTP_UNAUTHORIZED;
   }
   return(res);
}


static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(ae_auth_user,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_auth_checker(ae_check_access,NULL,NULL,APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA authn_acache_module =
{
    STANDARD20_MODULE_STUFF,
    ae_create_auth_dir_config,     /* dir config creater */
    NULL,                          /* dir merger --- default is to override */
    NULL,                          /* server config */
    NULL,                          /* merge server config */
    aeauth_cmds,                   /* command apr_table_t */
    register_hooks                 /* register hooks */
};



