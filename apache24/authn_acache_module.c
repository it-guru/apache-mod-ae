/* ====================================================================
 */

/*
 * http_auth: authentication
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "apr_strings.h"
#include "apr_md5.h"
#include "ap_config.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "mod_auth.h"
#include "acache.h"


typedef struct authn_cache_config_struct {
    int   acctolower;
    const char *seplist;
    const char *SSOUser;
    const char *SSOPass;
    const char *SSOHeaderUserAttr;
    const char *SSODomain;
    const char *SSOBasicAuthUser;
} authn_cache_config_rec;

module AP_MODULE_DECLARE_DATA authn_acache_module;

static void *create_authn_acache_dir_config(apr_pool_t *p, char *d)
{
   authn_cache_config_rec *sec =apr_pcalloc(p, sizeof(*sec));

   sec->acctolower=0;
   sec->seplist = "/_\\";
   sec->SSOUser = NULL;
   sec->SSOPass = NULL;
   sec->SSOHeaderUserAttr = NULL;
   sec->SSODomain = NULL;
   sec->SSOBasicAuthUser = NULL;

   return sec;
}

static const char *add_seplist(cmd_parms *cmd, void *config,
                                       const char *args)
{
   authn_cache_config_rec *conf = (authn_cache_config_rec *)config;

   conf->seplist=args;
   return(NULL);
}


static const char *add_SSOUser(cmd_parms *cmd, void *config,
                                      const char *args)
{
   authn_cache_config_rec *conf = (authn_cache_config_rec *)config;

   conf->SSOUser=args;
   return(NULL);
}

static const char *add_SSOPass(cmd_parms *cmd, void *config,
                                      const char *args)
{
   authn_cache_config_rec *conf = (authn_cache_config_rec *)config;

   conf->SSOPass=args;
   return(NULL);
}

static const char *add_SSOHeaderUserAttr(cmd_parms *cmd, void *config,
                                      const char *args)
{
   authn_cache_config_rec *conf = (authn_cache_config_rec *)config;

   conf->SSOHeaderUserAttr=args;
   return(NULL);
}

static const char *add_SSODomain(cmd_parms *cmd, void *config,
                                      const char *args)
{
   authn_cache_config_rec *conf = (authn_cache_config_rec *)config;

   conf->SSODomain=args;
   return(NULL);
}

static const char *add_SSOBasicAuthUser(cmd_parms *cmd, void *config,
                                      const char *args)
{
   authn_cache_config_rec *conf = (authn_cache_config_rec *)config;

   conf->SSOBasicAuthUser=args;
   return(NULL);
}

static const command_rec authn_acache_cmds[] =
{
   AP_INIT_FLAG("aeAccountToLower", ap_set_flag_slot,
                (void *)APR_OFFSETOF(authn_cache_config_rec, acctolower),
                OR_AUTHCFG,
                "Set to 'yes' if the the typed in Account should convert "
                "to lower"),
   AP_INIT_RAW_ARGS("aeDomainSeperator", add_seplist,
                (void *)APR_OFFSETOF(authn_cache_config_rec, seplist),
                OR_AUTHCFG,
                "List of valid Seperators between domain and account"),
   AP_INIT_RAW_ARGS("aeSSOUser", add_SSOUser,
                (void *)APR_OFFSETOF(authn_cache_config_rec, seplist),
                OR_AUTHCFG,
                "SSO User-Account"),
   AP_INIT_RAW_ARGS("aeSSOPass", add_SSOPass,
                (void *)APR_OFFSETOF(authn_cache_config_rec, seplist),
                OR_AUTHCFG,
                "SSO Password"),
   AP_INIT_RAW_ARGS("aeSSOHeaderUserAttr", add_SSOHeaderUserAttr,
                (void *)APR_OFFSETOF(authn_cache_config_rec, seplist),
                OR_AUTHCFG,
                "SSO Header-Variable name from which username get"),
   AP_INIT_RAW_ARGS("aeSSODomain", add_SSODomain,
                (void *)APR_OFFSETOF(authn_cache_config_rec, seplist),
                OR_AUTHCFG,
                "SSO Domain to add bevor Username"),
   AP_INIT_RAW_ARGS("aeSSOBasicAuthUser", add_SSOBasicAuthUser,
                (void *)APR_OFFSETOF(authn_cache_config_rec, seplist),
                OR_AUTHCFG,
                "BasicAuth Username, to redirect to SSO URL/Namespace"),
   {NULL}
};

module AP_MODULE_DECLARE_DATA authn_acache_module;



static authn_status check_password(request_rec *r, const char *user,
                                   const char *password)
{
   apr_status_t rv=NULL;
   int        res,code,c,s;
   char       wpassword[255];
   char       wusername[255];
   char       *puser,*pBasicAuthUser,*plastuser;
   const apr_array_header_t    *fields;
   int                         i;
   int                         foundHeaderUserAttr=0;
   apr_table_entry_t           *e = 0;
   authn_cache_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                       &authn_acache_module);


   if (conf->SSOBasicAuthUser && (!strcmp(password,"") || 
                                  !strcmp(password,user))){
      pBasicAuthUser=apr_pstrdup(r->pool,conf->SSOBasicAuthUser);
      puser=apr_strtok(pBasicAuthUser," ",&plastuser);
      while (puser != NULL) {
         //ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,rv, r,
         //                   APLOGNO(10000)
         //                   "check User: %s", puser);
         if (!strcmp(user,puser)){
            res=AUTH_GRANTED;
            return(res);
         }
         puser=apr_strtok(NULL," ", &plastuser);
      }
   }


   if (user!=NULL && conf->SSOUser && !strcmp(user,conf->SSOUser)){
      r->user=apr_pstrdup(r->pool,"anonymous");
      res=AUTH_GRANTED;
      if (conf->SSOHeaderUserAttr!=NULL){
         fields = apr_table_elts(r->headers_in);
         e = (apr_table_entry_t *) fields->elts;
         for(i = 0; i < fields->nelts; i++) {
            if (!strcmp(conf->SSOHeaderUserAttr,e[i].key)){
               r->user=apr_pstrdup(r->pool,e[i].val);
               foundHeaderUserAttr++;
            }
         }
         if (!foundHeaderUserAttr){
            res=AUTH_DENIED;
         }
      } 
      if (conf->SSODomain!=NULL){
         r->user=apr_pstrcat(r->pool,conf->SSODomain,r->user,NULL);
      }
      return(res);
   }
   if (user!=NULL){
      puser=(char *)user;  // dirty hack, to allow modifications of const char *

      // If  aeAccountToLower is set
      if (conf->acctolower){
        for(c=0;c<strlen(puser);c++){
            puser[c]=tolower((int)puser[c]);
         }
      }
      // aeDomainSeperator handling
      if (conf->seplist && strlen(conf->seplist)){
         if (puser){
            for(c=0;c<strlen(puser);c++){
               for(s=0;s<strlen(conf->seplist);s++){
                  if (conf->seplist[s]==user[c]){
                     puser[c]='/';
                     break;
                  }
               }
               if (puser[c]=='/') break;
            }
         }
      }


   }
   ap_log_rerror(APLOG_MARK,APLOG_DEBUG,APR_SUCCESS,r,
                 "DEBUG:acache_check_password(%d)",getpid());





   if (password && user && strlen(password) && strlen(user)){
      apr_cpystrn(wpassword,password,255);
      apr_cpystrn(wusername,user,255);
      code=CliCachelogin(wusername,wpassword);
      if (code>0 || code<0){
         if (code<0){
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,rv, r,
                               APLOGNO(10000)
                               "access to acache denied for user %s: %s (%d)", 
                          user, r->uri,code);
         }
         else{
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR,APR_SUCCESS, r,
                               "external user %s: password mismatch: %s (%d)", 
                          user, r->uri,code);
         }
         ap_note_basic_auth_failure(r);
         res=AUTH_DENIED;
      }
      else{
         /*res=OK;*/
       //  res=ae_check_access(r);
         res=AUTH_GRANTED;
      }
   }
   else{
      res=AUTH_DENIED;
   }
   return(res);
}






static const authn_provider authn_acache_provider =
{
    &check_password, 
    NULL,
};



static void register_hooks(apr_pool_t *p)
{
    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "acache",
                              AUTHN_PROVIDER_VERSION,
                              &authn_acache_provider, AP_AUTH_INTERNAL_PER_CONF);
}

//module AP_MODULE_DECLARE_DATA authn_acache_module =
AP_DECLARE_MODULE(authn_acache) =
{
    STANDARD20_MODULE_STUFF,
    create_authn_acache_dir_config,  /* dir config creater */
    NULL,                            /* dir merger --- default is to override */
    NULL,                            /* server config */
    NULL,                            /* merge server config */
    authn_acache_cmds,               /* command apr_table_t */
    register_hooks                   /* register hooks */
};



