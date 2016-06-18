/* Copyright 1999-2004 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * mod_auth_memcookie_module: memcached cookies authentication
 * 
 * Autor: Mathieu CARBONNEAUX
 * 
 */

#include <stdio.h>
#include <string.h>
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_uuid.h"
#include "apr_md5.h"            /* for apr_password_validate */
#include "apr_tables.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/
#include "apr_base64.h"

#include "libmemcached-1.0/memcached.h"


#define ERRTAG "Auth_memCookie: "
#define VERSION "1.1.0"
#define unless(c) if(!(c))

/* apache module name */
module AP_MODULE_DECLARE_DATA mod_auth_memcookie_module;

/* config structure */
typedef struct {
    char *	szAuth_memCookie_memCached_Configuration;
    apr_time_t 	tAuth_memCookie_MemcacheObjectExpiry;
    int 	nAuth_memCookie_MemcacheObjectExpiryReset;

    int 	nAuth_memCookie_SetSessionHTTPHeader;
    int 	nAuth_memCookie_SetSessionHTTPHeaderEncode;
    int 	nAuth_memCookie_SessionTableSize;

    char *	szAuth_memCookie_CookieName;

    int 	nAuth_memCookie_GroupAuthoritative;
    int 	nAuth_memCookie_Authoritative;
    int 	nAuth_memCookie_MatchIP_Mode;

    int 	nAuth_memCookie_authbasicfix;
#if MODULE_MAGIC_NUMBER_MAJOR > 20051115
    apr_array_header_t *requireelems;
#endif
} strAuth_memCookie_config_rec;

/* Look through 'Cookie' header for indicated cookie; extract it
 * and URL-unescape it. Return the cookie on success, NULL on failure. */
static char * extract_cookie(request_rec *r, const char *szCookie_name) 
{
  char *szRaw_cookie_start=NULL, *szRaw_cookie_end;
  char *szCookie;
  /* get cookie string */
  char*szRaw_cookie = (char*)apr_table_get( r->headers_in, "Cookie");
  unless(szRaw_cookie) return 0;

  /* loop to search cookie name in cookie header */
  do {
    /* search cookie name in cookie string */
    unless (szRaw_cookie =strstr(szRaw_cookie, szCookie_name)) return 0;
    szRaw_cookie_start=szRaw_cookie;
    /* search '=' */
    unless (szRaw_cookie = strchr(szRaw_cookie, '=')) return 0;
  } while (strncmp(szCookie_name,szRaw_cookie_start,szRaw_cookie-szRaw_cookie_start)!=0);

  /* skip '=' */
  szRaw_cookie++;

  /* search end of cookie name value: ';' or end of cookie strings */
  unless ((szRaw_cookie_end = strchr(szRaw_cookie, ';')) || (szRaw_cookie_end = strchr(szRaw_cookie, '\0'))) return 0;

  /* dup the value string found in apache pool and set the result pool ptr to szCookie ptr */
  unless (szCookie = apr_pstrndup(r->pool, szRaw_cookie, szRaw_cookie_end-szRaw_cookie)) return 0;
  /* unescape the value string */ 
  unless (ap_unescape_url(szCookie) == 0) return 0;

  return szCookie;
}

/* function to fix any headers in the input request that may be relied on by an
   application. e.g. php uses the Authorization header when logging the request
   in apache and not r->user (like it ought to). It is applied after the request
   has been authenticated. */
static void fix_headers_in(request_rec *r,char*szPassword)
{

   char *szUser=NULL;

   /* Set an Authorization header in the input request table for php and
      other applications that use it to obtain the username (mainly to fix
      apache logging of php scripts). We only set this if there is no header
      already present. */

   if (apr_table_get(r->headers_in,"Authorization")==NULL) 
   {

     ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "fixing apache Authorization header for this request using user:%s",r->user);

     /* concat username and ':' */
     if (szPassword!=NULL) szUser=(char*)apr_pstrcat(r->pool,r->user,":",szPassword,NULL);
     else szUser=(char*)apr_pstrcat(r->pool,r->user,":",NULL);

     /* alloc memory for the estimated encode size of the username */
     char *szB64_enc_user=(char*)apr_palloc(r->pool,apr_base64_encode_len(strlen(szUser))+1);
     unless (szB64_enc_user) {
       ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memory alloc failed!");
       return;
     }

     /* encode username in base64 format */
     apr_base64_encode(szB64_enc_user,szUser,strlen(szUser));


     /* set authorization header */
     apr_table_set(r->headers_in,"Authorization", (char*)apr_pstrcat(r->pool,"Basic ",szB64_enc_user,NULL));

     /* force auth type to basic */
     r->ap_auth_type=apr_pstrdup(r->pool,"Basic");
   }
 
   return;
} 

/* get session with szCookieValue key from memcached server */
static apr_table_t *Auth_memCookie_get_session(request_rec *r, strAuth_memCookie_config_rec *conf, char *szCookieValue)
{
    char *szMemcached_Configuration=conf->szAuth_memCookie_memCached_Configuration;
    apr_time_t tExpireTime=conf->tAuth_memCookie_MemcacheObjectExpiry;

    memcached_st *memc=NULL;
    uint32_t flags=0;
    memcached_return_t rc;

    apr_table_t *pMySession=NULL;
    size_t nGetKeyLen=strlen(szCookieValue);
    size_t nGetLen=0;
    char *szServer;
    char *szTokenPos;
    char *szFieldTokenPos;
    char *szField;
    char *szValue;
    char *szFieldName;
    char *szFieldValue;
    char *szMyValue;
    char *szSeparator=", \t";
    int nbInfo=0;
    
    /* init memcache lib */
    unless(memc=memcached(szMemcached_Configuration,strlen(szMemcached_Configuration))) {
	 ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memcache lib init failed");
	 return NULL;
    }

    unless(pMySession=apr_table_make(r->pool,conf->nAuth_memCookie_SessionTableSize)) {
       ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, ERRTAG "apr_tablemake failed");
       return NULL;
    }

    /* get value for the key 'szCookieValue' in memcached server */
    unless(szValue=(char*)memcached_get(memc,szCookieValue,nGetKeyLen,&nGetLen,&flags,&rc)) {
       memcached_free(memc);
       ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "memcached_get failed to found key '%s'",szCookieValue);
       return NULL;
    }

    /* dup szValue in pool */
    szMyValue=apr_pstrdup(r->pool,szValue);

    /* split szValue into struct strAuthSession */
    /* szValue is formated multi line (\r\n) with name=value on each line */
    /* must containe UserName,Groups,RemoteIP fieldname */
    szTokenPos=NULL;
    for(szField=apr_strtok(szMyValue,"\r\n",&szTokenPos);szField;szField=apr_strtok(NULL,"\r\n",&szTokenPos)) {
        szFieldTokenPos=NULL;
	ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "session field:%s",szField);
        szFieldName=apr_strtok(szField,"=",&szFieldTokenPos);
        szFieldValue=apr_strtok(NULL,"\r\n",&szFieldTokenPos);
	if (szFieldName!=NULL&&szFieldValue!=NULL) {
	  /* add key and value in pMySession table */
	  apr_table_set(pMySession,szFieldName,szFieldValue);
	  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "session information %s=%s",szFieldName,szFieldValue);

	  /* count the number of element added to table to check table size not reached */
	  nbInfo++;
          if (nbInfo>conf->nAuth_memCookie_SessionTableSize) {
	    ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "maximum session information reached!");
	    return NULL;
	  }
	}
    }

    if (!apr_table_get(pMySession,"UserName")) {
       ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "Username not found in Session value(key:%s) found = %s",szCookieValue,szValue);
       pMySession=NULL;
    } else if (conf->nAuth_memCookie_MatchIP_Mode!=0&&!apr_table_get(pMySession,"RemoteIP")) {
       ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,ERRTAG "MatchIP_Mode activated and RemoteIP not found in Session value(key:%s) found = %s",szCookieValue,szValue);
       pMySession=NULL;
    } else {
       ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "Value for Session (key:%s) found => Username=%s Groups=%s RemoteIp=%s",
				 szCookieValue,
				 apr_table_get(pMySession,"UserName"),
				 apr_table_get(pMySession,"Groups"),
				 apr_table_get(pMySession,"RemoteIP"));
			      }

    /* reset expire time */
    if (conf->nAuth_memCookie_MemcacheObjectExpiryReset&&pMySession) {
     if ((rc=memcached_set(memc,szCookieValue,nGetKeyLen,szValue,nGetLen,tExpireTime,flags))) {
       ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,ERRTAG  "Expire time with memcached_set (key:%s) failed with errcode=%d",szCookieValue,memcached_last_error_message(memc));
       pMySession=NULL;
     }
    }

    /* free memcached_get retruned valued */
    if (!szValue) free(szValue);

    /* free the libmemcached session */
    memcached_free(memc);
    
    /* set the good username found in request structure */
    if (pMySession!=NULL&&apr_table_get(pMySession,"UserName")!=NULL) r->user=(char*)apr_table_get(pMySession,"UserName");

    return pMySession;
}

/* check if szGroup are in szGroups. */
static int get_Auth_memCookie_grp(request_rec *r, char *szGroup, char *szGroups)
 {
    char *szMyGroups;
    char *szMyGroup;

    /* Add delimiters at start and end of groups string */
    /* and search group with delimiters */
    szMyGroups=apr_pstrcat(r->pool,":",szGroups,":",NULL);
    szMyGroup=apr_pstrcat(r->pool,":",szGroup,":",NULL);

    if (!strstr(szMyGroups,szMyGroup))
        return DECLINED;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "group found=%s", szGroup);
    return OK;
}


/* user apr_table_do to set session information in child environment variable */
static int Auth_memCookie_DoSetEnv(void*rec,const char *szKey, const char *szValue)
{
    request_rec *r=(request_rec*)rec;
    char*szEnvName=apr_pstrcat(r->pool,"MCAC_",szKey,NULL);
    /* set env var MCAC_USER to the user session value */
    apr_table_setn(r->subprocess_env,szEnvName,szValue);
    return 1;
}

/* user apr_table_do to set session information in header http */
static int Auth_memCookie_DoSetHeader(void*rec,const char *szKey, const char *szValue)
{
    strAuth_memCookie_config_rec *conf=NULL;
    request_rec *r=(request_rec*)rec;
    char *szB64_enc_string=NULL;
    char *szHeaderName=apr_pstrcat(r->pool,"X-MCAC_",szKey,NULL);

    /* get apache config */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module);

    if (conf->nAuth_memCookie_SetSessionHTTPHeaderEncode) {
      /* alloc memory for the estimated encode size of the string */
      szB64_enc_string=(char*)apr_palloc(r->pool,apr_base64_encode_len(strlen(szValue))+1);
      unless (szB64_enc_string) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "memory alloc for encoding http header failed!");
	return 0;
      }

      /* encode string in base64 format */
      apr_base64_encode(szB64_enc_string,szValue,strlen(szValue));

      /* set string header */
      apr_table_set(r->headers_in,szHeaderName, (char*)szB64_enc_string);
    }
    else
    {
      /* set string header */
      apr_table_set(r->headers_in,szHeaderName, (char*)szValue);
    }
    return 1;
}
/**************************************************
 * authentification phase: 
 * verify if cookie is set and if is know in memcache server 
 **************************************************/
static int Auth_memCookie_check_cookie(request_rec *r)
{
    strAuth_memCookie_config_rec *conf=NULL;
    char *szCookieValue=NULL;
    apr_table_t *pAuthSession=NULL;
    apr_status_t tRetStatus;
    char *szRemoteIP=NULL;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "ap_hook_check_user_id in");

    /* get apache config */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module);

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "check MatchIP_Mode:%d",conf->nAuth_memCookie_MatchIP_Mode);
    /* set remote ip in case of conf->nAuth_memCookie_MatchIP_Mode value */
    if (conf->nAuth_memCookie_MatchIP_Mode==2&&apr_table_get(r->headers_in,"Via")!=NULL)
      szRemoteIP=apr_pstrdup(r->pool,apr_table_get(r->headers_in,"Via"));
    else if (conf->nAuth_memCookie_MatchIP_Mode==1&&apr_table_get(r->headers_in,"X-Forwarded-For")!=NULL)
      szRemoteIP=apr_pstrdup(r->pool,apr_table_get(r->headers_in,"X-Forwarded-For"));
    else
#if MODULE_MAGIC_NUMBER_MAJOR > 20051115
      szRemoteIP=apr_pstrdup(r->pool,r->useragent_ip);
#else
      szRemoteIP=apr_pstrdup(r->pool,r->connection->remote_ip);
#endif


    unless(conf->nAuth_memCookie_Authoritative)
	return DECLINED;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "AuthType are '%s'", ap_auth_type(r));
    unless(strncmp("Cookie",ap_auth_type(r),6)==0) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "Auth type not specified as 'Cookie'");
	return DECLINED; //IIG: Allow basic auth to be set
    }

    // cookie found the user is authentified
    apr_table_setn(r->subprocess_env,"AUTHMEMCOOKIE_AUTH","yes");

    unless(conf->szAuth_memCookie_CookieName) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "No Auth_memCookie_CookieName specified");
        return HTTP_UNAUTHORIZED;
    }

    unless(conf->szAuth_memCookie_memCached_Configuration) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "No Auth_memCookie_Memcached_AddrPort specified");
        return HTTP_UNAUTHORIZED;
    }
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "Memcached server(s) adresse(s) are %s",conf->szAuth_memCookie_memCached_Configuration);

    /* get cookie who are named szAuth_memCookie_CookieName */
    unless(szCookieValue = extract_cookie(r, conf->szAuth_memCookie_CookieName))
    {
      ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, ERRTAG "cookie not found! not authorized! RemoteIP:%s",szRemoteIP);
      return HTTP_UNAUTHORIZED;
    }
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "got cookie; value is %s", szCookieValue);

    /* check cookie vs session in memcache */
    if((pAuthSession = Auth_memCookie_get_session(r, conf, szCookieValue))==NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, ERRTAG "AuthSession %s not found: %s", szCookieValue, r->filename);
        return HTTP_UNAUTHORIZED;
    }

    /* push session returned structure in request pool */
    if ((tRetStatus=apr_pool_userdata_setn(pAuthSession,"SESSION",NULL,r->pool))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "apr_pool_userdata_setn Apr Error: %d", tRetStatus);
        return HTTP_UNAUTHORIZED;
    }

    /* check remote ip if option is enabled */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "check ip: remote_ip=%s cookie_ip=%s", szRemoteIP ,apr_table_get(pAuthSession,"RemoteIP"));
    if (conf->nAuth_memCookie_MatchIP_Mode!=0) {
       if (strcmp(szRemoteIP ,apr_table_get(pAuthSession,"RemoteIP"))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, ERRTAG "unauthorized, by ip. user:%s remote_ip:%s != cookie_ip:%s", apr_table_get(pAuthSession,"UserName"),szRemoteIP ,apr_table_get(pAuthSession,"RemoteIP"));
        return HTTP_UNAUTHORIZED;
       }
    }

    /* set env var MCAC_ to the information session value */
    apr_table_do(Auth_memCookie_DoSetEnv,r,pAuthSession,NULL);

    /* set REMOTE_USER var for scripts language */
    apr_table_setn(r->subprocess_env,"REMOTE_USER",apr_table_get(pAuthSession,"UserName"));

    /* set MCAC-SESSIONKEY var for scripts language */
    apr_table_setn(r->subprocess_env,"MCAC_SESSIONKEY",szCookieValue);
    
    /* set in http header the session value */
    if (conf->nAuth_memCookie_SetSessionHTTPHeader) apr_table_do(Auth_memCookie_DoSetHeader,r,pAuthSession,NULL);

    /* log authorisation ok */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, ERRTAG "authentication ok");

    /* fix http header for php */
    if (conf->nAuth_memCookie_authbasicfix) fix_headers_in(r,(char*)apr_table_get(pAuthSession,"Password"));

    /* if all is ok return auth ok */
    return OK;
}


/**************************************************
 * authentification phase: 
 * Checking authoriszation for user and group of the authenticated cookie 
 **************************************************/

static int Auth_memCookie_check_auth(request_rec *r)
{
    strAuth_memCookie_config_rec *conf=NULL;
    char *szMyUser=r->user;
    char *szUser;
    int m = r->method_number;

    const apr_array_header_t *reqs_arr=NULL;
    require_line *reqs=NULL;

    register int x;
    const char *szRequireLine;
    char *szRequire_cmd;
    char *szGroup;
    char *szGroups;

    apr_table_t *pAuthSession=NULL;
    apr_status_t tRetStatus;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "ap_hook_auth_checker in");

    /* get apache config */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module);

    /* check if module are authoritative */
    unless(conf->nAuth_memCookie_Authoritative)
	return DECLINED;

    /* check if module are authoritative in group check */
    unless(conf->nAuth_memCookie_GroupAuthoritative)
        return DECLINED;

    // no cookie session validated go in next auth check stage (DECLINED)
    if((tRetStatus=apr_pool_userdata_get((void**)&pAuthSession,"SESSION",r->pool))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,ERRTAG "apr_pool_userdata_get Apr Error: %d", tRetStatus);
        return DECLINED;
    }

    /* get require line */
#if MODULE_MAGIC_NUMBER_MAJOR > 20051115
    reqs_arr = conf->requireelems;
#else
    reqs_arr = ap_requires(r);
#endif
    reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;

    /* decline if no require line found */
    if (!reqs_arr) return DECLINED;

    /* walk throug the array to check eatch require command */
    for (x = 0; x < reqs_arr->nelts; x++) {
#if MODULE_MAGIC_NUMBER_MAJOR <= 20051115
      if (!(reqs[x].method_mask & (AP_METHOD_BIT << m)))
	  continue;
#endif

      /* get require line */
      szRequireLine = reqs[x].requirement;
      ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG  "Require Line is '%s'", szRequireLine);

      /* get the first word in require line */
      szRequire_cmd = ap_getword_white(r->pool, &szRequireLine);
      ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "Require Cmd is '%s'", szRequire_cmd);

      if (szRequire_cmd) {
	/* if require cmd are valid-user, they are already authenticated (session cookie found) then allow and return OK */
	if (!strcmp("valid-user",szRequire_cmd)) {
	    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,ERRTAG "Require Cmd valid-user");
	    return OK;
	} else if (!strcmp("user",szRequire_cmd)) { /* check the required users */ 
	    szUser=NULL;
	    while (*szRequireLine && (szUser = ap_getword_conf(r->pool, &szRequireLine))) {
	      if (szUser==NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r ,ERRTAG  "user %s not in user", szMyUser);
		continue;
	      }
	      ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r ,ERRTAG  "check user '%s' vs '%s'",szUser,szMyUser);
	      if (!strcmp(szMyUser, szUser)) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r ,ERRTAG  "the user logged '%s' is authorized",szMyUser);
		return OK;
	      }
	    }
	} else if (!strcmp("group",szRequire_cmd)) { /* check the required groups */
	    szGroups=NULL;
	    while(*szRequireLine && (szGroup = ap_getword_white(r->pool, &szRequireLine))) {
	       if (szGroups==NULL) {
		   ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r ,ERRTAG  "user %s not in group", szMyUser);
		   continue;
	       }
	       ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r ,ERRTAG  "check group '%s' in '%s'",szGroup,szGroups);
	       if (get_Auth_memCookie_grp(r, szGroup, szGroups)==OK) {
		   ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r ,ERRTAG  "the user logged '%s' as the good group %s and is authorized",szMyUser,szGroup);
		   return OK;
	       }
	    }
	}
      }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r ,ERRTAG  "the user logged '%s' not authorized",szMyUser);
    /* forbid by default */
    return HTTP_FORBIDDEN;
}


/**************************************************
 * register module hook 
 **************************************************/
static void register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(Auth_memCookie_check_cookie, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_auth_checker(Auth_memCookie_check_auth, NULL, NULL, APR_HOOK_FIRST);
}

/************************************************************************************
 *  Apache CONFIG Phase:
 ************************************************************************************/
static void *create_Auth_memCookie_dir_config(apr_pool_t *p, char *d)
{
    strAuth_memCookie_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->szAuth_memCookie_memCached_Configuration = apr_pstrdup(p,"--SERVER=127.0.0.1:11211");
    conf->szAuth_memCookie_CookieName = apr_pstrdup(p,"AuthMemCookie");
    conf->tAuth_memCookie_MemcacheObjectExpiry = 3600; /* memcache object expire time, 1H by default */
    conf->nAuth_memCookie_MemcacheObjectExpiryReset = 1;  /* fortress is secure by default, reset object expire time in memcache by default */
    conf->nAuth_memCookie_MatchIP_Mode = 0;  /* method used in matchip, use (0) remote ip by default, if set to 1 for use ip from x_forwarded_for http header and 2 for use Via http header */
    conf->nAuth_memCookie_GroupAuthoritative = 1;  /* group are handled by this module by default */
    conf->nAuth_memCookie_Authoritative = 0;  /* not by default */
    conf->nAuth_memCookie_authbasicfix = 1;  /* fix header for php auth by default */
    conf->nAuth_memCookie_SetSessionHTTPHeader = 0; /* set session information in http header of authenticated user */
    conf->nAuth_memCookie_SetSessionHTTPHeaderEncode = 1; /* encode http header groups value by default */
    conf->nAuth_memCookie_SessionTableSize=10; /* Max number of element in session information table, 10 by default */
#if MODULE_MAGIC_NUMBER_MAJOR > 20051115
    conf->requireelems=apr_array_make(p,20,sizeof(require_line));
#endif

    return conf;
}

#if MODULE_MAGIC_NUMBER_MAJOR > 20051115
static const char* add_require_tag(cmd_parms *cmd, void *InDirConf, const char *p1) {
     strAuth_memCookie_config_rec *conf=(strAuth_memCookie_config_rec*)InDirConf;
     require_line *rt = apr_array_push(conf->requireelems);
     rt->requirement = (char*) p1;
     return NULL;       
}
#endif

static const char *cmd_MatchIP_Mode(cmd_parms *cmd, void *InDirConf, const char *p1) {
    strAuth_memCookie_config_rec *conf=(strAuth_memCookie_config_rec*)InDirConf;

    if ((strcasecmp("1",p1)==0) || (strcasecmp("X-Forwarded-For",p1)==0))
    {
       conf->nAuth_memCookie_MatchIP_Mode=1;
    }
    else if ((strcasecmp("2",p1)==0) || (strcasecmp("Via",p1)==0))
    {
       conf->nAuth_memCookie_MatchIP_Mode=2;
    }
    else if ((strcasecmp("3",p1)==0) || (strcasecmp("RemoteIP",p1)==0))
    {
       conf->nAuth_memCookie_MatchIP_Mode=3;
    }
    else
    {
       conf->nAuth_memCookie_MatchIP_Mode=0;
    }

    return NULL;
}

/* apache config fonction of the module */
static const command_rec Auth_memCookie_cmds[] =
{
    AP_INIT_TAKE1("Auth_memCookie_Memcached_Configuration", ap_set_string_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, szAuth_memCookie_memCached_Configuration),
     OR_AUTHCFG, "libmemcached configuration - http://docs.libmemcached.org/libmemcached_configuration.html"),
    AP_INIT_TAKE1("Auth_memCookie_Memcached_SessionObject_ExpireTime", ap_set_int_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, tAuth_memCookie_MemcacheObjectExpiry),
     OR_AUTHCFG, "Session object in memcached expiry time, in secondes."),
    AP_INIT_TAKE1("Auth_memCookie_SessionTableSize", ap_set_int_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_SessionTableSize),
     OR_AUTHCFG, "Max number of element in session information table. 10 by default"),
    AP_INIT_FLAG ("Auth_memCookie_Memcached_SessionObject_ExpiryReset", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_MemcacheObjectExpiryReset),
     OR_AUTHCFG, "Set to 'no' to not reset object expiry time in memcache... yes by default"),
    AP_INIT_FLAG ("Auth_memCookie_SetSessionHTTPHeader", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_SetSessionHTTPHeader),
     OR_AUTHCFG, "Set to 'yes' to set session information to http header of the authenticated users, no by default"),
    AP_INIT_FLAG ("Auth_memCookie_SetSessionHTTPHeaderEncode", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_SetSessionHTTPHeaderEncode),
     OR_AUTHCFG, "Set to 'yes' to mime64 encode session information to http header, no by default"),
    AP_INIT_TAKE1("Auth_memCookie_CookieName", ap_set_string_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, szAuth_memCookie_CookieName),
     OR_AUTHCFG, "Name of cookie to set"),
    AP_INIT_TAKE1 ( "Auth_memCookie_MatchIP_Mode", cmd_MatchIP_Mode, 
     NULL, 
     OR_AUTHCFG, "To check cookie ip adresse, Set to '1' to use 'X-Forwarded-For' http header, to '2' to use 'Via' http header, and to '3' to use apache remote_ip. set to '0' by default to desactivate the ip check."),
    AP_INIT_FLAG ("Auth_memCookie_GroupAuthoritative", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_GroupAuthoritative),
     OR_AUTHCFG, "Set to 'no' to allow access control to be passed along to lower modules, for group acl check, set to 'yes' by default."),
    AP_INIT_FLAG ("Auth_memCookie_Authoritative", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_Authoritative),
     OR_AUTHCFG, "Set to 'yes' to allow access control to be passed along to lower modules, set to 'no' by default"),
    AP_INIT_FLAG ("Auth_memCookie_SilmulateAuthBasic", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_authbasicfix),
     OR_AUTHCFG, "Set to 'no' to fix http header and auth_type for simulating auth basic for scripting language like php auth framework work, set to 'yes' by default"),
#if MODULE_MAGIC_NUMBER_MAJOR > 20051115
    AP_INIT_RAW_ARGS("Require", add_require_tag, NULL, OR_AUTHCFG,
                        "specifies require directive"
                        "which one must pass (or not) for a request to suceeed"), 
#endif
    {NULL}
};

/* apache module structure */
module AP_MODULE_DECLARE_DATA mod_auth_memcookie_module =
{
    STANDARD20_MODULE_STUFF,
    create_Auth_memCookie_dir_config, /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    Auth_memCookie_cmds,              /* command apr_table_t */
    register_hooks              /* register hooks */
};
