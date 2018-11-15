/* Copyright 1999-2016 Mathieu CARBONNEAUX
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

#include "mod_auth_memcookie.h"
#include <stdio.h>
#include <string.h>

#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_base64.h"
#include "apr_md5.h"            /* for apr_password_validate */
#include "apr_uuid.h"
#include "apr_tables.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "ap_provider.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/
#include "util_md5.h"

#include "mod_auth.h"

#include "libmemcached-1.0/memcached.h"

#define LOGTAG_PREFIX "Auth_memCookie: "
#define VERSION "2.0.1"
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
    char *	szAuth_memCookie_SetSessionHTTPHeaderPrefix;
    int 	nAuth_memCookie_SessionTableSize;

    char *	szAuth_memCookie_CookieName;

#if MODULE_MAGIC_NUMBER_MAJOR <= 20051115
    int 	nAuth_memCookie_GroupAuthoritative;
#endif
    int 	nAuth_memCookie_Authoritative;
    int 	nAuth_memCookie_MatchIP_Mode;

    int 	nAuth_memCookie_authbasicfix;
    int 	nAuth_memCookie_disable_no_store;
#ifdef HAVE_MEMCACHED_SASL
    int 	nAuth_memCookie_SASLAuth;
    char *	szAuth_memCookie_SASLUsername;
    char *	szAuth_memCookie_SASLPassword;
#endif
} strAuth_memCookie_config_rec;

/***********************************************************************
 *
 * extract_cookie
 *
 * Look through 'Cookie' header for indicated cookie; extract it
 * and URL-unescape it. Return the cookie on success, NULL on failure. 
 *
 ***********************************************************************/
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

/************************************************************************************
 *
 * fix_headers_in
 *
 * Function to fix any headers in the input request that may be relied on by an
 * application. e.g. php uses the Authorization header when logging the request
 * in apache and not r->user (like it ought to). It is applied after the request
 * has been authenticated. 
 *
 ************************************************************************************/
static void fix_headers_in(request_rec *r,char*szPassword)
{

   char *szUser=NULL;

   /* Set an Authorization header in the input request table for php and
      other applications that use it to obtain the username (mainly to fix
      apache logging of php scripts). We only set this if there is no header
      already present. */

   if (apr_table_get(r->headers_in,"Authorization")==NULL) 
   {

     ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "fixing apache Authorization header for this request using user:%s",r->user);

     /* concat username and ':' */
     if (szPassword!=NULL) szUser=(char*)apr_pstrcat(r->pool,r->user,":",szPassword,NULL);
     else szUser=(char*)apr_pstrcat(r->pool,r->user,":",NULL);

     /* alloc memory for the estimated encode size of the username */
     char *szB64_enc_user=(char*)apr_palloc(r->pool,apr_base64_encode_len(strlen(szUser))+1);
     unless (szB64_enc_user) {
       ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "memory alloc failed!");
       return;
     }

     /* encode username in base64 format */
     apr_base64_encode(szB64_enc_user,szUser,strlen(szUser));


     /* set authorization header */
     apr_table_set(r->headers_in,"Authorization", (char*)apr_pstrcat(r->pool,"Basic ",szB64_enc_user,NULL));
     apr_table_set(r->subprocess_env,"PHP_AUTH_DIGEST_RAW", (char*)apr_pstrcat(r->pool,"Basic ",szB64_enc_user,NULL));
     apr_table_set(r->subprocess_env,"HTTP_AUTHORIZATION", (char*)apr_pstrcat(r->pool,"Basic ",szB64_enc_user,NULL));

     /* force auth type to basic */
     r->ap_auth_type=apr_pstrdup(r->pool,"Basic");
   }
 
   return;
} 

/***********************************************************************************
 *
 * Auth_memCookie_get_session 
 *
 * Get session with szCookieValue key from memcached server.
 *
 ***********************************************************************************/
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
    char *szTokenPos;
    char *szFieldTokenPos;
    char *szField;
    char *szValue;
    char *szFieldName;
    char *szFieldValue;
    char *szMyValue;
    int nbInfo=0;
    
    /* check if libmemcached configuration are set */
    unless(conf->szAuth_memCookie_memCached_Configuration) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "No Auth_memCookie_memCached_Configuration specified");
        return NULL;
    }
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX  "libmemcached configuration are %s",conf->szAuth_memCookie_memCached_Configuration);

    /* init memcache lib */
    unless(memc=memcached(szMemcached_Configuration,strlen(szMemcached_Configuration))) {
	 ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "memcache lib init failed");
	 return NULL;
    }

#ifdef HAVE_MEMCACHED_SASL
    /* set sasl auth data */
    if(conf->nAuth_memCookie_SASLAuth) {
        rc = memcached_set_sasl_auth_data(memc, conf->szAuth_memCookie_SASLUsername, conf->szAuth_memCookie_SASLPassword);
        if(rc != MEMCACHED_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX
                    "Failed to set SASL credentials: %s", memcached_last_error_message(memc));
        }
    }
#endif

    unless(pMySession=apr_table_make(r->pool,conf->nAuth_memCookie_SessionTableSize)) {
       ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, LOGTAG_PREFIX "apr_tablemake failed");
       return NULL;
    }

    /* get value for the key 'szCookieValue' in memcached server */
    unless(szValue=(char*)memcached_get(memc,szCookieValue,nGetKeyLen,&nGetLen,&flags,&rc)) {
        if(rc == MEMCACHED_SUCCESS) {
            ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r, LOGTAG_PREFIX
                    "memcached_get did not return data for key '%s'",szCookieValue);
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX
                    "memcached_get call failed: %s", memcached_last_error_message(memc));
        }
#ifdef HAVE_MEMCACHED_SASL
        /* free sasl auth data */
        if(conf->nAuth_memCookie_SASLAuth) {
            rc = memcached_destroy_sasl_auth_data(memc);
            if(rc != MEMCACHED_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX
                        "Failed to free SASL auth data: %s", memcached_last_error_message(memc));
            }
        }
#endif
        /* free the libmemcached session */
        memcached_free(memc);
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
        szFieldName=apr_strtok(szField,"=",&szFieldTokenPos);
        szFieldValue=apr_strtok(NULL,"\r\n",&szFieldTokenPos);
	if (szFieldName!=NULL&&szFieldValue!=NULL) {
	  /* add key and value in pMySession table */
	  apr_table_set(pMySession,szFieldName,szFieldValue);
	  ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX "session information '%s'='%s'",szFieldName,szFieldValue);

	  /* count the number of element added to table to check table size not reached */
	  nbInfo++;
          if (nbInfo>conf->nAuth_memCookie_SessionTableSize) {
	    ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX "maximum session information reached!");
	    return NULL;
	  }
	}
    }

    if (!apr_table_get(pMySession,"UserName")) {
       ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX "Username not found in Session value(key:%s) found = %s",szCookieValue,szValue);
       pMySession=NULL;
    } else if (conf->nAuth_memCookie_MatchIP_Mode!=0&&!apr_table_get(pMySession,"RemoteIP")) {
       ap_log_rerror(APLOG_MARK,APLOG_ERR|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX "MatchIP_Mode activated and RemoteIP not found in Session value(key:%s) found = %s",szCookieValue,szValue);
       pMySession=NULL;
    } else {
       ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX "Value for Session (key:%s) found => Username=%s Groups=%s RemoteIp=%s",
				 szCookieValue,
				 apr_table_get(pMySession,"UserName"),
				 apr_table_get(pMySession,"Groups"),
				 apr_table_get(pMySession,"RemoteIP"));
			      }

    /* reset expire time in memcached */
    if (conf->nAuth_memCookie_MemcacheObjectExpiryReset&&pMySession) {
     if ((rc=memcached_set(memc,szCookieValue,nGetKeyLen,szValue,nGetLen,tExpireTime,flags))) {
       ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,LOGTAG_PREFIX  "Expire time with memcached_set (key:%s) failed with errcode=%s",szCookieValue,memcached_last_error_message(memc));
       pMySession=NULL;
     }
    }

    /* free memcached_get retruned valued */
    if (!szValue) free(szValue);

#ifdef HAVE_MEMCACHED_SASL
    /* free sasl auth data */
    if(conf->nAuth_memCookie_SASLAuth) {
        rc = memcached_destroy_sasl_auth_data(memc);
        if(rc != MEMCACHED_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX
                    "Failed to free SASL auth data: %s", memcached_last_error_message(memc));
        }
    }
#endif
    /* free the libmemcached session */
    memcached_free(memc);

    /* set the good username found in request structure */
    if (pMySession!=NULL&&apr_table_get(pMySession,"UserName")!=NULL) r->user=(char*)apr_table_get(pMySession,"UserName");

    return pMySession;
}

/**************************************
 *
 * get_Auth_memCookie_grp
 *
 * check if szGroup are in szGroups. 
 *
 **************************************/
static int get_Auth_memCookie_grp(request_rec *r, const char *szGroup, const char *szGroups)
{
    char *szMyGroups;
    char *szMyGroup;

    /* Add delimiters at start and end of groups string */
    /* and search group with delimiters */
    szMyGroups=apr_pstrcat(r->pool,":",szGroups,":",NULL);
    szMyGroup=apr_pstrcat(r->pool,":",szGroup,":",NULL);

    if (!strstr(szMyGroups,szMyGroup))
        return DECLINED;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "group found=%s", szGroup);
    return OK;
}

char* strupr(char* s)
{
    char* tmp = s;

    for (;*tmp;++tmp) {
        *tmp = toupper((unsigned char) *tmp);
    }

    return s;
}

/***************************************************************
 *
 * Auth_memCookie_DoSetHeader
 *
 * user apr_table_do to set session information in header http. 
 *
 **************************************************************/
static int Auth_memCookie_DoSetHeader(void*rec,const char *szKey, const char *szValue)
{
    strAuth_memCookie_config_rec *conf=NULL;
    request_rec *r=(request_rec*)rec;
    char *szB64_enc_string=NULL;

    /* get apache config */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module);

    /* prefix each variable with "szAuth_memCookie_SetSessionHTTPHeaderPrefix" (by default MCAC_) */
    char*szHeaderName=apr_pstrcat(r->pool,conf->szAuth_memCookie_SetSessionHTTPHeaderPrefix,szKey,NULL);
    strupr(szHeaderName);

    if (conf->nAuth_memCookie_SetSessionHTTPHeaderEncode) {
      /* alloc memory for the estimated encode size of the string */
      szB64_enc_string=(char*)apr_palloc(r->pool,apr_base64_encode_len(strlen(szValue))+1);
      unless (szB64_enc_string) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "memory alloc for encoding http header failed!");
	return 0;
      }

      /* encode string in base64 format */
      apr_base64_encode(szB64_enc_string,szValue,strlen(szValue));

      /* set string header */
      apr_table_setn(r->subprocess_env,szHeaderName,(char*)szB64_enc_string);
      apr_table_setn(r->headers_in,szHeaderName,(char*)szB64_enc_string);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "Send HTTP Header %s=%s", szHeaderName,szB64_enc_string);
    }
    else
    {
      /* set string header */
      apr_table_setn(r->subprocess_env,szHeaderName,(char*)szValue);
      apr_table_setn(r->headers_in,szHeaderName,(char*)szValue);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "Send HTTP Header %s=%s", szHeaderName,szValue);
    }
    return 1;
}

/****************************************************************************
 *
 * Auth_memCookie_Return_Safe_Unauthorized
 *
 * potential security issue: if we return a login to the browser, we must
 * send a no-store to make sure a well behaved browser will not try and
 * send the login details a second time if the back button is pressed.
 *
 * if the user has full control over the backend, the
 * AuthCookieDisableNoStore can be used to turn this off.
 *
 ****************************************************************************/
static int Auth_memCookie_Return_Safe_Unauthorized(request_rec *r)
{
    strAuth_memCookie_config_rec *conf=NULL;

    /* get mod_auth_memcookie_module apache config */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module);

    if (!conf->nAuth_memCookie_disable_no_store) {
        apr_table_addn(r->headers_out, "Cache-Control", "no-store");
        apr_table_addn(r->err_headers_out, "Cache-Control", "no-store");
    }

    return HTTP_UNAUTHORIZED;
}

/******************************************************************************
 *
 * Auth_memCookie_check_cookie
 *
 * This is the Authentication phase (authn), they verify 
 * if authentification cookie is set and if is know in memcache server.
 *
 * If the login is not valid, a 401 Not Authorized will be returned. 
 *
 * It is up to the webmaster to ensure this screen displays a suitable login
 * form to give the user the opportunity to log in.
 *****************************************************************************/
static int Auth_memCookie_check_cookie(request_rec *r)
{
    strAuth_memCookie_config_rec *conf=NULL;
    char *szCookieValue=NULL;
    apr_table_t *pAuthSession=NULL;
    apr_status_t tRetStatus;
    char *szRemoteIP=NULL;
    const char *current_auth = NULL;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX  "ap_hook_check_user_id in");

    /* get mod_auth_memcookie_module apache config */
    conf = ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module);

    /* check if module are authoritative */
    unless(conf->nAuth_memCookie_Authoritative)
	return DECLINED;

    /* set szRemoteIP in case of conf->nAuth_memCookie_MatchIP_Mode value */
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX  "check MatchIP_Mode:%d",conf->nAuth_memCookie_MatchIP_Mode);
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


    /*
     * XSS security warning: using cookies to store private data only works
     * when the administrator has full control over the source website. When
     * in forward-proxy mode, websites are public by definition, and so can
     * never be secure. Abort the auth attempt in this case.
     */
    if (PROXYREQ_PROXY == r->proxyreq) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, LOGTAG_PREFIX
                      "mcac auth cannot be used for proxy "
                      "requests due to XSS risk, access denied: %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* We need an authentication realm. */
    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, LOGTAG_PREFIX
                      "need AuthName: %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* check auth type if they are setted to "Cookie" */
    current_auth = ap_auth_type(r);
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX  "AuthType are '%s'", current_auth);
    unless(strncasecmp("cookie",current_auth,6)==0) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "Auth type not specified as 'Cookie'");
	return DECLINED; //IIG: Allow basic auth to be set
    }

    /* check if the cookie name are set */
    unless(conf->szAuth_memCookie_CookieName) {
	ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "No Auth_memCookie_CookieName specified");
        return Auth_memCookie_Return_Safe_Unauthorized(r);
    }

    /* get cookie named "szAuth_memCookie_CookieName" */
    unless(szCookieValue = extract_cookie(r, conf->szAuth_memCookie_CookieName))
    {
      ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "cookie not found! not authorized! RemoteIP:%s",szRemoteIP);
      return Auth_memCookie_Return_Safe_Unauthorized(r);
    }
    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX  "got cookie; value is %s", szCookieValue);

    /* get session name "szCookieValue" from memcached */
    if((pAuthSession = Auth_memCookie_get_session(r, conf, szCookieValue))==NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "AuthSession %s not found: %s", szCookieValue, r->filename);
        return Auth_memCookie_Return_Safe_Unauthorized(r);
    }

    /* push session returned structure in request pool */
    if ((tRetStatus=apr_pool_userdata_setn(pAuthSession,"SESSION",NULL,r->pool))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "apr_pool_userdata_setn Apr Error: %d", tRetStatus);
        return Auth_memCookie_Return_Safe_Unauthorized(r);
    }

    /* check remote ip if option is enabled */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "check ip: remote_ip=%s cookie_ip=%s", szRemoteIP ,apr_table_get(pAuthSession,"RemoteIP"));
    if (conf->nAuth_memCookie_MatchIP_Mode!=0) {
       if (strcmp(szRemoteIP ,apr_table_get(pAuthSession,"RemoteIP"))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "unauthorized, by ip. user:%s remote_ip:%s != cookie_ip:%s", 
	                     apr_table_get(pAuthSession,"UserName"),szRemoteIP ,apr_table_get(pAuthSession,"RemoteIP"));
        return Auth_memCookie_Return_Safe_Unauthorized(r);
       }
    }

    /* send http header of the session value to the backend */
    if (conf->nAuth_memCookie_SetSessionHTTPHeader) {
       ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "nAuth_memCookie_SetSessionHTTPHeader is set then send http header...");
       apr_table_do(Auth_memCookie_DoSetHeader,r,pAuthSession,NULL);
    }

    /* set MCAC_SESSIONKEY var for scripts language */
    apr_table_setn(r->subprocess_env, apr_pstrcat(r->pool,conf->szAuth_memCookie_SetSessionHTTPHeaderPrefix,"SESSIONKEY",NULL),szCookieValue);
    apr_table_setn(r->headers_in, apr_pstrcat(r->pool,conf->szAuth_memCookie_SetSessionHTTPHeaderPrefix,"SESSIONKEY",NULL),szCookieValue);

    /* HTTP Header Prefix */
    apr_table_setn(r->subprocess_env,"AUTHMEMCOOKIE_PREFIX",conf->szAuth_memCookie_SetSessionHTTPHeaderPrefix);
    apr_table_setn(r->headers_in,"AUTHMEMCOOKIE_PREFIX",conf->szAuth_memCookie_SetSessionHTTPHeaderPrefix);

    /* cookie found the user is authentified */
    apr_table_setn(r->subprocess_env,"AUTHMEMCOOKIE_AUTH","yes");
    apr_table_setn(r->headers_in,"AUTHMEMCOOKIE_AUTH","yes");

    /* set REMOTE_USER var for scripts language */
    apr_table_setn(r->subprocess_env,"REMOTE_USER",apr_table_get(pAuthSession,"UserName"));
    apr_table_setn(r->headers_in,"REMOTE_USER",apr_table_get(pAuthSession,"UserName"));
    
    /* log authorisation ok */
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "authentication ok");

    /* fix http header for php */
    if (conf->nAuth_memCookie_authbasicfix) fix_headers_in(r,(char*)apr_table_get(pAuthSession,"Password"));

    /* if all is ok return auth ok */
    return OK;
}

#if MODULE_MAGIC_NUMBER_MAJOR > 20051115

static authz_status Auth_memCookie_public_authz_checker(request_rec *r, const char *require_args, const void *parsed_require_args) {

    strAuth_memCookie_config_rec *conf=NULL;
    char *szMyUser=r->user;
    char *szCookieValue=NULL;

    apr_table_t *pAuthSession=NULL;

    authz_status nReturn=AUTHZ_GRANTED;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX  "Auth_memCookie_public_authz_checker in");
    if (!szMyUser) {

      /* get apache config */
      conf = ap_get_module_config(r->per_dir_config, &mod_auth_memcookie_module);

      /* check if the cookie name are set */
      unless(conf->szAuth_memCookie_CookieName) {
	  ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "No Auth_memCookie_CookieName specified");
	  return AUTHZ_GENERAL_ERROR;
      }

      /* get cookie named "szAuth_memCookie_CookieName" */
      unless(szCookieValue = extract_cookie(r, conf->szAuth_memCookie_CookieName))
      {
	ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "cookie not found, continue !");
	return nReturn;
      }
      ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX  "got cookie; value is %s", szCookieValue);

      /* get session name "szCookieValue" from memcached */
      if((pAuthSession = Auth_memCookie_get_session(r, conf, szCookieValue))==NULL) {
	  ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "AuthSession %s not found: %s", szCookieValue, r->filename);
	  return nReturn;
      }

      /* send http header of the session value to the backend */
      if (conf->nAuth_memCookie_SetSessionHTTPHeader) {
	 ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, r, LOGTAG_PREFIX "nAuth_memCookie_SetSessionHTTPHeader is set then send http header...");
	 apr_table_do(Auth_memCookie_DoSetHeader,r,pAuthSession,NULL);
      }

      /* set MCAC_SESSIONKEY var for scripts language */
      apr_table_setn(r->subprocess_env, apr_pstrcat(r->pool,conf->szAuth_memCookie_SetSessionHTTPHeaderPrefix,"SESSIONKEY",NULL),szCookieValue);
      apr_table_setn(r->headers_in, apr_pstrcat(r->pool,conf->szAuth_memCookie_SetSessionHTTPHeaderPrefix,"SESSIONKEY",NULL),szCookieValue);
    
      /* HTTP Header Prefix */
      apr_table_setn(r->subprocess_env,"AUTHMEMCOOKIE_PREFIX",conf->szAuth_memCookie_SetSessionHTTPHeaderPrefix);
      apr_table_setn(r->headers_in,"AUTHMEMCOOKIE_PREFIX",conf->szAuth_memCookie_SetSessionHTTPHeaderPrefix);

      /* cookie found but they are in public zone */
      apr_table_setn(r->subprocess_env,"AUTHMEMCOOKIE_AUTH","no");
      apr_table_setn(r->headers_in,"AUTHMEMCOOKIE_AUTH","no");

    }
    return nReturn;
}
/**************************************************
 *
 * Auth_memCookie_check_auth
 *
 * Authorization phase (authz) in apache >2.3 : 
 * Checking authoriszation group for the authenticated cookie 
 **************************************************/

static authz_status Auth_memCookie_group_authz_checker(request_rec *r, const char *require_args, const void *parsed_require_args) {

    char *szMyUser=r->user;
    //int m = r->method_number;

    const char *err = NULL;

    const ap_expr_info_t *expr = parsed_require_args;
    const char *require;

    const char *szGroups;
    const char *szGroup;
    const char *t;

    apr_table_t *pAuthSession=NULL;
    apr_status_t tRetStatus;


    if (!szMyUser) {
         return AUTHZ_DENIED_NO_USER;
    }

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX  "Auth_memCookie_group_authz_checker in");

    // no cookie session validated go denied
    if((tRetStatus=apr_pool_userdata_get((void**)&pAuthSession,"SESSION",r->pool))) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,LOGTAG_PREFIX "apr_pool_userdata_get Apr Error: %d", tRetStatus);
        return AUTHZ_DENIED;
    }

    szGroups=apr_table_get(pAuthSession,"Groups");
    if (szGroups==NULL) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, LOGTAG_PREFIX
	                   "authorization denied: no group asociated to the session");
	 return AUTHZ_DENIED;
    }

    require = ap_expr_str_exec(r, expr, &err);
    if (err) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, LOGTAG_PREFIX
	                   "authorization denied: Can't evaluate require expression: %s", err);
	 return AUTHZ_DENIED;
    }

    t = require;
    while ((szGroup = ap_getword_conf(r->pool, &t)) && szGroup[0]) {
         ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r ,LOGTAG_PREFIX  "check group '%s' in '%s'",szGroup,szGroups);
         if (get_Auth_memCookie_grp(r,szGroup, szGroups)==OK) {
	      ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r ,LOGTAG_PREFIX  "the user logged '%s' as the good group %s and is authorized",szMyUser,szGroup);
	      return AUTHZ_GRANTED;
	 }
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, LOGTAG_PREFIX
                    "Authorization of user %s to access %s failed, reason: "
		    "user is not part of the 'require'ed group(s).",
				                    r->user, r->uri);

    return AUTHZ_DENIED;
}

#else 

/**************************************************
 *
 * Auth_memCookie_check_auth
 *
 * Authorization phase in apache 2.0 to 2.2 : 
 *   Checking authoriszation for user and group of the authenticated cookie 
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
    const char *szGroup;
    const char *szGroups;

    apr_table_t *pAuthSession=NULL;
    apr_status_t tRetStatus;

    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX  "Auth_memCookie_check_auth in");

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
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,LOGTAG_PREFIX "apr_pool_userdata_get Apr Error: %d", tRetStatus);
        return DECLINED;
    }

    /* get require line */
    reqs_arr = ap_requires(r);
    reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;

    /* decline if no require line found */
    if (!reqs_arr) return DECLINED;

    /* walk throug the array to check eatch require command */
    for (x = 0; x < reqs_arr->nelts; x++) {

      // skip require elt if request method 'm' not match the require method_mask
      if (!(reqs[x].method_mask & (AP_METHOD_BIT << m)))
	  continue;

      /* get require line */
      szRequireLine = reqs[x].requirement;
      ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX  "Require Line is '%s'", szRequireLine);

      /* get the first word in require line */
      szRequire_cmd = ap_getword_white(r->pool, &szRequireLine);
      ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX "Require Cmd is '%s'", szRequire_cmd);

      if (szRequire_cmd) {
	/* if require cmd are valid-user, they are already authenticated (session cookie found) then allow and return OK */
	if (!strcmp("valid-user",szRequire_cmd)) {
	    ap_log_rerror(APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO, 0,r,LOGTAG_PREFIX "Require Cmd valid-user");
	    return OK;
	} else if (!strcmp("user",szRequire_cmd)) { /* check the required users */ 
	    szUser=NULL;
	    while (*szRequireLine && (szUser = ap_getword_conf(r->pool, &szRequireLine))) {
	      if (szUser==NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r ,LOGTAG_PREFIX  "user %s not in user", szMyUser);
		continue;
	      }
	      ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r ,LOGTAG_PREFIX  "check user '%s' vs '%s'",szUser,szMyUser);
	      if (!strcmp(szMyUser, szUser)) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r ,LOGTAG_PREFIX  "the user logged '%s' is authorized",szMyUser);
		return OK;
	      }
	    }
	} else if ((!strcmp("group",szRequire_cmd))||(!strcmp("mcac-group",szRequire_cmd))) { /* check the required groups */
	    szGroups=apr_table_get(pAuthSession,"Groups");
	    if (szGroups==NULL) {
		 ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, LOGTAG_PREFIX
				   "authorization denied: no group asociated to the session");
		 return AUTH_DENIED;
	    }
	    while(*szRequireLine && (szGroup = ap_getword_white(r->pool, &szRequireLine))) {
	       ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r ,LOGTAG_PREFIX  "check group '%s' in '%s'",szGroup,szGroups);
	       if (get_Auth_memCookie_grp(r, szGroup, szGroups)==OK) {
		   ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, r ,LOGTAG_PREFIX  "the user logged '%s' as the good group %s and is authorized",szMyUser,szGroup);
		   return OK;
	       }
	    }
	}
      }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r ,LOGTAG_PREFIX  "the user logged '%s' not authorized",szMyUser);
    /* forbid by default */
    return HTTP_FORBIDDEN;
}

#endif

#if MODULE_MAGIC_NUMBER_MAJOR > 20051115

static const char *Auth_memCookie_authz_parse_config( cmd_parms *cmd, const char *require_line, const void **parsed_require_line)
{
    const char *expr_err = NULL;
    ap_expr_info_t *expr;

    expr = ap_expr_parse_cmd(cmd, require_line, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err)
        return apr_pstrcat(cmd->temp_pool,
                           "Cannot parse expression in require line: ",
                           expr_err, NULL);

    *parsed_require_line = expr;

    return NULL;
}

static const authz_provider Auth_memCookie_authz_public_provider = {
 		&Auth_memCookie_public_authz_checker,
		NULL,
};

static const authz_provider Auth_memCookie_authz_group_provider = {
 		&Auth_memCookie_group_authz_checker,
		&Auth_memCookie_authz_parse_config,
};

#endif

/**************************************************
 * register module hook 
 **************************************************/
static void register_hooks(apr_pool_t *p)
{
    // Authz refactoring are done in 20060110 with 2.3.0 creation
    // https://github.com/apache/httpd/commit/ce3c76283dd74148c631030116a7b74dbaf18ba5
    // apache >=2.3 model
#if MODULE_MAGIC_NUMBER_MAJOR > 20051115
    ap_hook_check_authn(Auth_memCookie_check_cookie, NULL, NULL, APR_HOOK_FIRST, AP_AUTH_INTERNAL_PER_CONF);

    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "mcac-group", 
				 AUTHZ_PROVIDER_VERSION, 
				 &Auth_memCookie_authz_group_provider, 
				 AP_AUTH_INTERNAL_PER_CONF);

    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "mcac-public", 
				 AUTHZ_PROVIDER_VERSION, 
				 &Auth_memCookie_authz_public_provider, 
				 AP_AUTH_INTERNAL_PER_CONF);

#else
    // apache 2.0 to 2.2 model
    ap_hook_check_user_id(Auth_memCookie_check_cookie, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_auth_checker(Auth_memCookie_check_auth, NULL, NULL, APR_HOOK_FIRST);
#endif
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
#if MODULE_MAGIC_NUMBER_MAJOR <= 20051115
    conf->nAuth_memCookie_GroupAuthoritative = 1;  /* group are handled by this module by default */
#endif
    conf->nAuth_memCookie_Authoritative = 1;  /* is set by default */
    conf->nAuth_memCookie_authbasicfix = 1;  /* fix header for php auth by default */
    conf->nAuth_memCookie_SetSessionHTTPHeader = 0; /* set session information in http header of authenticated user */
    conf->nAuth_memCookie_SetSessionHTTPHeaderEncode = 0; /* encode http header groups value by default */
    conf->szAuth_memCookie_SetSessionHTTPHeaderPrefix = apr_pstrdup(p,"MCAC_"); 
    conf->nAuth_memCookie_SessionTableSize=10; /* Max number of element in session information table, 10 by default */
    conf->nAuth_memCookie_disable_no_store=0; /* no store cache option are the default */
#ifdef HAVE_MEMCACHED_SASL
    conf->nAuth_memCookie_SASLAuth = 0; /* Disabled by default */
    conf->szAuth_memCookie_SASLUsername = apr_pstrdup(p, "user");
    conf->szAuth_memCookie_SASLPassword = apr_pstrdup(p, "pass");
#endif

    return conf;
}

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
     OR_AUTHCFG, "Max number of element in session information table. is set to 10 by default"),
    AP_INIT_FLAG ("Auth_memCookie_Memcached_SessionObject_ExpiryReset", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_MemcacheObjectExpiryReset),
     OR_AUTHCFG, "Set to 'off' to not reset object expiry time in memcache... is 'on' by default"),
    AP_INIT_FLAG ("Auth_memCookie_SetSessionHTTPHeader", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_SetSessionHTTPHeader),
     OR_AUTHCFG, "Set to 'on' to set session information to http header of the authenticated users, is set 'off' by default"),
    AP_INIT_FLAG ("Auth_memCookie_SetSessionHTTPHeaderEncode", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_SetSessionHTTPHeaderEncode),
     OR_AUTHCFG, "Set to 'on' to mime64 encode session information to http header, is set 'off' by default"),
    AP_INIT_TAKE1("Auth_memCookie_SetSessionHTTPHeaderPrefix", ap_set_string_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, szAuth_memCookie_SetSessionHTTPHeaderPrefix),
     OR_AUTHCFG, "Set HTTP header prefix - set to 'MCAC_' by default"),
    AP_INIT_TAKE1("Auth_memCookie_CookieName", ap_set_string_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, szAuth_memCookie_CookieName),
     OR_AUTHCFG, "Name of cookie to set"),
    AP_INIT_TAKE1("Auth_memCookie_MatchIP_Mode", cmd_MatchIP_Mode, NULL, 
     OR_AUTHCFG, "To check cookie ip adresse, Set to '1' to use 'X-Forwarded-For' http header, to '2' to use 'Via' http header, and to '3' to use apache remote_ip. set to '0' by default to desactivate the ip check."),
#if MODULE_MAGIC_NUMBER_MAJOR <= 20051115
    AP_INIT_FLAG ("Auth_memCookie_GroupAuthoritative", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_GroupAuthoritative),
     OR_AUTHCFG, "Set to 'off' to allow access control to be passed along to lower modules, for group acl check, is set to 'on' by default."),
#endif
    AP_INIT_FLAG ("Auth_memCookie_Authoritative", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_Authoritative),
     OR_AUTHCFG, "Set to 'off' to allow access control to be passed along to lower modules, is set to 'on' by default"),
    AP_INIT_FLAG ("Auth_memCookie_SilmulateAuthBasic", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_authbasicfix),
     OR_AUTHCFG, "Set to 'off' to fix http header and auth_type for simulating auth basic for scripting language like php auth framework work, is set to 'on' by default"),
    AP_INIT_FLAG ("Auth_memCookie_DisableNoStore", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_disable_no_store),
     OR_AUTHCFG,
     "Set to 'on' to stop the sending of a Cache-Control no-store header with "
     "the login screen. This allows the browser to cache the credentials, but "
     "at the risk of it being possible for the login form to be resubmitted "
     "and revealed to the backend server through XSS. Use at own risk."),
#ifdef HAVE_MEMCACHED_SASL
    AP_INIT_FLAG ("Auth_memCookie_SASLAuth", ap_set_flag_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, nAuth_memCookie_SASLAuth),
     OR_AUTHCFG, "Set to 'on' to use SASL authentication. If this is set then "
     "Auth_memCookie_SASLUsername and Auth_memCookie_SASLPassword should also be set. "
     "Set to 'off' by default"),
    AP_INIT_TAKE1("Auth_memCookie_SASLUsername", ap_set_string_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, szAuth_memCookie_SASLUsername),
     OR_AUTHCFG, "User name to use for SASL authentication to memcached. "
     "Set to 'user' by default"),
    AP_INIT_TAKE1("Auth_memCookie_SASLPassword", ap_set_string_slot,
     (void *)APR_OFFSETOF(strAuth_memCookie_config_rec, szAuth_memCookie_SASLPassword),
     OR_AUTHCFG, "Password to use for SASL authentication to memcached. "
     "Set to 'pass' by default"),
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
