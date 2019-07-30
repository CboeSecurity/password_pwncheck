/*
 * Authored by: Jan Grzymala-Busse 
 * Cboe Security
 * Provided as is, no warranties, please see included licensing.
*/

/*
 * apt install gcc g++ libssl-dev libcurl4-openssl-dev libkrb5-dev
 * gcc -fPIC -fno-stack-protector -c src/pwncheck.c -lcurl -lcrypto -o bin/pwncheck.o  && \
 * gcc -fPIC -fno-stack-protector -c src/config.c -lcurl -lcrypto -o bin/config.o && \
 * gcc -fPIC -fno-stack-protector -c src/curl.c -lcurl -lcrypto -o bin/curl.o && \
 * ld -x --shared -o pwncheck.so bin/pwncheck.o bin/config.o bin/curl.o -lcurl -lcrypto && mv pwncheck.so /lib/security/
 *
 * --------------
 *  [plugins]
 *          pwqual = {
 *                 module = pwncheck:pwqual/pwncheck.so
 *          }
 *  --------------
 */

#pragma ident   "@(#)pwncheck.c      1.1     01/16/18 SMI"

#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include "config.h"
#include "../common/curl.h"
#include "../common/constants.h"


// kerberos

#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>

#include <krb5/pwqual_plugin.h>
#define DEF_PWD_RETURN KADM5_PASS_Q_GENERIC

#ifndef __export
#define __export __attribute__((__visibility__("default")))
#endif

////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
// KERBEROS PLUGIN CODE BELOW                                                     //
////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////
// Perform the actual password quality check                                      //
////////////////////////////////////////////////////////////////////////////////////
static krb5_error_code
pwqual_pwncheck_check(krb5_context context, krb5_pwqual_moddata data,
              const char *passwd, const char *policy_name,
              krb5_principal princ, const char **languages)
{
    char        msg[1024];
    char const *user;
    size_t      user_len;
    int 	ret 		= DEF_PWD_RETURN; // default is unspecified issue
    int		isInsecure 	= FALSE;

   struct cfgpwned config; 
   syslog(LOG_DEBUG, "pwncheck: check: started\n");
   int retconfig = parseConfig(&config, "/etc/krb5-pwned-password.conf");

    if (princ->data && krb5_princ_size(context, princ) > 0) {
        user = princ->data[0].data;
        user_len = princ->data[0].length;
    } else {
        user = "";
        user_len = 0;
    }

    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;
    memset(chunk.memory,'\0',1);


    char* url = DEFAULT_PASSWORD_URL;

    if (retconfig == 0)
    {
      syslog(LOG_DEBUG, "pwncheck: check: configuration in use\n");
      ret = config.DefaultReturn;
      isInsecure = config.isInsecure;
      url = config.url;
    }
     
    

    char filled_url[CURL_MAX_BUFLEN];
    int furllen = CURL_MAX_BUFLEN > strlen(url)+strlen(user)+strlen(passwd) ? CURL_MAX_BUFLEN : strlen(url)+strlen(user)+strlen(passwd);
    snprintf(filled_url, furllen, url, user, passwd);
#ifdef DEBUG
    syslog(LOG_DEBUG, "pwncheck: check: user:%s  password:%s",user,passwd);
    syslog(LOG_DEBUG, "pwncheck: check: Created Filling URL: %s", filled_url);
#endif 
    int queryRet =  queryUrl(filled_url, &chunk, isInsecure);
    syslog(LOG_DEBUG, "pwncheck: check: queryUrl output: %d: %d,%s", queryRet, (int)chunk.size, chunk.memory);
    if (queryRet == 0 ) { // 0 == CURLE_OK
        if (strncmp("True",chunk.memory,4) == 0 ) {
            syslog(LOG_WARNING,"pwncheck: check: Password change successfully checked via %s", url);
            ret = 0;
        } else {
	    int errcode = atoi(&chunk.memory[6]);
            syslog(LOG_WARNING,"pwncheck: check: Password change failed: %d: %s", errcode, chunk.memory);
	    if ( (errcode & 1) == 1) {
                ret = KADM5_PASS_Q_TOOSHORT;
                syslog(LOG_WARNING,"pwncheck: check: Password change too short: %d",ret);
	    } else if ( (errcode & 100) == 100) {
                ret = KADM5_PASS_Q_DICT;
                syslog(LOG_WARNING,"pwncheck: check: Password breached: %d",ret );
	    } else if ( (errcode & 10) == 10) {
                ret = KADM5_PASS_Q_DICT;
                syslog(LOG_WARNING,"pwncheck: check: Password too similar: %d",ret );
	    } else {
                syslog(LOG_WARNING,"pwncheck: check: Unknown bad password reason: %d %d %d %d",errcode&100,errcode&10,errcode&1,errcode);
            }
        }
    }

   
    memset(filled_url,'\0',CURL_MAX_BUFLEN);
    memset(chunk.memory,'\0',chunk.size);
    free(chunk.memory);
    krb5_set_error_message(context, ret, "%.*s", queryRet, msg);
    return ret;
}

////////////////////////////////////////////////////////////////////////////////////
// Initialize Kerberos KDC to know what we are a pwqual plugin, and where we hook //
////////////////////////////////////////////////////////////////////////////////////
krb5_error_code __export
pwqual_pwncheck_initvt(krb5_context context, int maj_ver, int min_ver,
               krb5_plugin_vtable vtable)
{
    FILE* fp;
    syslog(LOG_DEBUG,"pwncheck: initvt: Initiating");
    struct krb5_pwqual_vtable_st    *vt;
/*
    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
*/
    vt = (struct krb5_pwqual_vtable_st *)vtable;
    memset(vt, 0, sizeof *vt);

    vt->name  = "pwncheck";
    vt->check = pwqual_pwncheck_check;
    syslog(LOG_DEBUG,"pwncheck: initvt: Initiated");

    return 0;
}
