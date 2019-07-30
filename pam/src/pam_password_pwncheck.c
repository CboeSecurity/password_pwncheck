/*
 * Authored by: Jan Grzymala-Busse 
 * Cboe Security
 * Provided as is, no warranties, please see included licensing.
*/

/*
 * apt install gcc g++ libssl-dev libpam0g-dev libcurl4-openssl-dev
 * gcc -fPIC -fno-stack-protector -c pam_password_pwncheck.c -lcurl -lcrypto -o bin/pam_password_pwncheck.o && ld -x --shared -o pam_password_pwncheck.so bin/pam_password_pwncheck.o -lpam -lcurl -lcrypto && mv pam_password_pwncheck.so /lib/security/
 *
 * password        requisite                       pam_password_pwncheck.so debug url=http://localhost/u=%s&p=%s
 * password        [success=1 default=ignore]      pam_unix.so obscure sha512 use_authtok
 * password        requisite                       pam_deny.so
 * password        required                        pam_permit.so
 */

#pragma ident   "@(#)pam_password_pwncheck.c      1.1     01/16/18 SMI"

// pam-specific

#include <stdarg.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

// curl
//#include <stdio.h>
//#include <curl/curl.h>
#include "../../common/constants.h"
#include "../../common/curl.h"

// our code
#include <unistd.h>

////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
//         PAM PLUGIN CODE BELOW                                                  //
////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////
//  Check authtoken (password) here                                               //
////////////////////////////////////////////////////////////////////////////////////
int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
  const char **argv)
{
    int ret = PAM_SUCCESS;
    int i;
    int debug = 0;
    int maxequal = 0;
    int pam_err;
    char *service;
    char *user;
    const char *url;
    char *passwd;   /* the newly typed password */
    int isInsecure = 0;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0)
            debug = 1;
        else if (strncmp(argv[i], "maxequal=", 9) == 0)
            maxequal = atoi(&argv[i][9]);
        else if (strncmp(argv[i], "url=", 4) == 0)
            url = &argv[i][4];
        else if (strncmp(argv[i], "isinsecure=", 11) == 0)
            isInsecure = atoi(&argv[i][11]);
    }
    
    struct MemoryStruct chunk;
 

    if (debug)
        syslog(LOG_DEBUG, "pam_password_pwncheck: entering pam_sm_chauthtok");

    if ((flags & PAM_PRELIM_CHECK) != 0)
    {
        if (debug)
            syslog(LOG_DEBUG, "pam_password_pwncheck: Preliminary stage, returning ignore");
        return (PAM_IGNORE);
    }
    
   if ((flags & PAM_UPDATE_AUTHTOK) != 0)
   {
        if (debug)
            syslog(LOG_DEBUG, "pam_password_pwncheck: Update stage, Continuing...");
   }

    pam_err = pam_get_item(pamh, PAM_SERVICE, (const void **)&service);
    if (debug)
        syslog(LOG_DEBUG, "pam_password_pwncheck: Service: %s",service);

    if (pam_err != PAM_SUCCESS) {
         syslog(LOG_ERR, "pam_password_pwncheck: error getting service item");
         return (pam_err);
    }

    pam_err = pam_get_item(pamh, PAM_USER, (const void **)&user);
    if (pam_err != PAM_SUCCESS) {
        syslog(LOG_ERR, "pam_password_pwncheck: can't get user item");
        return (pam_err);
    }
    if (debug)
        syslog(LOG_DEBUG, "pam_password_pwncheck: User: %s",user);

    if (user == NULL || service == NULL) {
        syslog(LOG_ERR, "pam_password_pwncheck: %s is NULL", user == NULL ? "PAM_USER" : "PAM_SERVICE");
        return (PAM_SYSTEM_ERR);
    }

    pam_err = pam_get_authtok(pamh, PAM_AUTHTOK, (const char**)&passwd, NULL);
    if (pam_err != PAM_SUCCESS) {
        syslog(LOG_ERR, "pam_password_pwncheck: can't get password item!");
        return (pam_err);
    }
    if (debug)
    	syslog(LOG_DEBUG, "pam_password_pwncheck: New Password: %s",passwd != NULL ? "<Exists>" : "<Null>" );

    if (passwd == NULL) {
        if (debug)
            syslog(LOG_DEBUG, "pam_password_pwncheck: No password available.");
        return (PAM_IGNORE);
    }

    char filled_url[CURL_MAX_BUFLEN];
    int furllen = CURL_MAX_BUFLEN > strlen(url)+strlen(user)+strlen(passwd) ? CURL_MAX_BUFLEN : strlen(url)+strlen(user)+strlen(passwd);
    snprintf(filled_url, furllen, url, user, passwd);
#ifdef DEBUG
    syslog(LOG_DEBUG, "pam_password_pwncheck: check: user:%s  password:%s",user,passwd);
    syslog(LOG_DEBUG, "pam_password_pwncheck: Created Filling URL: %s", filled_url);
#endif
    chunk.memory = malloc(1); /* will be grown as needed by the realloc above */ 
    chunk.size = 0; /* no data at this point */ 
    memset(chunk.memory,'\0',1); 
    int retUrl = queryUrl(filled_url, &chunk, isInsecure);

    syslog(LOG_DEBUG, "pam_password_pwncheck: queryUrl output: %d: %d,%s", retUrl, (int)chunk.size, chunk.memory);
    if ((retUrl == CURLE_OK) && (strncmp("True",chunk.memory,4) == 0 )) {
        syslog(LOG_INFO,"pam_password_pwncheck: %s: Password change successfully checked via %s", service, url); 
    } else
    {
        int errcode = atoi(&chunk.memory[6]);
        syslog(LOG_WARNING,"pam_password_pwncheck: Password change failed: %d: %s", errcode, chunk.memory);
	char* errmsg = "";
        if ( (errcode & 1) == 1) {
            syslog(LOG_WARNING,"pam_password_pwncheck: Password change too short: %d",ret);
	    errmsg = "Too short";
        } else if ( (errcode & 200) == 200) {
            syslog(LOG_WARNING,"pam_password_pwncheck: Password too similar to breached: %d",ret );
	    errmsg = "Similar to known breached";
        } else if ( (errcode & 100) == 100) {
            syslog(LOG_WARNING,"pam_password_pwncheck: Password breached: %d",ret );
	    errmsg = "Known breached";
        } else if ( (errcode & 10) == 10) {
            syslog(LOG_WARNING,"pam_password_pwncheck: Password too similar: %d",ret );
	    errmsg = "Too similar to previous";
        } else {
            syslog(LOG_WARNING,"pam_password_pwncheck: Unknown bad password reason: %d %d %d %d %d",errcode&200,errcode&100,errcode&10,errcode&1,errcode);
	    errmsg = "Unknown bad password, see logs";
        }
        syslog(LOG_WARNING,"pam_password_pwncheck: Password change too short: %d",ret);
	pam_error(pamh, "Password change failed: %s", errmsg);
        ret = PAM_AUTHTOK_ERR;
    }
    memset(filled_url,'\0',CURL_MAX_BUFLEN);
    memset(chunk.memory,'\0',chunk.size);
    free(chunk.memory);
    return ret;
}
