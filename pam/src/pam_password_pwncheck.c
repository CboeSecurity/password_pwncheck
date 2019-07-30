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
#include <stdio.h>
#include <curl/curl.h>

// our code

#define CURL_RESPONSE_INIT_SIZE 1024 
#define CURL_MAX_BUFLEN 2048
#define INSECURE

#include <unistd.h>

// more curl
#ifdef INSECURE
#define SKIP_PEER_VERIFICATION
#define SKIP_HOSTNAME_VERIFICATION
#endif

////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
// The following is the Curl-based SSL query code                                 //
////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////

struct MemoryStruct {
  char *memory;
  size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    /* out of memory! */ 
    syslog(LOG_INFO,"pam_password_pwncheck: curl: not enough memory (realloc returned NULL)\n");
    return 0;
  }
 
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

int queryUrl(pam_handle_t *pamh, const char* dest_url, struct MemoryStruct* chunk)
{
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
 
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, dest_url);
 
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)chunk); 

#ifdef SKIP_PEER_VERIFICATION
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        syslog(LOG_WARNING, "pam_password_pwncheck: queryUrl: INSECURE: Verify Peer disabled");
#endif
 
#ifdef SKIP_HOSTNAME_VERIFICATION
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        syslog(LOG_WARNING, "pam_password_pwncheck: queryUrl: INSECURE: Verify Host disabled");
#endif
 
        /* Perform the request, res will get the return code */ 
        res = curl_easy_perform(curl);
        /* Check for errors */ 
        if(res != CURLE_OK)
            syslog(LOG_ERR, "pam_password_pwncheck: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
 
        /* always cleanup */ 
        curl_easy_cleanup(curl);
    }
 
    curl_global_cleanup();
    return res;
}

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

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0)
            debug = 1;
        else if (strncmp(argv[i], "maxequal=", 9) == 0)
            maxequal = atoi(&argv[i][9]);
        else if (strncmp(argv[i], "url=", 4) == 0)
            url = &argv[i][4];
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
    syslog(LOG_DEBUG, "pam_password_pwncheck: Created Filling URL: %s", filled_url);

    chunk.memory = malloc(1); /* will be grown as needed by the realloc above */ 
    chunk.size = 0; /* no data at this point */ 
    memset(chunk.memory,'\0',1); 
    int retUrl = queryUrl(pamh, filled_url, &chunk);

    syslog(LOG_DEBUG, "pam_password_pwncheck: queryUrl output: %d: %d,%s", retUrl, (int)chunk.size, chunk.memory);
    if ((retUrl == CURLE_OK) && (strncmp("True",chunk.memory,4) == 0 )) {
        syslog(LOG_INFO,"pam_password_pwncheck: %s: Password change successfully checked via %s", service, url); 
    } else
    {
        ret = PAM_AUTHTOK_ERR;
    }
    memset(filled_url,'\0',CURL_MAX_BUFLEN);
    memset(chunk.memory,'\0',chunk.size);
    free(chunk.memory);
    return ret;
}
