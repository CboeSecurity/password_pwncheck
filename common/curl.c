/*
 * Authored by: Jan Grzymala-Busse 
 * Cboe Security
 * Provided as is, no warranties, please see included licensing.
*/

// curl
#include "curl.h"
#include <stdio.h>
//#include <curl/curl.h> // curl
#include <syslog.h> // syslog, LOG_INFO, etc
#include <string.h> // memcpy
#include <stdlib.h> // realloc

////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
// The following is the Curl-based SSL query code                                 //
////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////

char rfc3986[256] = {0};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    /* out of memory! */ 
    syslog(LOG_INFO,"pwncheck: WriteMemoryCallback: not enough memory (realloc returned NULL)");
    return 0;
  }
 
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

void init_urlencode(void)
{
    int i;
    for (i = 0; i < 256; i++)
    {
        rfc3986[i] = isalnum(i)||i == '~'||i == '-'||i == '.'||i == '_' ? i : 0;
    }
}

void urlencode(const char* src, char* encoded)
{
    //syslog(LOG_DEBUG,"Got url escape request: %s",src);
    for (; *src; src++) {
        if (rfc3986[*src])
        {
            sprintf(encoded, "%c", rfc3986[*src]);
            //syslog(LOG_DEBUG,"std Here: %c: %s",*src,src);
        }
        else
        {
            sprintf(encoded, "%%%02X", *src);
            //syslog(LOG_DEBUG,"esc Here: %c: %s",*src,src);
        }
        while (*++encoded);
    }
}

////////////////////////////////////////////////////////////////////////////////////

#ifdef DEBUG
int __export queryUrl(const char* dest_url, struct MemoryStruct* chunk, int useInsecureSSL)
#else
int queryUrl(const char* dest_url, struct MemoryStruct* chunk, int useInsecureSSL)
#endif
{
    CURL *curl;
    CURLcode res;

    syslog(LOG_INFO, "pwncheck: queryUrl: Initiating query: %d",useInsecureSSL);
    curl_global_init(CURL_GLOBAL_DEFAULT);
 
    curl = curl_easy_init();
    if(curl) {
        //char* escaped_url = curl_easy_escape(curl, dest_url, 0);
#ifdef DEBUG
        syslog(LOG_INFO, "pwncheck: queryUrl: DEBUG: destination url: %s",dest_url);
#endif
        curl_easy_setopt(curl, CURLOPT_URL, dest_url);
 
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)chunk); 

        if (useInsecureSSL != 0)
        {
            syslog(LOG_WARNING, "pwncheck: queryUrl: Insecure SSL enabled");
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        }
 
        /* Perform the request, res will get the return code */ 
        res = curl_easy_perform(curl);
        /* Check for errors */ 
        if(res != CURLE_OK)
            syslog(LOG_ERR, "pwncheck: queryUrl: curl_easy_perform() failed: %s", curl_easy_strerror(res));
 
        /* always cleanup */ 
        //curl_free(escaped_url);
        curl_easy_cleanup(curl);
    }
 
    curl_global_cleanup();
    syslog(LOG_INFO, "pwncheck: queryUrl: Finished");
    return res;
}

