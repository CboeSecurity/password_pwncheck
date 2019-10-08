////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
// The following is the Curl-based SSL query code                                 //
////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////
#include <stddef.h> // define of size_t

#include <curl/curl.h> // curl

#ifdef DEBUG
#ifndef __export
#define __export __attribute__((__visibility__("default")))
#endif
#endif

struct MemoryStruct {
  char *memory;
  size_t size;
};

void init_urlencode(void);
void urlencode(const char* src, char* encoded);

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
#ifdef DEBUG
int __export queryUrl(const char* dest_url, struct MemoryStruct* chunk, int useInsecureSSL);
#else
int queryUrl(const char* dest_url, struct MemoryStruct* chunk, int useInsecureSSL);
#endif
