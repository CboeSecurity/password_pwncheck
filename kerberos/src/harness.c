/*
 * Authored by: Jan Grzymala-Busse 
 * Cboe Security
 * Provided as is, no warranties, please see included licensing.
*/

#include <krb5/pwqual_plugin.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

#include <stddef.h>

/*
krb5_error_code __export
pwqual_pwncheck_initvt(krb5_context context, int maj_ver, int min_ver,
               krb5_plugin_vtable vtable)
*/

#ifndef NULL
#define NULL 0
#endif

#define GROUP 0
#define NODELETE RTLD_NODELETE
#define PLUGIN_DLOPEN_FLAGS (RTLD_NOW | RTLD_LOCAL | GROUP | NODELETE)

int main(int argc, char **argv) {
    void *handle;
    krb5_error_code (*initvt)(krb5_context context, int maj_ver, int min_ver, krb5_plugin_vtable vtable);
    krb5_error_code (*check)(krb5_context context, krb5_pwqual_moddata data, const char *passwd, const char *policy_name, krb5_principal princ, const char **languages);
    char *error;

    printf("Opening Dynamic Library...");
    //handle = dlopen ("./pwncheck.so", RTLD_LAZY);
    //handle = dlopen (argv[1], RTLD_LAZY);
    handle = dlopen (argv[1], PLUGIN_DLOPEN_FLAGS);
    if (!handle) {
        fputs (dlerror(), stderr);
    	printf("\n");
        exit(1);
    }
    printf("Done\n");

    printf("Loading Dynamic Symbol (initvt)...");
    initvt = dlsym(handle, "pwqual_pwncheck_initvt");
    if ((error = dlerror()) != NULL)  {
        fputs(error, stderr);
    	printf("\n");
        exit(1);
    }
    printf("Done\n");


    krb5_context context;
    //krb5_plugin_vtable vt;
    struct krb5_pwqual_vtable_st harness_vt = {NULL,NULL,NULL,NULL};
    krb5_pwqual_moddata moddata;
    const char* passwd = "test password";
    const char* policy_name = "policy";
    krb5_principal princ = NULL; // {0,{7,"norealm"},NULL,5,0};
    char** langs = NULL;
    printf("Attempting to execute loaded symbol (function initvt)...");
    printf("\n");
    (*initvt)(context, 2, 0, (struct krb5_plugin_vtable_st *)&harness_vt);
    check = harness_vt.check;
    printf("\n");
    printf("Function initvt execution done\n");
    printf("\n");
    (*check)(context, moddata, passwd, policy_name,princ, NULL);
    printf("\n");
    
    printf("Closing the Dynamic Library handle...");
    dlclose(handle);
    printf("Done\n");
}
