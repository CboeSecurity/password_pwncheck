/*
 * Authored by: Jan Grzymala-Busse 
 * Cboe Security
 * Provided as is, no warranties, please see included licensing.
*/


enum kvMode { KVNONE = 0, KVKEY = 1, KVVALUE = 2};

struct cfgpwned {
  int 		DefaultReturn;
  int       isInsecure;
  char*     url;
};

int parseConfig(struct cfgpwned* config, char* filepath);
