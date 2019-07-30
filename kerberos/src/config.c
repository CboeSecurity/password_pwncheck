/*
 * Authored by: Jan Grzymala-Busse 
 * Cboe Security
 * Provided as is, no warranties, please see included licensing.
*/

#include <yaml.h>
#include <syslog.h>
#include "config.h"


int parseConfig(struct cfgpwned* config, char* filepath)
{
  syslog(LOG_DEBUG, "pwncheck: parseConfig: started");
  FILE* fh = fopen(filepath,"r");
  yaml_parser_t cfgparse;
  yaml_token_t cfgtoken;

  if (!yaml_parser_initialize(&cfgparse))
  {
    syslog(LOG_DEBUG, "pwncheck: parseConfig: Failed to iniialize YAML parser!\n");
    return -1;
  }

  if (fh == NULL)
  {
    syslog(LOG_DEBUG, "pwncheck: parseConfig: Failed to open file!\n");
    return -2;
  }

  yaml_parser_set_input_file(&cfgparse, fh);

  char* lpszDefaultReturn = NULL;
  char* lpszInsecureSSL = NULL;
  char* lpszQueryURL = NULL;
  char** curKeyValue = NULL;
  enum kvMode curMode = KVNONE;
  do {
    yaml_parser_scan(&cfgparse, &cfgtoken);
    switch(cfgtoken.type)
    {
    case YAML_KEY_TOKEN:
      curMode = KVKEY;
      break;
    case YAML_VALUE_TOKEN:
      curMode = KVVALUE;
      break;
    /* Data */
    case YAML_SCALAR_TOKEN:
      if (curMode == KVKEY) {
        if (strncmp("InsecureSSL",cfgtoken.data.scalar.value,strlen("InsecureSSL")) == 0)
	{
            //syslog(LOG_INFO, "pwncheck: parseConfig: InsecureSSL being set\n");
            curKeyValue = &lpszInsecureSSL;        
	}
	else if (strncmp("QueryUrl",cfgtoken.data.scalar.value,strlen("QueryUrl")) == 0)
	{
            //syslog(LOG_INFO, "pwncheck: parseConfig: QueryUrl being set\n");
	    curKeyValue = &lpszQueryURL;        
	}
        else if (strncmp("DefaultReturn",cfgtoken.data.scalar.value,strlen("DefaultReturn")) == 0)
	{
            //syslog(LOG_INFO, "pwncheck: parseConfig: DefaultReturn being set\n");
            curKeyValue = &lpszDefaultReturn;
	}
        else
	{
            curKeyValue = NULL;
	}
      } else if (curMode == KVVALUE) {
        if (curKeyValue != NULL)
        {
          (*curKeyValue) = malloc(cfgtoken.data.scalar.length+1);
          memset(*curKeyValue,'\0',cfgtoken.data.scalar.length+1);
          strncpy(*curKeyValue,cfgtoken.data.scalar.value,cfgtoken.data.scalar.length);
        }
      }
    /* Others */
    default:
      break;
    }
    if(cfgtoken.type != YAML_STREAM_END_TOKEN)
      yaml_token_delete(&cfgtoken);
  } while(cfgtoken.type != YAML_STREAM_END_TOKEN);
  yaml_token_delete(&cfgtoken);

  yaml_parser_delete(&cfgparse);
  fclose(fh);

  syslog(LOG_INFO, "pwncheck: parseConfig: (strings) url:'%s' insecureSSL:'%s' defaultReturn:'%s'",lpszQueryURL,lpszInsecureSSL,lpszDefaultReturn);
  config->url = lpszQueryURL;
  int lenmin = (4 < strlen(lpszInsecureSSL))?4:strlen(lpszInsecureSSL);
  config->isInsecure = (strncasecmp("True",lpszInsecureSSL,lenmin) == 0)?1:0;
  config->isInsecure = (strncasecmp("1",lpszInsecureSSL,lenmin) == 0)?1:config->isInsecure;
  config->DefaultReturn = atoi(lpszDefaultReturn);
  syslog(LOG_INFO, "pwncheck: parseConfig: (struct) url:'%s' insecureSSL:%d defaultReturn:%d",config->url,config->isInsecure,config->DefaultReturn);
  free(lpszInsecureSSL);
  free(lpszDefaultReturn);
  syslog(LOG_DEBUG, "pwncheck: parseConfig: Done");
  return 0;
}
