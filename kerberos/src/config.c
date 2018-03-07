#include <yaml.h>
#include "config.h"

int parseConfig(struct cfgpwned* config, char* filepath)
{
  FILE* fh = fopen(filepath,"r");
  yaml_parser_t cfgparse;
  yaml_token_t cfgtoken;

  if (!yaml_parser_initialize(&cfgparse))
  {
    fputs("Failed to iniialize YAML parser!\n", stderr);
    return -1;
  }

  if (fh == NULL)
  {
    fputs("Failed to open file!\n", stderr);
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
          curKeyValue = &lpszInsecureSSL;        
        else if (strncmp("QueryUrl",cfgtoken.data.scalar.value,strlen("QueryUrl")) == 0)
          curKeyValue = &lpszQueryURL;        
        else if (strncmp("DefaultReturn",cfgtoken.data.scalar.value,strlen("DefaultReturn")) == 0)
          curKeyValue = &lpszDefaultReturn;
        else
          curKeyValue = NULL;
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

  config->url = lpszQueryURL;
  int lenmin = (4 < strlen(lpszInsecureSSL))?4:strlen(lpszInsecureSSL);
  config->isInsecure = (strncasecmp("True",lpszInsecureSSL,lenmin) == 0)?1:0;
  config->DefaultReturn = atoi(lpszDefaultReturn);
  free(lpszInsecureSSL);
  free(lpszDefaultReturn);
  return 0;
}
