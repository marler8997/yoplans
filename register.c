#include <stdio.h>

#include "weblib.h"

#include "global.h"
#include "request.h"
#include "send.h"
#include "print.h"

#include "log.macros.c"

int main()
{
  int ret;
  char requestVarsBuffer[MAX_REQUEST_VARS_STRING];
  const char *registerData;


  registerData = getRequestVariablesDefaultPost(requestVarsBuffer);
  if(registerData == NULL) return sendRegisterError();





  puts("Content-Type: text/html");
  printf("\r\n");


  printf("<html>\n");
  printf("<head>\n");
  ret = printFile("headers.html");
  if(ret) {
    logError("Could not print 'headers.html'");
    return ret;
  }
  printf("</head>\n");

  printf("<body>\n");
  printf("<div id=\"page\">\n");
  ret = printFile("page_header.html");
  if(ret) {
    logError("Could not print 'page_header.html'");
    return ret;
  }
  
  printf("<h1>Under Construction</h1>");

  printf("</div>\n");
  printf("</body>\n");
  printf("</html>\n");
  return 0;
}
