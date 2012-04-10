#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "print.h"

#include "log.macros.c"

#define file(name)					\
  ret = printFile(name);				\
  if(ret) {						\
    logError("Could not print file '" name "'");	\
    return ret;						\
  }

int sendRegisterError()
{
  int ret;

  printf("\r\n");

  printf("<html><head>");
  file("headers.html");
  printf("</head>\n");

  printf("<body><div id=\"page\">\n");
  file("page_header.html");
  file("login.html");
  file("register.html");
  //  if(optionalMessage) {
    printf("<div id=\"register-message\">Registration Failed for some reason?</div>\n");
    //  }
  printf("</div></body></html>\n");

  return 0;

}


int sendLoginPage(char *optionalMessage)
{
  int ret;

  printf("\r\n");

  printf("<html><head>");
  file("headers.html");
  printf("</head>\n");

  printf("<body><div id=\"page\">\n");
  file("page_header.html");
  file("login.html");
  file("register.html");
  if(optionalMessage) {
    printf("<div id=\"login-message\">%s</div>\n", optionalMessage);
  }
  printf("</div></body></html>\n");

  return 0;
}


int sendHomePage(uint64_t uid)
{
  //
  // Get user info
  //

  int ret;

  printf("\r\n");
  printf("<html><head>");
  file("headers.html");
  printf("</head>\n");

  printf("<body><div id=\"page\">\n");
  file("page_header.html");
  printf("<h1> You are logged in! </h1>\n");
  printf("<h2> Your User ID is %llu. Click <a href=\"debug/user?%llu\">here</a> to get your user info </h2>\n", uid);
  printf("<table>\n");
  printf("<tr><td>Your IP Address is:</td><td>%s</td></tr>\n", getenv("REMOTE_ADDR"));
  printf("<tr><td>The port you connected from is:</td><td>%s</td></tr>\n", getenv("REMOTE_PORT"));
  printf("</div></body></html>\n");
  return 0;
}

int sendSqlInjection()
{
  int ret;

  printf("\r\n");

  printf("<html><head>");
  file("headers.html");
  printf("</head>\n");

  printf("<body><div id=\"page\">\n");
  file("page_header.html");
  file("login.html");
  file("register.html");
  file("sqlInjection.html");
  printf("</div></body></html>\n");

  return 0;
  
}
