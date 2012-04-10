#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <crypt.h>

#include <my_global.h>
#include <mysql.h>

#define DEBUG

#include "weblib.h"

#include "global.h"
#include "base64.h"
#include "request.h"
#include "sql.h"
#include "url.h"
#include "string_util.h"
#include "sha1.h"
#include "send.h"
#include "sid.h"

#include "hb.macros.c"
#include "sql.macros.c"
#include "log.macros.c"

int main()
{
  int ret, temp;
  uint32_t ip;

  MYSQL mysql;
  char mysqlConnected = 0;

  char optionalBufferForSid[40];
  char requestVarsBuffer[MAX_REQUEST_VARS_STRING];

  char *loginData;

  char *str, *email, *password, *longlogin;
  char *loginFailedReason = NULL;

  HB_HANDLE hbHandle;

  char *sidBase64;
  unsigned sidLength;
  unsigned char sidBytes[SHA1_HASH_BYTE_LENGTH];
  uint32_t sidUint32[SHA1_HASH_UINT32_LENGTH];

  char encodedSidBuffer[SHA1_HASH_BASE64_LENGTH + 1]; // + 1 for '\0'
  uint32_t hash[SHA1_HASH_UINT32_LENGTH];

  puts("Content-Type: text/html");

  /*
  //
  // Check for SID from Cookie
  //
  char *cookie = getenv("HTTP_COOKIE");
  if(cookie == NULL) goto NOT_LOGGED_IN;

  getAndCheckSidFromCookie(sidBase64, cookie, sidLength, INVALID_SID);
  // Decode Sid
  sidLength = base64dec(sidBase64, sidBytes);
  if(sidLength != SHA1_HASH_BYTE_LENGTH) {
    logError("Expected the decoded Sid to have a length of %u, but it was %u", SHA1_HASH_BYTE_LENGTH, sidLength);
    goto INVALID_SID;
  }
  goto RECEIVED_VALID_SID;

 INVALID_SID:
  // TODO: Add Set-Cookie header if cookie that was received was bad
  goto NOT_LOGGED_IN;

 RECEIVED_VALID_SID:

  // Get Session Data from Database
  hbHandle.sidBase64 = sidBase64;
  hbHandle.sidBytes = sidBytes;
    
  ret = getSessionData(&mysql, &mysqlConnected, &hbHandle);
  if(ret) {
    if(ret == 1) {
      logDebug("Sid '%s' was not found in the database.", sidBase64);
      goto NOT_LOGGED_IN;
    } else {
      logError("Could not retrieve the sid '%s' from the database, check previous error.", sidBase64);
      goto NOT_LOGGED_IN;
    }
  }


  //
  // ALREADY LOGGED IN
  //
  printf("\r\n");
  printFile("alreadyLoggedIn.html");

  return 0;
  */


 NOT_LOGGED_IN:
  
  loginData = getRequestVariablesDefaultPost(requestVarsBuffer);
  if(loginData == NULL) return sendLoginPage(NULL);

 PROCESS_LOGIN_DATA:

  // find 'email='
  email = strstr(loginData, "email=");
  if(email == NULL) {
    logBadPostData("login post data '%.*s' did not contain 'email='", temp, loginData);
    goto SEND_ERROR_PAGE;
  }
  // find 'password='
  password = strstr(loginData, "password=");
  if(password == NULL) {
    logBadPostData("login post data '%.*x' did not contain 'password='", temp, loginData);
    goto SEND_ERROR_PAGE;
  }
  // find 'longlogin='
  longlogin = strstr(loginData, "longlogin=");
  
  email += sizeof("email");
  password += sizeof("password");
  
  // Convert login strings to NULL terminated strings
  for(char *c = email + 1; *c != '\0'; c++) {
    if(*c == '&') {
      *c = '\0';
      break;
    }
  }
  for(char *c = password + 1; *c != '\0'; c++) {
    if(*c == '&') {
      *c = '\0';
      break;
    }
  }
  
  urlDecode(email);
  urlDecode(password);

  logDebug("Your Email is '%s' and password is '%s'\n", email, password);

 CHECK_PREVIOUS_LOGIN_ATTEMPTS:
  //
  // Get IP Address as UInt32 (to check for previous logins attempts)
  //
  if(str2ip(getenv("REMOTE_ADDR"), &ip)) {
    if(getenv("REMOTE_ADDR") == NULL) {
      logMissingEnv("remoteAddress");
      logError("While checking previous login attempts, could not get ip address because environment variable 'REMOTE_ADDR' is missing");
    } else {
      logError("While checking previous login attempts, str2ip('%s') failed", getenv("REMOTE_ADDR"));
    }
    ip = 0;
  }

  // Check for sql injection
  if(strchr(email, '\'') != NULL) {
    logSqlInjection("email", email);

    // Change '\'' to '\"' to store in database
    for(int i = 0; email[i]; i++) if(email[i] == '\'') email[i] = '"';
    storeBadLogin(&mysql, &mysqlConnected, ip, email);


    return sendSqlInjection();
  }

  // Get the number of previous login attempts
  ret = getLoginAttempts(&mysql, &mysqlConnected, ip, email);
  if(ret > MAX_LOGIN_ATTEMPTS) {
    storeBadLogin(&mysql, &mysqlConnected, ip, email);

    // Don't Allow Login Attempt
    printf("\r\n");
    printf("<html><h1>Only %d failed logins are allowed, you've had (%d)</h1></html>\n", MAX_LOGIN_ATTEMPTS, ret);
    return -1;
  }

  if(ret < 0) {
    logWarning("Allowing login attempt because getLoginAttempts issued an error");
  }
  
 ALLOW_LOGIN_ATTEMPT:

  ret = checkCredentials(&mysql, &mysqlConnected,
			 ip, email, password, &hbHandle);

  if(ret == 0) goto LOGIN_SUCCESS;

  if(ret) {
    if(ret < 0) {
      logError("An internal error occurred while checking credentials");
      loginFailedReason = "Internal Server Error.";
    } else if(ret == 1) {
      loginFailedReason = "Email Address not Found";
    } else if(ret == 2) {
      loginFailedReason = "Invalid Password";
    } else {
      logError("Expected checkCredentials to return a value less than or equal to 2, but it returned %d", ret);
      loginFailedReason = "Internal Server Error";
    }
    logDebug("%s",loginFailedReason);
    goto LOGIN_FAILED;
  }



  ////////////////////////////////////////
  // Send Response Section
  ////////////////////////////////////////

 LOGIN_SUCCESS:

  //
  // Create and Store Session ID
  //

  if(generateSid(sidUint32)) goto SEND_ERROR_PAGE;
  htonHash(sidUint32);
  hbHandle.sidBytes = (unsigned char *)sidUint32;
  ret = storeNewSession(&mysql, &mysqlConnected, &hbHandle, ip);
  macro_MysqlDisconnect(mysql, mysqlConnected);

  if(ret) goto SEND_ERROR_PAGE;

  // Convert to network order
  base64enc(hbHandle.sidBytes, SHA1_HASH_BYTE_LENGTH, encodedSidBuffer);
  logDebug("Generated SID: '%s'", encodedSidBuffer);
  printf("Set-Cookie: s=%s;\r\n\r\n", encodedSidBuffer);
  

  //
  // Print Page
  //
  return sendHomePage(hbHandle.uid);
  /*
  printf("\r\n");
  printf("<html><head><title>Highlight Book - Welcome</title></head><body>\r\n");
  printf("<h1> Congratulations, you have successfully logged in! </h1>\n");
  printf("<h4>Client Info</h4>\n");
  printf("<table>\n");
  printf("<tr><td>Your IP Address is:</td><td>%s</td></tr>\n", getenv("REMOTE_ADDR"));
  printf("<tr><td>The port you connected from is:</td><td>%s</td></tr>\n", getenv("REMOTE_PORT"));
  printf("</table>\n");
  printf("<h4>Cookies</h4>\n");
  if(cookie) {
    printf("The cookie you sent the server was '%s'.\n", cookie);
  } else {
    printf("You didn't send the server a cookie:(\n");
  }
  printf("</body></html>\r\n");

  return 0;
  */
 LOGIN_FAILED:

  macro_MysqlDisconnect(mysql, mysqlConnected);

  return sendLoginPage(loginFailedReason ? loginFailedReason: "Login Failed for some unknown reason?");

 SEND_ERROR_PAGE:

  macro_MysqlDisconnect(mysql, mysqlConnected)

  printf("\r\n");
  printf("<html><h1> Some sort of error occurred? Check the server logs </h1></html>");

  return -1;
}
