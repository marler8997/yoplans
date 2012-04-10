#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG

#include <my_global.h>
#include <mysql.h>

#include "global.h"
#include "sql.h"
#include "send.h"
#include "base64.h"
#include "print.h"

#include "hb.macros.c"
#include "sql.macros.c"
#include "log.macros.c"

int main()
{
  int ret;
  MYSQL mysql;
  char mysqlConnected = 0;

  HB_HANDLE hbHandle;

  char optionalBufferForSid[SHA1_HASH_BASE64_LENGTH];

  unsigned sidLength;
  char *sidBase64;
  unsigned char sidBytes[SHA1_HASH_BYTE_LENGTH];

  puts("Content-Type: text/html");

  //
  // Check for SID from Cookie
  //
  char *cookie = getenv("HTTP_COOKIE");
  if(cookie == NULL) return sendLoginPage(NULL);
  goto PROCESS_SID;

 INVALID_SID:
  // TODO: Add Set-Cookie header if cookie that was received was bad
  return sendLoginPage(NULL);

 PROCESS_SID:
  getAndCheckSidFromCookie(sidBase64, cookie, sidLength, INVALID_SID);
  sidLength = base64dec(sidBase64, sidBytes);
  if(sidLength != SHA1_HASH_BYTE_LENGTH) {
    logError("Expected the decoded Sid to have a length of %u, but it was %u", SHA1_HASH_BYTE_LENGTH, sidLength);
    goto INVALID_SID;
  }

 RECEIVED_VALID_SID:

  // Get Session Data from Database
  hbHandle.sidBase64 = sidBase64;
  hbHandle.sidBytes = sidBytes;
    
  ret = getSessionData(&mysql, &mysqlConnected, &hbHandle);
  if(ret) {
    if(ret == 1) {
      logDebug("Sid '%s' was not found in the database.", sidBase64);
      goto SID_NOT_FOUND;
    } else {
      logError("Could not retrieve the sid '%s' from the database, check previous error.", sidBase64);
      goto SEND_LOGIN_PAGE_ON_ERROR;
    }
  }

  ////////////////////////////////////////
  // Send Response Section
  ////////////////////////////////////////

 LOGGED_IN:
  macro_MysqlDisconnect(mysql, mysqlConnected);

  return sendHomePage(hbHandle.uid);

 SID_NOT_FOUND:
  macro_MysqlDisconnect(mysql, mysqlConnected);
  return sendLoginPage(NULL);

 SEND_LOGIN_PAGE_ON_ERROR:
  macro_MysqlDisconnect(mysql, mysqlConnected);
  logDebug("Sending login page from SEND_LOGIN_PAGE_ON_ERROR in index.c");
  return sendLoginPage(NULL);
}
