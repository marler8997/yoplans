#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
#include <mysql.h>
#include <netinet/in.h>

#define DEBUG

#include "string_util.h"
#include "sha1.h"

#include "global.h"
#include "sql.h"
#include "password.h"


#include "hb.macros.c"
#include "sql.macros.c"
#include "log.macros.c"

#define sqlConnect							\
  if(*mysqlConnected == 0) {						\
    if(mysql_init(mysql) == NULL) {					\
      logMysqlError(mysql, "mysql_init");				\
      return -1;							\
    }									\
    if(!mysql_real_connect(mysql, "localhost", "hb", NULL, "hb", 0, NULL, 0)) {	\
      logMysqlError(mysql, "mysql_real_connect");			\
      return -1;							\
    }									\
    *mysqlConnected = 1;						\
  }									




#define STORE_BAD_LOGIN_QUERY "INSERT INTO badLogins (ip,time,email) values ('%d',NOW(),'%s');"

#define ADD_USER_QUERY "INSERT INTO users (email,salt,passwordHash,fName,lName) VALUES ('%s', x'%02x',x'%08x%08x%08x%08x%08x','%s','%s');"

// returns the index after the last char written
static inline unsigned char * sqlCopyBinaryToEscaped(unsigned char *to, const unsigned char *from, unsigned length)
{
  for(unsigned fromIndex = 0; fromIndex < length; fromIndex++) {
    //logDebug("[%d] = 0x%02X\n", fromIndex, from[fromIndex]);
    if(from[fromIndex] == '\'') {
      *to++ = '\\';
      *to++ = '\'';
    } else if(from[fromIndex] == '\\') {
      *to++ = '\\';
      *to++ = '\\';
    } else if(from[fromIndex] == '\0') {
      *to++ = '\\';
      *to++ = '\0';
    } else {
      *to++ = from[fromIndex];
    }
  }
  return to;
}

int                      //      [OUT] <  0 Error occured
                         //            == 0 Success (session data retrieved)
                         //            == 1 sid not found
getSessionData(
  MYSQL *mysql,          // [IN] [OUT] pointer to MYSQL structure (already allocated)
  char *mysqlConnected,  // [IN] [OUT] keeps track of connected state (0 = not connected)
  HB_HANDLE *hbHandle    // [IN] [OUT] pointer to HB_HANDLE (already allocated) to input sidBytes and output uid
                         //            also (let sidBase64 be a pointer to the sid base64 string)
) {
#define SQL_GET_SESSION_A "SELECT uid FROM sessions WHERE sid='"

  char sqlQuery[sizeof(SQL_GET_SESSION_A) + 
		3 + // room for "';\0" at the end
		(2*SHA1_HASH_BYTE_LENGTH)];

  //
  // Construct Query
  //
  strcpy(sqlQuery, SQL_GET_SESSION_A);
  unsigned char * next = sqlCopyBinaryToEscaped(sqlQuery + sizeof(SQL_GET_SESSION_A) - 1,
						hbHandle->sidBytes, SHA1_HASH_BYTE_LENGTH);
  *next++ = '\'';
  *next++ = ';';
  *next++ = '\0';

  unsigned long queryLength = next - (unsigned char*)sqlQuery;
  logDebug("getSession(%lu)='%s'", queryLength, sqlQuery);


  //
  // Connect to Database
  //
  sqlConnect;

  //
  // Query the database
  //
  if(mysql_real_query(mysql, sqlQuery, queryLength)) {
    logMysqlError(mysql, "mysql_real_query");
    return -1;
  }

  //
  // Read Query
  //
  MYSQL_RES *sqlResult = mysql_store_result(mysql);
  if(!sqlResult) {
    logMysqlError(mysql, "mysql_store_result");
    return -1;
  }

  MYSQL_ROW sqlRow = mysql_fetch_row(sqlResult);
  if(sqlRow == NULL) {
    mysql_free_result(sqlResult);
    return 1;
  }

  // If there is more than one match (more than one row with the same sid, this shouldn't happen)
  //if(mysql_fetch_row(sqlResult)) {
  //  logError("A query for session with sid '%s' returned more than one row!", hbHandle->sidBase64);
  //  return -1;
  //}
  
  if(sqlRow[0] == NULL) {
    logError("Expected sqlRow[0] to contain 'uid', but is was NULL");
    mysql_free_result(sqlResult);
    return -1;
  }

  hbHandle->uid = strtoul(sqlRow[0], NULL, 10);
  
  mysql_free_result(sqlResult);
  return 0;
}

int                      //      [OUT] : Success returns 0
storeNewSession(
  MYSQL *mysql,          // [IN] [OUT] : pointer to MYSQL structure (already allocated)
  char *mysqlConnected,  // [IN] [OUT] : keeps track of connected state (0 = not connected)
  HB_HANDLE *hbHandle,   // [IN]       : pointer to HB_SESSION where uid and sid contain values
                         //            : to store in the database, namely sidBytes and uid
  uint32_t ip            // [IN]       : the client ip address
) {
#define SQL_STORE_NEW_SESSION_A "INSERT INTO sessions (sid,genTime,uid,lastRequest,ip) VALUES ('"
#define SQL_STORE_NEW_SESSION_B                                                             "',NOW(),'%llu',NOW(),%u);"

  char sqlQuery[sizeof(SQL_STORE_NEW_SESSION_A) +
		sizeof(SQL_STORE_NEW_SESSION_B) +
		(2*SHA1_HASH_BYTE_LENGTH) +
		MAX_DIGITS_FOR_DECIMAL_UID +
		MAX_DIGITS_FOR_DECIMAL_IP];

  //
  // Construct Query
  //
  strcpy(sqlQuery, SQL_STORE_NEW_SESSION_A);
  unsigned char * next = sqlCopyBinaryToEscaped(sqlQuery + sizeof(SQL_STORE_NEW_SESSION_A) - 1,
						hbHandle->sidBytes, SHA1_HASH_BYTE_LENGTH);
  int sprintfLength = sprintf(next, SQL_STORE_NEW_SESSION_B, hbHandle->uid, ip);
  if(sprintfLength <= 0) {
    logError("sprintf of SQL_STORE_NEW_SESSION '%s' failed", SQL_STORE_NEW_SESSION_B);
    return -1;
  }
  unsigned long queryLength = (next + sprintfLength) - (unsigned char*)sqlQuery;
  logDebug("storeNewSession(%lu)='%s'", queryLength, sqlQuery);

  //
  // Connect to Database
  //
  sqlConnect;

  //
  // Query the database
  //
  if(mysql_real_query(mysql, sqlQuery, queryLength)) {
    logMysqlError(mysql, "mysql_real_query");
    return -1;
  }

  return 0;
}


int                      //      [OUT] <  0 error getting login attempts
                         //            >= 0 returns the login attempts stored in the database
getLoginAttempts(
  MYSQL *mysql,          // [IN] [OUT] pointer to MYSQL structure (already allocated)
  char *mysqlConnected,  // [IN] [OUT] keeps track of connected state (0 = not connected)
  uint32_t ip,           // [IN]       ip address of client (used to store bad login attempts)
                         //            NOTE: if an error occured whilte getting the ip, a value of 0 is fine
  char *email            // [IN]       email used to login (already checked for sql injection)
		 )
{
#define BAD_LOGIN_QUERY_WITH_IP "SELECT count(ip) FROM badLogins WHERE ip='%u' or email='%s';"
#define BAD_LOGIN_QUERY_NO_IP "SELECT count(ip) FROM badLogins WHERE email='%s';"

  char sqlQuery[sizeof(BAD_LOGIN_QUERY_WITH_IP) + MAX_DIGITS_FOR_DECIMAL_IP + MAX_EMAIL];  

  //
  // Construct Query
  //
  if(ip) {
    if(sprintf(sqlQuery, BAD_LOGIN_QUERY_WITH_IP, ip, email) <= 0) {
      logError("sprintf of BadLoginQuery '%s' failed", BAD_LOGIN_QUERY_WITH_IP);
      return -1;
    }
  } else {
    if(sprintf(sqlQuery, BAD_LOGIN_QUERY_NO_IP, email) <= 0) {
      logError("sprintf of BadLoginQuery '%s' failed", BAD_LOGIN_QUERY_NO_IP);
      return -1;
    }
  }

  //
  // Connect to Database
  //
  sqlConnect;

  //
  // Query the database
  //
  if(mysql_query(mysql, sqlQuery)) {
    logMysqlError(mysql, "mysql_query");
    return -1;
  }

  //
  // Read Query
  //
  MYSQL_RES *sqlResult;
  MYSQL_ROW sqlRow;

  sqlResult = mysql_store_result(mysql);
  if(!sqlResult) {
    logMysqlError(mysql, "mysql_store_result");
    return -1;
  }

  sqlRow = mysql_fetch_row(sqlResult);
  if(sqlRow == NULL) {
    mysql_free_result(sqlResult);
    return 0;
  }

  if(sqlRow[0] == NULL) {
    logError("Expected sqlRow[0] to contain ATTEMPTS, but is was NULL");
    mysql_free_result(sqlResult);
    return -1;
  }

  if(sqlRow[0][0] == '0') {
    mysql_free_result(sqlResult);
    return 0;
  }

  int count = atoi(sqlRow[0]);
  if(count <= 0) {
    logError("atoi of attempts '%s' returned %d", sqlRow[0], count);
    mysql_free_result(sqlResult);
    return -1;
  }
  
  mysql_free_result(sqlResult);
  return count;
}

int                      //      [OUT] <  0 error checking credentials
                         //            == 0 login succeeded
                         //            == 1 email not found
                         //            == 2 password mismatch
checkCredentials(
  MYSQL *mysql,          // [IN] [OUT] pointer to MYSQL structure (already allocated)
  char *mysqlConnected,  // [IN] [OUT] keeps track of connected state (0 = not connected)
  uint32_t ip,           // [IN]       ip address of client (used to store bad login attempts)
                         //            NOTE: if an error occured whilte getting the ip, a value of 0 is fine
  char *email,           // [IN]       email used to login (already checked for sql injection)
  char *password,        // [IN]       password used to login (already checked for sql injection)
  HB_HANDLE *hbHandle    //      [OUT] pointer to HB_HANDLE (already allocated) used to return the uid
		 )
{
#define LOGIN_QUERY "SELECT uid,salt,passwordHash FROM users WHERE email='%s';"

  char sqlBuffer[sizeof(LOGIN_QUERY) + MAX_EMAIL];

  uint32_t calculatedHash[SHA1_HASH_UINT32_LENGTH];
  uint32_t *storedPasswordHash;

  //
  // Construct Query
  //
  if(sprintf(sqlBuffer, LOGIN_QUERY, email) <= 0) {
    logError("sprintf of LoginQuery '%s' failed", LOGIN_QUERY);
    return -1;
  }

  //
  // Connect to Database
  //
  sqlConnect;

  //
  // Query the database
  //
  if(mysql_query(mysql, sqlBuffer)) {
    logMysqlError(mysql, "mysql_query");
    return -1;
  }

  //
  // Read Query
  //
  MYSQL_RES *sqlResult;
  MYSQL_ROW sqlRow;

  sqlResult = mysql_store_result(mysql);
  if(!sqlResult) {
    logMysqlError(mysql, "mysql_store_result");
    return -1;
  }

  sqlRow = mysql_fetch_row(sqlResult);
  if(sqlRow == NULL) {
    mysql_free_result(sqlResult);

    //
    // store bad login (for now)
    // NOTE: should I really store a bad login where the username was wrong?
    //       Or only when there is a password mismatch?
    //
    storeBadLogin(mysql, mysqlConnected, ip, email);

    return 1;
  }

  // If there is more than one match (more than one row with the same email, this should never happen)
  if(mysql_fetch_row(sqlResult)) {
    logError("A query for user with email '%s' returned more than one row! (from ip %u)", email, ip);
    return -1;
  }

  if(sqlRow[0] == NULL) {
    logError("Expected sqlRow[0] to contain 'uid', but it is NULL");
    mysql_free_result(sqlResult);
    return -1;
  }  
  if(sqlRow[1] == NULL) {
    logError("Expected sqlRow[1] to contain 'salt', but it is NULL");
    mysql_free_result(sqlResult);
    return -1;
  }
  if(sqlRow[2] == NULL) {
    logError("Expected sqlRow[2] to contain 'passwordHash', but it is NULL");
    mysql_free_result(sqlResult);
    return -1;
  }

  char *uidString = sqlRow[0];
  char salt = sqlRow[1][0];
  storedPasswordHash = (uint32_t*)(sqlRow[2]);

  hbHandle->uid = strtoull(uidString, NULL, 10);
  if(hbHandle->uid == 0 && uidString[0] != '0') {
    mysql_free_result(sqlResult);
    logError("Could not convert uidString from database '%s' to unsigned long long", uidString);
    return -1;
  }


  //
  // Hash the given password
  //
  ntohHash(storedPasswordHash);
  logDebug("givenPassword = '%s' salt = '%c' (%d)", password, sqlRow[1][0], sqlRow[1][0]);
 
  if(passwordHash1000(password, salt, calculatedHash)) {
    mysql_free_result(sqlResult);
    logError("passwordHash1000(%s, 0x%02X) returned an error", password, salt);
    return -1;
  }

  //
  // Compare passwords
  //
  logDebug("calculatedHash = '%08x%08x%08x%08x%08x', storedHash = '%08x%08x%08x%08x%08x'",
	   calculatedHash[0],calculatedHash[1],calculatedHash[2],calculatedHash[3],calculatedHash[4],
	   storedPasswordHash[0], storedPasswordHash[1], storedPasswordHash[2], storedPasswordHash[3], storedPasswordHash[4]);

  if(!sha1Equal(calculatedHash, storedPasswordHash)) {
    mysql_free_result(sqlResult);

    storeBadLogin(mysql, mysqlConnected, ip, email);

    return 2;
  }

  mysql_free_result(sqlResult);
  return 0;
}


void storeBadLogin(MYSQL *mysql, char *mysqlConnected, uint32_t ip, char *email) {

  char sqlBuffer[sizeof(STORE_BAD_LOGIN_QUERY) + MAX_EMAIL + MAX_DIGITS_FOR_DECIMAL_IP];  

  //
  // Connect to Database
  //
  if(*mysqlConnected == 0) {
    if(mysql_init(mysql) == NULL) {
      logError("failed to connect to database whilte trying to store bad login for ip '%u', email '%s'",
	       ip, email);
      logMysqlError(mysql, "mysql_init");
      return;
    }
    if(!mysql_real_connect(mysql, "localhost", "hb", NULL, "hb", 0, NULL, 0)) {
      logError("failed to connect to database whilte trying to store bad login for ip '%u', email '%s'",
	       ip, email);
      logMysqlError(mysql, "mysql_real_connect");
      return;
    }
    *mysqlConnected = 1;
  }

  if(sprintf(sqlBuffer, STORE_BAD_LOGIN_QUERY, ip, email) <= 0) {
    logError("sprintf of '%s' failed when trying to store bad login for ip '%u', email '%s'",
	     STORE_BAD_LOGIN_QUERY, ip, email);
    return;
  }
  if(mysql_query(mysql, sqlBuffer)) {
    logError("mysql_query '%s' failed when trying to store bad login for ip '%u', email '%s'",
	     sqlBuffer, ip, email);
    logMysqlError(mysql, "mysql_query");
  }      
}




int addUser(MYSQL *mysql, char *mysqlConnected, HB_USER *user) {

  char sqlBuffer[sizeof(ADD_USER_QUERY) +
		 MAX_EMAIL + 
		 2 + // 2 characters for salt
		 (2*SHA1_HASH_BYTE_LENGTH) +
		 MAX_FIRST_NAME +
		 MAX_LAST_NAME];

  //
  // Construct Query
  //
  if(sprintf(sqlBuffer, ADD_USER_QUERY, user->email, user->salt, 
	     user->passwordHash[0], user->passwordHash[1], user->passwordHash[2],
	     user->passwordHash[3], user->passwordHash[4],
	     user->fName, user->lName) <= 0) {
    logError("sprintf of AddUserQuery '%s' failed", ADD_USER_QUERY);
    return -1;
  }

  logDebug("addUser: query '%s'", sqlBuffer);
  
  //
  // Connect to Database
  //
  sqlConnect;
  
  //
  // Query the database
  //
  if(mysql_query(mysql, sqlBuffer)) {
    logMysqlError(mysql, "mysql_query");
    return -1;
  }

  return 0;
}


