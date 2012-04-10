#ifndef SQL_H
#define SQL_H

#include <mysql.h>
#include <stdint.h>

#include "global.h"

int getLoginAttempts(MYSQL *mysql, char *mysqlConnected, uint32_t ip, char *email);


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
  char *password,        // [IN]       password used to login (no sql injection check needed, because 
  HB_HANDLE *hbHandle    //      [OUT] pointer to HB_HANDLE (already allocated) used to return the uid
		 );


void storeBadLogin(MYSQL *mysql, char *mysqlConnected, uint32_t ip, char *email);

int                      //      [OUT] 0 Success
getSessionData(
  MYSQL *mysql,          // [IN] [OUT] pointer to MYSQL structure (already allocated)
  char *mysqlConnected,  // [IN] [OUT] keeps track of connected state (0 = not connected)
  HB_HANDLE *hbHandle    //      [OUT] pointer to HB_HANDLE (already allocated) to output uid
);

int                      //      [OUT] : Success returns 0
storeNewSession(
  MYSQL *mysql,          // [IN] [OUT] : pointer to MYSQL structure (already allocated)
  char *mysqlConnected,  // [IN] [OUT] : keeps track of connected state (0 = not connected)
  HB_HANDLE *hbHandle,   // [IN]       : pointer to HB_SESSION where uid and sid contain values
                         //            : to store in the database
  uint32_t ip            // [IN]       : the client ip address
);

int addUser(MYSQL *mysql, char *mysqlConnected, HB_USER *user);

#endif
