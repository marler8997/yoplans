#include <stdio.h>
#include "string.h"


#include "sha1.h"
#include "password.h"
#include "sql.h"

#include "sql.macros.c"

int main(int argc, char *argv[])
{
  int ret;
  HB_USER user;

  MYSQL mysql;
  char mysqlConnected = 0;

  uint32_t passwordHashed[SHA1_HASH_UINT32_LENGTH];

  char passwordBuffer[65];


  //
  // Jonathan Marler
  //
  user.email = "marler8997@vandals.uidaho.edu";
  user.salt = 'a';
  strcpy(passwordBuffer, "password");
  ret = passwordHash(passwordBuffer, user.salt, passwordHashed);
  if(ret) {
    fprintf(stderr, "passwordHash returned error %d\n", ret);
    return -1;
  }
  user.passwordHash = passwordHashed;
  user.fName = "Jonathan";
  user.lName = "Marler";

  ret = addUser(&mysql, &mysqlConnected, &user);
  if(ret) {
    printf("Error: addUser returned %d\n", ret);
    return -1;
  }

  //
  // Corey Norberg
  //
  user.email = "corey.b.norberg@hp.com";
  user.salt = 'z';
  strcpy(passwordBuffer, "1234");
  ret = passwordHash(passwordBuffer, user.salt, passwordHashed);
  if(ret) {
    fprintf(stderr, "passwordHash returned error %d\n", ret);
    return -1;
  }
  user.fName = "Corey";
  user.lName = "Norberg";

  ret = addUser(&mysql, &mysqlConnected, &user);
  if(ret) {
    printf("Error: addUser returned %d\n", ret);
    return -1;
  }


  macro_MysqlDisconnect(mysql, mysqlConnected)

  printf("Success\n");
  return 0;
}
