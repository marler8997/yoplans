#ifndef SQL_MACROS_C
#define SQL_MACROS_C

//
// If you use macro_MysqlConnect to connect, then make sure to use
// macro_MysqlDisonnect.  This is beacuse it protected from closing
// a connected that wasn't initialized, which will cause a seg fault.
//

//
// mysql = A MYSQL structure
// connected = Boolean keeping track of the connected state
// database = A string of the database name i.e. "my_database"
// errorLabel = place to jump to in case of an error
//
#define macro_MysqlConnect(mysql, connected, database, errorLabel)	\
  if(!connected) {							\
    if(mysql_init(&mysql) == NULL) {					\
      connected = 0;							\
      logMysqlError(&mysql, "mysql_init");				\
      goto errorLabel;							\
    }									\
    if(!mysql_real_connect(&mysql, "localhost", "hb", NULL, database, 0, NULL, 0)) { \
      connected = 0;							\
      logMysqlError(&mysql, "mysql_real_connect");			\
      goto errorLabel;							\
    }									\
    connected = 1;							\
  }


#define macro_MysqlDisconnect(mysql, connected)	 \
  if(connected) {				 \
    mysql_close(&mysql);			 \
    connected = 0;				 \
  }
  

#endif
