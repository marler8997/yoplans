#ifndef SEND_H
#define SEND_H

int sendRegisterError();
int sendLoginPage(char *optionalMessage);
int sendHomePage(uint64_t uid);
int sendSqlInjection();

#endif
