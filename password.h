#ifndef PASSWORD_H
#define PASSWORD_H

#include <stdint.h>

int passwordHash1000(char *password, char salt, uint32_t *digest);

#endif
