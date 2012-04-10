#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

#include "sha1.h"

//
// NOTE: if password is not immutable, then you will get a seg fault
//
int passwordHash1000(char *password, char salt, uint32_t *hash) {
  int ret,i;
  uint32_t tempHash[SHA1_HASH_UINT32_LENGTH];

  password[0] += salt;

  ret = sha1String(password, tempHash);

  if(ret) return ret;

  for(int i = 0; i < 498; i++) {
    sha1Binary((unsigned char*)tempHash, SHA1_HASH_BYTE_LENGTH, hash);
    sha1Binary((unsigned char*)hash, SHA1_HASH_BYTE_LENGTH, tempHash);
  }

  return sha1Binary((unsigned char*)tempHash, SHA1_HASH_BYTE_LENGTH, hash);
}
