#ifndef HB_H
#define HB_H

#include <stdint.h>

#include "../weblib/sha1.h"

#define MAX_DIGITS_FOR_DECIMAL_IP 10
#define MAX_DIGITS_FOR_DECIMAL_UID 20 // A uint64_t.MAX is represented by 20 decimal digits
#define MAX_EMAIL 128
#define MAX_PASSWORD 64
#define MAX_FIRST_NAME 64
#define MAX_LAST_NAME 64

#define MAX_LOGIN_ATTEMPTS 10

#define PRINT_FILE_BUFFER_SIZE 1024

//
// A SHA1 Hash is 20 bytes (160 bits) and will be represented in the following forms:
//   1. uint32_t[5] hashUint32      : 32 bit array
//   2. unsigned char[20] hashBytes : 8 bit array
//   3. char[27] hashBase64         : base64 string
//   // is this needed? 4. char[40] hashHex            : hex string
//
// SHA1 Conversions:
//   In order to convert from the first representation to any of the other 3, a host2network or
//   network2host must occur.  The 32 bit array is in host order and the other 3 are in network order.
//     * hashUint32 --> hashBytes
//        - Perform htonl on each uint32, then cast
//     * hashUint32 --> hashBase64
//        - Convert to unsigned char[20] then use base64.c:base64enc(...)
//     * hashUint32 --> hashHex
//        - Use sprintf '%08X%08X%08X%08x%08x', this will take care of the network to host order for you
// 
//     * hashBytes  --> hashUint32
//        - Perform ntohl on each uint32, then case
//     * hashBytes  --> hashBase64
//        - Use base64.c:base64enc(...)
//     * hashBytes  --> hashHex
//        - Use sprintf on each byte '%02X%02X...(20 times)' or Use a custom function/macro (util.c:hashBytes2Hex(..))
//
//     * hashHex    --> hashUint32
//        - ??? (Maybe use scanf)?
//     * hashHex    --> hashBase64
//        - 2 part conversion, first convert to hashBytes, then to hashBase64
//     * hashHex    --> hashBytes
//        - ??? Maybe use a custom function/macro
//
//     * hashBase64 --> hashUint32
//      
// When to use each form:
//   Comparison: The speed of comparison is listed in the following order from best to worst
//               hashUint32 - hashBytes - hashBase64 - hashHex
//   Endianness: The hashUint32 form is in host order, but the other 3 are in network order (big endian)


typedef struct {
  uint64_t uid;

  // SID Hash
  uint32_t *sidUint32;
  unsigned char *sidBytes;
  char * sidBase64;

  //char *passwordHash;

} HB_HANDLE;


typedef struct {
  uint64_t uid;
  uint32_t sid[SHA1_HASH_UINT32_LENGTH];
} HB_SESSION;

typedef struct {
  char *userAgent;
  char *accept;
  char *acceptEncoding;
  char *acceptLanguage;
  char *acceptCharset;
} CLIENT_INFO;

typedef struct {
  char *uid; //uint64_t uid;
  char salt;
  char *passwordHash;
} HB_USER_LOGIN;

typedef struct {
  char *email;
  char salt;
  uint32_t *passwordHash;
  char *fName;
  char *lName;

} HB_USER;


#endif
