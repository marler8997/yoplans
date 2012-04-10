#ifndef HB_MACROS_C
#define HB_MACROS_C

#include <netinet/in.h>

#include "log.macros.c"

// sidBase64         : [IN]       : The Sid encoded as a base64 string
// cookieString      : [IN]       : The Cookie string
// sidLengthUnsigned :      [OUT] : Outputs the length of the sid string
// failJumpLabel     : [IN]       : Label to jump to on error
#define getAndCheckSidFromCookie(sidBase64, cookieString, sidLengthUnsigned, failJumpLabel) \
  sidBase64 = strstr(cookie, "s=");						\
  if(sidBase64 == NULL) goto failJumpLabel;					\
  									\
  sidBase64 += 2; /* skip 's=' */						\
  									\
  sidLengthUnsigned = base64CountValidEncodedChars(sidBase64);		\
  if(sidLength < SHA1_HASH_BASE64_LENGTH) {				\
    if(sidBase64[sidLengthUnsigned] == '&' || sidBase64[sidLengthUnsigned] == '\0') {	\
      sidBase64[sidLengthUnsigned] = '\0';					\
      logBadCookie("s", "Expected Sid '%s' to have %u characters but it only had %u.", \
		   sidBase64, SHA1_HASH_BASE64_LENGTH, sidLengthUnsigned);	\
    } else if(sidBase64[sidLengthUnsigned] == '\'') {				\
      logSqlInjection("Sid-Cookie", sidBase64);				\
    } else {								\
      logBadCookie("s", "The Sid '%s' had an invalid character '%c' (hex=0x%x) at index %u.", \
		   sidBase64, sidBase64[sidLengthUnsigned], sidBase64[sidLengthUnsigned], sidLengthUnsigned); \
    }									\
    goto failJumpLabel;							\
  }

//
// TODO: Add regression test for this function
//
#define bytes2uint64_t(bytes)				\
  (							\
   ( ((uint64_t)ntohl(((uint32_t*)bytes)[0])) << 32) |	\
     ((uint64_t)ntohl(((uint32_t*)bytes)[1]))		\
  )

//
// Host 2 Network Order for a SHA1 Hash
//
#define htonHash(hash)				\
  hash[0] = htonl(((uint32_t*)hash)[0]);	\
  hash[1] = htonl(((uint32_t*)hash)[1]);	\
  hash[2] = htonl(((uint32_t*)hash)[2]);	\
  hash[3] = htonl(((uint32_t*)hash)[3]);	\
  hash[4] = htonl(((uint32_t*)hash)[4]);

//
// Network 2 Host Order for a SHA1 Hash
//
#define ntohHash(hash)				\
  hash[0] = ntohl(hash[0]);			\
  hash[1] = ntohl(hash[1]);			\
  hash[2] = ntohl(hash[2]);			\
  hash[3] = ntohl(hash[3]);			\
  hash[4] = ntohl(hash[4]);


#endif
