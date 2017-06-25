#ifndef server__srp_h__included
#define server__srp_h__included

#define WOLFCRYPT_HAVE_SRP
#include <wolfssl/wolfcrypt/srp.h>

// FIXME: make this overridable
#define PASSWORD "031-45-154"
#define PASSWORD_LEN 10

void srp_prepare();

#endif