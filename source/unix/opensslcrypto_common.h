#ifndef AWS_C_CAL_OPENSSLCRYPTO_COMMON_H
#define AWS_C_CAL_OPENSSLCRYPTO_COMMON_H

#include "openssl/opensslv.h"

/**
 * openssl with OPENSSL_VERSION_NUMBER < 0x10100003L made data type details
 * unavailable libressl use openssl with data type details available, but
 * mandatorily set OPENSSL_VERSION_NUMBER = 0x20000000L, insane!
 * https://github.com/aws/aws-sdk-cpp/pull/507/commits/2c99f1fe0c4b4683280caeb161538d4724d6a179
 */
#if defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER == 0x20000000L)
#    undef OPENSSL_VERSION_NUMBER
#    define OPENSSL_VERSION_NUMBER 0x1000107fL
#endif
#define OPENSSL_VERSION_LESS_1_1 (OPENSSL_VERSION_NUMBER < 0x10100003L)

#endif /* AWS_C_CAL_OPENSSLCRYPTO_COMMON_H */
