/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/cal/cal.h>
#include <aws/cal/private/opensslcrypto_common.h>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/err.h>
#include <openssl/evp.h>

#if defined(OPENSSL_IS_OPENSSL)
/*Error defines were part of evp.h in 1.0.x and were moved to evperr.h in 1.1.0*/
#    if OPENSSL_VERSION_NUMBER >= 0x10100000L
#        include <openssl/evperr.h>
#    endif
#else
#    include <openssl/evp_errors.h>
#endif

/*
 * Transforms evp error code into crt error code and raises it as necessary.
 * All evp functions follow the same:
 * >= 1 for success
 * <= 0 for failure
 * -2 always indicates incorrect algo for operation
 */
int aws_reinterpret_lc_evp_error_as_crt(int evp_error, const char *function_name, enum aws_cal_log_subject subject) {
    if (evp_error > 0) {
        return AWS_OP_SUCCESS;
    }

    /* AWS-LC/BoringSSL error code is uint32_t, but OpenSSL uses unsigned long. */
#if defined(OPENSSL_IS_OPENSSL)
    uint32_t error = ERR_peek_error();
#else
    unsigned long error = ERR_peek_error();
#endif

    int crt_error = AWS_OP_ERR;
    const char *error_message = ERR_reason_error_string(error);

    if (evp_error == -2) {
        crt_error = AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM;
        goto on_error;
    }

    if (ERR_GET_LIB(error) == ERR_LIB_EVP) {
        switch (ERR_GET_REASON(error)) {
            case EVP_R_BUFFER_TOO_SMALL: {
                crt_error = AWS_ERROR_SHORT_BUFFER;
                goto on_error;
            }
            case EVP_R_UNSUPPORTED_ALGORITHM: {
                crt_error = AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM;
                goto on_error;
            }
        }
    }

    crt_error = AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED;

on_error:
    AWS_LOGF_ERROR(
        subject,
        "%s() failed. returned: %d extended error:%lu(%s) aws_error:%s",
        function_name,
        evp_error,
        (unsigned long)error,
        error_message == NULL ? "" : error_message,
        aws_error_name(crt_error));

    return aws_raise_error(crt_error);
}

/* Validate at runtime that we're linked against the same libcrypto we compiled against. */
void aws_validate_libcrypto_linkage(void) {
    /* NOTE: the choice of stack buffer size is somewhat arbitrary. it's
     * possible, but unlikely, that libcrypto version strings may exceed this in
     * the future. we guard against buffer overflow by limiting write size in
     * snprintf with the size of the buffer itself. if libcrypto version strings
     * do eventually exceed the chosen size, this runtime check will fail and
     * will need to be addressed by increasing buffer size.*/
    char expected_version[64] = {0};
#if defined(OPENSSL_IS_AWSLC)
    /* get FIPS mode at runtime because headers don't give any indication of
     * AWS-LC's FIPSness at aws-c-cal compile time. version number can still be
     * captured at preprocess/compile time from AWSLC_VERSION_NUMBER_STRING.*/
    const char *mode = FIPS_mode() ? "AWS-LC FIPS" : "AWS-LC";
    snprintf(expected_version, sizeof(expected_version), "%s %s", mode, AWSLC_VERSION_NUMBER_STRING);
#elif defined(OPENSSL_IS_BORINGSSL)
    snprintf(expected_version, sizeof(expected_version), "BoringSSL");
#elif defined(OPENSSL_IS_OPENSSL)
    snprintf(expected_version, sizeof(expected_version), OPENSSL_VERSION_TEXT);
#elif !defined(BYO_CRYPTO)
#    error Unsupported libcrypto!
#endif
    const char *runtime_version = SSLeay_version(SSLEAY_VERSION);
    AWS_LOGF_DEBUG(
        AWS_LS_CAL_LIBCRYPTO_RESOLVE,
        "Compiled with libcrypto %s, linked to libcrypto %s",
        expected_version,
        runtime_version);
#if defined(OPENSSL_IS_OPENSSL)
    /* Validate that the string "AWS-LC" doesn't appear in OpenSSL version str. */
    AWS_FATAL_ASSERT(strstr("AWS-LC", expected_version) == NULL);
    AWS_FATAL_ASSERT(strstr("AWS-LC", runtime_version) == NULL);
    /* Validate both expected and runtime versions begin with OpenSSL's version str prefix. */
    const char *openssl_prefix = "OpenSSL ";
    AWS_FATAL_ASSERT(strncmp(openssl_prefix, expected_version, strlen(openssl_prefix)) == 0);
    AWS_FATAL_ASSERT(strncmp(openssl_prefix, runtime_version, strlen(openssl_prefix)) == 0);
#else
    AWS_FATAL_ASSERT(strcmp(expected_version, runtime_version) == 0 && "libcrypto mislink");
#endif
}
