/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/cal.h>

#include <aws/cal/hkdf.h>

#include <openssl/evp.h>

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
// OpenSSL 1.1.0 or later - can use kdf.h
#    include <openssl/kdf.h>
#endif

int aws_hkdf_derive_impl(
    struct aws_allocator *allocator,
    enum aws_hkdf_hmac_type hmac_type,
    struct aws_byte_cursor ikm,
    struct aws_byte_cursor salt,
    struct aws_byte_cursor info,
    struct aws_byte_buf *out_buf,
    size_t length) {
    AWS_PRECONDITION(hmac_type == HKDF_HMAC_SHA512);

/*
 * KDF are only supported since 1.1.0. In practice very few callers should
 * still be using anything older than that, so throw error.
 * We can revisit if there is a need for hkdf on old libcrypto.
 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000
    size_t available_len = out_buf->capacity - out_buf->len;
    if (available_len < length) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
        goto on_error;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
        goto on_error;
    }

    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha512()) <= 0) {
        aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
        goto on_error;
    }

    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.ptr, salt.len) <= 0) {
        aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
        goto on_error;
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.ptr, ikm.len) <= 0) {
        aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
        goto on_error;
    }

    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.ptr, info.len) <= 0) {
        aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
        goto on_error;
    }

    if (EVP_PKEY_derive(pctx, out_buf->buffer, &out_buf->len) <= 0) {
        
        aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
        goto on_error;
    }

    AWS_LOGF_DEBUG(0, "derive success %zu", out_buf->len);

    EVP_PKEY_CTX_free(pctx);
    return AWS_OP_SUCCESS;

on_error:
    EVP_PKEY_CTX_free(pctx);
    return AWS_OP_ERR;
#else
    return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM);
#endif
}
