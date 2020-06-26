/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/hmac.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

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

static void s_destroy(struct aws_hmac *hmac);
static int s_update(struct aws_hmac *hmac, const struct aws_byte_cursor *to_hmac);
static int s_finalize(struct aws_hmac *hmac, struct aws_byte_buf *output);

static struct aws_hmac_vtable s_sha256_hmac_vtable = {
    .destroy = s_destroy,
    .update = s_update,
    .finalize = s_finalize,
    .alg_name = "SHA256 HMAC",
    .provider = "OpenSSL Compatible libcrypto",
};

struct aws_hmac *aws_sha256_hmac_default_new(struct aws_allocator *allocator, const struct aws_byte_cursor *secret) {
    AWS_ASSERT(secret->ptr);

    struct aws_hmac *hmac = aws_mem_acquire(allocator, sizeof(struct aws_hmac));

    if (!hmac) {
        return NULL;
    }

    hmac->allocator = allocator;
    hmac->vtable = &s_sha256_hmac_vtable;
    hmac->digest_size = AWS_SHA256_HMAC_LEN;
    HMAC_CTX *ctx = NULL;
#if OPENSSL_VERSION_LESS_1_1
    ctx = aws_mem_acquire(allocator, sizeof(HMAC_CTX));
#else
    ctx = HMAC_CTX_new();
#endif
    hmac->impl = ctx;
    hmac->good = true;

    if (!hmac->impl) {
        aws_raise_error(AWS_ERROR_OOM);
        aws_mem_release(allocator, hmac);
        return NULL;
    }

#if OPENSSL_VERSION_LESS_1_1
    HMAC_CTX_init(ctx);
#endif

    if (!HMAC_Init_ex(ctx, secret->ptr, (int)secret->len, EVP_sha256(), NULL)) {
#if OPENSSL_VERSION_LESS_1_1
        HMAC_CTX_cleanup(ctx);
        aws_mem_release(allocator, ctx);
#else
        HMAC_CTX_reset(ctx);
        HMAC_CTX_free(ctx);
#endif
        aws_mem_release(allocator, hmac);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    return hmac;
}

static void s_destroy(struct aws_hmac *hmac) {
    HMAC_CTX *ctx = hmac->impl;
#if OPENSSL_VERSION_LESS_1_1
    HMAC_CTX_cleanup(ctx);
    aws_mem_release(hmac->allocator, ctx);
#else
    HMAC_CTX_reset(ctx);
    HMAC_CTX_free(ctx);
#endif
    aws_mem_release(hmac->allocator, hmac);
}

static int s_update(struct aws_hmac *hmac, const struct aws_byte_cursor *to_hmac) {
    if (!hmac->good) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    HMAC_CTX *ctx = hmac->impl;

    if (AWS_LIKELY(HMAC_Update(ctx, to_hmac->ptr, to_hmac->len))) {
        return AWS_OP_SUCCESS;
    }

    hmac->good = false;
    return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
}

static int s_finalize(struct aws_hmac *hmac, struct aws_byte_buf *output) {
    if (!hmac->good) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    HMAC_CTX *ctx = hmac->impl;

    size_t buffer_len = output->capacity - output->len;

    if (buffer_len < hmac->digest_size) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    if (AWS_LIKELY(HMAC_Final(ctx, output->buffer + output->len, (unsigned int *)&buffer_len))) {
        hmac->good = false;
        output->len += buffer_len;
        return AWS_OP_SUCCESS;
    }

    hmac->good = false;
    return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
}
