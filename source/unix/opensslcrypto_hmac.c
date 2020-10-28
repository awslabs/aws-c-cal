/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/hmac.h>
#include <aws/cal/private/opensslcrypto_common.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

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

static void s_destroy(struct aws_hmac *hmac) {
    if (hmac == NULL) {
        return;
    }

    HMAC_CTX *ctx = hmac->impl;
    if (ctx != NULL) {
        if (g_aws_openssl_hmac_ctx_1_0_table != NULL) {
            g_aws_openssl_hmac_ctx_1_0_table->clean_up_fn(ctx);
            aws_mem_release(hmac->allocator, ctx);
        } else {
            g_aws_openssl_hmac_ctx_1_1_table->reset_fn(ctx);
            g_aws_openssl_hmac_ctx_1_1_table->free_fn(ctx);
        }
    }

    aws_mem_release(hmac->allocator, hmac);
}

#define SIZEOF_OPENSSL_HMAC_CTX (4 * sizeof(void *))

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
    if (g_aws_openssl_hmac_ctx_1_0_table != NULL) {
        ctx = aws_mem_acquire(allocator, SIZEOF_OPENSSL_HMAC_CTX);
    } else {
        ctx = g_aws_openssl_hmac_ctx_1_1_table->new_fn();
    }

    hmac->impl = ctx;
    hmac->good = true;

    if (!hmac->impl) {
        aws_raise_error(AWS_ERROR_OOM);
        aws_mem_release(allocator, hmac);
        return NULL;
    }

    if (g_aws_openssl_hmac_ctx_1_0_table != NULL) {
        g_aws_openssl_hmac_ctx_1_0_table->init_fn(ctx);
    }

    if (!HMAC_Init_ex(ctx, secret->ptr, (int)secret->len, EVP_sha256(), NULL)) {
        s_destroy(hmac);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    return hmac;
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
