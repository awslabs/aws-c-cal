/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/hash.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

static void s_destroy(struct aws_hash *hash);
static int s_update(struct aws_hash *hash, const struct aws_byte_cursor *to_hash);
static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output);

static struct aws_hash_vtable s_md5_vtable = {
    .destroy = s_destroy,
    .update = s_update,
    .finalize = s_finalize,
    .alg_name = "MD5",
    .provider = "OpenSSL Compatible libcrypto",
};

static struct aws_hash_vtable s_sha256_vtable = {
    .destroy = s_destroy,
    .update = s_update,
    .finalize = s_finalize,
    .alg_name = "SHA256",
    .provider = "OpenSSL Compatible libcrypto",
};

struct aws_hash *aws_md5_default_new(struct aws_allocator *allocator) {
    struct aws_hash *hash = aws_mem_acquire(allocator, sizeof(struct aws_hash));

    if (!hash) {
        return NULL;
    }

    hash->allocator = allocator;
    hash->vtable = &s_md5_vtable;
    hash->digest_size = AWS_MD5_LEN;
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    hash->impl = ctx;
    hash->good = true;

    if (!hash->impl) {
        aws_raise_error(AWS_ERROR_OOM);
        aws_mem_release(allocator, hash);
        return NULL;
    }

    if (!EVP_DigestInit_ex(ctx, EVP_md5(), NULL)) {
        EVP_MD_CTX_destroy(ctx);
        aws_mem_release(allocator, hash);
        aws_raise_error(AWS_ERROR_UNKNOWN);
        return NULL;
    }

    return hash;
}

struct aws_hash *aws_sha256_default_new(struct aws_allocator *allocator) {
    struct aws_hash *hash = aws_mem_acquire(allocator, sizeof(struct aws_hash));

    if (!hash) {
        return NULL;
    }

    hash->allocator = allocator;
    hash->vtable = &s_sha256_vtable;
    hash->digest_size = AWS_SHA256_LEN;
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    hash->impl = ctx;
    hash->good = true;

    if (!hash->impl) {
        aws_raise_error(AWS_ERROR_OOM);
        aws_mem_release(allocator, hash);
        return NULL;
    }

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_destroy(ctx);
        aws_mem_release(allocator, hash);
        aws_raise_error(AWS_ERROR_UNKNOWN);
        return NULL;
    }

    return hash;
}

static void s_destroy(struct aws_hash *hash) {
    EVP_MD_CTX *ctx = hash->impl;
    EVP_MD_CTX_destroy(ctx);
    aws_mem_release(hash->allocator, hash);
}

static int s_update(struct aws_hash *hash, const struct aws_byte_cursor *to_hash) {
    if (!hash->good) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    EVP_MD_CTX *ctx = hash->impl;

    if (AWS_LIKELY(EVP_DigestUpdate(ctx, to_hash->ptr, to_hash->len))) {
        return AWS_OP_SUCCESS;
    }

    hash->good = false;
    return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
}

static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output) {
    if (!hash->good) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    EVP_MD_CTX *ctx = hash->impl;

    size_t buffer_len = output->capacity - output->len;

    if (buffer_len < hash->digest_size) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    if (AWS_LIKELY(EVP_DigestFinal_ex(ctx, output->buffer + output->len, (unsigned int *)&buffer_len))) {
        output->len += buffer_len;
        hash->good = false;
        return AWS_OP_SUCCESS;
    }

    hash->good = false;
    return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
}
