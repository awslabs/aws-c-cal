/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
#include <aws/cal/hash.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

static void s_destroy(struct aws_hash *hash);
static int s_update(struct aws_hash *hash, struct aws_byte_cursor *to_hash);
static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output);

static struct aws_hash_vtable s_vtable = {
    .destroy = s_destroy,
    .update = s_update,
    .finalize = s_finalize,
};

struct aws_hash *aws_md5_default_new(struct aws_allocator *allocator) {
    struct aws_hash *hash = aws_mem_acquire(allocator, sizeof(struct aws_hash));

    if (!hash) {
        return NULL;
    }

    hash->allocator = allocator;
    hash->alg_name = "MD5 (From: OpenSSL Compatible LibCrypto)";
    hash->vtable = &s_vtable;
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    hash->impl = ctx;

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

static void s_destroy(struct aws_hash *hash) {
    EVP_MD_CTX *ctx = hash->impl;
    EVP_MD_CTX_destroy(ctx);
    aws_mem_release(hash->allocator, hash);
}

static int s_update(struct aws_hash *hash, struct aws_byte_cursor *to_hash) {
    EVP_MD_CTX *ctx = hash->impl;

    if (AWS_LIKELY(EVP_DigestUpdate(ctx, to_hash->ptr, to_hash->len))) {
        return AWS_OP_SUCCESS;
    }

    return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
}

static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output) {
    EVP_MD_CTX *ctx = hash->impl;

    size_t buffer_len = output->capacity - output->len;

    if (buffer_len < AWS_MD5_LEN) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    if (AWS_LIKELY(EVP_DigestFinal_ex(ctx, output->buffer + output->len, (unsigned int *)&buffer_len))) {
        output->len += buffer_len;
        return AWS_OP_SUCCESS;
    }

    return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
}
