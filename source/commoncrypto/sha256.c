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

#include <CommonCrypto/CommonDigest.h>

static void s_destroy(struct aws_hash *hash);
static int s_update(struct aws_hash *hash, struct aws_byte_cursor *to_hash);
static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output);

static struct aws_hash_vtable s_vtable = {
    .destroy = s_destroy,
    .update = s_update,
    .finalize = s_finalize,
};

struct aws_hash *aws_sha256_default_new(struct aws_allocator *allocator) {
    struct aws_hash *hash = aws_mem_acquire(allocator, sizeof(struct aws_hash));

    if (!hash) {
        return NULL;
    }

    hash->allocator = allocator;
    hash->alg_name = "SHA256 (From: OpenSSL Compatible LibCrypto)";
    hash->vtable = &s_vtable;
    CC_SHA256_CTX *ctx = aws_mem_acquire(allocator, sizeof(CC_SHA256_CTX));
    hash->impl = ctx;

    if (!hash->impl) {
        aws_raise_error(AWS_ERROR_OOM);
        aws_mem_release(allocator, hash);
        return NULL;
    }

    CC_SHA256_Init(ctx);
    return hash;
}

static void s_destroy(struct aws_hash *hash) {
    CC_SHA256_CTX *ctx = hash->impl;
    aws_mem_release(hash->allocator, ctx);
    aws_mem_release(hash->allocator, hash);
}

static int s_update(struct aws_hash *hash, struct aws_byte_cursor *to_hash) {
    CC_SHA256_CTX *ctx = hash->impl;

    CC_SHA256_Update(ctx, to_hash->ptr, (CC_LONG)to_hash->len);
    return AWS_OP_SUCCESS;
}

static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output) {
    CC_SHA256_CTX *ctx = hash->impl;

    size_t buffer_len = output->capacity - output->len;

    if (buffer_len < AWS_SHA256_LEN) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    CC_SHA256_Final(output->buffer + output->len, ctx);
    output->len += buffer_len;
    return AWS_OP_SUCCESS;
}
