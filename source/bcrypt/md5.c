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
#include <aws/common/thread.h>

#include <windows.h>

#include <bcrypt.h>
#include <winerror.h>
#include <winternl.h>

static BCRYPT_ALG_HANDLE s_md5_alg = NULL;
static size_t s_md5_obj_len = 0;

static aws_thread_once s_md5_once = AWS_THREAD_ONCE_STATIC_INIT;

static void s_destroy(struct aws_hash *hash);
static int s_update(struct aws_hash *hash, struct aws_byte_cursor *to_hash);
static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output);

static struct aws_hash_vtable s_vtable = {
    .destroy = s_destroy,
    .update = s_update,
    .finalize = s_finalize,
};

struct md5_handle {
    BCRYPT_HASH_HANDLE hash_handle;
    uint8_t *hash_obj;
};

static void s_load_alg_handle(void) {
    /* this function is incredibly slow, LET IT LEAK*/
    BCryptOpenAlgorithmProvider(&s_md5_alg, BCRYPT_MD5_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    assert(s_md5_alg);
    DWORD result_length = 0;
    BCryptGetProperty(s_md5_alg, BCRYPT_OBJECT_LENGTH, (PBYTE)&s_md5_obj_len, sizeof(s_md5_obj_len), &result_length, 0);
}

struct aws_hash *aws_md5_default_new(struct aws_allocator *allocator) {
    aws_thread_call_once(&s_md5_once, s_load_alg_handle);

    struct aws_hash *hash = aws_mem_acquire(allocator, sizeof(struct aws_hash));

    if (!hash) {
        return NULL;
    }

    hash->allocator = allocator;
    hash->alg_name = "MD5 (From: Windows CNG)";
    hash->vtable = &s_vtable;
    struct md5_handle *ctx = NULL;
    uint8_t *hash_obj = NULL;
    aws_mem_acquire_many(allocator, 2, &ctx, sizeof(struct md5_handle), &hash_obj, s_md5_obj_len);
    hash->impl = ctx;

    if (!hash->impl) {
        aws_raise_error(AWS_ERROR_OOM);
        aws_mem_release(allocator, hash);
        return NULL;
    }

    AWS_ZERO_STRUCT(*ctx);
    ctx->hash_obj = hash_obj;
    NTSTATUS status = BCryptCreateHash(s_md5_alg, &ctx->hash_handle, ctx->hash_obj, (ULONG)s_md5_obj_len, NULL, 0, 0);

    if (!NT_SUCCESS(status)) {
        aws_mem_release(hash->allocator, ctx);
        aws_mem_release(hash->allocator, hash);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    return hash;
}

static void s_destroy(struct aws_hash *hash) {
    struct md5_handle *ctx = hash->impl;
    BCryptDestroyHash(ctx->hash_handle);
    aws_mem_release(hash->allocator, ctx);
    aws_mem_release(hash->allocator, hash);
}

static int s_update(struct aws_hash *hash, struct aws_byte_cursor *to_hash) {
    struct md5_handle *ctx = hash->impl;
    NTSTATUS status = BCryptHashData(ctx->hash_handle, to_hash->ptr, (ULONG)to_hash->len, 0);

    if (!NT_SUCCESS(status)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    return AWS_OP_SUCCESS;
}

static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output) {
    struct md5_handle *ctx = hash->impl;

    size_t buffer_len = output->capacity - output->len;

    if (buffer_len < AWS_MD5_LEN) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    NTSTATUS status = BCryptFinishHash(ctx->hash_handle, output->buffer + output->len, (ULONG)buffer_len, 0);
    if (!NT_SUCCESS(status)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    output->len += buffer_len;
    return AWS_OP_SUCCESS;
}
