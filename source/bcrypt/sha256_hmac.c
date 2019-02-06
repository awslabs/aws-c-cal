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
#include <aws/cal/hmac.h>
#include <aws/common/thread.h>

#include <windows.h>

#include <bcrypt.h>
#include <winerror.h>
#include <winternl.h>

static BCRYPT_ALG_HANDLE s_sha256_hmac_alg = NULL;
static size_t s_sha256_hmac_obj_len = 0;

static aws_thread_once s_sha256_hmac_once = AWS_THREAD_ONCE_STATIC_INIT;

static void s_destroy(struct aws_hmac *hash);
static int s_update(struct aws_hmac *hash, struct aws_byte_cursor *to_hash);
static int s_finalize(struct aws_hmac *hash, struct aws_byte_buf *output);

static struct aws_hmac_vtable s_vtable = {
    .destroy = s_destroy,
    .update = s_update,
    .finalize = s_finalize,
};

struct sha256_hmac_handle {
    BCRYPT_HASH_HANDLE hash_handle;
    uint8_t *hash_obj;
};

static void s_load_alg_handle(void) {
    /* this function is incredibly slow, LET IT LEAK*/
    BCryptOpenAlgorithmProvider(
        &s_sha256_hmac_alg, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    assert(s_sha256_hmac_alg);
    DWORD result_length = 0;
    BCryptGetProperty(
        s_sha256_hmac_alg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&s_sha256_hmac_obj_len,
        sizeof(s_sha256_hmac_obj_len),
        &result_length,
        0);
}

struct aws_hmac *aws_sha256_hmac_default_new(struct aws_allocator *allocator, struct aws_byte_cursor *secret) {
    aws_thread_call_once(&s_sha256_hmac_once, s_load_alg_handle);

    struct aws_hmac *hmac = aws_mem_acquire(allocator, sizeof(struct aws_hmac));

    if (!hmac) {
        return NULL;
    }

    hmac->allocator = allocator;
    hmac->alg_name = "SHA256 HMAC (From: Windows CNG)";
    hmac->vtable = &s_vtable;
    struct sha256_hmac_handle *ctx = NULL;
    uint8_t *hash_obj = NULL;
    aws_mem_acquire_many(allocator, 2, &ctx, sizeof(struct sha256_hmac_handle), &hash_obj, s_sha256_hmac_obj_len);
    hmac->impl = ctx;

    if (!hmac->impl) {
        aws_raise_error(AWS_ERROR_OOM);
        aws_mem_release(allocator, hmac);
        return NULL;
    }

    AWS_ZERO_STRUCT(*ctx);
    ctx->hash_obj = hash_obj;
    NTSTATUS status = BCryptCreateHash(
        s_sha256_hmac_alg,
        &ctx->hash_handle,
        ctx->hash_obj,
        (ULONG)s_sha256_hmac_obj_len,
        secret->ptr,
        (ULONG)secret->len,
        0);

    if (!NT_SUCCESS(status)) {
        aws_mem_release(hmac->allocator, ctx);
        aws_mem_release(hmac->allocator, hmac);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    return hmac;
}

static void s_destroy(struct aws_hmac *hmac) {
    struct sha256_hmac_handle *ctx = hmac->impl;
    BCryptDestroyHash(ctx->hash_handle);
    aws_mem_release(hmac->allocator, ctx);
    aws_mem_release(hmac->allocator, hmac);
}

static int s_update(struct aws_hmac *hmac, struct aws_byte_cursor *to_hash) {
    struct sha256_hmac_handle *ctx = hmac->impl;
    NTSTATUS status = BCryptHashData(ctx->hash_handle, to_hash->ptr, (ULONG)to_hash->len, 0);

    if (!NT_SUCCESS(status)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    return AWS_OP_SUCCESS;
}

static int s_finalize(struct aws_hmac *hmac, struct aws_byte_buf *output) {
    struct sha256_hmac_handle *ctx = hmac->impl;

    size_t buffer_len = output->capacity - output->len;

    if (buffer_len < AWS_SHA256_HMAC_LEN) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    NTSTATUS status = BCryptFinishHash(ctx->hash_handle, output->buffer + output->len, (ULONG)buffer_len, 0);
    if (!NT_SUCCESS(status)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    output->len += buffer_len;
    return AWS_OP_SUCCESS;
}
