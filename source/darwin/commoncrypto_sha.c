/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/hash.h>

#include <CommonCrypto/CommonDigest.h>

static void s_destroy(struct aws_hash *hash);
static int s_update_sha256(struct aws_hash *hash, const struct aws_byte_cursor *to_hash);
static int s_finalize_sha256(struct aws_hash *hash, struct aws_byte_buf *output);
static int s_update_sha1(struct aws_hash *hash, const struct aws_byte_cursor *to_hash);
static int s_finalize_sha1(struct aws_hash *hash, struct aws_byte_buf *output);

static struct aws_hash_vtable s_sha256_vtable = {
    .destroy = s_destroy,
    .update = s_update_sha256,
    .finalize = s_finalize_sha256,
    .alg_name = "SHA256",
    .provider = "CommonCrypto",
};

static struct aws_hash_vtable s_sha1_vtable = {
    .destroy = s_destroy,
    .update = s_update_sha1,
    .finalize = s_finalize_sha1,
    .alg_name = "SHA1",
    .provider = "CommonCrypto",
};

struct cc_sha256_hash {
    struct aws_hash hash;
    CC_SHA256_CTX cc_hash;
};

struct cc_sha1_hash {
    struct aws_hash hash;
    CC_SHA1_CTX cc_hash;
};

static int sha256_update_resolver(void *cc_ctx, const void *data, CC_LONG len) {
    CC_SHA256_CTX *sha256_ctx = (CC_SHA256_CTX *)cc_ctx;
    return CC_SHA256_Update(sha256_ctx, data, len);
}

static int sha1_update_resolver(void *cc_ctx, const void *data, CC_LONG len) {
    CC_SHA1_CTX *sha1_ctx = (CC_SHA1_CTX *)cc_ctx;
    return CC_SHA1_Update(sha1_ctx, data, len);
}

static int sha256_final_resolver(unsigned char *md, void *cc_ctx) {
    CC_SHA256_CTX *sha256_ctx = (CC_SHA256_CTX *)cc_ctx;
    return CC_SHA256_Final(md, sha256_ctx);
}

static int sha1_final_resolver(unsigned char *md, void *cc_ctx) {
    CC_SHA1_CTX *sha1_ctx = (CC_SHA1_CTX *)cc_ctx;
    return CC_SHA1_Final(md, sha1_ctx);
}

struct aws_hash *aws_sha256_default_new(struct aws_allocator *allocator) {
    struct cc_sha256_hash *sha256_hash = aws_mem_acquire(allocator, sizeof(struct cc_sha256_hash));

    if (!sha256_hash) {
        return NULL;
    }

    sha256_hash->hash.allocator = allocator;
    sha256_hash->hash.vtable = &s_sha256_vtable;
    sha256_hash->hash.impl = sha256_hash;
    sha256_hash->hash.digest_size = AWS_SHA256_LEN;
    sha256_hash->hash.good = true;

    CC_SHA256_Init(&sha256_hash->cc_hash);
    return &sha256_hash->hash;
}

struct aws_hash *aws_sha1_default_new(struct aws_allocator *allocator) {
    struct cc_sha1_hash *sha1_hash = aws_mem_acquire(allocator, sizeof(struct cc_sha1_hash));

    if (!sha1_hash) {
        return NULL;
    }

    sha1_hash->hash.allocator = allocator;
    sha1_hash->hash.vtable = &s_sha1_vtable;
    sha1_hash->hash.impl = sha1_hash;
    sha1_hash->hash.digest_size = AWS_SHA1_LEN;
    sha1_hash->hash.good = true;

    CC_SHA1_Init(&sha1_hash->cc_hash);
    return &sha1_hash->hash;
}

static void s_destroy(struct aws_hash *hash) {
    struct cc_sha256_hash *ctx = hash->impl;
    aws_mem_release(hash->allocator, ctx);
}

static int s_update_common(
    struct aws_hash *hash,
    void *cc_hash,
    const struct aws_byte_cursor *to_hash,
    int (*cc_sha_update)(void *, const void *, CC_LONG)) {
    if (!hash->good) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    cc_sha_update(cc_hash, to_hash->ptr, (CC_LONG)to_hash->len);
    return AWS_OP_SUCCESS;
}

static int s_update_sha256(struct aws_hash *hash, const struct aws_byte_cursor *to_hash) {
    struct cc_sha256_hash *ctx = hash->impl;
    return s_update_common(hash, &ctx->cc_hash, to_hash, sha256_update_resolver);
}

static int s_update_sha1(struct aws_hash *hash, const struct aws_byte_cursor *to_hash) {
    struct cc_sha1_hash *ctx = hash->impl;
    return s_update_common(hash, &ctx->cc_hash, to_hash, sha1_update_resolver);
}

static int s_finalize_common(
    struct aws_hash *hash,
    void *cc_hash,
    struct aws_byte_buf *output,
    int output_len,
    int (*cc_final)(unsigned char *, void *)) {
    if (!hash->good) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    size_t buffer_len = output->capacity - output->len;

    if (buffer_len < output_len) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    cc_final(output->buffer + output->len, cc_hash);
    hash->good = false;
    output->len += buffer_len;
    return AWS_OP_SUCCESS;
}

static int s_finalize_sha256(struct aws_hash *hash, struct aws_byte_buf *output) {
    struct cc_sha256_hash *ctx = hash->impl;
    return s_finalize_common(hash, &ctx->cc_hash, output, AWS_SHA256_LEN, sha256_final_resolver);
}

static int s_finalize_sha1(struct aws_hash *hash, struct aws_byte_buf *output) {
    struct cc_sha1_hash *ctx = hash->impl;
    return s_finalize_common(hash, &ctx->cc_hash, output, AWS_SHA1_LEN, sha1_final_resolver);
}
