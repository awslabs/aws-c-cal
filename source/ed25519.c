/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/cal/ed25519.h>

#include <openssl/evp.h>
#include <aws/common/ref_count.h>

struct aws_ed25519_key_pair {
    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;

    EVP_PKEY *key;
};

static void s_ed25519_destroy_key(void *key_pair) {
    if (key_pair == NULL) {
        return;
    }

    struct aws_ed25519_key_pair *lc_key_pair = (struct aws_ed25519_key_pair *)(key_pair);

    if (lc_key_pair->key != NULL) {
        EVP_PKEY_free(lc_key_pair->key);
    }

    aws_mem_release(lc_key_pair->allocator, lc_key_pair);
}

struct aws_ed25519_key_pair *aws_ed25519_key_pair_new_generate(struct aws_allocator *allocator) {
    EVP_PKEY *pkey = NULL;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (ctx == NULL) {
        aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        goto on_error;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        goto on_error;
    }
    
    struct aws_ed25519_key_pair *key_pair = aws_mem_calloc(allocator, 1, sizeof(struct aws_ed25519_key_pair));

    aws_ref_count_init(&key_pair->ref_count, key_pair, s_ed25519_destroy_key);
    key_pair->allocator = allocator;
    key_pair->key = pkey;

    return key_pair;

on_error:
    EVP_PKEY_CTX_free(ctx);
    aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
    return NULL;
}

struct aws_ed25519_key_pair *aws_ed25519_key_pair_acquire(struct aws_ed25519_key_pair *key_pair) {
    return aws_ref_count_acquire(&key_pair->ref_count);
}

struct aws_ed25519_key_pair *aws_ed25519_key_pair_release(struct aws_ed25519_key_pair *key_pair) {
    if (key_pair != NULL) {
        aws_ref_count_release(&key_pair->ref_count);
    }
    return NULL;
}

int aws_ed25519_key_pair_get_public_key(
    const struct aws_ed25519_key_pair *key_pair,
    enum aws_ed25519_key_export_format format,
    struct aws_byte_buf *out) {
    return AWS_OP_SUCCESS;
}


int aws_ed25519_key_pair_get_private_key(
    const struct aws_ed25519_key_pair *key_pair,
    enum aws_ed25519_key_export_format format,
    struct aws_byte_buf *out) {
    return AWS_OP_SUCCESS;
}
