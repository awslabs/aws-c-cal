/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/private/rsa.h>

#include <aws/cal/cal.h>
#include <aws/common/encoding.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

struct lc_rsa_key_pair {
    struct aws_rsa_key_pair base;
    EVP_PKEY *key;
};

static void s_rsa_destroy_key(struct aws_rsa_key_pair *key_pair) {
    if (key_pair == NULL) {
        return;
    }

    struct lc_rsa_key_pair *rsa_key = key_pair->impl;

    if (rsa_key->key != NULL) {
        EVP_PKEY_free(rsa_key->key);
    }

    aws_mem_release(key_pair->allocator, rsa_key);
}

int s_set_enc_ctx_from_algo (EVP_PKEY_CTX *ctx, enum aws_rsa_encryption_algorithm algorithm) {
    if (algorithm == AWS_CAL_RSA_ENCRYPTION_PKCS1_5) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        }

    } else if (algorithm == AWS_CAL_RSA_ENCRYPTION_OAEP_SHA256 || algorithm == AWS_CAL_RSA_ENCRYPTION_OAEP_SHA512) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        }

        const EVP_MD *md = algorithm == AWS_CAL_RSA_ENCRYPTION_OAEP_SHA256 ? EVP_sha256() : EVP_sha512();
        if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md)) {
            return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        }
    } else {
        return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM);
    }

    return AWS_OP_SUCCESS;
}

int s_rsa_encrypt(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_encryption_algorithm algorithm,
    struct aws_byte_cursor plaintext,
    struct aws_byte_buf *out) {
    struct lc_rsa_key_pair *key_pair_impl = key_pair->impl;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key_pair_impl->key, NULL);
    if (ctx == NULL) {
        return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    if (s_set_enc_ctx_from_algo(ctx, algorithm)) {
        goto on_error;
    }

    size_t ct_len = out->capacity - out->len;
    if (EVP_PKEY_encrypt(ctx, out->buffer, &ct_len, plaintext.ptr, plaintext.len) <= 0) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }
    out->len += ct_len;

    EVP_PKEY_CTX_free(ctx);

    return AWS_OP_SUCCESS;

on_error:
    EVP_PKEY_CTX_free(ctx);
    return AWS_OP_ERR;
}

int s_rsa_decrypt(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_encryption_algorithm algorithm,
    struct aws_byte_cursor ciphertext,
    struct aws_byte_buf *out) {
    struct lc_rsa_key_pair *key_pair_impl = key_pair->impl;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key_pair_impl->key, NULL);
    if (ctx == NULL) {
        return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    if (s_set_enc_ctx_from_algo(ctx, algorithm)) {
        goto on_error;
    }

    size_t ct_len = out->capacity - out->len;
    if (EVP_PKEY_decrypt(ctx, out->buffer, &ct_len, ciphertext.ptr, ciphertext.len) <= 0) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }
    out->len += ct_len;

    EVP_PKEY_CTX_free(ctx);

    return AWS_OP_SUCCESS;

on_error:
    EVP_PKEY_CTX_free(ctx);
    return AWS_OP_ERR;
}

int s_set_sign_ctx_from_algo (EVP_PKEY_CTX *ctx, enum aws_rsa_signing_algorithm algorithm) {
    if (algorithm == AWS_CAL_RSA_SIGNATURE_PKCS1_5_SHA256) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        }
        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
            return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        }
    } else if (algorithm == AWS_CAL_RSA_SIGNATURE_PSS_SHA256) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        }

        if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
            return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        }
    } else {
        return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM);
    }

    return AWS_OP_SUCCESS;
}

int s_rsa_sign(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_signing_algorithm algorithm,
    struct aws_byte_cursor digest,
    struct aws_byte_buf *out) {
    struct lc_rsa_key_pair *key_pair_impl = key_pair->impl;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key_pair_impl->key, NULL);
    if (ctx == NULL) {
        return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    if (s_set_sign_ctx_from_algo(ctx, algorithm)) {
        goto on_error;
    }

    size_t ct_len = out->capacity - out->len;
    if (EVP_PKEY_sign(ctx, out->buffer, &ct_len, digest.ptr, digest.len) <= 0) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }
    out->len += ct_len;

    EVP_PKEY_CTX_free(ctx);

    return AWS_OP_SUCCESS;

on_error:
    EVP_PKEY_CTX_free(ctx);
    return AWS_OP_ERR;
}

int s_rsa_verify(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_signing_algorithm algorithm,
    struct aws_byte_cursor digest,
    struct aws_byte_cursor signature) {
    struct lc_rsa_key_pair *key_pair_impl = key_pair->impl;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key_pair_impl->key, NULL);
    if (ctx == NULL) {
        return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    if (s_set_enc_ctx_from_algo(ctx, algorithm)) {
        goto on_error;
    }

    int ret = EVP_PKEY_verify(ctx, signature.ptr, signature.len, digest.ptr, digest.len);
    if (ret < 0) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    EVP_PKEY_CTX_free(ctx);

    return ret == 1 ? AWS_OP_SUCCESS : aws_raise_error(AWS_ERROR_CAL_SIGNATURE_VALIDATION_FAILED);

on_error:
    EVP_PKEY_CTX_free(ctx);
    return AWS_OP_ERR;
}

static struct aws_rsa_key_vtable s_rsa_key_pair_vtable = {
    .destroy = s_rsa_destroy_key,
    .encrypt = s_rsa_encrypt,
    .decrypt = s_rsa_decrypt,
    .sign = s_rsa_sign,
    .verify = s_rsa_verify,
};

struct aws_rsa_key_pair *aws_rsa_key_pair_new_generate_random(
    struct aws_allocator *allocator,
    size_t key_size_in_bits) {

    if (key_size_in_bits < AWS_CAL_RSA_MIN_SUPPORTED_KEY_SIZE ||
        key_size_in_bits > AWS_CAL_RSA_MAX_SUPPORTED_KEY_SIZE) {
        aws_raise_error(AWS_ERROR_INVALID_STATE);
        return NULL;
    }

    struct lc_rsa_key_pair *key_pair = aws_mem_calloc(allocator, 1, sizeof(struct lc_rsa_key_pair));

    aws_ref_count_init(&key_pair->base.ref_count, &key_pair->base, aws_rsa_key_pair_destroy);
    key_pair->base.impl = key_pair;
    key_pair->base.allocator = allocator;

    EVP_PKEY *pkey = NULL;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size_in_bits) <= 0) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);

    int len = i2d_RSAPrivateKey(rsa, NULL);
    if (len < 0 || aws_byte_buf_init(&key_pair->base.priv, allocator, len)) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    uint8_t *p = key_pair->base.priv.buffer;
    if (i2d_RSAPrivateKey(rsa, &p) < 0) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    len = i2d_RSAPublicKey(rsa, NULL);
    if (len < 0 || aws_byte_buf_init(&key_pair->base.pub, allocator, len)) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    p = key_pair->base.pub.buffer;
    if (i2d_RSAPublicKey(rsa, &p) < 0) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    key_pair->key = pkey;
    key_pair->base.vtable = &s_rsa_key_pair_vtable;
    key_pair->base.key_size_in_bits = key_size_in_bits;
    key_pair->base.good = true;

    RSA_free(rsa);
    EVP_PKEY_CTX_free(ctx);

    return &key_pair->base;

on_error:
    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    
    s_rsa_destroy_key(&key_pair->base);
    return NULL;
}

struct aws_rsa_key_pair *aws_rsa_key_pair_new_from_private_key_pkcs1_impl(
    struct aws_allocator *allocator,
    struct aws_byte_cursor key) {
    struct lc_rsa_key_pair *key_pair_impl = aws_mem_calloc(allocator, 1, sizeof(struct lc_rsa_key_pair));

    aws_ref_count_init(&key_pair_impl->base.ref_count, &key_pair_impl->base, aws_rsa_key_pair_destroy);
    key_pair_impl->base.impl = key_pair_impl;
    key_pair_impl->base.allocator = allocator;
    aws_byte_buf_init_copy_from_cursor(&key_pair_impl->base.priv, allocator, key);

    RSA *rsa = NULL;
    EVP_PKEY *private_key = NULL;

    if (d2i_RSAPrivateKey(&rsa, (const uint8_t **)&key.ptr, key.len) == NULL) {
        goto on_error;
    }

    private_key = EVP_PKEY_new();
    if (private_key == NULL || !EVP_PKEY_assign_RSA(private_key, rsa)) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    key_pair_impl->key = private_key;

    key_pair_impl->base.vtable = &s_rsa_key_pair_vtable;
    key_pair_impl->base.key_size_in_bits = EVP_PKEY_bits(key_pair_impl->key);
    key_pair_impl->base.good = true;

    return &key_pair_impl->base;

on_error:
    if (private_key) {
        EVP_PKEY_free(private_key);
    }

    aws_byte_buf_clean_up_secure(&key_pair_impl->base.priv);
    aws_byte_buf_clean_up_secure(&key_pair_impl->base.pub);
    s_rsa_destroy_key(&key_pair_impl->base);
    return NULL;
}

struct aws_rsa_key_pair *aws_rsa_key_pair_new_from_public_key_pkcs1_impl(
    struct aws_allocator *allocator,
    struct aws_byte_cursor key) {
    struct lc_rsa_key_pair *key_pair_impl = aws_mem_calloc(allocator, 1, sizeof(struct lc_rsa_key_pair));

    aws_ref_count_init(&key_pair_impl->base.ref_count, &key_pair_impl->base, aws_rsa_key_pair_destroy);
    key_pair_impl->base.impl = key_pair_impl;
    key_pair_impl->base.allocator = allocator;
    aws_byte_buf_init_copy_from_cursor(&key_pair_impl->base.pub, allocator, key);

    RSA *rsa = NULL;
    EVP_PKEY *public_key = NULL;

    if (d2i_RSAPublicKey(&rsa, (const uint8_t **)&key.ptr, key.len) == NULL) {
        goto on_error;
    }

    public_key = EVP_PKEY_new();
    if (public_key == NULL || !EVP_PKEY_assign_RSA(public_key, rsa)) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }
    
    key_pair_impl->key = public_key;

    key_pair_impl->base.vtable = &s_rsa_key_pair_vtable;
    key_pair_impl->base.key_size_in_bits = EVP_PKEY_bits(key_pair_impl->key);
    key_pair_impl->base.good = true;

    return &key_pair_impl->base;

on_error:
    if (public_key) {
        EVP_PKEY_free(public_key);
    }
    aws_byte_buf_clean_up_secure(&key_pair_impl->base.priv);
    aws_byte_buf_clean_up_secure(&key_pair_impl->base.pub);
    s_rsa_destroy_key(&key_pair_impl->base);
    return NULL;
}
