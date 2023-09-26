/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/private/rsa.h>

#include <aws/cal/cal.h>
#include <aws/common/encoding.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/evp_errors.h>
#include <openssl/rsa.h>

struct lc_rsa_key_pair {
    struct aws_rsa_key_pair base;
    EVP_PKEY *key;
};

static void s_rsa_destroy_key(void *key_pair) {
    if (key_pair == NULL) {
        return;
    }

    struct aws_rsa_key_pair *base = key_pair;
    struct lc_rsa_key_pair *impl = base->impl;

    if (impl->key != NULL) {
        EVP_PKEY_free(impl->key);
    }

    aws_rsa_key_pair_base_clean_up(base);

    aws_mem_release(base->allocator, impl);
}

/*
* Transforms evp error code into crt error code and raises it as necessary.
* All evp functions follow the same:
* >= 1 for success
* <= 0 for failure
* -2 always indicates incorrect algo for operation
*/
static int s_reinterpret_evp_error_as_crt(int evp_error, const char *function_name) {
    if (evp_error > 0) {
        return AWS_OP_SUCCESS;
    } else {
        uint32_t error = ERR_peek_error();
        if (evp_error == -2) {
            return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM);
        }

        AWS_LOGF_ERROR(AWS_LS_CAL_RSA, "Calling function %s failed with %d and extended error %lu",
            function_name, evp_error, (unsigned long)error);

        if (ERR_GET_LIB(error) == ERR_LIB_EVP) {
            switch (ERR_GET_REASON(error)) {
                case EVP_R_BUFFER_TOO_SMALL:
                    return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM);
                case EVP_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE:
                case EVP_R_UNSUPPORTED_ALGORITHM:
                    return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM);
            }
        }

        return aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);   
    }
}

int s_set_encryption_ctx_from_algo(EVP_PKEY_CTX *ctx, enum aws_rsa_encryption_algorithm algorithm) {
    if (algorithm == AWS_CAL_RSA_ENCRYPTION_PKCS1_5) {
        if (s_reinterpret_evp_error_as_crt(
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING), "EVP_PKEY_CTX_set_rsa_padding")) {
            return AWS_OP_ERR;;
        }

    } else if (algorithm == AWS_CAL_RSA_ENCRYPTION_OAEP_SHA256 || algorithm == AWS_CAL_RSA_ENCRYPTION_OAEP_SHA512) {
        if (s_reinterpret_evp_error_as_crt(
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), "EVP_PKEY_CTX_set_rsa_padding")) {
            return AWS_OP_ERR;
        }

        const EVP_MD *md = algorithm == AWS_CAL_RSA_ENCRYPTION_OAEP_SHA256 ? EVP_sha256() : EVP_sha512();
        if (s_reinterpret_evp_error_as_crt(
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md), "EVP_PKEY_CTX_set_rsa_oaep_md")) {
            return AWS_OP_ERR;
        }
    } else {
        return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM);
    }

    return AWS_OP_SUCCESS;
}

int s_rsa_encrypt(
    const struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_encryption_algorithm algorithm,
    struct aws_byte_cursor plaintext,
    struct aws_byte_buf *out) {
    struct lc_rsa_key_pair *key_pair_impl = key_pair->impl;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key_pair_impl->key, NULL);
    if (ctx == NULL) {
        return aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
    }

    if (s_reinterpret_evp_error_as_crt(
        EVP_PKEY_encrypt_init(ctx), "EVP_PKEY_encrypt_init")) {
        goto on_error;
    }

    if (s_set_encryption_ctx_from_algo(ctx, algorithm)) {
        goto on_error;
    }

    size_t ct_len = out->capacity - out->len;
    if (s_reinterpret_evp_error_as_crt(
        EVP_PKEY_encrypt(ctx, out->buffer, &ct_len, plaintext.ptr, plaintext.len), "EVP_PKEY_encrypt")) {
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
    const struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_encryption_algorithm algorithm,
    struct aws_byte_cursor ciphertext,
    struct aws_byte_buf *out) {
    struct lc_rsa_key_pair *key_pair_impl = key_pair->impl;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key_pair_impl->key, NULL);
    if (ctx == NULL) {
        return aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
    }

    if (s_reinterpret_evp_error_as_crt(
        EVP_PKEY_decrypt_init(ctx), "EVP_PKEY_decrypt_init")) {
        goto on_error;
    }

    if (s_set_encryption_ctx_from_algo(ctx, algorithm)) {
        goto on_error;
    }

    size_t ct_len = out->capacity - out->len;
    if (s_reinterpret_evp_error_as_crt(
        EVP_PKEY_decrypt(ctx, out->buffer, &ct_len, ciphertext.ptr, ciphertext.len), "EVP_PKEY_decrypt")) {
        goto on_error;
    }
    out->len += ct_len;

    EVP_PKEY_CTX_free(ctx);
    return AWS_OP_SUCCESS;

on_error:
    EVP_PKEY_CTX_free(ctx);
    return AWS_OP_ERR;
}

int s_set_signature_ctx_from_algo(EVP_PKEY_CTX *ctx, enum aws_rsa_signature_algorithm algorithm) {
    if (algorithm == AWS_CAL_RSA_SIGNATURE_PKCS1_5_SHA256) {
        if (s_reinterpret_evp_error_as_crt(
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING), "EVP_PKEY_CTX_set_rsa_padding")) {
            return AWS_OP_ERR;
        }
        if (s_reinterpret_evp_error_as_crt(
            EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()), "EVP_PKEY_CTX_set_signature_md")) {
            return AWS_OP_ERR;
        }
    } else if (algorithm == AWS_CAL_RSA_SIGNATURE_PSS_SHA256) {
        if (s_reinterpret_evp_error_as_crt(
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING), "EVP_PKEY_CTX_set_rsa_padding")) {
            return AWS_OP_ERR;
        }

        if (s_reinterpret_evp_error_as_crt(
            EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -1), "EVP_PKEY_CTX_set_rsa_pss_saltlen")) {
            return AWS_OP_ERR;
        }

        if (s_reinterpret_evp_error_as_crt(
            EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()), "EVP_PKEY_CTX_set_signature_md")) {
            return AWS_OP_ERR;
        }
    } else {
        return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM);
    }

    return AWS_OP_SUCCESS;
}

int s_rsa_sign(
    const struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_signature_algorithm algorithm,
    struct aws_byte_cursor digest,
    struct aws_byte_buf *out) {
    struct lc_rsa_key_pair *key_pair_impl = key_pair->impl;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key_pair_impl->key, NULL);
    if (ctx == NULL) {
        return aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
    }

    if (s_reinterpret_evp_error_as_crt(
        EVP_PKEY_sign_init(ctx), "EVP_PKEY_sign_init")) {
        goto on_error;
    }

    if (s_set_signature_ctx_from_algo(ctx, algorithm)) {
        goto on_error;
    }

    size_t ct_len = out->capacity - out->len;
    if (s_reinterpret_evp_error_as_crt(
        EVP_PKEY_sign(ctx, out->buffer, &ct_len, digest.ptr, digest.len), "EVP_PKEY_sign")) {
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
    const struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_signature_algorithm algorithm,
    struct aws_byte_cursor digest,
    struct aws_byte_cursor signature) {
    struct lc_rsa_key_pair *key_pair_impl = key_pair->impl;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key_pair_impl->key, NULL);
    if (ctx == NULL) {
        return aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
    }

    if (s_reinterpret_evp_error_as_crt(
        EVP_PKEY_verify_init(ctx), "EVP_PKEY_verify_init")) {
        goto on_error;
    }

    if (s_set_signature_ctx_from_algo(ctx, algorithm)) {
        goto on_error;
    }

    if (s_reinterpret_evp_error_as_crt(
        EVP_PKEY_verify(ctx, signature.ptr, signature.len, digest.ptr, digest.len), "EVP_PKEY_verify")) {
        aws_raise_error(AWS_ERROR_CAL_SIGNATURE_VALIDATION_FAILED);
        goto on_error;
    }

    EVP_PKEY_CTX_free(ctx);
    return AWS_OP_SUCCESS;

on_error:
    EVP_PKEY_CTX_free(ctx);
    return AWS_OP_ERR;
}

static struct aws_rsa_key_vtable s_rsa_key_pair_vtable = {
    .encrypt = s_rsa_encrypt,
    .decrypt = s_rsa_decrypt,
    .sign = s_rsa_sign,
    .verify = s_rsa_verify,
};

struct aws_rsa_key_pair *aws_rsa_key_pair_new_generate_random(
    struct aws_allocator *allocator,
    size_t key_size_in_bits) {

    if (is_valid_rsa_key_size(key_size_in_bits)) {
        return NULL;
    }

    struct lc_rsa_key_pair *key_pair = aws_mem_calloc(allocator, 1, sizeof(struct lc_rsa_key_pair));

    aws_ref_count_init(&key_pair->base.ref_count, &key_pair->base, s_rsa_destroy_key);
    key_pair->base.impl = key_pair;
    key_pair->base.allocator = allocator;

    EVP_PKEY *pkey = NULL;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
        goto on_error;
    }

    if (s_reinterpret_evp_error_as_crt(
        EVP_PKEY_keygen_init(ctx), "EVP_PKEY_keygen_init")) {
        goto on_error;
    }

    if (s_reinterpret_evp_error_as_crt(
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size_in_bits), "EVP_PKEY_CTX_set_rsa_keygen_bits")) {
        goto on_error;
    }

    if (s_reinterpret_evp_error_as_crt(
        EVP_PKEY_keygen(ctx, &pkey), "EVP_PKEY_keygen")) {
        goto on_error;
    }

    RSA *rsa = EVP_PKEY_get0_RSA(pkey);

    int len = i2d_RSAPrivateKey(rsa, NULL);
    AWS_FATAL_ASSERT(len > 0 && "should not fail on newly generated key");

    aws_byte_buf_init(&key_pair->base.priv, allocator, len);

    uint8_t *p = key_pair->base.priv.buffer;
    len = i2d_RSAPrivateKey(rsa, &p);
    AWS_FATAL_ASSERT(len > 0 && "should not fail on newly generated key");

    len = i2d_RSAPublicKey(rsa, NULL);
    AWS_FATAL_ASSERT(len > 0 && "should not fail on newly generated key");

    aws_byte_buf_init(&key_pair->base.pub, allocator, len);
    p = key_pair->base.pub.buffer;
    len = i2d_RSAPublicKey(rsa, &p);
    AWS_FATAL_ASSERT(len > 0 && "should not fail on newly generated key");

    key_pair->key = pkey;
    key_pair->base.vtable = &s_rsa_key_pair_vtable;
    key_pair->base.key_size_in_bits = key_size_in_bits;

    EVP_PKEY_CTX_free(ctx);

    return &key_pair->base;

on_error:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }

    s_rsa_destroy_key(&key_pair->base);
    return NULL;
}

struct aws_rsa_key_pair *aws_rsa_key_pair_new_from_private_key_pkcs1_impl(
    struct aws_allocator *allocator,
    struct aws_byte_cursor key) {
    struct lc_rsa_key_pair *key_pair_impl = aws_mem_calloc(allocator, 1, sizeof(struct lc_rsa_key_pair));

    aws_ref_count_init(&key_pair_impl->base.ref_count, &key_pair_impl->base, s_rsa_destroy_key);
    key_pair_impl->base.impl = key_pair_impl;
    key_pair_impl->base.allocator = allocator;
    aws_byte_buf_init_copy_from_cursor(&key_pair_impl->base.priv, allocator, key);

    RSA *rsa = NULL;
    EVP_PKEY *private_key = NULL;

    if (d2i_RSAPrivateKey(&rsa, (const uint8_t **)&key.ptr, key.len) == NULL) {
        goto on_error;
    }

    private_key = EVP_PKEY_new();
    if (private_key == NULL || EVP_PKEY_assign_RSA(private_key, rsa) == 0) {
        aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
        goto on_error;
    }

    key_pair_impl->key = private_key;

    key_pair_impl->base.vtable = &s_rsa_key_pair_vtable;
    key_pair_impl->base.key_size_in_bits = EVP_PKEY_bits(key_pair_impl->key);

    return &key_pair_impl->base;

on_error:
    if (private_key) {
        EVP_PKEY_free(private_key);
    }

    s_rsa_destroy_key(&key_pair_impl->base);
    return NULL;
}

struct aws_rsa_key_pair *aws_rsa_key_pair_new_from_public_key_pkcs1_impl(
    struct aws_allocator *allocator,
    struct aws_byte_cursor key) {
    struct lc_rsa_key_pair *key_pair_impl = aws_mem_calloc(allocator, 1, sizeof(struct lc_rsa_key_pair));

    aws_ref_count_init(&key_pair_impl->base.ref_count, &key_pair_impl->base, s_rsa_destroy_key);
    key_pair_impl->base.impl = key_pair_impl;
    key_pair_impl->base.allocator = allocator;
    aws_byte_buf_init_copy_from_cursor(&key_pair_impl->base.pub, allocator, key);

    RSA *rsa = NULL;
    EVP_PKEY *public_key = NULL;

    if (d2i_RSAPublicKey(&rsa, (const uint8_t **)&key.ptr, key.len) == NULL) {
        goto on_error;
    }

    public_key = EVP_PKEY_new();
    if (public_key == NULL || EVP_PKEY_assign_RSA(public_key, rsa) == 0) {
        aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
        goto on_error;
    }

    key_pair_impl->key = public_key;

    key_pair_impl->base.vtable = &s_rsa_key_pair_vtable;
    key_pair_impl->base.key_size_in_bits = EVP_PKEY_bits(key_pair_impl->key);

    return &key_pair_impl->base;

on_error:
    if (public_key) {
        EVP_PKEY_free(public_key);
    }
    s_rsa_destroy_key(&key_pair_impl->base);
    return NULL;
}
