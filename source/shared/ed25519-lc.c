/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/cal/ed25519.h>
#include <aws/cal/private/opensslcrypto_common.h>

#include <aws/common/device_random.h>
#include <aws/common/encoding.h>
#include <aws/common/ref_count.h>

#include <openssl/evp.h>

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
#if defined(OPENSSL_IS_OPENSSL) && OPENSSL_VERSION_NUMBER <= 0x10101000L
    /* ed25519 support does not exist prior to 1.1.1 */
    aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM);
    return NULL;
#else
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

    EVP_PKEY_CTX_free(ctx);
    return key_pair;

on_error:
    EVP_PKEY_CTX_free(ctx);
    aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
    return NULL;
#endif
}

struct aws_ed25519_key_pair *aws_ed25519_key_pair_acquire(struct aws_ed25519_key_pair *key_pair) {
    if (key_pair != NULL) {
        aws_ref_count_acquire(&key_pair->ref_count);
    }
    return key_pair;
}

struct aws_ed25519_key_pair *aws_ed25519_key_pair_release(struct aws_ed25519_key_pair *key_pair) {
    if (key_pair != NULL) {
        aws_ref_count_release(&key_pair->ref_count);
    }
    return NULL;
}

static struct aws_byte_cursor s_key_type_literal = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("ssh-ed25519");

int s_ed25519_openssh_encode_public_key(const struct aws_ed25519_key_pair *key_pair, struct aws_byte_buf *out) {
    if (!aws_byte_buf_write_be32(out, s_key_type_literal.len) ||
        aws_byte_buf_append(out, &s_key_type_literal) != AWS_OP_SUCCESS || !aws_byte_buf_write_be32(out, 32)) {
        return aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
    }

    size_t pub_len = 32;
    AWS_FATAL_ASSERT(out->capacity - out->len >= pub_len);
    if (EVP_PKEY_get_raw_public_key(key_pair->key, out->buffer + out->len, &pub_len) <= 0) {
        return aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
    }
    AWS_ASSERT(pub_len == 32);
    out->len += 32;

    return AWS_OP_SUCCESS;
}

/**
 * format here is b64 of the following structure
 * string "ssh-ed25519" #literal
 * string key
 * Note: string is always u32 size followed by the data. all multibyte ints are in big-endian
 */
int s_ed25519_export_public_openssh(const struct aws_ed25519_key_pair *key_pair, struct aws_byte_buf *out) {
    uint8_t key_data[4 /*id len*/ + 11 /* ssh-ed25519 literal */ + 4 /*key len*/ + 32 /* key */] = {0};

    struct aws_byte_buf key_buf = aws_byte_buf_from_empty_array(key_data, AWS_ARRAY_SIZE(key_data));

    if (s_ed25519_openssh_encode_public_key(key_pair, &key_buf)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor key_cur = aws_byte_cursor_from_buf(&key_buf);

    if (aws_base64_encode(&key_cur, out) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int s_ed25519_export_public_raw(const struct aws_ed25519_key_pair *key_pair, struct aws_byte_buf *out) {
    size_t remaining = out->capacity - out->len;
    if (remaining < 32) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    if (EVP_PKEY_get_raw_public_key(key_pair->key, out->buffer + out->len, &remaining) <= 0) {
        return aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
    }
    AWS_ASSERT(remaining == 32);
    out->len += 32;

    return AWS_OP_SUCCESS;
}

int aws_ed25519_key_pair_get_public_key(
    const struct aws_ed25519_key_pair *key_pair,
    enum aws_ed25519_key_export_format format,
    struct aws_byte_buf *out) {
    AWS_PRECONDITION(key_pair);
    AWS_PRECONDITION(aws_byte_buf_is_valid(out));

    switch (format) {
        case AWS_CAL_ED25519_KEY_EXPORT_RAW:
            return s_ed25519_export_public_raw(key_pair, out);
        case AWS_CAL_ED25519_KEY_EXPORT_OPENSSH_B64:
            return s_ed25519_export_public_openssh(key_pair, out);
        default:
            return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_KEY_FORMAT);
    }

    return AWS_OP_SUCCESS;
}

size_t aws_ed25519_key_pair_get_public_key_size(enum aws_ed25519_key_export_format format) {
    switch (format) {
        case AWS_CAL_ED25519_KEY_EXPORT_RAW:
            return 32;
        case AWS_CAL_ED25519_KEY_EXPORT_OPENSSH_B64:
            return 68;
        default:
            return 0;
    }
}

static struct aws_byte_cursor s_private_magic = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("openssh-key-v1");
static struct aws_byte_cursor s_private_none_literal = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL("none");

/**
 * Openssl only added helpers for this format in 3.0 so we are out of luck with lc and boringssl.
 * Hence lets just implement export ourselves.
 * Some of the spec features (encryption, comments) are not supported.
 * High level format is:
 * string "openssh-key-v1\0" #literal
 * string cipher #literal none since we dont support enc
 * string kdf #literal none since we dont support enc
 * string kdf options #empty since we dont support enc
 * u32 num keys
 * string public key #openssh encoded version
 * string private key blob
 * - u32 check #random num
 * - u32 check #same check repeated
 * - string "ssh-ed25519" #literal
 * - string raw pub key
 * - string raw priv key
 * - string comment # no comment for now
 * - padding to 8 bytes # just add bytes 1, 2, 3, ... until priv block is divisible by 8
 * Note: string is always u32 size followed by the data. all multibyte ints are in big-endian
 */
int s_ed25519_export_private_openssh(const struct aws_ed25519_key_pair *key_pair, struct aws_byte_buf *out) {

    struct aws_byte_buf key_buf;
    aws_byte_buf_init(&key_buf, key_pair->allocator, 256);

    /* magic */
    if (aws_byte_buf_append(&key_buf, &s_private_magic) != AWS_OP_SUCCESS || !aws_byte_buf_write_u8(&key_buf, 0)) {
        goto on_error;
    }

    /* cipher name (we dont support it now, but still need to write out 0) */
    if (!aws_byte_buf_write_be32(&key_buf, 4) ||
        aws_byte_buf_append(&key_buf, &s_private_none_literal) != AWS_OP_SUCCESS) {
        goto on_error;
    }

    /* kdf name (we dont support it now, but still need to write out 0) */
    if (!aws_byte_buf_write_be32(&key_buf, 4) ||
        aws_byte_buf_append(&key_buf, &s_private_none_literal) != AWS_OP_SUCCESS) {
        goto on_error;
    }

    /* kdf options (we dont support it now, but still need to write out 0) */
    if (!aws_byte_buf_write_be32(&key_buf, 0)) {
        goto on_error;
    }

    /* number of keys */
    if (!aws_byte_buf_write_be32(&key_buf, 1)) {
        goto on_error;
    }

    /* encoded public key */
    const size_t pub_encoded_len = 4 /*id len*/ + 11 /* ssh-ed25519 literal */ + 4 /*key len*/ + 32 /* key */;
    if (!aws_byte_buf_write_be32(&key_buf, pub_encoded_len) ||
        s_ed25519_openssh_encode_public_key(key_pair, &key_buf) != AWS_OP_SUCCESS) {
        goto on_error;
    }

    size_t priv_block_len = 4 +                          /* check1 */
                            4 +                          /* check2 */
                            4 + s_key_type_literal.len + /* key type string */
                            4 + 32 +                     /* public key */
                            4 + 64 +                     /* private key (includes public) */
                            4 + 0;                       /* comment (0, since comment not currently supported) */

    /* pad block to the next multiple of 8 */
    size_t priv_block_padded_len = (priv_block_len + 7) & ~7;

    if (!aws_byte_buf_write_be32(&key_buf, priv_block_padded_len)) {
        goto on_error;
    }

    uint32_t check = 0;
    if (aws_device_random_u32(&check) != AWS_OP_SUCCESS) {
        goto on_error;
    }

    /* check (and yeah its written twice on purpose) */
    if (!aws_byte_buf_write_be32(&key_buf, check) || !aws_byte_buf_write_be32(&key_buf, check)) {
        goto on_error;
    }

    /* key type */
    if (!aws_byte_buf_write_be32(&key_buf, s_key_type_literal.len) ||
        aws_byte_buf_append(&key_buf, &s_key_type_literal) != AWS_OP_SUCCESS) {
        goto on_error;
    }

    /* public key (raw) */
    if (!aws_byte_buf_write_be32(&key_buf, 32) ||
        aws_ed25519_key_pair_get_public_key(key_pair, AWS_CAL_ED25519_KEY_EXPORT_RAW, &key_buf) != AWS_OP_SUCCESS) {
        goto on_error;
    }

    /* private key (raw) */
    if (!aws_byte_buf_write_be32(&key_buf, 64) ||
        aws_ed25519_key_pair_get_private_key(key_pair, AWS_CAL_ED25519_KEY_EXPORT_RAW, &key_buf) != AWS_OP_SUCCESS) {
        goto on_error;
    }

    /* comment */
    if (!aws_byte_buf_write_be32(&key_buf, 0)) {
        goto on_error;
    }

    /* padding */
    for (uint8_t i = 1; i < (priv_block_padded_len - priv_block_len + 1); ++i) {
        if (!aws_byte_buf_write_u8(&key_buf, i)) {
            goto on_error;
        }
    }

    struct aws_byte_cursor key_cur = aws_byte_cursor_from_buf(&key_buf);

    if (aws_base64_encode(&key_cur, out) != AWS_OP_SUCCESS) {
        aws_byte_buf_clean_up(&key_buf);
        return AWS_OP_ERR;
    }

    aws_byte_buf_clean_up(&key_buf);
    return AWS_OP_SUCCESS;

on_error:
    aws_byte_buf_clean_up(&key_buf);
    return aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
}

int s_ed25519_export_private_raw(const struct aws_ed25519_key_pair *key_pair, struct aws_byte_buf *out) {
    size_t remaining = out->capacity - out->len;
    if (remaining < 64) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    if (EVP_PKEY_get_raw_private_key(key_pair->key, out->buffer + out->len, &remaining) <= 0) {
        return aws_raise_error(AWS_ERROR_CAL_CRYPTO_OPERATION_FAILED);
    }

    AWS_LOGF_DEBUG(0, "remaining size %zu", remaining);

    AWS_ASSERT(remaining == 64);
    out->len += 64;

    return AWS_OP_SUCCESS;
}

int aws_ed25519_key_pair_get_private_key(
    const struct aws_ed25519_key_pair *key_pair,
    enum aws_ed25519_key_export_format format,
    struct aws_byte_buf *out) {
    AWS_PRECONDITION(key_pair);
    AWS_PRECONDITION(aws_byte_buf_is_valid(out));

    switch (format) {
        case AWS_CAL_ED25519_KEY_EXPORT_RAW:
            return s_ed25519_export_private_raw(key_pair, out);
        case AWS_CAL_ED25519_KEY_EXPORT_OPENSSH_B64:
            return s_ed25519_export_private_openssh(key_pair, out);
        default:
            return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_KEY_FORMAT);
    }

    return AWS_OP_SUCCESS;
}

size_t aws_ed25519_key_pair_get_private_key_size(enum aws_ed25519_key_export_format format) {
    switch (format) {
        case AWS_CAL_ED25519_KEY_EXPORT_RAW:
            return 64;
        case AWS_CAL_ED25519_KEY_EXPORT_OPENSSH_B64:
            return 312;
        default:
            return 0;
    }
}
