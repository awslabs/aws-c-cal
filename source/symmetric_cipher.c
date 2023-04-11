/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/private/symmetric_cipher_priv.h>
#include <aws/cal/symmetric_cipher.h>
#include <aws/common/device_random.h>

static bool s_check_input_size_limits(const struct aws_symmetric_cipher *cipher, const struct aws_byte_cursor *input) {
    /* libcrypto uses int, not size_t, so this is the limit.
     * For simplicity, enforce the same rules on all platforms. */
    return input->len <= INT_MAX - cipher->block_size;
}

void aws_symmetric_cipher_destroy(struct aws_symmetric_cipher *cipher) {
    if (cipher) {
        cipher->vtable->destroy(cipher);
    }
}

int aws_symmetric_cipher_encrypt(
    struct aws_symmetric_cipher *cipher,
    struct aws_byte_cursor to_encrypt,
    struct aws_byte_buf *out) {

    if (AWS_UNLIKELY(!s_check_input_size_limits(cipher, &to_encrypt))) {
        return aws_raise_error(AWS_ERROR_CAL_BUFFER_TOO_LARGE_FOR_ALGORITHM);
    }

    if (cipher->good) {
        return cipher->vtable->encrypt(cipher, to_encrypt, out);
    }

    return aws_raise_error(AWS_ERROR_INVALID_STATE);
}

int aws_symmetric_cipher_decrypt(
    struct aws_symmetric_cipher *cipher,
    struct aws_byte_cursor to_encrypt,
    struct aws_byte_buf *out) {

    if (AWS_UNLIKELY(!s_check_input_size_limits(cipher, &to_encrypt))) {
        return aws_raise_error(AWS_ERROR_CAL_BUFFER_TOO_LARGE_FOR_ALGORITHM);
    }

    if (cipher->good) {
        return cipher->vtable->decrypt(cipher, to_encrypt, out);
    }

    return aws_raise_error(AWS_ERROR_INVALID_STATE);
}

int aws_symmetric_cipher_finalize_encryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    if (cipher->good) {
        int ret_val = cipher->vtable->finalize_encryption(cipher, out);
        cipher->good = false;
        return ret_val;
    }

    return aws_raise_error(AWS_ERROR_INVALID_STATE);
}

int aws_symmetric_cipher_finalize_decryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    if (cipher->good) {
        int ret_val = cipher->vtable->finalize_decryption(cipher, out);
        cipher->good = false;
        return ret_val;
    }
    return aws_raise_error(AWS_ERROR_INVALID_STATE);
}

int aws_symmetric_cipher_reset(struct aws_symmetric_cipher *cipher) {
    int ret_val = cipher->vtable->reset(cipher);
    if (ret_val == AWS_OP_SUCCESS) {
        cipher->good = true;
    }

    return ret_val;
}

struct aws_byte_cursor aws_symmetric_cipher_get_tag(const struct aws_symmetric_cipher *cipher) {
    return aws_byte_cursor_from_buf(&cipher->tag);
}

struct aws_byte_cursor aws_symmetric_cipher_get_initialization_vector(const struct aws_symmetric_cipher *cipher) {
    return aws_byte_cursor_from_buf(&cipher->iv);
}

struct aws_byte_cursor aws_symmetric_cipher_get_key(const struct aws_symmetric_cipher *cipher) {
    return aws_byte_cursor_from_buf(&cipher->key);
}

bool aws_symmetric_cipher_is_good(const struct aws_symmetric_cipher *cipher) {
    return cipher->good;
}

void aws_symmetric_cipher_generate_initialization_vector(
    size_t len_bytes,
    bool is_counter_mode,
    struct aws_byte_buf *out) {
    size_t counter_len = is_counter_mode ? sizeof(uint32_t) : 0;
    AWS_ASSERT(len_bytes > counter_len);
    size_t rand_len = len_bytes - counter_len;

    AWS_FATAL_ASSERT(aws_device_random_buffer_append(out, rand_len) == AWS_OP_SUCCESS);

    if (is_counter_mode) {
        /* put counter at the end, initialized to 1 */
        aws_byte_buf_write_be32(out, 1);
    }
}

void aws_symmetric_cipher_generate_key(size_t key_len_bytes, struct aws_byte_buf *out) {
    AWS_FATAL_ASSERT(aws_device_random_buffer_append(out, key_len_bytes) == AWS_OP_SUCCESS);
}

int aws_symmetric_cipher_try_ensure_sufficient_buffer_space(struct aws_byte_buf *buf, size_t size) {
    if (buf->capacity - buf->len < size) {
        return aws_byte_buf_reserve_relative(buf, size);
    }

    return AWS_OP_SUCCESS;
}
