/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/private/symmetric_cipher_priv.h>
#include <aws/cal/symmetric_cipher.h>
#include <aws/common/device_random.h>

static bool s_check_input_size_limits(const struct aws_symmetric_cipher *cipher, const struct aws_byte_cursor *input) {
    return input->len <= INT_MAX - cipher->block_size;
}

void aws_symmetric_cipher_destroy(struct aws_symmetric_cipher *cipher) {
    if (cipher) {
        cipher->vtable->destroy(cipher);
    }
}

int aws_symmetric_cipher_encrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor to_encrypt,
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
    const struct aws_byte_cursor to_encrypt,
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

static int s_symmetric_cipher_generate_random_bytes(struct aws_byte_buf *out, size_t len, bool is_counter_mode) {
    AWS_ASSERT(len > sizeof(uint32_t));
    size_t len_to_generate = is_counter_mode ? len - sizeof(uint32_t) : len;

    if (aws_symmetric_cipher_try_ensure_sufficient_buffer_space(out, len)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    return aws_device_random_buffer_append(out, len_to_generate);
}

int aws_symmetric_cipher_generate_initialization_vector(
    size_t len_bytes,
    bool is_counter_mode,
    struct aws_byte_buf *out) {
    size_t buf_start_len = out->len;
    if (s_symmetric_cipher_generate_random_bytes(out, len_bytes, is_counter_mode) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    /* get the length we wrote back out of it */
    size_t iv_length = len_bytes;

    if (is_counter_mode) {
        /* init the counter */
        /* [nonce 1/4] [ iv 1/2 ] [ctr 1/4] */
        AWS_ASSERT(iv_length > sizeof(uint32_t));
        size_t ctr_start = iv_length - sizeof(uint32_t);
        out->len = buf_start_len + ctr_start;
        /* initialize it to a 1, but we don't know the iv size. So just write zeros til the last byte) */
        if (!aws_byte_buf_write_u8_n(out, 0, iv_length - ctr_start - 1) != AWS_OP_SUCCESS) {
            return AWS_OP_ERR;
        }

        if (!aws_byte_buf_write_u8(out, 1)) {
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

int aws_symmetric_cipher_generate_key(size_t key_len_bytes, struct aws_byte_buf *out) {
    return s_symmetric_cipher_generate_random_bytes(out, key_len_bytes, false);
}

int aws_symmetric_cipher_try_ensure_sufficient_buffer_space(struct aws_byte_buf *buf, size_t size) {
    if (buf->capacity - buf->len < size) {
        return aws_byte_buf_reserve_relative(buf, size);
    }

    return AWS_OP_SUCCESS;
}
