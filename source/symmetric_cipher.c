/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/symmetric_cipher.h>
#include <aws/common/device_random.h>

void aws_symmetric_cipher_destroy(struct aws_symmetric_cipher *cipher) {
    cipher->vtable->destroy(cipher);
}

int aws_symmetric_cipher_encrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_encrypt,
    struct aws_byte_buf *out) {
    if (cipher->good) {
        return cipher->vtable->encrypt(cipher, to_encrypt, out);
    }

    return aws_raise_error(AWS_ERROR_INVALID_STATE);
}

int aws_symmetric_cipher_decrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_encrypt,
    struct aws_byte_buf *out) {
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

int aws_symmetric_cipher_get_tag(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    struct aws_byte_cursor tag_cur = aws_byte_cursor_from_buf(&cipher->tag);
    return aws_byte_buf_append_dynamic(out, &tag_cur);
}

int aws_symmetric_cipher_get_initialization_vector(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    struct aws_byte_cursor iv_cur = aws_byte_cursor_from_buf(&cipher->iv);
    return aws_byte_buf_append_dynamic(out, &iv_cur);
}

int aws_symmetric_cipher_get_key(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    struct aws_byte_cursor key_cur = aws_byte_cursor_from_buf(&cipher->key);
    return aws_byte_buf_append_dynamic(out, &key_cur);
}

static int s_symmetric_cipher_generate_random_bytes(struct aws_byte_buf *out, size_t len, bool is_counter_mode) {
    size_t len_to_generate = is_counter_mode ? (3 * len) / 4 : len;

    if ((out->capacity - out->len) < len) {
        if (aws_byte_buf_reserve_relative(out, len)) {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    struct aws_byte_buf output_cpy = *out;
    /* the device random function below fills the buffer, so clamp it down to the size we need. */
    output_cpy.capacity = output_cpy.len + len_to_generate;

    if (aws_device_random_buffer(&output_cpy) != AWS_OP_SUCCESS) {
        return AWS_OP_ERR;
    }

    out->len += len_to_generate;
    return AWS_OP_SUCCESS;
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
        size_t ctr_start = (iv_length / 2) + (iv_length / 4);
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