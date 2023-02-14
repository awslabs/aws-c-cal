/**
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
* SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/cal/symmetric_cipher.h>

#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonSymmetricKeywrap.h>
#include <Availability.h>

/* for OSX < 10.10 compatibility */
typedef int32_t CCStatus;
typedef int32_t CCCryptorStatus;

struct cc_aes_cipher {
    struct aws_symmetric_cipher cipher_base;
    struct _CCCryptor *encryptor_handle;
    struct _CCCryptor *decryptor_handle;
};

static int s_encrypt(struct aws_symmetric_cipher *cipher, const struct aws_byte_cursor *input, struct aws_byte_buf *out) {
    size_t required_buffer_space = input->len + cipher->block_size - 1;

    size_t available_write_space = out->capacity - out->len;
    if (available_write_space < required_buffer_space)
    {
        if (aws_byte_buf_reserve_relative(out, required_buffer_space - available_write_space) != AWS_OP_SUCCESS)
        {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    struct cc_aes_cipher* cc_cipher = cipher->impl;

    size_t len_written = 0;
    CCStatus status = CCCryptorUpdate(cc_cipher->encryptor_handle, input->ptr, input->len, out->buffer + out->len, available_write_space, &len_written);

    if (status != kCCSuccess)
    {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += len_written;
    return AWS_OP_SUCCESS;
}

static int s_decrypt(struct aws_symmetric_cipher *cipher, const struct aws_byte_cursor *input, struct aws_byte_buf *out) {
    size_t required_buffer_space = input->len + cipher->block_size - 1;

    size_t available_write_space = out->capacity - out->len;
    if (available_write_space < required_buffer_space)
    {
        if (aws_byte_buf_reserve_relative(out, required_buffer_space - available_write_space) != AWS_OP_SUCCESS)
        {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    struct cc_aes_cipher* cc_cipher = cipher->impl;

    size_t len_written = 0;
    CCStatus status = CCCryptorUpdate(cc_cipher->decryptor_handle, input->ptr, input->len, out->buffer + out->len, available_write_space, &len_written);

    if (status != kCCSuccess)
    {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += len_written;
    return AWS_OP_SUCCESS;
}

static int s_finalize_encryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out)
{
    size_t required_buffer_space = cipher->block_size;
    size_t len_written = 0;

    size_t available_write_space = out->capacity - out->len;
    if (available_write_space < required_buffer_space)
    {
        if (aws_byte_buf_reserve_relative(out, required_buffer_space - available_write_space) != AWS_OP_SUCCESS)
        {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    struct cc_aes_cipher* cc_cipher = cipher->impl;

    CCStatus status = CCCryptorFinal(cc_cipher->encryptor_handle, out->buffer + out->len, available_write_space, &len_written);

    if (status != kCCSuccess)
    {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += len_written;
    return AWS_OP_SUCCESS;
}

static int s_finalize_decryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out)
{
    size_t required_buffer_space = cipher->block_size;
    size_t len_written = 0;

    size_t available_write_space = out->capacity - out->len;
    if (available_write_space < required_buffer_space)
    {
        if (aws_byte_buf_reserve_relative(out, required_buffer_space - available_write_space) != AWS_OP_SUCCESS)
        {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    struct cc_aes_cipher* cc_cipher = cipher->impl;

    CCStatus status = CCCryptorFinal(cc_cipher->decryptor_handle, out->buffer + out->len, available_write_space, &len_written);

    if (status != kCCSuccess)
    {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += len_written;
    return AWS_OP_SUCCESS;
}
