/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/cal/symmetric_cipher.h>

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonSymmetricKeywrap.h>

#include <aws/cal/private/darwin/common_cryptor_spi.h>

#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED)
#    if defined(__MAC_10_13) && (__MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_10_13)
#        define MAC_13_AVAILABLE 1
#    elif defined(__MAC_10_14_4) && (__MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_10_14_4)
#        define MAC_14_4_AVAILABLE 1
#    endif
#endif

/* for OSX < 10.10 compatibility */
typedef int32_t CCStatus;
typedef int32_t CCCryptorStatus;

struct cc_aes_cipher {
    struct aws_symmetric_cipher cipher_base;
    struct _CCCryptor *encryptor_handle;
    struct _CCCryptor *decryptor_handle;
};

static int s_encrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *input,
    struct aws_byte_buf *out) {
    size_t required_buffer_space = input->len + cipher->block_size - 1;

    size_t available_write_space = out->capacity - out->len;
    if (available_write_space < required_buffer_space) {
        if (aws_byte_buf_reserve_relative(out, required_buffer_space) != AWS_OP_SUCCESS) {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    available_write_space = out->capacity - out->len;
    struct cc_aes_cipher *cc_cipher = cipher->impl;

    size_t len_written = 0;
    CCStatus status = CCCryptorUpdate(
        cc_cipher->encryptor_handle,
        input->ptr,
        input->len,
        out->buffer + out->len,
        available_write_space,
        &len_written);

    if (status != kCCSuccess) {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += len_written;
    return AWS_OP_SUCCESS;
}

static int s_decrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *input,
    struct aws_byte_buf *out) {
    size_t required_buffer_space = input->len + cipher->block_size - 1;

    size_t available_write_space = out->capacity - out->len;
    if (available_write_space < required_buffer_space) {
        if (aws_byte_buf_reserve_relative(out, required_buffer_space) != AWS_OP_SUCCESS) {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    available_write_space = out->capacity - out->len;
    struct cc_aes_cipher *cc_cipher = cipher->impl;

    size_t len_written = 0;
    CCStatus status = CCCryptorUpdate(
        cc_cipher->decryptor_handle,
        input->ptr,
        input->len,
        out->buffer + out->len,
        available_write_space,
        &len_written);

    if (status != kCCSuccess) {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += len_written;
    return AWS_OP_SUCCESS;
}

static int s_finalize_encryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    size_t required_buffer_space = cipher->block_size;
    size_t len_written = 0;

    size_t available_write_space = out->capacity - out->len;
    if (available_write_space < required_buffer_space) {
        if (aws_byte_buf_reserve_relative(out, required_buffer_space) != AWS_OP_SUCCESS) {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    available_write_space = out->capacity - out->len;
    struct cc_aes_cipher *cc_cipher = cipher->impl;

    CCStatus status =
        CCCryptorFinal(cc_cipher->encryptor_handle, out->buffer + out->len, available_write_space, &len_written);

    if (status != kCCSuccess) {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += len_written;
    return AWS_OP_SUCCESS;
}

static int s_finalize_decryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    size_t required_buffer_space = cipher->block_size;
    size_t len_written = 0;

    size_t available_write_space = out->capacity - out->len;
    if (available_write_space < required_buffer_space) {
        if (aws_byte_buf_reserve_relative(out, required_buffer_space - available_write_space) != AWS_OP_SUCCESS) {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    struct cc_aes_cipher *cc_cipher = cipher->impl;

    CCStatus status =
        CCCryptorFinal(cc_cipher->decryptor_handle, out->buffer + out->len, available_write_space, &len_written);

    if (status != kCCSuccess) {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += len_written;
    return AWS_OP_SUCCESS;
}

static void s_destroy(struct aws_symmetric_cipher *cipher) {
    aws_byte_buf_clean_up_secure(&cipher->key);
    aws_byte_buf_clean_up_secure(&cipher->iv);

    struct cc_aes_cipher *cc_cipher = cipher->impl;

    if (cc_cipher->encryptor_handle) {
        CCCryptorRelease(cc_cipher->encryptor_handle);
    }

    if (cc_cipher->decryptor_handle) {
        CCCryptorRelease(cc_cipher->decryptor_handle);
    }

    aws_mem_release(cipher->allocator, cc_cipher);
}

static struct aws_symmetric_cipher_vtable s_aes_cbc_vtable = {
    .finalize_decryption = s_finalize_decryption,
    .finalize_encryption = s_finalize_encryption,
    .decrypt = s_decrypt,
    .encrypt = s_encrypt,
    .provider = "CommonCrypto",
    .alg_name = "AES-CBC 256",
    .destroy = s_destroy,
};

struct aws_symmetric_cipher *aws_aes_cbc_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv) {
    struct cc_aes_cipher *cc_cipher = aws_mem_calloc(allocator, 1, sizeof(struct cc_aes_cipher));
    cc_cipher->cipher_base.allocator = allocator;
    cc_cipher->cipher_base.block_size = AWS_AES_256_CIPHER_BLOCK_SIZE;
    cc_cipher->cipher_base.impl = cc_cipher;
    cc_cipher->cipher_base.vtable = &s_aes_cbc_vtable;

    if (key) {
        aws_byte_buf_init_copy_from_cursor(&cc_cipher->cipher_base.key, allocator, *key);
    } else {
        aws_byte_buf_init(&cc_cipher->cipher_base.key, allocator, AWS_AES_256_KEY_BYTE_LEN);
        aws_symmetric_cipher_generate_key(AWS_AES_256_KEY_BYTE_LEN, &cc_cipher->cipher_base.key);
    }

    if (iv) {
        aws_byte_buf_init_copy_from_cursor(&cc_cipher->cipher_base.iv, allocator, *iv);
    } else {
        aws_byte_buf_init(&cc_cipher->cipher_base.iv, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
        aws_symmetric_cipher_generate_initialization_vector(
            AWS_AES_256_CIPHER_BLOCK_SIZE, false, &cc_cipher->cipher_base.iv);
    }

    CCCryptorStatus status = CCCryptorCreateWithMode(
        kCCEncrypt,
        kCCModeCBC,
        kCCAlgorithmAES,
        ccPKCS7Padding,
        cc_cipher->cipher_base.iv.buffer,
        cc_cipher->cipher_base.key.buffer,
        cc_cipher->cipher_base.key.len,
        NULL,
        0,
        0,
        0,
        &cc_cipher->encryptor_handle);

    status |= CCCryptorCreateWithMode(
        kCCDecrypt,
        kCCModeCBC,
        kCCAlgorithmAES,
        ccPKCS7Padding,
        cc_cipher->cipher_base.iv.buffer,
        cc_cipher->cipher_base.key.buffer,
        cc_cipher->cipher_base.key.len,
        NULL,
        0,
        0,
        0,
        &cc_cipher->decryptor_handle);

    if (status != kCCSuccess) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        s_destroy(&cc_cipher->cipher_base);
    }

    cc_cipher->cipher_base.good = true;
    cc_cipher->cipher_base.key_length_bits = AWS_AES_256_KEY_BIT_LEN;

    return &cc_cipher->cipher_base;
}

static struct aws_symmetric_cipher_vtable s_aes_ctr_vtable = {
    .finalize_decryption = s_finalize_decryption,
    .finalize_encryption = s_finalize_encryption,
    .decrypt = s_decrypt,
    .encrypt = s_encrypt,
    .provider = "CommonCrypto",
    .alg_name = "AES-CTR 256",
    .destroy = s_destroy,
};

struct aws_symmetric_cipher *aws_aes_ctr_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv) {
    struct cc_aes_cipher *cc_cipher = aws_mem_calloc(allocator, 1, sizeof(struct cc_aes_cipher));
    cc_cipher->cipher_base.allocator = allocator;
    cc_cipher->cipher_base.block_size = AWS_AES_256_CIPHER_BLOCK_SIZE;
    cc_cipher->cipher_base.impl = cc_cipher;
    cc_cipher->cipher_base.vtable = &s_aes_ctr_vtable;

    if (key) {
        aws_byte_buf_init_copy_from_cursor(&cc_cipher->cipher_base.key, allocator, *key);
    } else {
        aws_byte_buf_init(&cc_cipher->cipher_base.key, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
        aws_symmetric_cipher_generate_key(AWS_AES_256_KEY_BYTE_LEN, &cc_cipher->cipher_base.key);
    }

    if (iv) {
        aws_byte_buf_init_copy_from_cursor(&cc_cipher->cipher_base.iv, allocator, *iv);
    } else {
        aws_byte_buf_init(&cc_cipher->cipher_base.iv, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
        aws_symmetric_cipher_generate_initialization_vector(
            AWS_AES_256_CIPHER_BLOCK_SIZE, true, &cc_cipher->cipher_base.iv);
    }

    CCCryptorStatus status = CCCryptorCreateWithMode(
        kCCEncrypt,
        kCCModeCTR,
        kCCAlgorithmAES,
        ccPKCS7Padding,
        cc_cipher->cipher_base.iv.buffer,
        cc_cipher->cipher_base.key.buffer,
        cc_cipher->cipher_base.key.len,
        NULL,
        0,
        0,
        kCCModeOptionCTR_BE,
        &cc_cipher->encryptor_handle);

    status |= CCCryptorCreateWithMode(
        kCCDecrypt,
        kCCModeCTR,
        kCCAlgorithmAES,
        ccPKCS7Padding,
        cc_cipher->cipher_base.iv.buffer,
        cc_cipher->cipher_base.key.buffer,
        cc_cipher->cipher_base.key.len,
        NULL,
        0,
        0,
        kCCModeOptionCTR_BE,
        &cc_cipher->decryptor_handle);

    if (status != kCCSuccess) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        s_destroy(&cc_cipher->cipher_base);
    }

    cc_cipher->cipher_base.good = true;
    cc_cipher->cipher_base.key_length_bits = AWS_AES_256_KEY_BIT_LEN;

    return &cc_cipher->cipher_base;
}

static int s_finalize_gcm_encryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    if (cipher->encryption_tag.len) {
        aws_byte_buf_clean_up_secure(&cipher->encryption_tag);
    }

    aws_byte_buf_init(&cipher->encryption_tag, cipher->allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
    struct cc_aes_cipher *cc_cipher = cipher->impl;

    CCStatus status;
    size_t tag_length = AWS_AES_256_CIPHER_BLOCK_SIZE;
    /* Note that CCCryptorGCMFinal is deprecated in Mac 10.13. It also doesn't compare the tag with expected tag
     * https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60118.1.1/include/CommonCryptorSPI.h.auto.html
     */
#ifdef MAC_13_AVAILABLE
    status = CCCryptorGCMFinalize(cc_cipher->encryptor_handle, cipher->encryption_tag.buffer, tag_length);
#else
    status = CCCryptorGCMFinal(cc_cipher->encryptor_handle, cipher->encryption_tag.buffer, &tag_length);
#endif

    if (status != kCCSuccess) {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    cipher->encryption_tag.len = tag_length;
    return AWS_OP_SUCCESS;
}

static int s_finalize_gcm_decryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    if (cipher->decryption_tag.len) {
        aws_byte_buf_clean_up_secure(&cipher->decryption_tag);
    }

    aws_byte_buf_init(&cipher->decryption_tag, cipher->allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
    struct cc_aes_cipher *cc_cipher = cipher->impl;

    CCStatus status;
    size_t tag_length = AWS_AES_256_CIPHER_BLOCK_SIZE;
    /* Note that CCCryptorGCMFinal is deprecated in Mac 10.13. It also doesn't compare the tag with expected tag
     * https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60118.1.1/include/CommonCryptorSPI.h.auto.html
     */
#ifdef MAC_13_AVAILABLE
    status = CCCryptorGCMFinalize(cc_cipher->decryptor_handle, cipher->decryption_tag.buffer, tag_length);
#else
    status = CCCryptorGCMFinal(cc_cipher->decryptor_handle, cipher->decryption_tag.buffer, &tag_length);
#endif

    if (status != kCCSuccess) {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    cipher->decryption_tag.len = tag_length;
    return AWS_OP_SUCCESS;
}

static struct aws_symmetric_cipher_vtable s_aes_gcm_vtable = {
    .finalize_decryption = s_finalize_gcm_decryption,
    .finalize_encryption = s_finalize_gcm_encryption,
    .decrypt = s_decrypt,
    .encrypt = s_encrypt,
    .provider = "CommonCrypto",
    .alg_name = "AES-GCM 256",
    .destroy = s_destroy,
};

struct aws_symmetric_cipher *aws_aes_gcm_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv,
    const struct aws_byte_cursor *aad) {
    struct cc_aes_cipher *cc_cipher = aws_mem_calloc(allocator, 1, sizeof(struct cc_aes_cipher));
    cc_cipher->cipher_base.allocator = allocator;
    cc_cipher->cipher_base.block_size = AWS_AES_256_CIPHER_BLOCK_SIZE;
    cc_cipher->cipher_base.impl = cc_cipher;
    cc_cipher->cipher_base.vtable = &s_aes_gcm_vtable;

    if (key) {
        aws_byte_buf_init_copy_from_cursor(&cc_cipher->cipher_base.key, allocator, *key);
    } else {
        aws_byte_buf_init(&cc_cipher->cipher_base.key, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
        aws_symmetric_cipher_generate_key(AWS_AES_256_KEY_BYTE_LEN, &cc_cipher->cipher_base.key);
    }

    if (iv) {
        aws_byte_buf_init_copy_from_cursor(&cc_cipher->cipher_base.iv, allocator, *iv);
    } else {
        /* GCM IVs are kind of a hidden implementation detail. 4 are reserved by the system for long running stream
         * blocks. */
        /* This is because there's a GMAC attached to the cipher (that's what tag is for). For that to work, it has
         * to control the actual counter */
        aws_byte_buf_init(&cc_cipher->cipher_base.iv, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE - 4);
        aws_symmetric_cipher_generate_initialization_vector(
            AWS_AES_256_CIPHER_BLOCK_SIZE - 4, false, &cc_cipher->cipher_base.iv);
    }

    if (aad && aad->len) {
        aws_byte_buf_init_copy_from_cursor(&cc_cipher->cipher_base.aad, allocator, *aad);
    }

    CCCryptorStatus status = CCCryptorCreateWithMode(
        kCCEncrypt,
        kCCModeGCM,
        kCCAlgorithmAES,
        ccPKCS7Padding,
        NULL,
        cc_cipher->cipher_base.key.buffer,
        cc_cipher->cipher_base.key.len,
        NULL,
        0,
        0,
        kCCModeOptionCTR_BE,
        &cc_cipher->encryptor_handle);

#ifdef MAC_13_AVAILABLE
    status |=
        CCCryptorGCMSetIV(cc_cipher->encryptor_handle, cc_cipher->cipher_base.iv.buffer, cc_cipher->cipher_base.iv.len);
#else
    status |=
        CCCryptorGCMAddIV(cc_cipher->encryptor_handle, cc_cipher->cipher_base.iv.buffer, cc_cipher->cipher_base.iv.len);
#endif
    if (aad && aad->len) {
        status |= CCCryptorGCMAddAAD(
            cc_cipher->encryptor_handle, cc_cipher->cipher_base.aad.buffer, cc_cipher->cipher_base.aad.len);
    }

    status |= CCCryptorCreateWithMode(
        kCCDecrypt,
        kCCModeGCM,
        kCCAlgorithmAES,
        ccPKCS7Padding,
        NULL,
        cc_cipher->cipher_base.key.buffer,
        cc_cipher->cipher_base.key.len,
        NULL,
        0,
        0,
        kCCModeOptionCTR_BE,
        &cc_cipher->decryptor_handle);

#ifdef MAC_13_AVAILABLE
    status |=
        CCCryptorGCMSetIV(cc_cipher->decryptor_handle, cc_cipher->cipher_base.iv.buffer, cc_cipher->cipher_base.iv.len);
#else
    status |=
        CCCryptorGCMAddIV(cc_cipher->decryptor_handle, cc_cipher->cipher_base.iv.buffer, cc_cipher->cipher_base.iv.len);
#endif
    if (aad && aad->len) {
        status |= CCCryptorGCMAddAAD(
            cc_cipher->decryptor_handle, cc_cipher->cipher_base.aad.buffer, cc_cipher->cipher_base.aad.len);
    }

    if (status != kCCSuccess) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        s_destroy(&cc_cipher->cipher_base);
    }

    cc_cipher->cipher_base.good = true;
    cc_cipher->cipher_base.key_length_bits = AWS_AES_256_KEY_BIT_LEN;

    return &cc_cipher->cipher_base;
}
