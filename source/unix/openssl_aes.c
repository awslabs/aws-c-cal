/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/symmetric_cipher.h>

#include <openssl/evp.h>

struct openssl_aes_cipher {
    struct aws_symmetric_cipher cipher_base;
    EVP_CIPHER_CTX *encryptor_ctx;
    EVP_CIPHER_CTX *decryptor_ctx;
};

static int s_encrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *input,
    struct aws_byte_buf *out) {
    size_t required_buffer_space = input->len + cipher->block_size;
    size_t available_write_space = out->capacity - out->len;

    if (available_write_space < required_buffer_space) {
        if (aws_byte_buf_reserve_relative(out, required_buffer_space) != AWS_OP_SUCCESS) {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    available_write_space = out->capacity - out->len;
    struct openssl_aes_cipher *openssl_cipher = cipher->impl;

    int len_written = (int)(available_write_space);
    if (!EVP_EncryptUpdate(
            openssl_cipher->encryptor_ctx, out->buffer + out->len, &len_written, input->ptr, (int)input->len)) {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += len_written;
    return AWS_OP_SUCCESS;
}

static int s_finalize_encryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    struct openssl_aes_cipher *openssl_cipher = cipher->impl;

    size_t required_buffer_space = cipher->block_size;
    size_t available_write_space = out->capacity - out->len;

    if (available_write_space < required_buffer_space) {
        if (aws_byte_buf_reserve_relative(out, required_buffer_space) != AWS_OP_SUCCESS) {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    int len_written = (int)(out->capacity - out->len);
    if (!EVP_EncryptFinal_ex(openssl_cipher->encryptor_ctx, out->buffer + out->len, &len_written)) {
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
    struct openssl_aes_cipher *openssl_cipher = cipher->impl;

    size_t required_buffer_space = input->len + cipher->block_size;
    size_t available_write_space = out->capacity - out->len;

    if (available_write_space < required_buffer_space) {
        if (aws_byte_buf_reserve_relative(out, required_buffer_space) != AWS_OP_SUCCESS) {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    available_write_space = out->capacity - out->len;

    int len_written = (int)available_write_space;
    if (!EVP_DecryptUpdate(
            openssl_cipher->decryptor_ctx, out->buffer + out->len, &len_written, input->ptr, (int)input->len)) {
        cipher->good = false;

        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += len_written;
    return AWS_OP_SUCCESS;
}

static int s_finalize_decryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    struct openssl_aes_cipher *openssl_cipher = cipher->impl;

    size_t required_buffer_space = cipher->block_size;
    size_t available_write_space = out->capacity - out->len;

    if (available_write_space < required_buffer_space) {
        if (aws_byte_buf_reserve_relative(out, required_buffer_space) != AWS_OP_SUCCESS) {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    available_write_space = out->capacity - out->len;

    int len_written = (int)available_write_space;
    if (!EVP_DecryptFinal_ex(openssl_cipher->decryptor_ctx, out->buffer + out->len, &len_written)) {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += len_written;
    return AWS_OP_SUCCESS;
}

static void s_destroy(struct aws_symmetric_cipher *cipher) {
    struct openssl_aes_cipher *openssl_cipher = cipher->impl;

    if (openssl_cipher->encryptor_ctx) {
        EVP_CIPHER_CTX_free(openssl_cipher->encryptor_ctx);
    }

    if (openssl_cipher->decryptor_ctx) {
        EVP_CIPHER_CTX_free(openssl_cipher->decryptor_ctx);
    }

    aws_byte_buf_clean_up_secure(&cipher->key);
    aws_byte_buf_clean_up_secure(&cipher->iv);

    if (cipher->tag.buffer) {
        aws_byte_buf_clean_up_secure(&cipher->tag);
    }

    if (cipher->aad.buffer) {
        aws_byte_buf_clean_up_secure(&cipher->aad);
    }

    aws_mem_release(cipher->allocator, openssl_cipher);
}

static int s_reset(struct aws_symmetric_cipher *cipher) {
    struct openssl_aes_cipher *openssl_cipher = cipher->impl;

    if (!EVP_CIPHER_CTX_reset(openssl_cipher->encryptor_ctx)) {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    if (!EVP_CIPHER_CTX_reset(openssl_cipher->decryptor_ctx)) {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    cipher->good = true;
    return AWS_OP_SUCCESS;
}

static int s_init_cbc_cipher_materials(struct aws_symmetric_cipher *cipher) {
    struct openssl_aes_cipher *openssl_cipher = cipher->impl;

    if (!EVP_EncryptInit_ex(
            openssl_cipher->encryptor_ctx,
            EVP_aes_256_cbc(),
            NULL,
            openssl_cipher->cipher_base.key.buffer,
            openssl_cipher->cipher_base.iv.buffer) ||
        !EVP_DecryptInit_ex(
            openssl_cipher->decryptor_ctx,
            EVP_aes_256_cbc(),
            NULL,
            openssl_cipher->cipher_base.key.buffer,
            openssl_cipher->cipher_base.iv.buffer)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    return AWS_OP_SUCCESS;
}

static int s_reset_cbc_cipher_materials(struct aws_symmetric_cipher *cipher) {
    int ret_val = s_reset(cipher);

    if (ret_val == AWS_OP_SUCCESS) {
        return s_init_cbc_cipher_materials(cipher);
    }

    return ret_val;
}

static struct aws_symmetric_cipher_vtable s_cbc_vtable = {
    .alg_name = "AES-CBC 256",
    .provider = "OpenSSL Compatible LibCrypto",
    .destroy = s_destroy,
    .reset = s_reset_cbc_cipher_materials,
    .decrypt = s_decrypt,
    .encrypt = s_encrypt,
    .finalize_decryption = s_finalize_decryption,
    .finalize_encryption = s_finalize_encryption,
};

struct aws_symmetric_cipher *aws_aes_cbc_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv) {
    struct openssl_aes_cipher *cipher = aws_mem_calloc(allocator, 1, sizeof(struct openssl_aes_cipher));

    cipher->cipher_base.allocator = allocator;
    cipher->cipher_base.block_size = AWS_AES_256_CIPHER_BLOCK_SIZE;
    cipher->cipher_base.key_length_bits = AWS_AES_256_KEY_BIT_LEN;
    cipher->cipher_base.vtable = &s_cbc_vtable;
    cipher->cipher_base.impl = cipher;

    if (key) {
        aws_byte_buf_init_copy_from_cursor(&cipher->cipher_base.key, allocator, *key);
    } else {
        aws_byte_buf_init(&cipher->cipher_base.key, allocator, AWS_AES_256_KEY_BYTE_LEN);
        aws_symmetric_cipher_generate_key(AWS_AES_256_KEY_BYTE_LEN, &cipher->cipher_base.key);
    }

    if (iv) {
        aws_byte_buf_init_copy_from_cursor(&cipher->cipher_base.iv, allocator, *iv);
    } else {
        aws_byte_buf_init(&cipher->cipher_base.iv, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
        aws_symmetric_cipher_generate_initialization_vector(
            AWS_AES_256_CIPHER_BLOCK_SIZE, false, &cipher->cipher_base.iv);
    }

    /* EVP_CIPHER_CTX_init() will be called inside EVP_CIPHER_CTX_new(). */
    cipher->encryptor_ctx = EVP_CIPHER_CTX_new();
    AWS_FATAL_ASSERT(cipher->encryptor_ctx && "Cipher initialization failed!");

    /* EVP_CIPHER_CTX_init() will be called inside EVP_CIPHER_CTX_new(). */
    cipher->decryptor_ctx = EVP_CIPHER_CTX_new();
    AWS_FATAL_ASSERT(cipher->decryptor_ctx && "Cipher initialization failed!");

    if (s_init_cbc_cipher_materials(&cipher->cipher_base) != AWS_OP_SUCCESS) {
        goto error;
    }

    cipher->cipher_base.good = true;
    return &cipher->cipher_base;

error:
    s_destroy(&cipher->cipher_base);
    return NULL;
}

static int s_init_ctr_cipher_materials(struct aws_symmetric_cipher *cipher) {
    struct openssl_aes_cipher *openssl_cipher = cipher->impl;

    if (!(EVP_EncryptInit_ex(
              openssl_cipher->encryptor_ctx,
              EVP_aes_256_ctr(),
              NULL,
              openssl_cipher->cipher_base.key.buffer,
              openssl_cipher->cipher_base.iv.buffer) &&
          EVP_CIPHER_CTX_set_padding(openssl_cipher->encryptor_ctx, 0)) ||
        !(EVP_DecryptInit_ex(
              openssl_cipher->decryptor_ctx,
              EVP_aes_256_ctr(),
              NULL,
              openssl_cipher->cipher_base.key.buffer,
              openssl_cipher->cipher_base.iv.buffer) &&
          EVP_CIPHER_CTX_set_padding(openssl_cipher->decryptor_ctx, 0))) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    return AWS_OP_SUCCESS;
}

static int s_reset_ctr_cipher_materials(struct aws_symmetric_cipher *cipher) {
    int ret_val = s_reset(cipher);

    if (ret_val == AWS_OP_SUCCESS) {
        return s_init_ctr_cipher_materials(cipher);
    }

    return ret_val;
}

static struct aws_symmetric_cipher_vtable s_ctr_vtable = {
    .alg_name = "AES-CTR 256",
    .provider = "OpenSSL Compatible LibCrypto",
    .destroy = s_destroy,
    .reset = s_reset_ctr_cipher_materials,
    .decrypt = s_decrypt,
    .encrypt = s_encrypt,
    .finalize_decryption = s_finalize_decryption,
    .finalize_encryption = s_finalize_encryption,
};

struct aws_symmetric_cipher *aws_aes_ctr_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv) {
    struct openssl_aes_cipher *cipher = aws_mem_calloc(allocator, 1, sizeof(struct openssl_aes_cipher));

    cipher->cipher_base.allocator = allocator;
    cipher->cipher_base.block_size = AWS_AES_256_CIPHER_BLOCK_SIZE;
    cipher->cipher_base.key_length_bits = AWS_AES_256_KEY_BIT_LEN;
    cipher->cipher_base.vtable = &s_ctr_vtable;
    cipher->cipher_base.impl = cipher;

    if (key) {
        aws_byte_buf_init_copy_from_cursor(&cipher->cipher_base.key, allocator, *key);
    } else {
        aws_byte_buf_init(&cipher->cipher_base.key, allocator, AWS_AES_256_KEY_BYTE_LEN);
        aws_symmetric_cipher_generate_key(AWS_AES_256_KEY_BYTE_LEN, &cipher->cipher_base.key);
    }

    if (iv) {
        aws_byte_buf_init_copy_from_cursor(&cipher->cipher_base.iv, allocator, *iv);
    } else {
        aws_byte_buf_init(&cipher->cipher_base.iv, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
        aws_symmetric_cipher_generate_initialization_vector(
            AWS_AES_256_CIPHER_BLOCK_SIZE, false, &cipher->cipher_base.iv);
    }

    /* EVP_CIPHER_CTX_init() will be called inside EVP_CIPHER_CTX_new(). */
    cipher->encryptor_ctx = EVP_CIPHER_CTX_new();
    AWS_FATAL_ASSERT(cipher->encryptor_ctx && "Cipher initialization failed!");

    /* EVP_CIPHER_CTX_init() will be called inside EVP_CIPHER_CTX_new(). */
    cipher->decryptor_ctx = EVP_CIPHER_CTX_new();
    AWS_FATAL_ASSERT(cipher->decryptor_ctx && "Cipher initialization failed!");

    if (s_init_ctr_cipher_materials(&cipher->cipher_base) != AWS_OP_SUCCESS) {
        goto error;
    }

    cipher->cipher_base.good = true;
    return &cipher->cipher_base;

error:
    s_destroy(&cipher->cipher_base);
    return NULL;
}

static int s_finalize_gcm_encryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    struct openssl_aes_cipher *openssl_cipher = cipher->impl;

    int ret_val = s_finalize_encryption(cipher, out);

    if (ret_val == AWS_OP_SUCCESS) {
        if (!cipher->tag.len) {
            if (!EVP_CIPHER_CTX_ctrl(
                    openssl_cipher->encryptor_ctx,
                    EVP_CTRL_GCM_GET_TAG,
                    (int)cipher->tag.capacity,
                    cipher->tag.buffer)) {
                cipher->good = false;
                return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
            }
            cipher->tag.len = AWS_AES_256_CIPHER_BLOCK_SIZE;
        }
    }

    return ret_val;
}

static int s_init_gcm_cipher_materials(struct aws_symmetric_cipher *cipher) {
    struct openssl_aes_cipher *openssl_cipher = cipher->impl;

    if (!(EVP_EncryptInit_ex(openssl_cipher->encryptor_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
          EVP_EncryptInit_ex(
              openssl_cipher->encryptor_ctx,
              NULL,
              NULL,
              openssl_cipher->cipher_base.key.buffer,
              openssl_cipher->cipher_base.iv.buffer) &&
          EVP_CIPHER_CTX_set_padding(openssl_cipher->encryptor_ctx, 0)) ||
        !(EVP_DecryptInit_ex(openssl_cipher->decryptor_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
          EVP_DecryptInit_ex(
              openssl_cipher->decryptor_ctx,
              NULL,
              NULL,
              openssl_cipher->cipher_base.key.buffer,
              openssl_cipher->cipher_base.iv.buffer) &&
          EVP_CIPHER_CTX_set_padding(openssl_cipher->decryptor_ctx, 0))) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (openssl_cipher->cipher_base.aad.len) {
        int outLen = 0;
        if (!EVP_EncryptUpdate(
                openssl_cipher->encryptor_ctx,
                NULL,
                &outLen,
                openssl_cipher->cipher_base.aad.buffer,
                (int)openssl_cipher->cipher_base.aad.len) ||
            !EVP_DecryptUpdate(
                openssl_cipher->decryptor_ctx,
                NULL,
                &outLen,
                openssl_cipher->cipher_base.aad.buffer,
                (int)openssl_cipher->cipher_base.aad.len)) {
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
    }

    if (openssl_cipher->cipher_base.tag.len) {
        if (!EVP_CIPHER_CTX_ctrl(
                openssl_cipher->decryptor_ctx,
                EVP_CTRL_GCM_SET_TAG,
                (int)openssl_cipher->cipher_base.tag.len,
                openssl_cipher->cipher_base.tag.buffer)) {
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_reset_gcm_cipher_materials(struct aws_symmetric_cipher *cipher) {
    int ret_val = s_reset(cipher);

    if (ret_val == AWS_OP_SUCCESS) {
        return s_init_gcm_cipher_materials(cipher);
    }

    return ret_val;
}

static struct aws_symmetric_cipher_vtable s_gcm_vtable = {
    .alg_name = "AES-GCM 256",
    .provider = "OpenSSL Compatible LibCrypto",
    .destroy = s_destroy,
    .reset = s_reset_gcm_cipher_materials,
    .decrypt = s_decrypt,
    .encrypt = s_encrypt,
    .finalize_decryption = s_finalize_decryption,
    .finalize_encryption = s_finalize_gcm_encryption,
};

struct aws_symmetric_cipher *aws_aes_gcm_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv,
    const struct aws_byte_cursor *aad,
    const struct aws_byte_cursor *decryption_tag) {

    struct openssl_aes_cipher *cipher = aws_mem_calloc(allocator, 1, sizeof(struct openssl_aes_cipher));
    cipher->cipher_base.allocator = allocator;
    cipher->cipher_base.block_size = AWS_AES_256_CIPHER_BLOCK_SIZE;
    cipher->cipher_base.key_length_bits = AWS_AES_256_KEY_BIT_LEN;
    cipher->cipher_base.vtable = &s_gcm_vtable;
    cipher->cipher_base.impl = cipher;

    /* Copy key into the cipher context. */
    if (key) {
        aws_byte_buf_init_copy_from_cursor(&cipher->cipher_base.key, allocator, *key);
    } else {
        aws_byte_buf_init(&cipher->cipher_base.key, allocator, AWS_AES_256_KEY_BYTE_LEN);
        aws_symmetric_cipher_generate_key(AWS_AES_256_KEY_BYTE_LEN, &cipher->cipher_base.key);
    }

    /* Copy initialization vector into the cipher context. */
    if (iv) {
        aws_byte_buf_init_copy_from_cursor(&cipher->cipher_base.iv, allocator, *iv);
    } else {
        aws_byte_buf_init(&cipher->cipher_base.iv, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE - 4);
        aws_symmetric_cipher_generate_initialization_vector(
            AWS_AES_256_CIPHER_BLOCK_SIZE - 4, false, &cipher->cipher_base.iv);
    }

    /* Initialize the cipher contexts. */
    cipher->encryptor_ctx = EVP_CIPHER_CTX_new();
    AWS_FATAL_ASSERT(cipher->encryptor_ctx && "Encryptor cipher initialization failed!");

    cipher->decryptor_ctx = EVP_CIPHER_CTX_new();
    AWS_FATAL_ASSERT(cipher->decryptor_ctx && "Decryptor cipher initialization failed!");

    /* Set AAD if provided */
    if (aad) {
        aws_byte_buf_init_copy_from_cursor(&cipher->cipher_base.aad, allocator, *aad);
    }

    /* Set tag for the decryptor to use.*/
    if (decryption_tag) {
        aws_byte_buf_init_copy_from_cursor(&cipher->cipher_base.tag, allocator, *decryption_tag);
    } else {
        /* we'll need this later when we grab the tag during encryption time. */
        aws_byte_buf_init(&cipher->cipher_base.tag, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
    }

    /* Initialize the cipher contexts with the specified key and IV. */
    if (s_init_gcm_cipher_materials(&cipher->cipher_base)) {
        goto error;
    }

    cipher->cipher_base.good = true;
    return &cipher->cipher_base;

error:
    s_destroy(&cipher->cipher_base);
    return NULL;
}
