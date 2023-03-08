/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/symmetric_cipher.h>

#include <windows.h>

/* keep the space to prevent formatters from reordering this with the Windows.h header. */
#include <bcrypt.h>

#define NT_SUCCESS(status) ((NTSTATUS)status >= 0)

static aws_thread_once s_aes_thread_once = AWS_THREAD_ONCE_STATIC_INIT;
static BCRYPT_ALG_HANDLE s_aes_cbc_algorithm_handle = NULL;
static BCRYPT_ALG_HANDLE s_aes_gcm_algorithm_handle = NULL;
static BCRYPT_ALG_HANDLE s_aes_ctr_algorithm_handle = NULL;

struct aes_bcrypt_cipher {
    struct aws_symmetric_cipher cipher;
    BCRYPT_ALG_HANDLE alg_handle;
    BCRYPT_KEY_HANDLE key_handle;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *auth_info_ptr;
    DWORD cipher_flags;
    struct aws_byte_buf overflow;
    struct aws_byte_buf working_iv;
    struct aws_byte_buf working_mac_buffer;
    bool encrypt_decrypt_called;
};

static void s_load_alg_handles(void *user_data) {
    (void)user_data;

    /* this function is incredibly slow, LET IT LEAK*/
    NTSTATUS status = BCryptOpenAlgorithmProvider(&s_aes_cbc_algorithm_handle, BCRYPT_AES_ALGORITHM, NULL, 0)
        AWS_ASSERT(s_aes_algorithm_handle && "BCryptOpenAlgorithmProvider() failed");

    status = BCryptSetProperty(
        s_aes_cbc_algorithm_handle,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        (ULONG)(wcslen(BCRYPT_CHAIN_MODE_CBC) + 1),
        0);

    AWS_FATAL_ASSERT(NT_SUCCESS(status) && "BCryptSetProperty for CBC chaining mode failed");

    /* Set up GCM algorithm */
    status = BCryptOpenAlgorithmProvider(&s_aes_gcm_algorithm_handle, BCRYPT_AES_ALGORITHM, NULL, 0);
    AWS_ASSERT(s_aes_gcm_algorithm_handle && "BCryptOpenAlgorithmProvider() failed");

    status = BCryptSetProperty(
        s_aes_gcm_algorithm_handle,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)(wcslen(BCRYPT_CHAIN_MODE_GCM) + 1),
        0);

    AWS_FATAL_ASSERT(NT_SUCCESS(status) && "BCryptSetProperty for GCM chaining mode failed");

    /* Setup CTR algorithm */
    status = BCryptOpenAlgorithmProvider(&s_aes_ctr_algorithm_handle, BCRYPT_AES_ALGORITHM, NULL, 0);
    AWS_ASSERT(s_aes_ctr_algorithm_handle && "BCryptOpenAlgorithmProvider() failed");

    status = BCryptSetProperty(
        s_aes_ctr_algorithm_handle,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
        (ULONG)(wcslen(BCRYPT_CHAIN_MODE_ECB) + 1),
        0);

    AWS_FATAL_ASSERT(NT_SUCCESS(status) && "BCryptSetProperty for ECB chaining mode failed");
}

static BCRYPT_KEY_HANDLE s_import_key_blob(
    BCRYPT_ALG_HANDLE algHandle,
    struct aws_allocator *allocator,
    struct aws_byte_buf *key) {
    NTSTATUS status = 0;

    BCRYPT_KEY_DATA_BLOB_HEADER key_data;
    key_data.dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    key_data.dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    key_data.cbKeyData = (ULONG)key->len;

    struct aws_byte_buf key_data_buf;
    aws_byte_buf_init(&key_data_buf, allocator, sizeof(key_data) + key->len);
    aws_byte_buf_write(&key_data_buf, (const uint8_t *)&key_data, sizeof(key_data));
    aws_byte_buf_write(&key_data_buf, key->buffer, key->len);

    BCRYPT_KEY_HANDLE key_handle;
    status = BCryptImportKey(
        algHandle, NULL, BCRYPT_KEY_DATA_BLOB, &key_handle, NULL, 0, key_data_buf.buffer, (ULONG)key_data_buf.len, 0);

    aws_byte_buf_clean_up_secure(&key_data_buf);

    if (!NT_SUCCESS(status)) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    return key_handle;
}

static void s_aes_default_destroy(struct aws_symmetric_cipher *cipher) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    /* unless we're in CTR mode, the working iv is the same buffer as the iv.
       so prevent a double free here by checking the addresses first. */
    bool working_iv_optimized = cipher->iv.buffer == cipher_impl->working_iv.buffer;
    aws_byte_buf_clean_up_secure(&cipher->key);
    aws_byte_buf_clean_up_secure(&cipher->iv);
    aws_byte_buf_clean_up_secure(&cipher->tag);
    aws_byte_buf_clean_up_secure(&cipher->aad);

    if (!working_iv_optimized) {
        aws_byte_buf_clean_up_secure(&cipher_impl->working_iv);
    }

    aws_byte_buf_clean_up_secure(&cipher_impl->overflow);
    aws_byte_buf_clean_up_secure(&cipher_impl->working_mac_buffer);

    if (cipher_impl->key_handle) {
        BCryptDestroyKey(cipher_impl->key_handle);
        cipher_impl->key_handle = NULL;
    }

    if (cipher_impl->auth_info_ptr) {
        aws_mem_release(cipher->allocator, cipher_impl->auth_info_ptr);
    }

    aws_mem_release(cipher->allocator, cipher_impl);
}

static int s_initialize_cipher_materials(
    struct aes_bcrypt_cipher *cipher,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv,
    const struct aws_byte_cursor *tag,
    const struct aws_byte_cursor *aad,
    size_t iv_size,
    bool is_ctr_mode,
    bool is_gcm) {

    if (!cipher->cipher.key.len) {
        if (key) {
            aws_byte_buf_init_copy_from_cursor(&cipher->cipher.key, cipher->cipher.allocator, *key);
        } else {
            aws_byte_buf_init(&cipher->cipher.key, cipher->cipher.allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
            aws_symmetric_cipher_generate_key(AWS_AES_256_KEY_BYTE_LEN, &cipher->cipher.key);
        }
    }

    if (!cipher->cipher.iv.len) {
        if (iv) {
            aws_byte_buf_init_copy_from_cursor(&cipher->cipher.iv, cipher->cipher.allocator, *iv);
        } else {
            aws_byte_buf_init(&cipher->cipher.iv, cipher->cipher.allocator, iv_size);
            aws_symmetric_cipher_generate_initialization_vector(iv_size, false, &cipher->cipher.iv);
        }
    }

    if (is_gcm) {

        if (!cipher->cipher.tag.len) {
            if (tag) {
                aws_byte_buf_init_copy_from_cursor(&cipher->cipher.tag, cipher->cipher.allocator, *tag);
            } else {
                aws_byte_buf_init(&cipher->cipher.tag, cipher->cipher.allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
                aws_byte_buf_secure_zero(&cipher->cipher.tag);
                /* windows handles this, just go ahead and tell the API it's got a length. */
                cipher->cipher.tag.len = AWS_AES_256_CIPHER_BLOCK_SIZE;
            }
        }

        if (!cipher->cipher.aad.len) {
            if (aad) {
                aws_byte_buf_init_copy_from_cursor(&cipher->cipher.aad, cipher->cipher.allocator, *aad);
            }
        }

        if (!cipher->working_mac_buffer.len) {
            aws_byte_buf_init(&cipher->working_mac_buffer, cipher->cipher.allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
            aws_byte_buf_secure_zero(&cipher->working_mac_buffer);
            /* windows handles this, just go ahead and tell the API it's got a length. */
            cipher->working_mac_buffer.len = AWS_AES_256_CIPHER_BLOCK_SIZE;
        }
    }

    cipher->key_handle = s_import_key_blob(cipher->alg_handle, cipher->cipher.allocator, &cipher->cipher.key);

    if (!cipher->key_handle) {
        cipher->cipher.good = false;
        return AWS_OP_ERR;
    }

    cipher->cipher_flags = 0;

    if (!is_gcm) {
        NTSTATUS status = BCryptSetProperty(
            cipher->key_handle,
            BCRYPT_INITIALIZATION_VECTOR,
            cipher->cipher.iv.buffer,
            (ULONG)cipher->cipher.iv.len,
            0);

        if (!NT_SUCCESS(status)) {
            cipher->cipher.good = false;
            return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        }
    } else {

        cipher->auth_info_ptr =
            aws_mem_acquire(cipher->cipher.allocator, sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));

        // Create a new authenticated cipher mode info object for GCM mode
        BCRYPT_INIT_AUTH_MODE_INFO(*cipher->auth_info_ptr);
        cipher->auth_info_ptr->pbNonce = cipher->cipher.iv.buffer;
        cipher->auth_info_ptr->cbNonce = (ULONG)cipher->cipher.iv.len;
        cipher->auth_info_ptr->dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
        cipher->auth_info_ptr->pbTag = cipher->cipher.tag.buffer;
        cipher->auth_info_ptr->cbTag = (ULONG)cipher->cipher.tag.len;
        cipher->auth_info_ptr->pbMacContext = cipher->working_mac_buffer.buffer;
        cipher->auth_info_ptr->cbMacContext = (ULONG)cipher->working_mac_buffer.len;

        if (cipher->cipher.aad.len) {
            cipher->auth_info_ptr->pbAuthData = (PUCHAR)cipher->cipher.aad.buffer;
            cipher->auth_info_ptr->cbAuthData = (ULONG)cipher->cipher.aad.len;
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_clear_reusable_components(struct aws_symmetric_cipher *cipher) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;
    bool working_iv_optimized = cipher->iv.buffer == cipher_impl->working_iv.buffer;

    if (!working_iv_optimized) {
        aws_byte_buf_secure_zero(&cipher_impl->working_iv);
    }

    if (cipher_impl->key_handle) {
        BCryptDestroyKey(cipher_impl->key_handle);
        cipher_impl->key_handle = NULL;
    }

    if (cipher_impl->auth_info_ptr) {
        aws_mem_release(cipher->allocator, cipher_impl->auth_info_ptr);
        cipher_impl->auth_info_ptr = NULL;
    }

    aws_byte_buf_secure_zero(&cipher_impl->overflow);
    aws_byte_buf_secure_zero(&cipher_impl->working_mac_buffer);
    /* windows handles this, just go ahead and tell the API it's got a length. */
    cipher_impl->working_mac_buffer.len = AWS_AES_256_CIPHER_BLOCK_SIZE;
}

static int s_reset_cbc_cipher(struct aws_symmetric_cipher *cipher) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    s_clear_reusable_components(cipher);
    return s_initialize_cipher_materials(
        cipher_impl, NULL, NULL, NULL, NULL, AWS_AES_256_CIPHER_BLOCK_SIZE, false, false);
}

static int s_reset_ctr_cipher(struct aws_symmetric_cipher *cipher) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    s_clear_reusable_components(cipher);
    struct aws_byte_cursor iv_cur = aws_byte_cursor_from_buf(&cipher->iv);
    aws_byte_buf_append_dynamic(&cipher_impl->working_iv, &iv_cur);
    return s_initialize_cipher_materials(
        cipher_impl, NULL, NULL, NULL, NULL, AWS_AES_256_CIPHER_BLOCK_SIZE, true, false);
}

static int s_reset_gcm_cipher(struct aws_symmetric_cipher *cipher) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    s_clear_reusable_components(cipher);
    return s_initialize_cipher_materials(
        cipher_impl, NULL, NULL, NULL, NULL, AWS_AES_256_CIPHER_BLOCK_SIZE - 4, false, true);
}

static int s_aes_default_encrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_encrypt,
    struct aws_byte_buf *out) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    if (to_encrypt->len == 0 && cipher_impl->encrypt_decrypt_called) {
        return AWS_OP_SUCCESS;
    }

    size_t predicted_write_length =
        cipher_impl->cipher_flags & BCRYPT_BLOCK_PADDING
            ? to_encrypt->len + (AWS_AES_256_CIPHER_BLOCK_SIZE - to_encrypt->len % AWS_AES_256_CIPHER_BLOCK_SIZE)
            : to_encrypt->len;

    ULONG length_written = (ULONG)(predicted_write_length);

    if (out->capacity - out->len < predicted_write_length) {
        if (aws_byte_buf_reserve_relative(out, predicted_write_length)) {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    PUCHAR iv = NULL;
    ULONG iv_size = 0;

    if (cipher_impl->auth_info_ptr) {
        iv = cipher_impl->working_iv.buffer;
        iv_size = (ULONG)cipher_impl->working_iv.capacity;
    }

    /* iv was set on the key itself, so we don't need to pass it here. */
    NTSTATUS status = BCryptEncrypt(
        cipher_impl->key_handle,
        to_encrypt->ptr,
        (ULONG)to_encrypt->len,
        cipher_impl->auth_info_ptr,
        iv,
        iv_size,
        out->buffer + out->len,
        (ULONG)(out->capacity - out->len),
        &length_written,
        cipher_impl->cipher_flags);

    cipher_impl->encrypt_decrypt_called = true;

    if (!NT_SUCCESS(status)) {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += length_written;
    return AWS_OP_SUCCESS;
}

static struct aws_byte_buf s_fill_in_overflow(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_operate) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    static const size_t RESERVE_SIZE = AWS_AES_256_CIPHER_BLOCK_SIZE * 2;
    cipher_impl->cipher_flags = 0;

    struct aws_byte_buf final_to_operate_on;
    AWS_ZERO_STRUCT(final_to_operate_on);

    if (cipher_impl->overflow.len > 0) {
        aws_byte_buf_init_copy(&final_to_operate_on, cipher->allocator, &cipher_impl->overflow);
        aws_byte_buf_append_dynamic(&final_to_operate_on, to_operate);
        aws_byte_buf_secure_zero(&cipher_impl->overflow);
    } else {
        aws_byte_buf_init_copy_from_cursor(&final_to_operate_on, cipher->allocator, *to_operate);
    }

    size_t overflow = final_to_operate_on.len % RESERVE_SIZE;

    if (final_to_operate_on.len > RESERVE_SIZE) {
        size_t offset = overflow == 0 ? RESERVE_SIZE : overflow;

        struct aws_byte_cursor slice_for_overflow = aws_byte_cursor_from_buf(&final_to_operate_on);
        aws_byte_cursor_advance(&slice_for_overflow, final_to_operate_on.len - offset);
        aws_byte_buf_append_dynamic(&cipher_impl->overflow, &slice_for_overflow);
        final_to_operate_on.len -= offset;
    } else {
        struct aws_byte_cursor final_cur = aws_byte_cursor_from_buf(&final_to_operate_on);
        aws_byte_buf_append_dynamic(&cipher_impl->overflow, &final_cur);
        aws_byte_buf_clean_up_secure(&final_to_operate_on);
    }

    return final_to_operate_on;
}

/* this is used only for CBC mode to handle padding without timing attack vulnerabilities. */
static int s_aes_cbc_encrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_encrypt,
    struct aws_byte_buf *out) {

    struct aws_byte_buf final_to_encrypt = s_fill_in_overflow(cipher, to_encrypt);
    struct aws_byte_cursor final_cur = aws_byte_cursor_from_buf(&final_to_encrypt);
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;
    cipher_impl->encrypt_decrypt_called = true;
    int ret_val = s_aes_default_encrypt(cipher, &final_cur, out);
    aws_byte_buf_clean_up_secure(&final_to_encrypt);

    return ret_val;
}

static int s_default_aes_finalize_encryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    (void)cipher;
    (void)out;
    return AWS_OP_SUCCESS;
}

static int s_aes_cbc_finalize_encryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    if (cipher->good && cipher_impl->overflow.len > 0) {
        cipher_impl->cipher_flags = BCRYPT_BLOCK_PADDING;
        struct aws_byte_cursor remaining_cur = aws_byte_cursor_from_buf(&cipher_impl->overflow);
        int ret_val = s_aes_default_encrypt(cipher, &remaining_cur, out);
        aws_byte_buf_secure_zero(&cipher_impl->overflow);
        return ret_val;
    }

    return AWS_OP_SUCCESS;
}

static int s_default_aes_decrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_decrypt,
    struct aws_byte_buf *out) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    if (to_decrypt->len == 0 && cipher_impl->encrypt_decrypt_called) {
        return AWS_OP_SUCCESS;
    }

    PUCHAR iv = NULL;
    ULONG iv_size = 0;

    if (cipher_impl->auth_info_ptr) {
        iv = cipher_impl->working_iv.buffer;
        iv_size = (ULONG)cipher_impl->working_iv.capacity;
    }

    size_t predicted_write_lengths = to_decrypt->len;
    ULONG length_written = (ULONG)(predicted_write_lengths);

    if (out->capacity - out->len < predicted_write_lengths) {
        if (aws_byte_buf_reserve_relative(out, predicted_write_lengths)) {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    /* iv was set on the key itself, so we don't need to pass it here. */
    NTSTATUS status = BCryptDecrypt(
        cipher_impl->key_handle,
        to_decrypt->ptr,
        (ULONG)to_decrypt->len,
        cipher_impl->auth_info_ptr,
        iv,
        iv_size,
        out->buffer + out->len,
        (ULONG)(out->capacity - out->len),
        &length_written,
        cipher_impl->cipher_flags);

    cipher_impl->encrypt_decrypt_called = true;

    if (!NT_SUCCESS(status)) {
        cipher->good = false;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += length_written;
    return AWS_OP_SUCCESS;
}

static int s_aes_cbc_decrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_decrypt,
    struct aws_byte_buf *out) {
    struct aws_byte_buf final_to_decrypt = s_fill_in_overflow(cipher, to_decrypt);
    struct aws_byte_cursor final_cur = aws_byte_cursor_from_buf(&final_to_decrypt);
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;
    cipher_impl->encrypt_decrypt_called = true;

    int ret_val = s_default_aes_decrypt(cipher, &final_cur, out);
    aws_byte_buf_clean_up_secure(&final_to_decrypt);

    return ret_val;
}

static int s_aes_default_finalize_decryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    (void)cipher;
    (void)out;
    return AWS_OP_SUCCESS;
}

static int s_aes_cbc_finalize_decryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    if (cipher->good && cipher_impl->overflow.len > 0) {
        cipher_impl->cipher_flags = BCRYPT_BLOCK_PADDING;
        struct aws_byte_cursor remaining_cur = aws_byte_cursor_from_buf(&cipher_impl->overflow);
        int ret_val = s_default_aes_decrypt(cipher, &remaining_cur, out);
        aws_byte_buf_secure_zero(&cipher_impl->overflow);
        return ret_val;
    }

    return AWS_OP_SUCCESS;
}

static struct aws_symmetric_cipher_vtable s_aes_cbc_vtable = {
    .alg_name = "AES-CBC 256",
    .provider = "Windows CNG",
    .decrypt = s_aes_cbc_decrypt,
    .encrypt = s_aes_cbc_encrypt,
    .finalize_encryption = s_aes_cbc_finalize_encryption,
    .finalize_decryption = s_aes_cbc_finalize_decryption,
    .destroy = s_aes_default_destroy,
    .reset = s_reset_cbc_cipher,
};

struct aws_symmetric_cipher *aws_aes_cbc_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv) {

    aws_thread_call_once(&s_aes_thread_once, s_load_alg_handles, NULL);

    struct aes_bcrypt_cipher *cipher = aws_mem_calloc(allocator, 1, sizeof(struct aes_bcrypt_cipher));

    cipher->cipher.allocator = allocator;
    cipher->cipher.block_size = AWS_AES_256_CIPHER_BLOCK_SIZE;
    cipher->cipher.key_length_bits = AWS_AES_256_KEY_BIT_LEN;
    cipher->alg_handle = s_aes_cbc_algorithm_handle;
    cipher->cipher.vtable = &s_aes_cbc_vtable;

    if (s_initialize_cipher_materials(cipher, key, iv, NULL, NULL, AWS_AES_256_CIPHER_BLOCK_SIZE, false, false) !=
        AWS_OP_SUCCESS) {
        goto error;
    }

    aws_byte_buf_init(&cipher->overflow, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE * 2);
    cipher->working_iv = cipher->cipher.iv;
    cipher->cipher.impl = cipher;
    cipher->cipher.good = true;

    return &cipher->cipher;

error:
    return NULL;
}

static int s_aes_gcm_encrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_encrypt,
    struct aws_byte_buf *out) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    if (to_encrypt->len == 0) {
        return AWS_OP_SUCCESS;
    }

    struct aws_byte_buf working_buffer;
    AWS_ZERO_STRUCT(working_buffer);

    if (cipher_impl->overflow.len) {
        struct aws_byte_cursor overflow_cur = aws_byte_cursor_from_buf(&cipher_impl->overflow);

        aws_byte_buf_init_copy_from_cursor(&working_buffer, cipher->allocator, overflow_cur);
        aws_byte_buf_reset(&cipher_impl->overflow, true);
        aws_byte_buf_append_dynamic(&working_buffer, to_encrypt);
    } else {
        struct aws_byte_cursor to_encrypt_cpy = *to_encrypt;
        aws_byte_buf_init_copy_from_cursor(&working_buffer, cipher->allocator, to_encrypt_cpy);
    }

    int ret_val = AWS_OP_ERR;

    if (working_buffer.len > AWS_AES_256_CIPHER_BLOCK_SIZE) {
        size_t offset = working_buffer.len % AWS_AES_256_CIPHER_BLOCK_SIZE;
        size_t seek_to = working_buffer.len - (AWS_AES_256_CIPHER_BLOCK_SIZE + offset);
        struct aws_byte_cursor working_buf_cur = aws_byte_cursor_from_buf(&working_buffer);
        struct aws_byte_cursor working_slice = aws_byte_cursor_advance(&working_buf_cur, seek_to);
        /* this is just here to make it obvious. The previous line advanced working_buf_cur to where the
           new overfloew should be. */
        struct aws_byte_cursor new_overflow_cur = working_buf_cur;
        aws_byte_buf_append_dynamic(&cipher_impl->overflow, &new_overflow_cur);

        cipher_impl->encrypt_decrypt_called = true;
        ret_val = s_aes_default_encrypt(cipher, &working_slice, out);
    } else {
        struct aws_byte_cursor working_buffer_cur = aws_byte_cursor_from_buf(&working_buffer);
        aws_byte_buf_append_dynamic(&cipher_impl->overflow, &working_buffer_cur);
        ret_val = AWS_OP_SUCCESS;
    }
    aws_byte_buf_clean_up_secure(&working_buffer);
    return ret_val;
}

static int s_aes_gcm_decrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_decrypt,
    struct aws_byte_buf *out) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    if (to_decrypt->len == 0) {
        return AWS_OP_SUCCESS;
    }

    struct aws_byte_buf working_buffer;
    AWS_ZERO_STRUCT(working_buffer);

    if (cipher_impl->overflow.len) {
        struct aws_byte_cursor overflow_cur = aws_byte_cursor_from_buf(&cipher_impl->overflow);

        aws_byte_buf_init_copy_from_cursor(&working_buffer, cipher->allocator, overflow_cur);
        aws_byte_buf_reset(&cipher_impl->overflow, true);
        aws_byte_buf_append_dynamic(&working_buffer, to_decrypt);
    } else {
        struct aws_byte_cursor to_encrypt_cpy = *to_decrypt;
        aws_byte_buf_init_copy_from_cursor(&working_buffer, cipher->allocator, to_encrypt_cpy);
    }

    int ret_val = AWS_OP_ERR;

    if (working_buffer.len > AWS_AES_256_CIPHER_BLOCK_SIZE) {
        size_t offset = working_buffer.len % AWS_AES_256_CIPHER_BLOCK_SIZE;
        size_t seek_to = working_buffer.len - (AWS_AES_256_CIPHER_BLOCK_SIZE + offset);
        struct aws_byte_cursor working_buf_cur = aws_byte_cursor_from_buf(&working_buffer);
        struct aws_byte_cursor working_slice = aws_byte_cursor_advance(&working_buf_cur, seek_to);
        /* this is just here to make it obvious. The previous line advanced working_buf_cur to where the
           new overfloew should be. */
        struct aws_byte_cursor new_overflow_cur = working_buf_cur;
        aws_byte_buf_append_dynamic(&cipher_impl->overflow, &new_overflow_cur);

        cipher_impl->encrypt_decrypt_called = true;
        ret_val = s_default_aes_decrypt(cipher, &working_slice, out);
    } else {
        struct aws_byte_cursor working_buffer_cur = aws_byte_cursor_from_buf(&working_buffer);
        aws_byte_buf_append_dynamic(&cipher_impl->overflow, &working_buffer_cur);
        ret_val = AWS_OP_SUCCESS;
    }
    aws_byte_buf_clean_up_secure(&working_buffer);
    return ret_val;
}

static int s_aes_gcm_finalize_encryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    cipher_impl->auth_info_ptr->dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
    struct aws_byte_cursor remaining_cur = aws_byte_cursor_from_buf(&cipher_impl->overflow);
    int ret_val = s_aes_default_encrypt(cipher, &remaining_cur, out);
    aws_byte_buf_secure_zero(&cipher_impl->overflow);
    aws_byte_buf_secure_zero(&cipher_impl->working_iv);
    return ret_val;
}

static int s_aes_gcm_finalize_decryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    cipher_impl->auth_info_ptr->dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;
    struct aws_byte_cursor remaining_cur = aws_byte_cursor_from_buf(&cipher_impl->overflow);
    int ret_val = s_default_aes_decrypt(cipher, &remaining_cur, out);
    aws_byte_buf_secure_zero(&cipher_impl->overflow);
    aws_byte_buf_secure_zero(&cipher_impl->working_iv);
    return ret_val;
}

static struct aws_symmetric_cipher_vtable s_aes_gcm_vtable = {
    .alg_name = "AES-GCM 256",
    .provider = "Windows CNG",
    .decrypt = s_aes_gcm_decrypt,
    .encrypt = s_aes_gcm_encrypt,
    .finalize_encryption = s_aes_gcm_finalize_encryption,
    .finalize_decryption = s_aes_gcm_finalize_decryption,
    .destroy = s_aes_default_destroy,
    .reset = s_reset_gcm_cipher,
};

struct aws_symmetric_cipher *aws_aes_gcm_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv,
    const struct aws_byte_cursor *aad,
    const struct aws_byte_cursor *decryption_tag) {

    aws_thread_call_once(&s_aes_thread_once, s_load_alg_handles, NULL);
    struct aes_bcrypt_cipher *cipher = aws_mem_calloc(allocator, 1, sizeof(struct aes_bcrypt_cipher));

    cipher->cipher.allocator = allocator;
    cipher->cipher.block_size = AWS_AES_256_CIPHER_BLOCK_SIZE;
    cipher->cipher.key_length_bits = AWS_AES_256_KEY_BIT_LEN;
    cipher->alg_handle = s_aes_gcm_algorithm_handle;
    cipher->cipher.vtable = &s_aes_gcm_vtable;

    /* GCM does the counting under the hood, so we let it handle the final 4 bytes of the IV. */
    if (s_initialize_cipher_materials(
            cipher, key, iv, decryption_tag, aad, AWS_AES_256_CIPHER_BLOCK_SIZE - 4, false, true) != AWS_OP_SUCCESS) {
        goto error;
    }

    aws_byte_buf_init(&cipher->overflow, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE * 2);
    aws_byte_buf_init(&cipher->working_iv, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
    aws_byte_buf_secure_zero(&cipher->working_iv);

    cipher->cipher.impl = cipher;
    cipher->cipher.good = true;

    return &cipher->cipher;

error:
    if (cipher != NULL) {
        s_aes_default_destroy(&cipher->cipher);
    }

    return NULL;
}

static int s_xor_cursors(const struct aws_byte_cursor *a, const struct aws_byte_cursor *b, struct aws_byte_buf *dest) {
    size_t min_size = 0;
    size_t max_size = 0;
    const struct aws_byte_cursor *larger_set;

    if (a->len > b->len) {
        larger_set = a;
        max_size = a->len;
        min_size = b->len;
    } else {
        larger_set = b;
        max_size = b->len;
        min_size = a->len;
    }

    if (dest->capacity - dest->len < max_size) {
        if (aws_byte_buf_reserve_relative(dest, max_size)) {
            return AWS_OP_ERR;
        }
    }

    /* If the profiler is saying this is slow, SIMD the loop below. */
    uint8_t *array_ref = dest->buffer + dest->len;

    for (size_t i = 0; i < min_size; ++i) {
        array_ref[i] = a->ptr[i] ^ b->ptr[i];
    }

    /* fill the back. */
    for (size_t i = min_size; i < max_size; ++i) {
        array_ref[i] = larger_set->ptr[i];
    }

    dest->len += max_size;

    return AWS_OP_SUCCESS;
}

static int s_aes_ctr_encrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_encrypt,
    struct aws_byte_buf *out) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    if (to_encrypt->len == 0) {
        return AWS_OP_SUCCESS;
    }

    struct aws_byte_buf working_buffer;
    AWS_ZERO_STRUCT(working_buffer);

    if (cipher_impl->overflow.len) {
        struct aws_byte_cursor overflow_cur = aws_byte_cursor_from_buf(&cipher_impl->overflow);
        aws_byte_buf_init_copy_from_cursor(&working_buffer, cipher->allocator, overflow_cur);
        aws_byte_buf_reset(&cipher_impl->overflow, true);
        aws_byte_buf_append_dynamic(&working_buffer, to_encrypt);
    } else {
        struct aws_byte_cursor to_encrypt_cpy = *to_encrypt;
        aws_byte_buf_init_copy_from_cursor(&working_buffer, cipher->allocator, to_encrypt_cpy);
    }

    struct aws_array_list sliced_buffers;
    aws_array_list_init_dynamic(
        &sliced_buffers,
        cipher->allocator,
        (to_encrypt->len / AWS_AES_256_CIPHER_BLOCK_SIZE) + 1,
        sizeof(struct aws_byte_cursor));

    struct aws_byte_cursor working_buf_cur = aws_byte_cursor_from_buf(&working_buffer);
    while (working_buf_cur.len) {
        struct aws_byte_cursor slice = working_buf_cur;

        if (working_buf_cur.len >= AWS_AES_256_CIPHER_BLOCK_SIZE) {
            slice = aws_byte_cursor_advance(&working_buf_cur, AWS_AES_256_CIPHER_BLOCK_SIZE);
        } else {
            aws_byte_cursor_advance(&working_buf_cur, slice.len);
        }

        aws_array_list_push_back(&sliced_buffers, &slice);
    }

    int ret_val = AWS_OP_ERR;

    size_t sliced_buffers_cnt = aws_array_list_length(&sliced_buffers);

    for (size_t i = 0; i < sliced_buffers_cnt; ++i) {
        struct aws_byte_cursor buffer_cur;
        AWS_ZERO_STRUCT(buffer_cur);

        aws_array_list_get_at(&sliced_buffers, &buffer_cur, i);
        if (buffer_cur.len == AWS_AES_256_CIPHER_BLOCK_SIZE ||
            (cipher_impl->overflow.len > 0 && sliced_buffers_cnt) == 1) {

            ULONG lengthWritten = (ULONG)AWS_AES_256_CIPHER_BLOCK_SIZE;
            uint8_t temp_buffer[AWS_AES_256_CIPHER_BLOCK_SIZE] = {0};
            struct aws_byte_cursor temp_cur = aws_byte_cursor_from_array(temp_buffer, sizeof(temp_buffer));

            NTSTATUS status = BCryptEncrypt(
                cipher_impl->key_handle,
                cipher_impl->working_iv.buffer,
                (ULONG)cipher_impl->working_iv.len,
                NULL,
                NULL,
                0,
                temp_cur.ptr,
                (ULONG)temp_cur.len,
                &lengthWritten,
                cipher_impl->cipher_flags);

            if (!NT_SUCCESS(status)) {
                cipher->good = false;
                ret_val = aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
                goto clean_up;
            }

            if (s_xor_cursors(&buffer_cur, &temp_cur, out)) {
                ret_val = AWS_OP_ERR;
                goto clean_up;
            }

            size_t counter_offset = AWS_AES_256_CIPHER_BLOCK_SIZE - 4;
            struct aws_byte_buf counter_buf = cipher_impl->working_iv;
            /* roll it back 4 so the write works. */
            counter_buf.len = counter_offset;
            struct aws_byte_cursor counter_cur = aws_byte_cursor_from_buf(&cipher_impl->working_iv);
            aws_byte_cursor_advance(&counter_cur, counter_offset);

            uint32_t counter = 0;
            aws_byte_cursor_read_be32(&counter_cur, &counter);
            counter += 1;
            aws_byte_buf_write_be32(&counter_buf, counter);
        } else {
            aws_byte_buf_append_dynamic(&cipher_impl->overflow, &buffer_cur);
        }

        ret_val = AWS_OP_SUCCESS;
    }

clean_up:
    aws_array_list_clean_up_secure(&sliced_buffers);
    aws_byte_buf_clean_up_secure(&working_buffer);

    return ret_val;
}

static int s_aes_ctr_finalize_encryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    struct aws_byte_cursor remaining_cur = aws_byte_cursor_from_buf(&cipher_impl->overflow);
    int ret_val = s_aes_ctr_encrypt(cipher, &remaining_cur, out);
    aws_byte_buf_secure_zero(&cipher_impl->overflow);
    aws_byte_buf_secure_zero(&cipher_impl->working_iv);
    return ret_val;
}

static struct aws_symmetric_cipher_vtable s_aes_ctr_vtable = {
    .alg_name = "AES-CTR 256",
    .provider = "Windows CNG",
    .decrypt = s_aes_ctr_encrypt,
    .encrypt = s_aes_ctr_encrypt,
    .finalize_encryption = s_aes_ctr_finalize_encryption,
    .finalize_decryption = s_aes_ctr_finalize_encryption,
    .destroy = s_aes_default_destroy,
    .reset = s_reset_ctr_cipher,
};

struct aws_symmetric_cipher *aws_aes_ctr_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv) {

    aws_thread_call_once(&s_aes_thread_once, s_load_alg_handles, NULL);
    struct aes_bcrypt_cipher *cipher = aws_mem_calloc(allocator, 1, sizeof(struct aes_bcrypt_cipher));

    cipher->cipher.allocator = allocator;
    cipher->cipher.block_size = AWS_AES_256_CIPHER_BLOCK_SIZE;
    cipher->cipher.key_length_bits = AWS_AES_256_KEY_BIT_LEN;
    cipher->alg_handle = s_aes_ctr_algorithm_handle;
    cipher->cipher.vtable = &s_aes_ctr_vtable;

    if (s_initialize_cipher_materials(cipher, key, iv, NULL, NULL, AWS_AES_256_CIPHER_BLOCK_SIZE, true, false) !=
        AWS_OP_SUCCESS) {
        goto error;
    }

    aws_byte_buf_init(&cipher->overflow, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE * 2);
    aws_byte_buf_init_copy(&cipher->working_iv, allocator, &cipher->cipher.iv);

    cipher->cipher.impl = cipher;
    cipher->cipher.good = true;

    return &cipher->cipher;

error:
    if (cipher != NULL) {
        s_aes_default_destroy(&cipher->cipher);
    }

    return NULL;
}
