/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/symmetric_cipher.h>

#include <bcrypt.h>
#include <windows.h>

#define NT_SUCCESS(status) ((NTSTATUS)status >= 0)

static BCRYPT_ALG_HANDLE s_aes_cbc_algorithm_handle = NULL;
static aws_thread_once s_aes_thread_once = AWS_THREAD_ONCE_STATIC_INIT;

static BCRYPT_ALG_HANDLE s_aes_gcm_algorithm_handle = NULL;
static aws_thread_once s_aes_gcm_thread_once = AWS_THREAD_ONCE_STATIC_INIT;

struct aes_bcrypt_cipher {
    struct aws_symmetric_cipher cipher;
    BCRYPT_ALG_HANDLE alg_handle;
    BCRYPT_KEY_HANDLE key_handle;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *auth_info_ptr;
    DWORD cipher_flags;
    struct aws_byte_buf overflow;
    struct aws_byte_buf working_iv;
    bool encrypt_decrypt_called;
};

static void s_load_cbc_alg_handle(void *user_data) {
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
}

static void s_load_gcm_alg_handle(void *user_data) {
    (void)user_data;

    /* Load the AES algorithm */
    NTSTATUS status = BCryptOpenAlgorithmProvider(&s_aes_gcm_algorithm_handle, BCRYPT_AES_ALGORITHM, NULL, 0);
    AWS_ASSERT(s_aes_algorithm_handle && "BCryptOpenAlgorithmProvider() failed");

    /* Set the chaining mode to GCM */
    status = BCryptSetProperty(
        s_aes_gcm_algorithm_handle,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)(wcslen(BCRYPT_CHAIN_MODE_GCM) + 1),
        0);

    AWS_FATAL_ASSERT(NT_SUCCESS(status) && "BCryptSetProperty for GCM chaining mode failed");
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

static int s_initialize_cipher_materials(
    struct aes_bcrypt_cipher *cipher,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv,
    bool is_ctr_mode,
    bool has_auth_info) {

    if (key) {
        aws_byte_buf_init_copy_from_cursor(&cipher->cipher.key, cipher->cipher.allocator, *key);
    } else {
        aws_byte_buf_init(&cipher->cipher.key, cipher->cipher.allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
        aws_symmetric_cipher_generate_key(AWS_AES_256_KEY_BYTE_LEN, &cipher->cipher.key);
    }

    if (iv) {
        aws_byte_buf_init_copy_from_cursor(&cipher->cipher.iv, cipher->cipher.allocator, *iv);
    } else {
        aws_byte_buf_init(&cipher->cipher.iv, cipher->cipher.allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
        aws_symmetric_cipher_generate_initialization_vector(AWS_AES_256_CIPHER_BLOCK_SIZE, false, &cipher->cipher.iv);
    }

    cipher->key_handle = s_import_key_blob(cipher->alg_handle, cipher->cipher.allocator, &cipher->cipher.key);

    if (!cipher->key_handle) {
        cipher->cipher.good = false;
        return AWS_OP_ERR;
    }

    if (!has_auth_info) {
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
    }

    return AWS_OP_SUCCESS;
}

static int s_aes_default_encrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_encrypt,
    struct aws_byte_buf *out) {
    struct aes_bcrypt_cipher *cipher_impl = cipher->impl;

    if (to_encrypt->len == 0) {
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
        iv_size = (ULONG)cipher_impl->working_iv.len;
    }

    // iv was set on the key itself, so we don't need to pass it here.
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
        aws_byte_buf_append(&final_to_operate_on, to_operate);
    } else {
        aws_byte_buf_init_copy_from_cursor(&final_to_operate_on, cipher->allocator, *to_operate);
    }

    aws_byte_buf_secure_zero(&cipher_impl->overflow);
    size_t overflow = final_to_operate_on.len % RESERVE_SIZE;

    if (final_to_operate_on.len > RESERVE_SIZE) {
        size_t offset = overflow == 0 ? RESERVE_SIZE : overflow;

        struct aws_byte_cursor slice_for_overflow = aws_byte_cursor_from_buf(&final_to_operate_on);
        aws_byte_cursor_advance(&slice_for_overflow, final_to_operate_on.len - offset);
        aws_byte_buf_write_from_whole_cursor(&cipher_impl->overflow, slice_for_overflow);
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

    if (to_decrypt->len == 0) {
        return AWS_OP_SUCCESS;
    }

    PUCHAR iv = NULL;
    ULONG iv_size = 0;

    if (cipher_impl->auth_info_ptr) {
        iv = cipher_impl->working_iv.buffer;
        iv_size = (ULONG)cipher_impl->working_iv.len;
    }

    size_t predicted_write_lengths = to_decrypt->len;
    ULONG length_written = (ULONG)(predicted_write_lengths);

    if (out->capacity - out->len < predicted_write_lengths) {
        if (aws_byte_buf_reserve_relative(out, predicted_write_lengths)) {
            return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
        }
    }

    // iv was set on the key itself, so we don't need to pass it here.
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

    if (cipher_impl->key_handle) {
        BCryptDestroyKey(cipher_impl->key_handle);
        cipher_impl->key_handle = NULL;
    }

    aws_mem_release(cipher->allocator, cipher_impl);
}

static struct aws_symmetric_cipher_vtable s_aes_cbc_vtable = {
    .alg_name = "AES-CBC 256",
    .provider = "Windows CNG",
    .decrypt = s_aes_cbc_decrypt,
    .encrypt = s_aes_cbc_encrypt,
    .finalize_encryption = s_aes_cbc_finalize_encryption,
    .finalize_decryption = s_aes_cbc_finalize_decryption,
    .destroy = s_aes_default_destroy,
};

struct aws_symmetric_cipher *aws_aes_cbc_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv) {

    aws_thread_call_once(&s_aes_thread_once, s_load_cbc_alg_handle, NULL);

    struct aes_bcrypt_cipher *cipher = aws_mem_calloc(allocator, 1, sizeof(struct aes_bcrypt_cipher));

    cipher->cipher.allocator = allocator;
    cipher->cipher.block_size = AWS_AES_256_CIPHER_BLOCK_SIZE;
    cipher->cipher.key_length_bits = AWS_AES_256_KEY_BIT_LEN;
    cipher->alg_handle = s_aes_cbc_algorithm_handle;
    cipher->cipher.vtable = &s_aes_cbc_vtable;

    if (s_initialize_cipher_materials(cipher, key, iv, false, false) != AWS_OP_SUCCESS) {
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

static struct aws_symmetric_cipher_vtable s_aes_gcm_vtable = {
    .alg_name = "AES-GCM 256",
    .provider = "Windows CNG",
    .decrypt = s_default_aes_decrypt,
    .encrypt = s_aes_default_encrypt,
    .finalize_encryption = s_default_aes_finalize_encryption,
    .finalize_decryption = s_aes_default_finalize_decryption,
    .destroy = s_aes_default_destroy,
};

struct aws_symmetric_cipher *aws_aes_gcm_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv,
    const struct aws_byte_cursor *aad) {

    // complete me please
    return NULL;
}

struct aws_symmetric_cipher *aws_aes_ctr_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv) {
    (void)allocator;
    (void)key;
    (void)iv;
    // complete me please

    return NULL;
}
