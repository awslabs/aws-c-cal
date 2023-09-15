/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/private/rsa.h>

#include <aws/cal/cal.h>
#include <aws/cal/private/der.h>
#include <aws/common/encoding.h>

#include <windows.h>

#include <bcrypt.h>

static BCRYPT_ALG_HANDLE s_rsa_alg = NULL;

static aws_thread_once s_rsa_thread_once = AWS_THREAD_ONCE_STATIC_INIT;

static void s_load_alg_handle(void *user_data) {
    (void)user_data;
    /* this function is incredibly slow, LET IT LEAK*/
    NTSTATUS status = BCryptOpenAlgorithmProvider(&s_rsa_alg, BCRYPT_RSA_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    AWS_FATAL_ASSERT(s_rsa_alg && "BCryptOpenAlgorithmProvider() failed");
    AWS_FATAL_ASSERT(BCRYPT_SUCCESS(status));
}

struct bcrypt_rsa_key_pair {
    struct aws_rsa_key_pair base;
    BCRYPT_KEY_HANDLE key_handle;
    struct aws_byte_buf key_buf;
};

static void s_rsa_destroy_key(struct aws_rsa_key_pair *key_pair) {
    if (key_pair == NULL) {
        return;
    }

    struct bcrypt_rsa_key_pair *rsa_key = key_pair->impl;

    if (rsa_key->key_handle) {
        BCryptDestroyKey(rsa_key->key_handle);
    }
    aws_byte_buf_clean_up_secure(&rsa_key->key_buf);

    aws_mem_release(key_pair->allocator, rsa_key);
}

int s_is_not_supported_enc_algo(enum aws_rsa_encryption_algorithm algorithm) {
    if (algorithm != AWS_CAL_RSA_ENCRYPTION_PKCS1_5 && algorithm != AWS_CAL_RSA_ENCRYPTION_OAEP_SHA256 &&
        algorithm != AWS_CAL_RSA_ENCRYPTION_OAEP_SHA512) {
        return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM);
    }
    return AWS_OP_SUCCESS;
}
int s_rsa_encrypt(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_encryption_algorithm algorithm,
    struct aws_byte_cursor plaintext,
    struct aws_byte_buf *out) {
    struct bcrypt_rsa_key_pair *key_pair_impl = key_pair->impl;

    if (s_is_not_supported_enc_algo(algorithm)) {
        return AWS_OP_ERR;
    }

    if (out->capacity - out->len < aws_rsa_key_pair_block_length(key_pair)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    BCRYPT_OAEP_PADDING_INFO padding_info_oaep;
    padding_info_oaep.pszAlgId =
        algorithm == AWS_CAL_RSA_ENCRYPTION_OAEP_SHA256 ? BCRYPT_SHA256_ALGORITHM : BCRYPT_SHA512_ALGORITHM;
    padding_info_oaep.pbLabel = NULL;
    padding_info_oaep.cbLabel = 0;

    ULONG length_written = 0;
    NTSTATUS status = BCryptEncrypt(
        key_pair_impl->key_handle,
        plaintext.ptr,
        (ULONG)plaintext.len,
        algorithm == AWS_CAL_RSA_ENCRYPTION_PKCS1_5 ? NULL : &padding_info_oaep,
        NULL,
        0,
        out->buffer + out->len,
        (ULONG)(out->capacity - out->len),
        &length_written,
        algorithm == AWS_CAL_RSA_ENCRYPTION_PKCS1_5 ? BCRYPT_PAD_PKCS1 : BCRYPT_PAD_OAEP);

    if (!BCRYPT_SUCCESS(status)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += length_written;
    return AWS_OP_SUCCESS;
}

int s_rsa_decrypt(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_encryption_algorithm algorithm,
    struct aws_byte_cursor ciphertext,
    struct aws_byte_buf *out) {
    struct bcrypt_rsa_key_pair *key_pair_impl = key_pair->impl;

    if (s_is_not_supported_enc_algo(algorithm)) {
        return AWS_OP_ERR;
    }

    if (ciphertext.len == 0) {
        return AWS_OP_SUCCESS;
    }

    BCRYPT_OAEP_PADDING_INFO padding_info_oaep;
    padding_info_oaep.pszAlgId =
        algorithm == AWS_CAL_RSA_ENCRYPTION_OAEP_SHA256 ? BCRYPT_SHA256_ALGORITHM : BCRYPT_SHA512_ALGORITHM;
    padding_info_oaep.pbLabel = NULL;
    padding_info_oaep.cbLabel = 0;

    ULONG length_written = 0;
    NTSTATUS status = BCryptDecrypt(
        key_pair_impl->key_handle,
        ciphertext.ptr,
        (ULONG)ciphertext.len,
        algorithm == AWS_CAL_RSA_ENCRYPTION_PKCS1_5 ? NULL : &padding_info_oaep,
        NULL,
        0,
        out->buffer + out->len,
        (ULONG)(out->capacity - out->len),
        &length_written,
        algorithm == AWS_CAL_RSA_ENCRYPTION_PKCS1_5 ? BCRYPT_PAD_PKCS1 : BCRYPT_PAD_OAEP);

    if (!BCRYPT_SUCCESS(status)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    out->len += length_written;
    return AWS_OP_SUCCESS;
}

/*
 * Allocates and fills out appropriate padding info for algo. Up to caller to destroy.
 */
void *s_create_sign_padding_info(struct aws_allocator *allocator, enum aws_rsa_signing_algorithm algorithm) {
    if (algorithm == AWS_CAL_RSA_SIGNATURE_PKCS1_5_SHA256) {
        BCRYPT_PKCS1_PADDING_INFO *padding_info = aws_mem_calloc(allocator, 1, sizeof(BCRYPT_PKCS1_PADDING_INFO));
        padding_info->pszAlgId = BCRYPT_SHA256_ALGORITHM;
        return padding_info;
    } else if (algorithm == AWS_CAL_RSA_SIGNATURE_PSS_SHA256) {
        BCRYPT_PSS_PADDING_INFO *padding_info = aws_mem_calloc(allocator, 1, sizeof(BCRYPT_PSS_PADDING_INFO));
        padding_info->pszAlgId = BCRYPT_SHA256_ALGORITHM;
        padding_info->cbSalt = 32;
        return padding_info;
    }

    return NULL;
}

int s_rsa_sign(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_signing_algorithm algorithm,
    struct aws_byte_cursor digest,
    struct aws_byte_buf *out) {
    struct bcrypt_rsa_key_pair *key_pair_impl = key_pair->impl;

    void *padding_info = s_create_sign_padding_info(key_pair->allocator, algorithm);
    if (padding_info == NULL) {
        return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM);
    }

    size_t output_buf_space = out->capacity - out->len;

    if (output_buf_space < aws_rsa_key_pair_signature_length(key_pair)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    struct aws_byte_buf temp_signature_buf;
    aws_byte_buf_init(&temp_signature_buf, key_pair->allocator, aws_rsa_key_pair_signature_length(key_pair));
    size_t signature_length = temp_signature_buf.capacity;

    NTSTATUS status = BCryptSignHash(
        key_pair_impl->key_handle,
        padding_info,
        digest.ptr,
        (ULONG)digest.len,
        temp_signature_buf.buffer,
        (ULONG)signature_length,
        (ULONG *)&signature_length,
        algorithm == AWS_CAL_RSA_SIGNATURE_PKCS1_5_SHA256 ? BCRYPT_PAD_PKCS1 : BCRYPT_PAD_PSS);

    if (!BCRYPT_SUCCESS(status)) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    temp_signature_buf.len = signature_length;

    struct aws_byte_cursor temp_signature_cur = aws_byte_cursor_from_buf(&temp_signature_buf);
    aws_byte_buf_append(out, &temp_signature_cur);

    aws_byte_buf_clean_up_secure(&temp_signature_buf);

    return AWS_OP_SUCCESS;
}

int s_rsa_verify(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_signing_algorithm algorithm,
    struct aws_byte_cursor digest,
    struct aws_byte_cursor signature) {
    struct bcrypt_rsa_key_pair *key_pair_impl = key_pair->impl;

    void *padding_info = s_create_sign_padding_info(key_pair->allocator, algorithm);
    if (padding_info == NULL) {
        return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM);
    }

    /* okay, now we've got a windows compatible signature, let's verify it. */
    NTSTATUS status = BCryptVerifySignature(
        key_pair_impl->key_handle,
        padding_info,
        digest.ptr,
        (ULONG)digest.len,
        signature.ptr,
        (ULONG)signature.len,
        algorithm == AWS_CAL_RSA_SIGNATURE_PKCS1_5_SHA256 ? BCRYPT_PAD_PKCS1 : BCRYPT_PAD_PSS);

    return status == 0 ? AWS_OP_SUCCESS : aws_raise_error(AWS_ERROR_CAL_SIGNATURE_VALIDATION_FAILED);
}

static struct aws_rsa_key_vtable s_rsa_key_pair_vtable = {
    .destroy = s_rsa_destroy_key,
    .encrypt = s_rsa_encrypt,
    .decrypt = s_rsa_decrypt,
    .sign = s_rsa_sign,
    .verify = s_rsa_verify,
};

struct aws_rsa_key_pair *aws_rsa_key_pair_new_generate_random(
    struct aws_allocator *allocator,
    size_t key_size_in_bits) {

    aws_thread_call_once(&s_rsa_thread_once, s_load_alg_handle, NULL);

    if (key_size_in_bits < AWS_CAL_RSA_MIN_SUPPORTED_KEY_SIZE ||
        key_size_in_bits > AWS_CAL_RSA_MAX_SUPPORTED_KEY_SIZE) {
        aws_raise_error(AWS_ERROR_INVALID_STATE);
        return NULL;
    }

    struct bcrypt_rsa_key_pair *key_impl = aws_mem_calloc(allocator, 1, sizeof(struct bcrypt_rsa_key_pair));

    aws_ref_count_init(&key_impl->base.ref_count, &key_impl->base, aws_rsa_key_pair_destroy);
    key_impl->base.impl = key_impl;
    key_impl->base.allocator = allocator;

    NTSTATUS status = BCryptGenerateKeyPair(s_rsa_alg, &key_impl->key_handle, (ULONG)key_size_in_bits, 0);

    if (!BCRYPT_SUCCESS(status)) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    status = BCryptFinalizeKeyPair(key_impl->key_handle, 0);

    if (!BCRYPT_SUCCESS(status)) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto on_error;
    }

    /*
     * bcrypt only exports to blob format, which is missing a few of the rsa
     * numbers needed to reconstruct pkcs1 format. lets not init key buffers for
     * now. this means we cannot support retrieving underlying key on win.
     * TODO: bcrypt workarounds to retrieve/compute missing things? old crypt lib
     * seems to have functionality we need.
     */
    AWS_ZERO_STRUCT(key_impl->base.priv);
    AWS_ZERO_STRUCT(key_impl->base.pub);

    key_impl->base.vtable = &s_rsa_key_pair_vtable;
    key_impl->base.key_size_in_bits = key_size_in_bits;
    key_impl->base.good = true;

    return &key_impl->base;

on_error:
    s_rsa_destroy_key(&key_impl->base);
    return NULL;
}

struct aws_rsa_key_pair *aws_rsa_key_pair_new_from_private_key_pkcs1_impl(
    struct aws_allocator *allocator,
    struct aws_byte_cursor key) {

    aws_thread_call_once(&s_rsa_thread_once, s_load_alg_handle, NULL);
    struct bcrypt_rsa_key_pair *key_pair_impl = aws_mem_calloc(allocator, 1, sizeof(struct bcrypt_rsa_key_pair));

    aws_ref_count_init(&key_pair_impl->base.ref_count, &key_pair_impl->base, aws_rsa_key_pair_destroy);
    key_pair_impl->base.impl = key_pair_impl;
    key_pair_impl->base.allocator = allocator;
    aws_byte_buf_init_copy_from_cursor(&key_pair_impl->base.priv, allocator, key);

    struct aws_der_decoder *decoder = aws_der_decoder_new(allocator, key);

    if (!decoder) {
        goto on_error;
    }

    struct s_rsa_private_key_pkcs1 private_key_data = {0};
    if (aws_der_decoder_load_private_rsa_pkcs1(decoder, &private_key_data)) {
        goto on_error;
    }

    /* Hard to predict final blob size, so use pkcs1 key size as upper bound. */
    size_t total_buffer_size = key.len + sizeof(BCRYPT_RSAKEY_BLOB);

    if (aws_byte_buf_init(&key_pair_impl->key_buf, allocator, total_buffer_size)) {
        goto on_error;
    }

    aws_byte_buf_secure_zero(&key_pair_impl->key_buf);

    BCRYPT_RSAKEY_BLOB key_blob;
    AWS_ZERO_STRUCT(key_blob);
    key_blob.Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
    key_blob.BitLength = (ULONG)private_key_data.modulus.len * 8;
    key_blob.cbPublicExp = (ULONG)private_key_data.publicExponent.len;
    key_blob.cbModulus = (ULONG)private_key_data.modulus.len;
    key_blob.cbPrime1 = (ULONG)private_key_data.prime1.len;
    key_blob.cbPrime2 = (ULONG)private_key_data.prime2.len;

    struct aws_byte_cursor header = aws_byte_cursor_from_array(&key_blob, sizeof(key_blob));
    aws_byte_buf_append(&key_pair_impl->key_buf, &header);

    LPCWSTR blob_type = BCRYPT_RSAFULLPRIVATE_BLOB;
    ULONG flags = 0;

    aws_byte_buf_append(&key_pair_impl->key_buf, &private_key_data.publicExponent);
    aws_byte_buf_append(&key_pair_impl->key_buf, &private_key_data.modulus);
    aws_byte_buf_append(&key_pair_impl->key_buf, &private_key_data.prime1);
    aws_byte_buf_append(&key_pair_impl->key_buf, &private_key_data.prime2);
    aws_byte_buf_append(&key_pair_impl->key_buf, &private_key_data.exponent1);
    aws_byte_buf_append(&key_pair_impl->key_buf, &private_key_data.exponent2);
    aws_byte_buf_append(&key_pair_impl->key_buf, &private_key_data.coefficient);
    aws_byte_buf_append(&key_pair_impl->key_buf, &private_key_data.privateExponent);

    NTSTATUS status = BCryptImportKeyPair(
        s_rsa_alg,
        NULL,
        blob_type,
        &key_pair_impl->key_handle,
        key_pair_impl->key_buf.buffer,
        (ULONG)key_pair_impl->key_buf.len,
        flags);

    if (!BCRYPT_SUCCESS(status)) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto on_error;
    }

    key_pair_impl->base.vtable = &s_rsa_key_pair_vtable;
    key_pair_impl->base.key_size_in_bits = private_key_data.modulus.len * 8;
    key_pair_impl->base.good = true;

    aws_der_decoder_destroy(decoder);

    return &key_pair_impl->base;

on_error:
    aws_der_decoder_destroy(decoder);
    aws_byte_buf_clean_up_secure(&key_pair_impl->base.priv);
    aws_byte_buf_clean_up_secure(&key_pair_impl->base.pub);
    s_rsa_destroy_key(&key_pair_impl->base);
    return NULL;
}

struct aws_rsa_key_pair *aws_rsa_key_pair_new_from_public_key_pkcs1_impl(
    struct aws_allocator *allocator,
    struct aws_byte_cursor key) {

    aws_thread_call_once(&s_rsa_thread_once, s_load_alg_handle, NULL);
    struct bcrypt_rsa_key_pair *key_pair_impl = aws_mem_calloc(allocator, 1, sizeof(struct bcrypt_rsa_key_pair));

    aws_ref_count_init(&key_pair_impl->base.ref_count, &key_pair_impl->base, aws_rsa_key_pair_destroy);
    key_pair_impl->base.impl = key_pair_impl;
    key_pair_impl->base.allocator = allocator;
    aws_byte_buf_init_copy_from_cursor(&key_pair_impl->base.pub, allocator, key);

    struct aws_der_decoder *decoder = aws_der_decoder_new(allocator, key);

    if (!decoder) {
        goto on_error;
    }

    struct s_rsa_public_key_pkcs1 public_key_data = {0};
    if (aws_der_decoder_load_public_rsa_pkcs1(decoder, &public_key_data)) {
        goto on_error;
    }

    /* Hard to predict final blob size, so use pkcs1 key size as upper bound. */
    size_t total_buffer_size = key.len + sizeof(BCRYPT_RSAKEY_BLOB);

    if (aws_byte_buf_init(&key_pair_impl->key_buf, allocator, total_buffer_size)) {
        goto on_error;
    }

    aws_byte_buf_secure_zero(&key_pair_impl->key_buf);

    BCRYPT_RSAKEY_BLOB key_blob;
    AWS_ZERO_STRUCT(key_blob);
    key_blob.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    key_blob.BitLength = (ULONG)public_key_data.modulus.len * 8;
    key_blob.cbPublicExp = (ULONG)public_key_data.publicExponent.len;
    key_blob.cbModulus = (ULONG)public_key_data.modulus.len;

    struct aws_byte_cursor header = aws_byte_cursor_from_array(&key_blob, sizeof(key_blob));
    aws_byte_buf_append(&key_pair_impl->key_buf, &header);

    LPCWSTR blob_type = BCRYPT_PUBLIC_KEY_BLOB;
    ULONG flags = 0;

    aws_byte_buf_append(&key_pair_impl->key_buf, &public_key_data.publicExponent);
    aws_byte_buf_append(&key_pair_impl->key_buf, &public_key_data.modulus);

    NTSTATUS status = BCryptImportKeyPair(
        s_rsa_alg,
        NULL,
        blob_type,
        &key_pair_impl->key_handle,
        key_pair_impl->key_buf.buffer,
        (ULONG)key_pair_impl->key_buf.len,
        flags);

    if (!BCRYPT_SUCCESS(status)) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto on_error;
    }

    key_pair_impl->base.vtable = &s_rsa_key_pair_vtable;
    key_pair_impl->base.key_size_in_bits = public_key_data.modulus.len * 8;
    key_pair_impl->base.good = true;

    aws_der_decoder_destroy(decoder);

    return &key_pair_impl->base;

on_error:
    aws_der_decoder_destroy(decoder);
    aws_byte_buf_clean_up_secure(&key_pair_impl->base.priv);
    aws_byte_buf_clean_up_secure(&key_pair_impl->base.pub);
    s_rsa_destroy_key(&key_pair_impl->base);
    return NULL;
}
