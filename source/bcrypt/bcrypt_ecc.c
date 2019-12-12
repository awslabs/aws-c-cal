/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/cal/ecc.h>

#include <aws/cal/cal.h>

#include <aws/common/thread.h>

#include <windows.h>

#include <bcrypt.h>
#include <winerror.h>

static BCRYPT_ALG_HANDLE s_ecdsa_p256_alg = NULL;
static BCRYPT_ALG_HANDLE s_ecdsa_p384_alg = NULL;
static BCRYPT_ALG_HANDLE s_ecdsa_p521_alg = NULL;

static aws_thread_once s_ecdsa_thread_once = AWS_THREAD_ONCE_STATIC_INIT;

static void s_load_alg_handle(void *user_data) {
    (void)user_data;
    /* this function is incredibly slow, LET IT LEAK*/
    NTSTATUS status =
        BCryptOpenAlgorithmProvider(&s_ecdsa_p256_alg, BCRYPT_ECDSA_P256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    AWS_ASSERT(s_ecdsa_p256_alg);

    status = BCryptOpenAlgorithmProvider(&s_ecdsa_p384_alg, BCRYPT_ECDSA_P384_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    AWS_ASSERT(s_ecdsa_p384_alg);

    status = BCryptOpenAlgorithmProvider(&s_ecdsa_p521_alg, BCRYPT_ECDSA_P521_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    AWS_ASSERT(s_ecdsa_p521_alg);

    (void)status;
}

struct bcrypt_ecc_key_pair {
    struct aws_ecc_key_pair key_pair;
    BCRYPT_KEY_HANDLE key_handle;
};

static size_t s_key_coordinate_byte_size_from_curve_name(enum aws_ecc_curve_name curve_name) {
    switch (curve_name) {
        case AWS_CAL_ECDSA_P256:
            return 32;
        case AWS_CAL_ECDSA_P384:
            return 48;
        case AWS_CAL_ECDSA_P521:
            return 68;
        default:
            return 0;
    }
}

static BCRYPT_ALG_HANDLE s_key_alg_handle_from_curve_name(enum aws_ecc_curve_name curve_name) {
    switch (curve_name) {
        case AWS_CAL_ECDSA_P256:
            return s_ecdsa_p256_alg;
        case AWS_CAL_ECDSA_P384:
            return s_ecdsa_p384_alg;
        case AWS_CAL_ECDSA_P521:
            return s_ecdsa_p521_alg;
        default:
            return 0;
    }
}

static void s_destroy_key_fn(struct aws_ecc_key_pair *key_pair) {
    struct bcrypt_ecc_key_pair *key_impl = key_pair->impl;

    if (key_impl->key_handle) {
        BCryptDestroyKey(key_impl->key_handle);
    }

    aws_byte_buf_clean_up_secure(&key_pair->key_buf);
    aws_mem_release(key_pair->allocator, key_impl);
}

static int s_sign_message_fn(
    const struct aws_ecc_key_pair *key_pair,
    const struct aws_byte_cursor *message,
    struct aws_byte_buf *signature_output) {
    struct bcrypt_ecc_key_pair *key_impl = key_pair->impl;

    size_t signature_length = signature_output->capacity - signature_output->len;

    /* TODO, the result of this needs to be DER encoded:
       0x30 <len of r|s plus padding> 0x02 <len of r plus padding if it's negative> <r with padding> 0x02
       < len of s plus padding > < s plus padding if it's negative > 
    */
    NTSTATUS status = BCryptSignHash(
        key_impl->key_handle,
        NULL,
        message->ptr,
        (ULONG)message->len,
        signature_output->buffer + signature_output->len,
        (ULONG)signature_length,
        (ULONG *)&signature_length,
        0);
    signature_output->len += signature_length;

    (void)status;

    return AWS_OP_SUCCESS;
}

static int s_derive_public_key_fn(struct aws_ecc_key_pair *key_pair) {
    struct bcrypt_ecc_key_pair *key_impl = key_pair->impl;

    ULONG result = 0;
    NTSTATUS status = BCryptExportKey(
        key_impl->key_handle,
        NULL,
        BCRYPT_ECCPRIVATE_BLOB,
        key_pair->key_buf.buffer,
        (ULONG)key_pair->key_buf.len,
        &result,
        0);

    (void)result;
    (void)status;

    return AWS_OP_SUCCESS;
}

static int s_verify_signature_fn(
    const struct aws_ecc_key_pair *key_pair,
    const struct aws_byte_cursor *message,
    const struct aws_byte_cursor *signature) {
    struct bcrypt_ecc_key_pair *key_impl = key_pair->impl;

    /* TODO, the signature  needs to be DER decoded:
      0x30 <len of r|s plus padding> 0x02 <len of r plus padding if it's negative> <r with padding> 0x02
      < len of s plus padding > < s plus padding if it's negative >
    */
    NTSTATUS status = BCryptVerifySignature(
        key_impl->key_handle, NULL, message->ptr, (ULONG)message->len, signature->ptr, (ULONG)signature->len, 0);

    return status == 0 ? AWS_OP_SUCCESS : aws_raise_error(AWS_CAL_SIGNATURE_VALIDATION_FAILED);
}

static size_t s_signature_length_fn(const struct aws_ecc_key_pair *key_pair) {
    static size_t s_der_overhead = 8;
    return s_der_overhead + s_key_coordinate_byte_size_from_curve_name(key_pair->curve_name) * 2;
}

static struct aws_ecc_key_pair_vtable s_vtable = {
    .destroy_fn = s_destroy_key_fn,
    .derive_pub_key_fn = s_derive_public_key_fn,
    .sign_message_fn = s_sign_message_fn,
    .verify_signature_fn = s_verify_signature_fn,
    .signature_length_fn = s_signature_length_fn,
};

static struct aws_ecc_key_pair *s_alloc_pair_and_init_buffers(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *pub_x,
    const struct aws_byte_cursor *pub_y,
    const struct aws_byte_cursor *priv_key) {

    aws_thread_call_once(&s_ecdsa_thread_once, s_load_alg_handle, NULL);

    struct bcrypt_ecc_key_pair *key_impl = aws_mem_calloc(allocator, 1, sizeof(struct bcrypt_ecc_key_pair));

    if (!key_impl) {
        return NULL;
    }

    key_impl->key_pair.allocator = allocator;
    key_impl->key_pair.curve_name = curve_name;
    key_impl->key_pair.impl = key_impl;
    key_impl->key_pair.vtable = &s_vtable;

    size_t s_key_coordinate_size = s_key_coordinate_byte_size_from_curve_name(curve_name);

    if (!s_key_coordinate_size) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto error;
    }

    if ((pub_x && pub_x->len != s_key_coordinate_size) || (pub_y && pub_y->len != s_key_coordinate_size) ||
        (priv_key && priv_key->len != s_key_coordinate_size)) {
        aws_raise_error(AWS_CAL_INVALID_KEY_LENGTH_FOR_ALGORITHM);
        goto error;
    }

    size_t total_buffer_size = s_key_coordinate_size * 3 + sizeof(BCRYPT_ECCKEY_BLOB);

    if (aws_byte_buf_init(&key_impl->key_pair.key_buf, allocator, total_buffer_size)) {
        goto error;
    }

    aws_byte_buf_secure_zero(&key_impl->key_pair.key_buf);

    BCRYPT_ECCKEY_BLOB key_blob;
    AWS_ZERO_STRUCT(key_blob);
    key_blob.dwMagic = BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC;
    key_blob.cbKey = (ULONG)s_key_coordinate_size;

    struct aws_byte_cursor header = aws_byte_cursor_from_array(&key_blob, sizeof(key_blob));
    aws_byte_buf_append(&key_impl->key_pair.key_buf, &header);

    LPCWSTR blob_type = BCRYPT_ECCPUBLIC_BLOB;
    ULONG flags = 0;
    if (pub_x && pub_y) {
        aws_byte_buf_append(&key_impl->key_pair.key_buf, pub_x);
        aws_byte_buf_append(&key_impl->key_pair.key_buf, pub_y);
    } else {
        key_impl->key_pair.key_buf.len += s_key_coordinate_size * 2;
        flags = BCRYPT_NO_KEY_VALIDATION;
    }

    if (priv_key) {
        blob_type = BCRYPT_ECCPRIVATE_BLOB;
        aws_byte_buf_append(&key_impl->key_pair.key_buf, priv_key);
    }

    key_impl->key_pair.pub_x.buffer = key_impl->key_pair.key_buf.buffer + sizeof(key_blob);
    key_impl->key_pair.pub_x.len = key_impl->key_pair.pub_x.capacity = s_key_coordinate_size;

    key_impl->key_pair.pub_y.buffer = key_impl->key_pair.pub_x.buffer + s_key_coordinate_size;
    key_impl->key_pair.pub_y.len = key_impl->key_pair.pub_y.capacity = s_key_coordinate_size;

    key_impl->key_pair.priv_d.buffer = key_impl->key_pair.pub_y.buffer + s_key_coordinate_size;
    key_impl->key_pair.priv_d.len = key_impl->key_pair.priv_d.capacity = s_key_coordinate_size;

    BCRYPT_ALG_HANDLE alg_handle = s_key_alg_handle_from_curve_name(curve_name);
    NTSTATUS status = BCryptImportKeyPair(
        alg_handle,
        NULL,
        blob_type,
        &key_impl->key_handle,
        key_impl->key_pair.key_buf.buffer,
        (ULONG)key_impl->key_pair.key_buf.len,
        flags);

    (void)status;

    return &key_impl->key_pair;

error:
    s_destroy_key_fn(&key_impl->key_pair);
    return NULL;
}

struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_private_key(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *priv_key) {

    return s_alloc_pair_and_init_buffers(allocator, curve_name, NULL, NULL, priv_key);
}

struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_public_key(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *public_key_x,
    const struct aws_byte_cursor *public_key_y) {

    return s_alloc_pair_and_init_buffers(allocator, curve_name, public_key_x, public_key_y, NULL);
}
