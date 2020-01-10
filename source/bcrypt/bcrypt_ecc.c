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
#include <aws/cal/der.h>

#include <aws/common/thread.h>

#include <windows.h>

#include <bcrypt.h>

#include <winerror.h>

static BCRYPT_ALG_HANDLE s_ecdsa_p256_alg = NULL;
static BCRYPT_ALG_HANDLE s_ecdsa_p384_alg = NULL;
static BCRYPT_ALG_HANDLE s_ecdsa_p521_alg = NULL;

/* size of the P521 curve's signatures. This is the largest we support at the moment.
   Since msvc doesn't support variable length arrays, we need to handle this with a macro. */
#define MAX_SIGNATURE_LENGTH (68 * 2)

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

static ULONG s_get_magic_from_curve_name(enum aws_ecc_curve_name curve_name, bool private_key) {
    switch (curve_name) {
        case AWS_CAL_ECDSA_P256:
            return private_key ? BCRYPT_ECDSA_PRIVATE_P256_MAGIC : BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        case AWS_CAL_ECDSA_P384:
            return private_key ? BCRYPT_ECDSA_PRIVATE_P384_MAGIC : BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
        case AWS_CAL_ECDSA_P521:
            return private_key ? BCRYPT_ECDSA_PRIVATE_P521_MAGIC : BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
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

    uint8_t temp_signature[MAX_SIGNATURE_LENGTH] = {0};
    struct aws_byte_buf temp_signature_buf = aws_byte_buf_from_empty_array(temp_signature, sizeof(temp_signature));
    size_t signature_length = temp_signature_buf.capacity;

    NTSTATUS status = BCryptSignHash(
        key_impl->key_handle,
        NULL,
        message->ptr,
        (ULONG)message->len,
        temp_signature_buf.buffer,
        (ULONG)signature_length,
        (ULONG *)&signature_length,
        0);

    if (status != 0) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    temp_signature_buf.len += signature_length;
    size_t coordinate_len = temp_signature_buf.len / 2;

    /* okay. Windows doesn't DER encode this to ASN.1, so we need to do it manually. */
    struct aws_der_encoder encoder;
    if (aws_der_encoder_init(&encoder, key_pair->allocator, signature_output->capacity - signature_output->len)) {
        return AWS_OP_ERR;
    }

    aws_der_encoder_begin_sequence(&encoder);
    struct aws_byte_cursor integer_cur = aws_byte_cursor_from_array(temp_signature_buf.buffer, coordinate_len);
    aws_der_encoder_write_integer(&encoder, integer_cur);
    integer_cur = aws_byte_cursor_from_array(temp_signature_buf.buffer + coordinate_len, coordinate_len);
    aws_der_encoder_write_integer(&encoder, integer_cur);
    aws_der_encoder_end_sequence(&encoder);

    struct aws_byte_cursor signature_out_cur;
    AWS_ZERO_STRUCT(signature_out_cur);
    aws_der_encoder_get_contents(&encoder, &signature_out_cur);
    aws_byte_buf_append(signature_output, &signature_out_cur);
    aws_der_encoder_clean_up(&encoder);

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
        (ULONG)key_pair->key_buf.capacity,
        &result,
        0);
    key_pair->key_buf.len = result;
    (void)result;
    (void)status;

    return AWS_OP_SUCCESS;
}

static int s_verify_signature_fn(
    const struct aws_ecc_key_pair *key_pair,
    const struct aws_byte_cursor *message,
    const struct aws_byte_cursor *signature) {
    struct bcrypt_ecc_key_pair *key_impl = key_pair->impl;

    /* OKAY Windows doesn't do the whole standard internet formats thing. So we need to manually decode
       the DER encoded ASN.1 format first.*/
    uint8_t temp_signature[MAX_SIGNATURE_LENGTH] = {0};
    struct aws_byte_buf temp_signature_buf = aws_byte_buf_from_empty_array(temp_signature, sizeof(temp_signature));

    struct aws_byte_buf der_encoded_signature = aws_byte_buf_from_array(signature->ptr, signature->len);

    struct aws_der_decoder decoder;
    if (aws_der_decoder_init(&decoder, key_pair->allocator, &der_encoded_signature)) {
        return AWS_OP_ERR;
    }

    if (aws_der_decoder_parse(&decoder)) {
        goto error;
    }

    if (!aws_der_decoder_next(&decoder) || aws_der_decoder_tlv_type(&decoder) != AWS_DER_SEQUENCE) {
        aws_raise_error(AWS_CAL_ERROR_MALFORMED_ASN1_ENCOUNTERED);
        goto error;
    }

    if (!aws_der_decoder_next(&decoder) || aws_der_decoder_tlv_type(&decoder) != AWS_DER_INTEGER) {
        aws_raise_error(AWS_CAL_ERROR_MALFORMED_ASN1_ENCOUNTERED);
        goto error;
    }

    /* there will be two coordinates. They need to be concatenated together. */
    struct aws_byte_cursor coordinate;
    AWS_ZERO_STRUCT(coordinate);
    aws_der_decoder_tlv_integer(&decoder, &coordinate);
    aws_byte_buf_append(&temp_signature_buf, &coordinate);

    if (!aws_der_decoder_next(&decoder) || aws_der_decoder_tlv_type(&decoder) != AWS_DER_INTEGER) {
        return aws_raise_error(AWS_CAL_ERROR_MALFORMED_ASN1_ENCOUNTERED);
    }
    AWS_ZERO_STRUCT(coordinate);
    aws_der_decoder_tlv_integer(&decoder, &coordinate);
    aws_byte_buf_append(&temp_signature_buf, &coordinate);

    aws_der_decoder_clean_up(&decoder);

    /* okay, now we've got a windows compatible signature, let's verify it. */
    NTSTATUS status = BCryptVerifySignature(
        key_impl->key_handle,
        NULL,
        message->ptr,
        (ULONG)message->len,
        temp_signature_buf.buffer,
        (ULONG)temp_signature_buf.len,
        0);

    return status == 0 ? AWS_OP_SUCCESS : aws_raise_error(AWS_CAL_ERROR_SIGNATURE_VALIDATION_FAILED);

error:
    aws_der_decoder_clean_up(&decoder);
    return AWS_OP_ERR;
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
        aws_raise_error(AWS_CAL_ERROR_INVALID_KEY_LENGTH_FOR_ALGORITHM);
        goto error;
    }

    size_t total_buffer_size = s_key_coordinate_size * 3 + sizeof(BCRYPT_ECCKEY_BLOB);

    if (aws_byte_buf_init(&key_impl->key_pair.key_buf, allocator, total_buffer_size)) {
        goto error;
    }

    aws_byte_buf_secure_zero(&key_impl->key_pair.key_buf);

    BCRYPT_ECCKEY_BLOB key_blob;
    AWS_ZERO_STRUCT(key_blob);
    key_blob.dwMagic = s_get_magic_from_curve_name(curve_name, priv_key && priv_key->len);
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

struct aws_ecc_key_pair *aws_ecc_key_pair_new_generate_random(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name) {
    aws_thread_call_once(&s_ecdsa_thread_once, s_load_alg_handle, NULL);

    struct bcrypt_ecc_key_pair *key_impl = aws_mem_calloc(allocator, 1, sizeof(struct bcrypt_ecc_key_pair));

    if (!key_impl) {
        return NULL;
    }

    key_impl->key_pair.allocator = allocator;
    key_impl->key_pair.curve_name = curve_name;
    key_impl->key_pair.impl = key_impl;
    key_impl->key_pair.vtable = &s_vtable;

    size_t key_coordinate_size = s_key_coordinate_byte_size_from_curve_name(curve_name);

    if (!key_coordinate_size) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto error;
    }

    BCRYPT_ALG_HANDLE alg_handle = s_key_alg_handle_from_curve_name(curve_name);

    ULONG key_bit_length = (ULONG)key_coordinate_size * 8;
    NTSTATUS status = BCryptGenerateKeyPair(alg_handle, &key_impl->key_handle, key_bit_length, 0);
    status = BCryptFinalizeKeyPair(key_impl->key_handle, 0);
    (status);
    size_t total_buffer_size = key_coordinate_size * 3 + sizeof(BCRYPT_ECCKEY_BLOB);

    if (aws_byte_buf_init(&key_impl->key_pair.key_buf, allocator, total_buffer_size)) {
        goto error;
    }

    aws_byte_buf_secure_zero(&key_impl->key_pair.key_buf);

    key_impl->key_pair.pub_x.buffer = key_impl->key_pair.key_buf.buffer + sizeof(BCRYPT_ECCKEY_BLOB);
    key_impl->key_pair.pub_x.len = key_impl->key_pair.pub_x.capacity = key_coordinate_size;

    key_impl->key_pair.pub_y.buffer = key_impl->key_pair.pub_x.buffer + key_coordinate_size;
    key_impl->key_pair.pub_y.len = key_impl->key_pair.pub_y.capacity = key_coordinate_size;

    key_impl->key_pair.priv_d.buffer = key_impl->key_pair.pub_y.buffer + key_coordinate_size;
    key_impl->key_pair.priv_d.len = key_impl->key_pair.priv_d.capacity = key_coordinate_size;

    if (s_derive_public_key_fn(&key_impl->key_pair)) {
        goto error;
    }

    return &key_impl->key_pair;

error:
    s_destroy_key_fn(&key_impl->key_pair);
    return NULL;
}

struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_asn1(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *encoded_keys) {
    struct aws_der_decoder decoder;

    struct aws_byte_buf key_buf = aws_byte_buf_from_array(encoded_keys->ptr, encoded_keys->len);
    if (aws_der_decoder_init(&decoder, allocator, &key_buf)) {
        goto error;
    }

    if (aws_der_decoder_parse(&decoder)) {
        goto error;
    }

    /* we could have private key or a public key, or a full pair. */
    struct aws_byte_cursor pair_part_1;
    AWS_ZERO_STRUCT(pair_part_1);
    struct aws_byte_cursor pair_part_2;
    AWS_ZERO_STRUCT(pair_part_2);
    struct aws_byte_cursor oid;
    AWS_ZERO_STRUCT(oid);

    /* work with this pointer and move it to the next after using it. We need
     * to know which curve we're dealing with before we can figure out which is which. */
    struct aws_byte_cursor *current_part = &pair_part_1;

    while (aws_der_decoder_next(&decoder)) {
        enum aws_der_type type = aws_der_decoder_tlv_type(&decoder);

        if (type == AWS_DER_OBJECT_IDENTIFIER) {
            aws_der_decoder_tlv_blob(&decoder, &oid);
            continue;
        }

        /* you'd think we'd get some type hints on which key this is, but it's not consistent
         * as far as I can tell. */
        if (type == AWS_DER_BIT_STRING || type == AWS_DER_OCTET_STRING) {
            aws_der_decoder_tlv_string(&decoder, current_part);
            current_part = &pair_part_2;
        }
    }

    if (!(oid.ptr && oid.len)) {
        aws_raise_error(AWS_CAL_ERROR_MALFORMED_ASN1_ENCOUNTERED);
        goto error;
    }

    /* we only know about 3 curves at the moment, it had better be one of those. */
    enum aws_ecc_curve_name curve_name;
    if (aws_ecc_curve_name_from_oid(&oid, &curve_name)) {
        goto error;
    }

    size_t key_coordinate_size = s_key_coordinate_byte_size_from_curve_name(curve_name);

    struct aws_byte_cursor *private_key = NULL;
    struct aws_byte_cursor *public_key = NULL;

    size_t public_key_blob_size = key_coordinate_size * 2 + 1;

    if (pair_part_1.ptr && pair_part_1.len) {
        if (pair_part_1.len == key_coordinate_size) {
            private_key = &pair_part_1;
        } else if (pair_part_1.len == public_key_blob_size) {
            public_key = &pair_part_1;
        }
    }

    if (pair_part_2.ptr && pair_part_2.len) {
        if (pair_part_2.len == key_coordinate_size) {
            private_key = &pair_part_2;
        } else if (pair_part_2.len == public_key_blob_size) {
            public_key = &pair_part_2;
        }
    }

    if (!private_key && !public_key) {
        aws_raise_error(AWS_CAL_ERROR_MISSING_REQUIRED_KEY_COMPONENT);
        goto error;
    }

    struct aws_byte_cursor pub_x_cur;
    struct aws_byte_cursor pub_y_cur;
    struct aws_byte_cursor *pub_x = NULL;
    struct aws_byte_cursor *pub_y = NULL;

    if (public_key) {
        aws_byte_cursor_advance(public_key, 1);
        pub_x_cur = *public_key;
        pub_x_cur.len = key_coordinate_size;
        pub_y_cur.ptr = public_key->ptr + key_coordinate_size;
        pub_y_cur.len = key_coordinate_size;
        pub_x = &pub_x_cur;
        pub_y = &pub_y_cur;
    }

    /* now that we have the buffers, we can just use the normal code path. */
    struct aws_ecc_key_pair *key_pair = s_alloc_pair_and_init_buffers(allocator, curve_name, pub_x, pub_y, private_key);
    aws_der_decoder_clean_up(&decoder);

    return key_pair;
error:
    aws_der_decoder_clean_up(&decoder);
    return NULL;
}
