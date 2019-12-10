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
#include <Security/SecKey.h>
#include <Security/SecSignVerifyTransform.h>
#include <Security/Security.h>
#include <aws/cal/ecc.h>

struct commoncrypto_ecc_key_pair {
    struct aws_ecc_key_pair key_pair;
    SecKeyRef priv_key_ref;
    SecKeyRef pub_key_ref;
    CFAllocatorRef cf_allocator;
};

size_t s_key_coordinate_byte_size_from_curve_name(enum aws_ecc_curve_name curve_name) {
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

static uint8_t s_preamble[] = {
    0x04,
};

static size_t s_der_overhead = 8;

static int s_sign_message_fn(
    const struct aws_ecc_key_pair *key_pair,
    const struct aws_byte_cursor *message,
    struct aws_byte_buf *signature_output) {
    struct commoncrypto_ecc_key_pair *cc_key = key_pair->impl;

    CFDataRef hash_ref =
        CFDataCreateWithBytesNoCopy(cc_key->cf_allocator, message->ptr, message->len, kCFAllocatorNull);

    CFErrorRef error = NULL;
    CFDataRef signature =
        SecKeyCreateSignature(cc_key->priv_key_ref, kSecKeyAlgorithmECDSASignatureDigestX962, hash_ref, &error);

    struct aws_byte_cursor to_write =
        aws_byte_cursor_from_array(CFDataGetBytePtr(signature), CFDataGetLength(signature));
    aws_byte_buf_append(signature_output, &to_write);

    CFRelease(signature);
    CFRelease(hash_ref);

    (void)error;
    return AWS_OP_SUCCESS;
}

static size_t s_signature_length_fn(const struct aws_ecc_key_pair *key_pair) {
    return s_key_coordinate_byte_size_from_curve_name(key_pair->curve_name) * 2 + s_der_overhead;
}

static int s_verify_signature_fn(
    const struct aws_ecc_key_pair *key_pair,
    const struct aws_byte_cursor *message,
    const struct aws_byte_cursor *signature) {
    struct commoncrypto_ecc_key_pair *cc_key = key_pair->impl;

    CFDataRef hash_ref =
        CFDataCreateWithBytesNoCopy(cc_key->cf_allocator, message->ptr, message->len, kCFAllocatorNull);
    CFDataRef signature_ref =
        CFDataCreateWithBytesNoCopy(cc_key->cf_allocator, signature->ptr, signature->len, kCFAllocatorNull);

    CFErrorRef error = NULL;

    bool verified = SecKeyVerifySignature(
        cc_key->pub_key_ref, kSecKeyAlgorithmECDSASignatureDigestX962, hash_ref, signature_ref, &error);

    CFRelease(signature_ref);
    CFRelease(hash_ref);

    return verified ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

static int s_derive_public_key_fn(struct aws_ecc_key_pair *key_pair) {
    return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
}

static void s_destroy_key_fn(struct aws_ecc_key_pair *key_pair) {
    struct commoncrypto_ecc_key_pair *cc_key = key_pair->impl;

    if (cc_key->pub_key_ref) {
        CFRelease(cc_key->pub_key_ref);
    }

    if (cc_key->priv_key_ref) {
        CFRelease(cc_key->priv_key_ref);
    }

    aws_byte_buf_clean_up_secure(&key_pair->key_buf);
    aws_mem_release(key_pair->allocator, cc_key);
}

static struct aws_ecc_key_pair_vtable s_key_pair_vtable = {
    .sign_message_fn = s_sign_message_fn,
    .signature_length_fn = s_signature_length_fn,
    .verify_signature_fn = s_verify_signature_fn,
    .derive_pub_key_fn = s_derive_public_key_fn,
    .destroy_fn = s_destroy_key_fn,
};

static struct commoncrypto_ecc_key_pair *s_alloc_pair_and_init_buffers(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *pub_x,
    const struct aws_byte_cursor *pub_y,
    const struct aws_byte_cursor *priv_key) {
    struct commoncrypto_ecc_key_pair *cc_key_pair =
        aws_mem_calloc(allocator, 1, sizeof(struct commoncrypto_ecc_key_pair));

    if (!cc_key_pair) {
        return NULL;
    }

    cc_key_pair->cf_allocator = aws_wrapped_cf_allocator_new(allocator);

    size_t s_key_coordinate_size = s_key_coordinate_byte_size_from_curve_name(curve_name);

    if (!s_key_coordinate_size) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto error;
    }

    if ((pub_x && pub_x->len != s_key_coordinate_size) || (pub_y && pub_y->len != s_key_coordinate_size) ||
        (priv_key && priv_key->len != s_key_coordinate_size)) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto error;
    }

    size_t total_buffer_size = s_key_coordinate_size * 3 + 1;

    if (aws_byte_buf_init(&cc_key_pair->key_pair.key_buf, allocator, total_buffer_size)) {
        goto error;
    }

    aws_byte_buf_secure_zero(&cc_key_pair->key_pair.key_buf);

    struct aws_byte_cursor to_append = aws_byte_cursor_from_array(s_preamble, sizeof(s_preamble));
    aws_byte_buf_append(&cc_key_pair->key_pair.key_buf, &to_append);

    if (pub_x && pub_y) {
        aws_byte_buf_append(&cc_key_pair->key_pair.key_buf, pub_x);
        aws_byte_buf_append(&cc_key_pair->key_pair.key_buf, pub_y);
    } else {
        cc_key_pair->key_pair.key_buf.len += s_key_coordinate_size * 2;
    }

    if (priv_key) {
        aws_byte_buf_append(&cc_key_pair->key_pair.key_buf, priv_key);
    }

    cc_key_pair->key_pair.impl = cc_key_pair;
    cc_key_pair->key_pair.allocator = allocator;

    cc_key_pair->key_pair.pub_x.buffer = cc_key_pair->key_pair.key_buf.buffer + 1;
    cc_key_pair->key_pair.pub_x.len = s_key_coordinate_size;

    cc_key_pair->key_pair.pub_y.buffer = cc_key_pair->key_pair.pub_x.buffer + s_key_coordinate_size;
    cc_key_pair->key_pair.pub_y.len = s_key_coordinate_size;

    cc_key_pair->key_pair.priv_d.buffer = cc_key_pair->key_pair.pub_y.buffer + s_key_coordinate_size;
    cc_key_pair->key_pair.priv_d.len = s_key_coordinate_size;
    cc_key_pair->key_pair.vtable = &s_key_pair_vtable;

    return cc_key_pair;

error:
    s_destroy_key_fn(&cc_key_pair->key_pair);
    return NULL;
}

struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_private_key(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *priv_key) {
    struct commoncrypto_ecc_key_pair *cc_key_pair =
        s_alloc_pair_and_init_buffers(allocator, curve_name, NULL, NULL, priv_key);

    if (!cc_key_pair) {
        return NULL;
    }

    CFDataRef private_key_data = CFDataCreate(
        cc_key_pair->cf_allocator, cc_key_pair->key_pair.key_buf.buffer, cc_key_pair->key_pair.key_buf.len);
    CFMutableDictionaryRef key_attributes = CFDictionaryCreateMutable(cc_key_pair->cf_allocator, 6, NULL, NULL);
    CFDictionaryAddValue(key_attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionaryAddValue(key_attributes, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFIndex key_size_bits = cc_key_pair->key_pair.priv_d.len * 8;
    CFDictionaryAddValue(key_attributes, kSecAttrKeySizeInBits, &key_size_bits);
    CFDictionaryAddValue(key_attributes, kSecAttrCanSign, kCFBooleanTrue);
    CFDictionaryAddValue(key_attributes, kSecAttrCanVerify, kCFBooleanFalse);
    CFDictionaryAddValue(key_attributes, kSecAttrCanDerive, kCFBooleanTrue);

    CFErrorRef error = NULL;

    cc_key_pair->priv_key_ref = SecKeyCreateWithData(private_key_data, key_attributes, &error);

    CFRelease(key_attributes);
    CFRelease(private_key_data);

    if (error) {
        CFRelease(error);
        goto error;
    }

    return &cc_key_pair->key_pair;

error:
    s_destroy_key_fn(&cc_key_pair->key_pair);
    return NULL;
}

struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_public_key(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *public_key_x,
    const struct aws_byte_cursor *public_key_y) {
    struct commoncrypto_ecc_key_pair *cc_key_pair =
        s_alloc_pair_and_init_buffers(allocator, curve_name, public_key_x, public_key_y, NULL);

    if (!cc_key_pair) {
        return NULL;
    }

    CFDataRef pub_key_data = CFDataCreate(
        cc_key_pair->cf_allocator, cc_key_pair->key_pair.key_buf.buffer, cc_key_pair->key_pair.key_buf.len);
    CFMutableDictionaryRef key_attributes = CFDictionaryCreateMutable(cc_key_pair->cf_allocator, 6, NULL, NULL);
    CFDictionaryAddValue(key_attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionaryAddValue(key_attributes, kSecAttrKeyClass, kSecAttrKeyClassPublic);
    CFIndex key_size_bits = cc_key_pair->key_pair.pub_x.len * 8;
    CFDictionaryAddValue(key_attributes, kSecAttrKeySizeInBits, &key_size_bits);
    CFDictionaryAddValue(key_attributes, kSecAttrCanSign, kCFBooleanFalse);
    CFDictionaryAddValue(key_attributes, kSecAttrCanVerify, kCFBooleanTrue);
    CFDictionaryAddValue(key_attributes, kSecAttrCanDerive, kCFBooleanFalse);

    CFErrorRef error = NULL;

    cc_key_pair->pub_key_ref = SecKeyCreateWithData(pub_key_data, key_attributes, &error);

    CFRelease(key_attributes);
    CFRelease(pub_key_data);

    if (error) {
        CFRelease(error);
        goto error;
    }

    return &cc_key_pair->key_pair;

error:
    s_destroy_key_fn(&cc_key_pair->key_pair);
    return NULL;
}
