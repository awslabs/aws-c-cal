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
#include <aws/cal/cal.h>
#include <aws/cal/der.h>
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

    if (!cc_key->priv_key_ref) {
        return aws_raise_error(AWS_ERROR_CAL_MISSING_REQUIRED_KEY_COMPONENT);
    }

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

    if (!cc_key->pub_key_ref) {
        return aws_raise_error(AWS_ERROR_CAL_MISSING_REQUIRED_KEY_COMPONENT);
    }

    CFDataRef hash_ref =
        CFDataCreateWithBytesNoCopy(cc_key->cf_allocator, message->ptr, message->len, kCFAllocatorNull);
    CFDataRef signature_ref =
        CFDataCreateWithBytesNoCopy(cc_key->cf_allocator, signature->ptr, signature->len, kCFAllocatorNull);

    CFErrorRef error = NULL;

    bool verified = SecKeyVerifySignature(
        cc_key->pub_key_ref, kSecKeyAlgorithmECDSASignatureDigestX962, hash_ref, signature_ref, &error);

    CFRelease(signature_ref);
    CFRelease(hash_ref);

    return verified ? AWS_OP_SUCCESS : aws_raise_error(AWS_ERROR_CAL_SIGNATURE_VALIDATION_FAILED);
}

static int s_derive_public_key_fn(struct aws_ecc_key_pair *key_pair) {
    /* we already have a public key, just lie and tell them we succeeded */
    if (key_pair->pub_x.buffer && key_pair->pub_x.len) {
        return AWS_OP_SUCCESS;
    }

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

    if (pub_x) {
        cc_key_pair->key_pair.pub_x.buffer = cc_key_pair->key_pair.key_buf.buffer + 1;
        cc_key_pair->key_pair.pub_x.len = s_key_coordinate_size;

        cc_key_pair->key_pair.pub_y.buffer = cc_key_pair->key_pair.pub_x.buffer + s_key_coordinate_size;
        cc_key_pair->key_pair.pub_y.len = s_key_coordinate_size;
    }

    cc_key_pair->key_pair.priv_d.buffer = cc_key_pair->key_pair.key_buf.buffer + 1 + (s_key_coordinate_size * 2);
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

struct aws_ecc_key_pair *aws_ecc_key_pair_new_generate_random(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name) {
    struct commoncrypto_ecc_key_pair *cc_key_pair =
        aws_mem_calloc(allocator, 1, sizeof(struct commoncrypto_ecc_key_pair));

    if (!cc_key_pair) {
        return NULL;
    }

    CFDataRef sec_key_export_data = NULL;
    CFStringRef key_size_cf_str = NULL;

    cc_key_pair->cf_allocator = aws_wrapped_cf_allocator_new(allocator);
    cc_key_pair->key_pair.allocator = allocator;

    size_t key_coordinate_size = s_key_coordinate_byte_size_from_curve_name(curve_name);

    if (!key_coordinate_size) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto error;
    }

    size_t total_buffer_size = key_coordinate_size * 3 + 1;

    if (aws_byte_buf_init(&cc_key_pair->key_pair.key_buf, allocator, total_buffer_size)) {
        goto error;
    }

    aws_byte_buf_secure_zero(&cc_key_pair->key_pair.key_buf);

    CFMutableDictionaryRef key_attributes = CFDictionaryCreateMutable(cc_key_pair->cf_allocator, 6, NULL, NULL);
    CFDictionaryAddValue(key_attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionaryAddValue(key_attributes, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFIndex key_size_bits = key_coordinate_size * 8;
    char key_size_str[32] = {0};
    snprintf(key_size_str, sizeof(key_size_str), "%d", (int)key_size_bits);
    key_size_cf_str = CFStringCreateWithCString(cc_key_pair->cf_allocator, key_size_str, kCFStringEncodingASCII);
    CFDictionaryAddValue(key_attributes, kSecAttrKeySizeInBits, key_size_cf_str);

    CFErrorRef error = NULL;

    cc_key_pair->priv_key_ref = SecKeyCreateRandomKey(key_attributes, &error);
    cc_key_pair->pub_key_ref = SecKeyCopyPublicKey(cc_key_pair->priv_key_ref);
    CFRelease(key_attributes);

    /* OKAY up to here was incredibly reasonable, after this we get attacked by the bad API design
     * dragons.
     *
     * Summary: Apple assumed we'd never need the raw key data. Apple was wrong. So we have to export each component
     * into the OpenSSL format (just fancy words for DER), but the public key and private key are exported separately
     * for some reason. Anyways, we export the keys, use our handy dandy DER decoder and grab the raw key data out. */
    OSStatus ret_code = SecItemExport(cc_key_pair->priv_key_ref, kSecFormatOpenSSL, 0, NULL, &sec_key_export_data);

    if (ret_code != errSecSuccess) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto error;
    }

    /* now we need to DER decode data */
    struct aws_der_decoder decoder;
    struct aws_byte_cursor key_cur =
        aws_byte_buf_from_array(CFDataGetBytePtr(sec_key_export_data), CFDataGetLength(sec_key_export_data));

    if (aws_der_decoder_init(&decoder, allocator, key_cur)) {
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
            if (aws_der_decoder_tlv_blob(&decoder, &oid)) {
                aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
                goto error;
            }
            continue;
        }

        /* you'd think we'd get some type hints on which key this is, but it's not consistent
         * as far as I can tell. */
        if (type == AWS_DER_BIT_STRING || type == AWS_DER_OCTET_STRING) {
            if (aws_der_decoder_tlv_string(&decoder, current_part)) {
                aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
                goto error;
            }
            current_part = &pair_part_2;
            continue;
        }
    }

    /* we only know about 3 curves at the moment, it had better be one of those. */
    enum aws_ecc_curve_name exported_curve_name;
    AWS_ASSERT(
        !aws_ecc_curve_name_from_oid(&oid, &exported_curve_name) && exported_curve_name == curve_name &&
        "If this assertion pops, just set your computer on fire and give up on this industry having any sanity.");

    (void)exported_curve_name;

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

    AWS_ASSERT(private_key && public_key && "Apple Security Framework had better have exported the full pair.");
    aws_byte_buf_append(&cc_key_pair->key_pair.key_buf, public_key);
    aws_byte_buf_append(&cc_key_pair->key_pair.key_buf, private_key);

    aws_der_decoder_clean_up(&decoder);
    CFRelease(sec_key_export_data);
    CFRelease(key_size_cf_str);

    if (cc_key_pair->key_pair.key_buf.len < key_coordinate_size * 3 + 1) {
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto error;
    }

    /* cc_key_pair->key_pair.key_buf is contiguous memory, so just load up the offsets. */
    cc_key_pair->key_pair.pub_x =
        aws_byte_buf_from_array(cc_key_pair->key_pair.key_buf.buffer + 1, key_coordinate_size);
    cc_key_pair->key_pair.pub_y =
        aws_byte_buf_from_array(cc_key_pair->key_pair.pub_x.buffer + key_coordinate_size, key_coordinate_size);
    cc_key_pair->key_pair.priv_d =
        aws_byte_buf_from_array(cc_key_pair->key_pair.pub_y.buffer + key_coordinate_size, key_coordinate_size);

    cc_key_pair->key_pair.impl = cc_key_pair;
    cc_key_pair->key_pair.allocator = allocator;
    cc_key_pair->key_pair.vtable = &s_key_pair_vtable;

    if (error) {
        CFRelease(error);
        goto error;
    }

    return &cc_key_pair->key_pair;

error:
    if (sec_key_export_data) {
        CFRelease(sec_key_export_data);
    }

    if (key_size_cf_str) {
        CFRelease(key_size_cf_str);
    }

    s_destroy_key_fn(&cc_key_pair->key_pair);
    return NULL;
}

struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_asn1(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *encoded_keys) {

    struct aws_der_decoder decoder;

    struct aws_byte_cursor key_cur = aws_byte_cursor_from_array(encoded_keys->ptr, encoded_keys->len);
    if (aws_der_decoder_init(&decoder, allocator, key_cur)) {
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
        aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
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
        aws_raise_error(AWS_ERROR_CAL_MISSING_REQUIRED_KEY_COMPONENT);
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

    struct commoncrypto_ecc_key_pair *cc_key_pair =
        s_alloc_pair_and_init_buffers(allocator, curve_name, pub_x, pub_y, private_key);

    CFDataRef key_data = CFDataCreate(
        cc_key_pair->cf_allocator, cc_key_pair->key_pair.key_buf.buffer, cc_key_pair->key_pair.key_buf.len);

    CFMutableDictionaryRef key_attributes = CFDictionaryCreateMutable(cc_key_pair->cf_allocator, 6, NULL, NULL);
    CFDictionaryAddValue(key_attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);

    if (private_key) {
        CFDictionaryAddValue(key_attributes, kSecAttrKeyClass, kSecAttrKeyClassPrivate);

        CFDictionaryAddValue(key_attributes, kSecAttrCanSign, kCFBooleanTrue);
        CFDictionaryAddValue(key_attributes, kSecAttrCanDerive, kCFBooleanTrue);

        if (public_key) {
            CFDictionaryAddValue(key_attributes, kSecAttrCanVerify, kCFBooleanTrue);
        }
    } else if (public_key) {
        CFDictionaryAddValue(key_attributes, kSecAttrKeyClass, kSecAttrKeyClassPublic);
        CFDictionaryAddValue(key_attributes, kSecAttrCanSign, kCFBooleanFalse);
        CFDictionaryAddValue(key_attributes, kSecAttrCanVerify, kCFBooleanTrue);
    }

    CFErrorRef error = NULL;

    cc_key_pair->priv_key_ref = SecKeyCreateWithData(key_data, key_attributes, &error);

    if (public_key) {
        cc_key_pair->pub_key_ref = SecKeyCopyPublicKey(cc_key_pair->priv_key_ref);
    }

    CFRelease(key_attributes);
    CFRelease(key_data);
    aws_der_decoder_clean_up(&decoder);

    return cc_key_pair->key_pair.impl;

error:
    aws_der_decoder_clean_up(&decoder);
    return NULL;
}
