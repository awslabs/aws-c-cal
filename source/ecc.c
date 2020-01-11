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
#include <aws/cal/cal.h>
#include <aws/cal/ecc.h>

#define STATIC_INIT_BYTE_CURSOR(a, name)                                                                               \
    static struct aws_byte_cursor s_##name = {                                                                         \
        .ptr = (a),                                                                                                    \
        .len = sizeof(a),                                                                                              \
    };

static uint8_t s_p256_oid[] = {
    0x2A,
    0x86,
    0x48,
    0xCE,
    0x3D,
    0x03,
    0x01,
    0x07,
};
STATIC_INIT_BYTE_CURSOR(s_p256_oid, ecc_p256_oid)

static uint8_t s_p384_oid[] = {
    0x2B,
    0x81,
    0x04,
    0x00,
    0x22,
};
STATIC_INIT_BYTE_CURSOR(s_p384_oid, ecc_p384_oid)

static uint8_t s_p521_oid[] = {
    0x2B,
    0x81,
    0x04,
    0x00,
    0x23,
};
STATIC_INIT_BYTE_CURSOR(s_p521_oid, ecc_p521_oid)

static struct aws_byte_cursor *s_ecc_curve_oids[] = {
    [AWS_CAL_ECDSA_P256] = &s_ecc_p256_oid,
    [AWS_CAL_ECDSA_P384] = &s_ecc_p384_oid,
    [AWS_CAL_ECDSA_P521] = &s_ecc_p521_oid,
};

int aws_ecc_curve_name_from_oid(struct aws_byte_cursor *oid, enum aws_ecc_curve_name *curve_name) {
    if (aws_byte_cursor_eq(oid, &s_ecc_p256_oid)) {
        *curve_name = AWS_CAL_ECDSA_P256;
        return AWS_OP_SUCCESS;
    }

    if (aws_byte_cursor_eq(oid, &s_ecc_p384_oid)) {
        *curve_name = AWS_CAL_ECDSA_P384;
        return AWS_OP_SUCCESS;
    }

    if (aws_byte_cursor_eq(oid, &s_ecc_p521_oid)) {
        *curve_name = AWS_CAL_ECDSA_P521;
        return AWS_OP_SUCCESS;
    }

    return aws_raise_error(AWS_ERROR_CAL_UNKNOWN_OBJECT_IDENTIFIER);
}

int aws_ecc_oid_from_curve_name(enum aws_ecc_curve_name curve_name, struct aws_byte_cursor *oid) {
    AWS_ASSERT(curve_name <= AWS_CAL_ECDSA_P521);
    *oid = *s_ecc_curve_oids[curve_name];
    return AWS_OP_SUCCESS;
}

void aws_ecc_key_pair_destroy(struct aws_ecc_key_pair *key_pair) {
    AWS_FATAL_ASSERT(key_pair->vtable->destroy_fn && "ECC KEY PAIR destroy function must be included on the vtable");
    key_pair->vtable->destroy_fn(key_pair);
}

int aws_ecc_key_pair_derive_public_key(struct aws_ecc_key_pair *key_pair) {
    AWS_FATAL_ASSERT(
        key_pair->vtable->derive_pub_key_fn && "ECC KEY PAIR derive function must be included on the vtable");
    return key_pair->vtable->derive_pub_key_fn(key_pair);
}

int aws_ecc_key_pair_sign_message(
    const struct aws_ecc_key_pair *key_pair,
    const struct aws_byte_cursor *message,
    struct aws_byte_buf *signature) {
    AWS_FATAL_ASSERT(key_pair->vtable->sign_message_fn && "ECC KEY PAIR sign message must be included on the vtable");
    return key_pair->vtable->sign_message_fn(key_pair, message, signature);
}

int aws_ecc_key_pair_verify_signature(
    const struct aws_ecc_key_pair *key_pair,
    const struct aws_byte_cursor *message,
    const struct aws_byte_cursor *signature) {
    AWS_FATAL_ASSERT(
        key_pair->vtable->verify_signature_fn && "ECC KEY PAIR verify signature must be included on the vtable");
    return key_pair->vtable->verify_signature_fn(key_pair, message, signature);
}

size_t aws_ecc_key_pair_signature_length(const struct aws_ecc_key_pair *key_pair) {
    AWS_FATAL_ASSERT(
        key_pair->vtable->signature_length_fn && "ECC KEY PAIR signature length must be included on the vtable");
    return key_pair->vtable->signature_length_fn(key_pair);
}

void aws_ecc_key_pair_get_public_key(
    const struct aws_ecc_key_pair *key_pair,
    struct aws_byte_cursor *pub_x,
    struct aws_byte_cursor *pub_y) {
    *pub_x = aws_byte_cursor_from_buf(&key_pair->pub_x);
    *pub_y = aws_byte_cursor_from_buf(&key_pair->pub_y);
}

void aws_ecc_key_pair_get_private_key(const struct aws_ecc_key_pair *key_pair, struct aws_byte_cursor *private_d) {
    *private_d = aws_byte_cursor_from_buf(&key_pair->priv_d);
}
