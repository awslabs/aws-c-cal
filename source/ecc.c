/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/private/ecc.h>

#include <aws/cal/cal.h>
#include <aws/cal/private/der.h>
#include <aws/common/encoding.h>

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

static struct aws_byte_cursor *s_ecc_curve_oids[] = {
    [AWS_CAL_ECDSA_P256] = &s_ecc_p256_oid,
    [AWS_CAL_ECDSA_P384] = &s_ecc_p384_oid,
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

    return aws_raise_error(AWS_ERROR_CAL_UNKNOWN_OBJECT_IDENTIFIER);
}

int aws_ecc_oid_from_curve_name(enum aws_ecc_curve_name curve_name, struct aws_byte_cursor *oid) {
    if (curve_name < AWS_CAL_ECDSA_P256 || curve_name > AWS_CAL_ECDSA_P384) {
        return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM);
    }
    *oid = *s_ecc_curve_oids[curve_name];
    return AWS_OP_SUCCESS;
}

typedef struct aws_ecc_key_pair *(aws_ecc_key_pair_new_from_public_key_fn)(struct aws_allocator *allocator,
                                                                           enum aws_ecc_curve_name curve_name,
                                                                           const struct aws_byte_cursor *public_key_x,
                                                                           const struct aws_byte_cursor *public_key_y);

typedef struct aws_ecc_key_pair *(aws_ecc_key_pair_new_from_private_key_fn)(struct aws_allocator *allocator,
                                                                            enum aws_ecc_curve_name curve_name,
                                                                            const struct aws_byte_cursor *priv_key);

#ifndef BYO_CRYPTO

extern struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_public_key_impl(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *public_key_x,
    const struct aws_byte_cursor *public_key_y);

extern struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_private_key_impl(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *priv_key);

#else /* BYO_CRYPTO */

struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_public_key_impl(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *public_key_x,
    const struct aws_byte_cursor *public_key_y) {
    (void)allocator;
    (void)curve_name;
    (void)public_key_x;
    (void)public_key_y;
    abort();
}

struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_private_key_impl(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *priv_key) {
    (void)allocator;
    (void)curve_name;
    (void)priv_key;
    abort();
}

#endif /* BYO_CRYPTO */

static aws_ecc_key_pair_new_from_public_key_fn *s_ecc_key_pair_new_from_public_key_fn =
    aws_ecc_key_pair_new_from_public_key_impl;

static aws_ecc_key_pair_new_from_private_key_fn *s_ecc_key_pair_new_from_private_key_fn =
    aws_ecc_key_pair_new_from_private_key_impl;

struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_public_key(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *public_key_x,
    const struct aws_byte_cursor *public_key_y) {
    return s_ecc_key_pair_new_from_public_key_fn(allocator, curve_name, public_key_x, public_key_y);
}

struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_private_key(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *priv_key) {
    return s_ecc_key_pair_new_from_private_key_fn(allocator, curve_name, priv_key);
}

static void s_aws_ecc_key_pair_destroy(struct aws_ecc_key_pair *key_pair) {
    if (key_pair) {
        AWS_FATAL_ASSERT(key_pair->vtable->destroy && "ECC KEY PAIR destroy function must be included on the vtable");
        key_pair->vtable->destroy(key_pair);
    }
}

int aws_ecc_key_pair_derive_public_key(struct aws_ecc_key_pair *key_pair) {
    AWS_FATAL_ASSERT(key_pair->vtable->derive_pub_key && "ECC KEY PAIR derive function must be included on the vtable");
    return key_pair->vtable->derive_pub_key(key_pair);
}

int aws_ecc_key_pair_sign_message(
    const struct aws_ecc_key_pair *key_pair,
    const struct aws_byte_cursor *message,
    struct aws_byte_buf *signature) {
    AWS_FATAL_ASSERT(key_pair->vtable->sign_message && "ECC KEY PAIR sign message must be included on the vtable");
    return key_pair->vtable->sign_message(key_pair, message, signature);
}

int aws_ecc_key_pair_verify_signature(
    const struct aws_ecc_key_pair *key_pair,
    const struct aws_byte_cursor *message,
    const struct aws_byte_cursor *signature) {
    AWS_FATAL_ASSERT(
        key_pair->vtable->verify_signature && "ECC KEY PAIR verify signature must be included on the vtable");
    return key_pair->vtable->verify_signature(key_pair, message, signature);
}

size_t aws_ecc_key_pair_signature_length(const struct aws_ecc_key_pair *key_pair) {
    AWS_FATAL_ASSERT(
        key_pair->vtable->signature_length && "ECC KEY PAIR signature length must be included on the vtable");
    return key_pair->vtable->signature_length(key_pair);
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

size_t aws_ecc_key_coordinate_byte_size_from_curve_name(enum aws_ecc_curve_name curve_name) {
    switch (curve_name) {
        case AWS_CAL_ECDSA_P256:
            return 32;
        case AWS_CAL_ECDSA_P384:
            return 48;
        default:
            return 0;
    }
}

static void s_parse_public_key(
    struct aws_byte_cursor public_key,
    size_t key_coordinate_size,
    struct aws_byte_cursor *out_public_x_coord,
    struct aws_byte_cursor *out_public_y_coord) {

    aws_byte_cursor_advance(&public_key, 1);
    *out_public_x_coord = aws_byte_cursor_advance(&public_key, key_coordinate_size);
    *out_public_y_coord = public_key;
}

/*
 * Both pkcs8 and sec1 have a shared overlapped structure.
 * This helper extracts common fields and then validation can differ in the caller.
 */
static int s_der_decoder_sec1_private_key_helper(
    struct aws_der_decoder *decoder,
    struct aws_byte_cursor *out_private_cursor,
    struct aws_byte_cursor *out_public_cursor,
    enum aws_ecc_curve_name *out_curve_name,
    bool *curve_name_set) {

    AWS_ZERO_STRUCT(*out_private_cursor);
    AWS_ZERO_STRUCT(*out_public_cursor);

    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_type(decoder) != AWS_DER_SEQUENCE) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    struct aws_byte_cursor version_cur;
    AWS_ZERO_STRUCT(version_cur);
    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_unsigned_integer(decoder, &version_cur)) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    if (version_cur.len != 1 || version_cur.ptr[0] != 1) {
        return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_KEY_FORMAT);
    }

    struct aws_byte_cursor private_key_cur;
    AWS_ZERO_STRUCT(private_key_cur);
    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_string(decoder, &private_key_cur)) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    struct aws_byte_cursor oid;
    AWS_ZERO_STRUCT(oid);
    struct aws_byte_cursor public_key_cur;
    AWS_ZERO_STRUCT(public_key_cur);
    enum aws_ecc_curve_name curve_name = {0};

    *curve_name_set = false;
    if (aws_der_decoder_next(decoder)) {

        bool version_found = false;
        /* tag 0 is optional params */
        if (aws_der_decoder_tlv_type(decoder) == (AWS_DER_CLASS_CONTEXT | AWS_DER_FORM_CONSTRUCTED)) {
            if (!aws_der_decoder_next(decoder)) {
                return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
            }

            if (aws_der_decoder_tlv_type(decoder) != AWS_DER_OBJECT_IDENTIFIER) {
                return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
            }

            if (aws_der_decoder_tlv_blob(decoder, &oid)) {
                return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
            }
            if (aws_ecc_curve_name_from_oid(&oid, &curve_name)) {
                return aws_raise_error(AWS_ERROR_CAL_UNKNOWN_OBJECT_IDENTIFIER);
            }
            *curve_name_set = true;
            version_found = true;
        }

        /* tag 1 is optional public key
         * Note: even though its optional, I could not get any modern tools to generate a key without one.
         * So from practical perspective it almost always is present.
         * */
        if (version_found && !aws_der_decoder_next(decoder)) {
            return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
        }

        if (aws_der_decoder_tlv_type(decoder) == (AWS_DER_CLASS_CONTEXT | AWS_DER_FORM_CONSTRUCTED | 1)) {
            if (!aws_der_decoder_next(decoder)) {
                return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
            }

            if (aws_der_decoder_tlv_string(decoder, &public_key_cur)) {
                return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
            }
        }
    }

    *out_public_cursor = public_key_cur;
    *out_private_cursor = private_key_cur;
    *out_curve_name = curve_name;

    return AWS_OP_SUCCESS;
}

/*
 * Load key from sec1 container. Aka "EC PRIVATE KEY" in pem
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) },
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 */
static int s_der_decoder_load_ecc_private_key_pair_from_sec1(
    struct aws_der_decoder *decoder,
    struct aws_byte_cursor *out_public_x_coord,
    struct aws_byte_cursor *out_public_y_coord,
    struct aws_byte_cursor *out_private_d,
    enum aws_ecc_curve_name *out_curve_name) {

    AWS_ZERO_STRUCT(*out_public_x_coord);
    AWS_ZERO_STRUCT(*out_public_y_coord);
    AWS_ZERO_STRUCT(*out_private_d);

    struct aws_byte_cursor private_key_cur;
    struct aws_byte_cursor public_key_cur;
    enum aws_ecc_curve_name curve_name;
    bool curve_name_set = false;

    if (s_der_decoder_sec1_private_key_helper(
            decoder, &private_key_cur, &public_key_cur, &curve_name, &curve_name_set)) {
        return AWS_OP_ERR;
    }

    if (!curve_name_set) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    size_t key_coordinate_size = aws_ecc_key_coordinate_byte_size_from_curve_name(curve_name);
    size_t public_key_blob_size = key_coordinate_size * 2 + 1;

    if (private_key_cur.len != key_coordinate_size ||
        (public_key_cur.len != 0 && public_key_cur.len != public_key_blob_size)) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    *out_private_d = private_key_cur;

    if (public_key_cur.len > 0) {
        s_parse_public_key(public_key_cur, key_coordinate_size, out_public_x_coord, out_public_y_coord);
    }

    *out_curve_name = curve_name;

    return AWS_OP_SUCCESS;
}

static uint8_t s_ec_private_key_oid[] = {
    0x2A,
    0x86,
    0x48,
    0xCE,
    0x3D,
    0x02,
    0x01,
};
STATIC_INIT_BYTE_CURSOR(s_ec_private_key_oid, ec_private_key_oid_cursor)

static uint8_t s_ec_public_key_oid[] = {
    0x2A,
    0x86,
    0x48,
    0xCE,
    0x3D,
    0x02,
    0x01,
};
STATIC_INIT_BYTE_CURSOR(s_ec_public_key_oid, ec_public_key_oid_cursor)

/*
 * Load key from PKCS8 container with the following format. "PRIVATE KEY" in pem
 * PrivateKeyInfo ::= SEQUENCE {
 *   version                  Integer,
 *   privateKeyAlgorithm      PrivateKeyAlgorithmIdentifier,
 *   privateKey               PrivateKey
 * }
 * PrivateKeyAlgorithmIdentifier ::= SEQUENCE {
 *   algorithm         OBJECT IDENTIFIER,
 *   parameters        ANY DEFINED BY algorithm OPTIONAL
 * }
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) },
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 */
static int s_der_decoder_load_ecc_private_key_pair_from_pkcs8(
    struct aws_der_decoder *decoder,
    struct aws_byte_cursor *out_public_x_coord,
    struct aws_byte_cursor *out_public_y_coord,
    struct aws_byte_cursor *out_private_d,
    enum aws_ecc_curve_name *out_curve_name) {

    AWS_ZERO_STRUCT(*out_public_x_coord);
    AWS_ZERO_STRUCT(*out_public_y_coord);
    AWS_ZERO_STRUCT(*out_private_d);

    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_type(decoder) != AWS_DER_SEQUENCE) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    if (!aws_der_decoder_next(decoder)) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    /* version */
    struct aws_byte_cursor version_cur;
    AWS_ZERO_STRUCT(version_cur);
    /* Note: this is not really spec compliant, but some implementations ignore the top level version.
     * So be lax here and treat version as optional. */
    if (aws_der_decoder_tlv_unsigned_integer(decoder, &version_cur) == AWS_OP_SUCCESS) {
        if (version_cur.len != 1 || version_cur.ptr[0] != 0) {
            return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_KEY_FORMAT);
        }
        if (!aws_der_decoder_next(decoder)) {
            return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
        }
    }

    if (aws_der_decoder_tlv_type(decoder) != AWS_DER_SEQUENCE) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    struct aws_byte_cursor algo_oid;
    AWS_ZERO_STRUCT(algo_oid);
    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_type(decoder) != AWS_DER_OBJECT_IDENTIFIER ||
        aws_der_decoder_tlv_blob(decoder, &algo_oid)) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    /*
     * Why check both public and private? Cause in real world standards are mostly a suggestion.
     * A lot of private keys in the wild use public also oid and its defacto standard for a lot of libs.
     */
    if (!aws_byte_cursor_eq(&algo_oid, &s_ec_public_key_oid_cursor) &&
        !aws_byte_cursor_eq(&algo_oid, &s_ec_private_key_oid_cursor)) {
        return aws_raise_error(AWS_ERROR_CAL_UNKNOWN_OBJECT_IDENTIFIER);
    }

    struct aws_byte_cursor curve_oid;
    AWS_ZERO_STRUCT(curve_oid);
    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_type(decoder) != AWS_DER_OBJECT_IDENTIFIER ||
        aws_der_decoder_tlv_blob(decoder, &curve_oid)) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    enum aws_ecc_curve_name curve_name;
    if (aws_ecc_curve_name_from_oid(&curve_oid, &curve_name)) {
        return aws_raise_error(AWS_ERROR_CAL_UNKNOWN_OBJECT_IDENTIFIER);
    }

    /* private key string */
    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_type(decoder) != AWS_DER_OCTET_STRING) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    struct aws_der_decoder *nested_decoder = aws_der_decoder_nested_tlv_decoder(decoder);

    if (!nested_decoder) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    struct aws_byte_cursor private_key_cur;
    struct aws_byte_cursor public_key_cur;
    enum aws_ecc_curve_name inner_curve_name;
    bool curve_name_set = false;
    if (s_der_decoder_sec1_private_key_helper(
            nested_decoder, &private_key_cur, &public_key_cur, &inner_curve_name, &curve_name_set)) {
        aws_der_decoder_destroy(nested_decoder);
        return AWS_OP_ERR;
    }

    aws_der_decoder_destroy(nested_decoder);

    if (curve_name_set && inner_curve_name != curve_name) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    size_t key_coordinate_size = aws_ecc_key_coordinate_byte_size_from_curve_name(curve_name);
    size_t public_key_blob_size = key_coordinate_size * 2 + 1;

    if (private_key_cur.len != key_coordinate_size ||
        (public_key_cur.len != 0 && public_key_cur.len != public_key_blob_size)) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    *out_private_d = private_key_cur;

    if (public_key_cur.len > 0) {
        s_parse_public_key(public_key_cur, key_coordinate_size, out_public_x_coord, out_public_y_coord);
    }

    *out_curve_name = curve_name;

    return AWS_OP_SUCCESS;
}

/*
 * Load public key from x509 (aka SPKI) ec key structure, "EC PUBLIC KEY" or "PUBLIC KEY" in pem
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm         AlgorithmIdentifier,
 *   subjectPublicKey  BIT STRING
 * }
 * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm        OBJECT IDENTIFIER,
 *   parameters       ANY DEFINED BY algorithm OPTIONAL
 * }
 */
static int s_der_decoder_load_ecc_public_key_pair_from_asn1(
    struct aws_der_decoder *decoder,
    struct aws_byte_cursor *out_public_x_coord,
    struct aws_byte_cursor *out_public_y_coord,
    struct aws_byte_cursor *out_private_d,
    enum aws_ecc_curve_name *out_curve_name) {

    AWS_ZERO_STRUCT(*out_public_x_coord);
    AWS_ZERO_STRUCT(*out_public_y_coord);
    AWS_ZERO_STRUCT(*out_private_d);

    /* sequence */
    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_type(decoder) != AWS_DER_SEQUENCE) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    /* algo identifier sequence */
    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_type(decoder) != AWS_DER_SEQUENCE) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    struct aws_byte_cursor algo_oid;
    AWS_ZERO_STRUCT(algo_oid);
    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_type(decoder) != AWS_DER_OBJECT_IDENTIFIER ||
        aws_der_decoder_tlv_blob(decoder, &algo_oid)) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    if (!aws_byte_cursor_eq(&algo_oid, &s_ec_public_key_oid_cursor)) {
        return aws_raise_error(AWS_ERROR_CAL_UNKNOWN_OBJECT_IDENTIFIER);
    }

    struct aws_byte_cursor curve_oid;
    AWS_ZERO_STRUCT(curve_oid);
    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_type(decoder) != AWS_DER_OBJECT_IDENTIFIER ||
        aws_der_decoder_tlv_blob(decoder, &curve_oid)) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    enum aws_ecc_curve_name curve_name;
    if (aws_ecc_curve_name_from_oid(&curve_oid, &curve_name)) {
        return aws_raise_error(AWS_ERROR_CAL_UNKNOWN_OBJECT_IDENTIFIER);
    }

    struct aws_byte_cursor public_key_cur;
    AWS_ZERO_STRUCT(public_key_cur);
    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_string(decoder, &public_key_cur)) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    size_t key_coordinate_size = aws_ecc_key_coordinate_byte_size_from_curve_name(curve_name);
    if ((public_key_cur.len != 0 && public_key_cur.len != (key_coordinate_size * 2 + 1))) {
        return aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
    }

    if (public_key_cur.len > 0) {
        s_parse_public_key(public_key_cur, key_coordinate_size, out_public_x_coord, out_public_y_coord);
    }

    *out_curve_name = curve_name;

    return AWS_OP_SUCCESS;
}

int aws_der_decoder_load_ecc_key_pair(
    struct aws_der_decoder *decoder,
    struct aws_byte_cursor *out_public_x_coord,
    struct aws_byte_cursor *out_public_y_coord,
    struct aws_byte_cursor *out_private_d,
    enum aws_ecc_curve_name *out_curve_name) {

    AWS_ERROR_PRECONDITION(decoder);
    AWS_ERROR_PRECONDITION(out_public_x_coord);
    AWS_ERROR_PRECONDITION(out_public_y_coord);
    AWS_ERROR_PRECONDITION(out_private_d);
    AWS_ERROR_PRECONDITION(out_curve_name);

    /**
     * Since this is a generic api to parse from ans1, we can encounter several key structures.
     * Just go through them one by one and see if any match the expected type.
     * Note: We should at least get some id in the structure or unique enough layout so ordering does not matter.
     */
    if (s_der_decoder_load_ecc_public_key_pair_from_asn1(
            decoder, out_public_x_coord, out_public_y_coord, out_private_d, out_curve_name) == AWS_OP_SUCCESS) {
        return AWS_OP_SUCCESS;
    }

    aws_der_decoder_reset(decoder);

    if (s_der_decoder_load_ecc_private_key_pair_from_pkcs8(
            decoder, out_public_x_coord, out_public_y_coord, out_private_d, out_curve_name) == AWS_OP_SUCCESS) {
        return AWS_OP_SUCCESS;
    }

    aws_der_decoder_reset(decoder);
    if (s_der_decoder_load_ecc_private_key_pair_from_sec1(
            decoder, out_public_x_coord, out_public_y_coord, out_private_d, out_curve_name) == AWS_OP_SUCCESS) {
        return AWS_OP_SUCCESS;
    }

    return aws_raise_error(AWS_ERROR_CAL_UNSUPPORTED_KEY_FORMAT);
}

void aws_ecc_key_pair_acquire(struct aws_ecc_key_pair *key_pair) {
    aws_atomic_fetch_add(&key_pair->ref_count, 1);
}

void aws_ecc_key_pair_release(struct aws_ecc_key_pair *key_pair) {
    if (key_pair == NULL) {
        return;
    }

    size_t old_value = aws_atomic_fetch_sub(&key_pair->ref_count, 1);

    if (old_value == 1) {
        s_aws_ecc_key_pair_destroy(key_pair);
    }
}

struct aws_ecc_key_pair *aws_ecc_key_new_from_hex_coordinates(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    struct aws_byte_cursor pub_x_hex_cursor,
    struct aws_byte_cursor pub_y_hex_cursor) {
    struct aws_byte_buf pub_x_buffer;
    AWS_ZERO_STRUCT(pub_x_buffer);
    struct aws_byte_buf pub_y_buffer;
    AWS_ZERO_STRUCT(pub_y_buffer);

    struct aws_ecc_key_pair *key = NULL;

    size_t pub_x_length = 0;
    size_t pub_y_length = 0;
    if (aws_hex_compute_decoded_len(pub_x_hex_cursor.len, &pub_x_length) ||
        aws_hex_compute_decoded_len(pub_y_hex_cursor.len, &pub_y_length)) {
        goto done;
    }

    if (aws_byte_buf_init(&pub_x_buffer, allocator, pub_x_length) ||
        aws_byte_buf_init(&pub_y_buffer, allocator, pub_y_length)) {
        goto done;
    }

    if (aws_hex_decode(&pub_x_hex_cursor, &pub_x_buffer) || aws_hex_decode(&pub_y_hex_cursor, &pub_y_buffer)) {
        goto done;
    }

    struct aws_byte_cursor pub_x_cursor = aws_byte_cursor_from_buf(&pub_x_buffer);
    struct aws_byte_cursor pub_y_cursor = aws_byte_cursor_from_buf(&pub_y_buffer);

    key = aws_ecc_key_pair_new_from_public_key(allocator, curve_name, &pub_x_cursor, &pub_y_cursor);

done:

    aws_byte_buf_clean_up(&pub_x_buffer);
    aws_byte_buf_clean_up(&pub_y_buffer);

    return key;
}

int aws_ecc_decode_signature_der_to_raw(
    struct aws_allocator *allocator,
    struct aws_byte_cursor signature,
    struct aws_byte_cursor *out_r,
    struct aws_byte_cursor *out_s) {

    AWS_ERROR_PRECONDITION(allocator);
    AWS_ERROR_PRECONDITION(out_r);
    AWS_ERROR_PRECONDITION(out_s);

    struct aws_der_decoder *decoder = aws_der_decoder_new(allocator, signature);

    if (!decoder) {
        return AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED;
    }

    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_type(decoder) != AWS_DER_SEQUENCE) {
        aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
        goto on_error;
    }

    struct aws_byte_cursor r;
    AWS_ZERO_STRUCT(r);
    struct aws_byte_cursor s;
    AWS_ZERO_STRUCT(s);

    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_unsigned_integer(decoder, &r)) {
        aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
        goto on_error;
    }
    if (!aws_der_decoder_next(decoder) || aws_der_decoder_tlv_unsigned_integer(decoder, &s)) {
        aws_raise_error(AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED);
        goto on_error;
    }

    aws_der_decoder_destroy(decoder);
    *out_r = r;
    *out_s = s;
    return AWS_OP_SUCCESS;

on_error:
    aws_der_decoder_destroy(decoder);
    return AWS_OP_ERR;
}

static bool s_trim_zeros_predicate(uint8_t value) {
    return value == 0;
}

int aws_ecc_encode_signature_raw_to_der(
    struct aws_allocator *allocator,
    struct aws_byte_cursor r,
    struct aws_byte_cursor s,
    struct aws_byte_buf *out_signature) {

    AWS_ERROR_PRECONDITION(allocator);
    AWS_ERROR_PRECONDITION(out_signature);

    struct aws_der_encoder *encoder = aws_der_encoder_new(allocator, out_signature->capacity - out_signature->len);

    if (aws_der_encoder_begin_sequence(encoder)) {
        aws_raise_error(AWS_ERROR_UNKNOWN);
        goto on_error;
    }

    r = aws_byte_cursor_left_trim_pred(&r, s_trim_zeros_predicate);
    if (aws_der_encoder_write_unsigned_integer(encoder, r)) {
        aws_raise_error(AWS_ERROR_UNKNOWN);
        goto on_error;
    }

    s = aws_byte_cursor_left_trim_pred(&s, s_trim_zeros_predicate);
    if (aws_der_encoder_write_unsigned_integer(encoder, s)) {
        aws_raise_error(AWS_ERROR_UNKNOWN);
        goto on_error;
    }

    if (aws_der_encoder_end_sequence(encoder)) {
        aws_raise_error(AWS_ERROR_UNKNOWN);
        goto on_error;
    }

    struct aws_byte_cursor contents;
    AWS_ZERO_STRUCT(contents);
    if (aws_der_encoder_get_contents(encoder, &contents)) {
        aws_raise_error(AWS_ERROR_UNKNOWN);
        goto on_error;
    }

    aws_byte_buf_append(out_signature, &contents);

    aws_der_encoder_destroy(encoder);
    return AWS_OP_SUCCESS;

on_error:
    aws_der_encoder_destroy(encoder);
    return AWS_OP_ERR;
}

int s_write_coord_padded(struct aws_byte_buf *buf, struct aws_byte_cursor coord, size_t pad_to) {
    for (size_t pad = 0; pad < pad_to - coord.len; ++pad) {
        if (aws_byte_buf_append_byte_dynamic(buf, 0x0)) {
            return AWS_OP_ERR;
        }
    }

    if (aws_byte_buf_append(buf, &coord)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/*
 * Export key to a sec1 container. Aka "EC PRIVATE KEY" in pem
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) },
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 *
 * Note: skip params is used for pkcs8 case, where params structure is written out top level instead.
 */
int s_export_sec1(const struct aws_ecc_key_pair *key_pair, bool should_skip_params, struct aws_byte_buf *out) {

    if (key_pair->priv_d.buffer == NULL) {
        return aws_raise_error(AWS_ERROR_CAL_MISSING_REQUIRED_KEY_COMPONENT);
    }

    struct aws_der_encoder *encoder = aws_der_encoder_new(key_pair->allocator, 256);

    if (aws_der_encoder_begin_sequence(encoder)) {
        goto on_error;
    }

    static uint8_t ver_one[] = {1};
    if (aws_der_encoder_write_unsigned_integer(encoder, aws_byte_cursor_from_array(ver_one, 1))) {
        goto on_error;
    }

    if (aws_der_encoder_write_octet_string(encoder, aws_byte_cursor_from_buf(&key_pair->priv_d))) {
        goto on_error;
    }

    if (!should_skip_params) {
        if (aws_der_encoder_begin_context_aware_tag(encoder, true, 0)) {
            goto on_error;
        }

        struct aws_byte_cursor oid;
        AWS_ZERO_STRUCT(oid);
        if (aws_ecc_oid_from_curve_name(key_pair->curve_name, &oid)) {
            goto on_error;
        }

        if (aws_der_encoder_write_object_identifier(encoder, oid)) {
            goto on_error;
        }

        if (aws_der_encoder_end_context_aware_tag(encoder)) {
            goto on_error;
        }
    }

    if (aws_der_encoder_begin_context_aware_tag(encoder, true, 1)) {
        goto on_error;
    }

    struct aws_byte_buf pub_buf;
    aws_byte_buf_init(&pub_buf, key_pair->allocator, 128);

    if (aws_byte_buf_append_byte_dynamic(&pub_buf, 0x04)) { /* uncompressed pub key */
        goto on_error_pub_key;
    }

    size_t coord_size = aws_ecc_key_coordinate_byte_size_from_curve_name(key_pair->curve_name);

    struct aws_byte_cursor pub_x_cur = aws_byte_cursor_from_buf(&key_pair->pub_x);
    if (s_write_coord_padded(&pub_buf, pub_x_cur, coord_size)) {
        goto on_error_pub_key;
    }

    struct aws_byte_cursor pub_y_cur = aws_byte_cursor_from_buf(&key_pair->pub_y);
    if (s_write_coord_padded(&pub_buf, pub_y_cur, coord_size)) {
        goto on_error_pub_key;
    }

    struct aws_byte_cursor pub_cur = aws_byte_cursor_from_buf(&pub_buf);
    if (aws_der_encoder_write_bit_string(encoder, pub_cur)) {
        goto on_error_pub_key;
    }
    aws_byte_buf_clean_up(&pub_buf);

    if (aws_der_encoder_end_context_aware_tag(encoder)) {
        goto on_error;
    }

    if (aws_der_encoder_end_sequence(encoder)) {
        goto on_error;
    }

    struct aws_byte_cursor contents;
    AWS_ZERO_STRUCT(contents);
    if (aws_der_encoder_get_contents(encoder, &contents)) {
        goto on_error;
    }

    if (aws_byte_buf_append(out, &contents)) {
        goto on_error;
    }

    aws_der_encoder_destroy(encoder);
    return AWS_OP_SUCCESS;

on_error:
    aws_der_encoder_destroy(encoder);
    return AWS_OP_ERR;

on_error_pub_key:
    aws_byte_buf_clean_up(&pub_buf);
    aws_der_encoder_destroy(encoder);
    return AWS_OP_ERR;
}

/*
 * Export key to PKCS8 container with the following format. "PRIVATE KEY" in pem
 * PrivateKeyInfo ::= SEQUENCE {
 *   version                  Integer,
 *   privateKeyAlgorithm      PrivateKeyAlgorithmIdentifier,
 *   privateKey               PrivateKey
 * }
 * PrivateKeyAlgorithmIdentifier ::= SEQUENCE {
 *   algorithm         OBJECT IDENTIFIER,
 *   parameters        ANY DEFINED BY algorithm OPTIONAL
 * }
 * ECPrivateKey ::= SEQUENCE {
 *   version        INTEGER { ecPrivkeyVer1(1) },
 *   privateKey     OCTET STRING,
 *   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
 *   publicKey  [1] BIT STRING OPTIONAL
 * }
 */
int s_export_pkcs8(const struct aws_ecc_key_pair *key_pair, struct aws_byte_buf *out) {
    if (key_pair->priv_d.buffer == NULL) {
        return aws_raise_error(AWS_ERROR_CAL_MISSING_REQUIRED_KEY_COMPONENT);
    }

    struct aws_der_encoder *encoder = aws_der_encoder_new(key_pair->allocator, 256);

    if (aws_der_encoder_begin_sequence(encoder)) {
        goto on_error;
    }

    /* version */
    static uint8_t ver_zero[] = {0};
    if (aws_der_encoder_write_unsigned_integer(encoder, aws_byte_cursor_from_array(ver_zero, 1))) {
        goto on_error;
    }

    /* privateKeyAlgorithm */
    if (aws_der_encoder_begin_sequence(encoder)) {
        goto on_error;
    }

    /* write id-ecPublicKey. yeah its technically private, but wider world has moved on from respecting standard here */
    if (aws_der_encoder_write_object_identifier(encoder, s_ec_public_key_oid_cursor)) {
        goto on_error;
    }

    struct aws_byte_cursor oid;
    AWS_ZERO_STRUCT(oid);
    if (aws_ecc_oid_from_curve_name(key_pair->curve_name, &oid)) {
        goto on_error;
    }

    if (aws_der_encoder_write_object_identifier(encoder, oid)) {
        goto on_error;
    }

    if (aws_der_encoder_end_sequence(encoder)) {
        goto on_error;
    }

    /* Private key, i.e. octet string of sec1 structure */
    struct aws_byte_buf priv_buf;
    aws_byte_buf_init(&priv_buf, key_pair->allocator, 256);
    if (s_export_sec1(key_pair, true, &priv_buf)) {
        goto on_priv_error;
    }

    if (aws_der_encoder_write_octet_string(encoder, aws_byte_cursor_from_buf(&priv_buf))) {
        goto on_priv_error;
    }

    aws_byte_buf_clean_up(&priv_buf);

    if (aws_der_encoder_end_sequence(encoder)) {
        goto on_error;
    }

    struct aws_byte_cursor contents;
    AWS_ZERO_STRUCT(contents);
    if (aws_der_encoder_get_contents(encoder, &contents)) {
        goto on_error;
    }

    if (aws_byte_buf_append(out, &contents)) {
        goto on_error;
    }

    aws_der_encoder_destroy(encoder);
    return AWS_OP_SUCCESS;

on_error:
    aws_der_encoder_destroy(encoder);
    return AWS_OP_ERR;

on_priv_error:
    aws_byte_buf_clean_up(&priv_buf);
    aws_der_encoder_destroy(encoder);
    return AWS_OP_ERR;
}

/*
 * Export public key to x509 (aka SPKI) ec key structure, "EC PUBLIC KEY" or "PUBLIC KEY" in pem
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm         AlgorithmIdentifier,
 *   subjectPublicKey  BIT STRING
 * }
 * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm        OBJECT IDENTIFIER,
 *   parameters       ANY DEFINED BY algorithm OPTIONAL
 * }
 */
int s_export_spki(const struct aws_ecc_key_pair *key_pair, struct aws_byte_buf *out) {
    struct aws_der_encoder *encoder = aws_der_encoder_new(key_pair->allocator, 256);

    if (aws_der_encoder_begin_sequence(encoder)) {
        goto on_error;
    }

    /* AlgorithmIdentifier */
    if (aws_der_encoder_begin_sequence(encoder)) {
        goto on_error;
    }

    if (aws_der_encoder_write_object_identifier(encoder, s_ec_public_key_oid_cursor)) {
        goto on_error;
    }

    struct aws_byte_cursor oid;
    AWS_ZERO_STRUCT(oid);
    if (aws_ecc_oid_from_curve_name(key_pair->curve_name, &oid)) {
        goto on_error;
    }

    if (aws_der_encoder_write_object_identifier(encoder, oid)) {
        goto on_error;
    }

    if (aws_der_encoder_end_sequence(encoder)) {
        goto on_error;
    }

    /* Public key */
    struct aws_byte_buf pub_buf;
    aws_byte_buf_init(&pub_buf, key_pair->allocator, 128);

    if (aws_byte_buf_append_byte_dynamic(&pub_buf, 0x04)) { /* uncompressed pub key */
        goto on_pub_error;
    }

    size_t coord_size = aws_ecc_key_coordinate_byte_size_from_curve_name(key_pair->curve_name);

    struct aws_byte_cursor pub_x_cur = aws_byte_cursor_from_buf(&key_pair->pub_x);
    if (s_write_coord_padded(&pub_buf, pub_x_cur, coord_size)) {
        goto on_pub_error;
    }

    struct aws_byte_cursor pub_y_cur = aws_byte_cursor_from_buf(&key_pair->pub_y);
    if (s_write_coord_padded(&pub_buf, pub_y_cur, coord_size)) {
        goto on_pub_error;
    }

    struct aws_byte_cursor pub_cur = aws_byte_cursor_from_buf(&pub_buf);
    if (aws_der_encoder_write_bit_string(encoder, pub_cur)) {
        aws_byte_buf_clean_up(&pub_buf);
        goto on_pub_error;
    }

    aws_byte_buf_clean_up(&pub_buf);

    if (aws_der_encoder_end_sequence(encoder)) {
        goto on_error;
    }

    struct aws_byte_cursor contents;
    AWS_ZERO_STRUCT(contents);
    if (aws_der_encoder_get_contents(encoder, &contents)) {
        goto on_error;
    }

    if (aws_byte_buf_append(out, &contents)) {
        goto on_error;
    }

    aws_der_encoder_destroy(encoder);
    return AWS_OP_SUCCESS;

on_error:
    aws_der_encoder_destroy(encoder);
    return AWS_OP_ERR;

on_pub_error:
    aws_byte_buf_clean_up(&pub_buf);
    aws_der_encoder_destroy(encoder);
    return AWS_OP_ERR;
}

int aws_ecc_key_pair_export(
    const struct aws_ecc_key_pair *key_pair,
    enum aws_ecc_key_export_format format,
    struct aws_byte_buf *out) {
    AWS_ERROR_PRECONDITION(key_pair);
    AWS_ERROR_PRECONDITION(out);

    switch (format) {
        case AWS_CAL_ECC_KEY_EXPORT_PRIVATE_SEC1:
            return s_export_sec1(key_pair, false /* skip_params */, out);
        case AWS_CAL_ECC_KEY_EXPORT_PRIVATE_PKCS8:
            return s_export_pkcs8(key_pair, out);
        case AWS_CAL_ECC_KEY_EXPORT_PUBLIC_SPKI:
            return s_export_spki(key_pair, out);
        default:
            return aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
    }
}
