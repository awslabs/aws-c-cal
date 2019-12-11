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

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

struct libcrypto_ecc_key {
    struct aws_ecc_key_pair key_pair;
    EC_KEY *ec_key;
};

static int s_curve_name_to_nid(enum aws_ecc_curve_name curve_name) {
    switch (curve_name) {
        case AWS_CAL_ECDSA_P256:
            return NID_X9_62_prime256v1;
        case AWS_CAL_ECDSA_P384:
            return NID_secp384r1;
        case AWS_CAL_ECDSA_P521:
            return NID_secp521r1;
    }

    AWS_FATAL_ASSERT(!"Unsupported elliptic curve name");
    return -1;
}

static void s_key_pair_destroy(struct aws_ecc_key_pair *key_pair) {

    if (key_pair) {
        aws_byte_buf_clean_up(&key_pair->pub_x);
        aws_byte_buf_clean_up(&key_pair->pub_y);
        aws_byte_buf_clean_up_secure(&key_pair->priv_d);

        struct libcrypto_ecc_key *key_impl = key_pair->impl;

        if (key_impl->ec_key) {
            EC_KEY_free(key_impl->ec_key);
        }
        aws_mem_release(key_pair->allocator, key_pair);
    }
}

static int s_sign_payload_fn(
    const struct aws_ecc_key_pair *key_pair,
    const struct aws_byte_cursor *hash,
    struct aws_byte_buf *signature_output) {
    struct libcrypto_ecc_key *libcrypto_key_pair = key_pair->impl;

    unsigned int signature_size = signature_output->capacity - signature_output->len;
    int ret_val = ECDSA_sign(
        0,
        hash->ptr,
        hash->len,
        signature_output->buffer + signature_output->len,
        &signature_size,
        libcrypto_key_pair->ec_key);
    signature_output->len += signature_size;

    return ret_val == 1 ? AWS_OP_SUCCESS : aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
}

static int s_verify_payload_fn(
    const struct aws_ecc_key_pair *key_pair,
    const struct aws_byte_cursor *hash,
    const struct aws_byte_cursor *signature) {
    struct libcrypto_ecc_key *libcrypto_key_pair = key_pair->impl;

    return ECDSA_verify(0, hash->ptr, hash->len, signature->ptr, signature->len, libcrypto_key_pair->ec_key) == 1
               ? AWS_OP_SUCCESS
               : aws_raise_error(AWS_CAL_SIGNATURE_VALIDATION_FAILED);
}

static size_t s_signature_length_fn(const struct aws_ecc_key_pair *key_pair) {
    struct libcrypto_ecc_key *libcrypto_key_pair = key_pair->impl;

    return ECDSA_size(libcrypto_key_pair->ec_key);
}

static int s_fill_in_public_key_info(
    struct libcrypto_ecc_key *libcrypto_key_pair,
    const EC_GROUP *group,
    const EC_POINT *pub_key_point) {
    BIGNUM *big_num_x = BN_new();
    BIGNUM *big_num_y = BN_new();

    int ret_val = EC_POINT_get_affine_coordinates(group, pub_key_point, big_num_x, big_num_y, NULL);
    (void)ret_val;

    size_t x_coor_size = BN_num_bytes(big_num_x);
    size_t y_coor_size = BN_num_bytes(big_num_y);

    aws_byte_buf_init(&libcrypto_key_pair->key_pair.pub_x, libcrypto_key_pair->key_pair.allocator, x_coor_size);
    aws_byte_buf_init(&libcrypto_key_pair->key_pair.pub_y, libcrypto_key_pair->key_pair.allocator, y_coor_size);

    BN_bn2bin(big_num_x, libcrypto_key_pair->key_pair.pub_x.buffer);
    BN_bn2bin(big_num_y, libcrypto_key_pair->key_pair.pub_y.buffer);

    libcrypto_key_pair->key_pair.pub_x.len = x_coor_size;
    libcrypto_key_pair->key_pair.pub_y.len = y_coor_size;
    BN_free(big_num_x);
    BN_free(big_num_y);

    return AWS_OP_SUCCESS;
}

static int s_derive_public_key_fn(struct aws_ecc_key_pair *key_pair) {
    struct libcrypto_ecc_key *libcrypto_key_pair = key_pair->impl;

    if (!libcrypto_key_pair->key_pair.priv_d.len) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    /* we already have a public key. */
    if (libcrypto_key_pair->key_pair.pub_x.len) {
        return AWS_OP_SUCCESS;
    }

    BIGNUM *priv_key_num =
        BN_bin2bn(libcrypto_key_pair->key_pair.priv_d.buffer, libcrypto_key_pair->key_pair.priv_d.len, NULL);

    const EC_GROUP *group = EC_KEY_get0_group(libcrypto_key_pair->ec_key);
    EC_POINT *point = EC_POINT_new(group);

    int ret_val = EC_POINT_mul(group, point, priv_key_num, NULL, NULL, NULL);
    BN_free(priv_key_num);

    EC_KEY_set_public_key(libcrypto_key_pair->ec_key, point);
    (void)ret_val;
    return s_fill_in_public_key_info(libcrypto_key_pair, group, point);
}

static struct aws_ecc_key_pair_vtable vtable = {
    .sign_message_fn = s_sign_payload_fn,
    .verify_signature_fn = s_verify_payload_fn,
    .derive_pub_key_fn = s_derive_public_key_fn,
    .signature_length_fn = s_signature_length_fn,
    .destroy_fn = s_key_pair_destroy,
};

struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_private_key(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *priv_key) {

    struct libcrypto_ecc_key *key_impl = aws_mem_calloc(allocator, 1, sizeof(struct libcrypto_ecc_key));

    key_impl->ec_key = EC_KEY_new_by_curve_name(s_curve_name_to_nid(curve_name));
    key_impl->key_pair.curve_name = curve_name;
    key_impl->key_pair.allocator = allocator;
    key_impl->key_pair.vtable = &vtable;
    key_impl->key_pair.impl = key_impl;
    aws_byte_buf_init_copy_from_cursor(&key_impl->key_pair.priv_d, allocator, *priv_key);

    BIGNUM *priv_key_num = BN_bin2bn(key_impl->key_pair.priv_d.buffer, key_impl->key_pair.priv_d.len, NULL);
    EC_KEY_set_private_key(key_impl->ec_key, priv_key_num);
    BN_free(priv_key_num);

    return &key_impl->key_pair;
}

struct aws_ecc_key_pair *aws_ecc_key_pair_new_generate_random(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name) {
    struct libcrypto_ecc_key *key_impl = aws_mem_calloc(allocator, 1, sizeof(struct libcrypto_ecc_key));

    key_impl->ec_key = EC_KEY_new_by_curve_name(s_curve_name_to_nid(curve_name));
    key_impl->key_pair.curve_name = curve_name;
    key_impl->key_pair.allocator = allocator;
    key_impl->key_pair.vtable = &vtable;
    key_impl->key_pair.impl = key_impl;

    EC_KEY_generate_key(key_impl->ec_key);

    const EC_POINT *pub_key_point = EC_KEY_get0_public_key(key_impl->ec_key);
    const EC_GROUP *group = EC_KEY_get0_group(key_impl->ec_key);

    const BIGNUM *private_key_num = EC_KEY_get0_private_key(key_impl->ec_key);
    size_t priv_key_size = BN_num_bytes(private_key_num);
    aws_byte_buf_init(&key_impl->key_pair.priv_d, allocator, priv_key_size);
    BN_bn2bin(private_key_num, key_impl->key_pair.priv_d.buffer);

    if (!s_fill_in_public_key_info(key_impl, group, pub_key_point)) {
        return &key_impl->key_pair;
    }

    s_key_pair_destroy(&key_impl->key_pair);
    return NULL;
}

struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_public_key(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *public_key_x,
    const struct aws_byte_cursor *public_key_y) {
    struct libcrypto_ecc_key *key_impl = aws_mem_calloc(allocator, 1, sizeof(struct libcrypto_ecc_key));

    key_impl->ec_key = EC_KEY_new_by_curve_name(s_curve_name_to_nid(curve_name));
    key_impl->key_pair.curve_name = curve_name;
    key_impl->key_pair.allocator = allocator;
    key_impl->key_pair.vtable = &vtable;
    key_impl->key_pair.impl = key_impl;

    aws_byte_buf_init_copy_from_cursor(&key_impl->key_pair.pub_x, allocator, *public_key_x);
    aws_byte_buf_init_copy_from_cursor(&key_impl->key_pair.pub_y, allocator, *public_key_y);

    BIGNUM *pub_x_num = BN_bin2bn(public_key_x->ptr, public_key_x->len, NULL);
    BIGNUM *pub_y_num = BN_bin2bn(public_key_y->ptr, public_key_y->len, NULL);

    int res = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key_impl->ec_key);
    EC_POINT *point = EC_POINT_new(group);
    res = EC_POINT_set_affine_coordinates(group, point, pub_x_num, pub_y_num, NULL);
    res = EC_KEY_set_public_key(key_impl->ec_key, point);
    (void)res;
    EC_POINT_free(point);
    BN_free(pub_x_num);
    BN_free(pub_y_num);

    return &key_impl->key_pair;
}

struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_asn1(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *encoded_keys) {

    struct libcrypto_ecc_key *key_impl = aws_mem_calloc(allocator, 1, sizeof(struct libcrypto_ecc_key));

    d2i_ECParameters(&key_impl->ec_key, (const unsigned char **)&encoded_keys->ptr, encoded_keys->len);

    const EC_GROUP *group = EC_KEY_get0_group(key_impl->ec_key);

    switch (EC_GROUP_get_curve_name(group)) {
        case NID_X9_62_prime256v1:
            key_impl->key_pair.curve_name = AWS_CAL_ECDSA_P256;
            break;
        case NID_secp384r1:
            key_impl->key_pair.curve_name = AWS_CAL_ECDSA_P384;
            break;
        case NID_secp521r1:
            key_impl->key_pair.curve_name = AWS_CAL_ECDSA_P521;
            break;
        default:
            aws_raise_error(AWS_ERROR_UNSUPPORTED_OPERATION);
            s_key_pair_destroy(&key_impl->key_pair);
            return NULL;
    }

    key_impl->key_pair.allocator = allocator;
    key_impl->key_pair.vtable = &vtable;
    key_impl->key_pair.impl = key_impl;

    const BIGNUM *private_key_num = EC_KEY_get0_private_key(key_impl->ec_key);
    size_t priv_key_size = BN_num_bytes(private_key_num);
    aws_byte_buf_init(&key_impl->key_pair.priv_d, allocator, priv_key_size);
    BN_bn2bin(private_key_num, key_impl->key_pair.priv_d.buffer);

    const EC_POINT *pub_key_point = EC_KEY_get0_public_key(key_impl->ec_key);

    if (pub_key_point) {
        if (!s_fill_in_public_key_info(key_impl, group, pub_key_point)) {
            return &key_impl->key_pair;
        }
        s_key_pair_destroy(&key_impl->key_pair);
        return NULL;
    }

    return &key_impl->key_pair;
}
