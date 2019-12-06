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

static struct aws_ecc_key_pair_vtable vtable = {
    .destroy_fn = s_key_pair_destroy,
};

struct aws_ecc_key_pair *aws_ecc_key_pair_new_derived_from_private_key(
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

    BIGNUM *priv_key_num = BN_bin2bn(priv_key->ptr, priv_key->len, NULL);

    const EC_GROUP *group = EC_KEY_get0_group(key_impl->ec_key);
    EC_POINT *point = EC_POINT_new(group);

    int ret_val = EC_POINT_mul(group, point, priv_key_num, NULL, NULL, NULL);
    EC_KEY_set_public_key(key_impl->ec_key, point);
    EC_KEY_set_private_key(key_impl->ec_key, priv_key_num);

    BN_free(priv_key_num);

    BIGNUM *big_num_x = BN_new();
    BIGNUM *big_num_y = BN_new();

    ret_val = EC_POINT_get_affine_coordinates(group, point, big_num_x, big_num_y, NULL);
    (void)ret_val;

    size_t x_coor_size = BN_num_bytes(big_num_x);
    size_t y_coor_size = BN_num_bytes(big_num_y);

    aws_byte_buf_init(&key_impl->key_pair.pub_x, allocator, x_coor_size);
    aws_byte_buf_init(&key_impl->key_pair.pub_y, allocator, y_coor_size);

    BN_bn2bin(big_num_x, key_impl->key_pair.pub_x.buffer);
    BN_bn2bin(big_num_y, key_impl->key_pair.pub_y.buffer);

    key_impl->key_pair.pub_x.len = x_coor_size;
    key_impl->key_pair.pub_y.len = y_coor_size;
    BN_free(big_num_x);
    BN_free(big_num_y);

    return &key_impl->key_pair;
}

struct aws_ecc_key_pair *aws_ecc_key_pair_new(struct aws_allocator *allocator, enum aws_ecc_curve_name curve_name) {
    struct libcrypto_ecc_key *key_impl = aws_mem_calloc(allocator, 1, sizeof(struct libcrypto_ecc_key));

    key_impl->ec_key = EC_KEY_new_by_curve_name(s_curve_name_to_nid(curve_name));
    key_impl->key_pair.curve_name = curve_name;
    key_impl->key_pair.allocator = allocator;
    key_impl->key_pair.vtable = &vtable;
    key_impl->key_pair.impl = key_impl;

    EC_KEY_generate_key(key_impl->ec_key);

    const EC_POINT *pub_key_point = EC_KEY_get0_public_key(key_impl->ec_key);
    const EC_GROUP *group = EC_KEY_get0_group(key_impl->ec_key);
    BIGNUM *big_num_x = BN_new();
    BIGNUM *big_num_y = BN_new();

    int ret_val = EC_POINT_get_affine_coordinates(group, pub_key_point, big_num_x, big_num_y, NULL);
    (void)ret_val;

    size_t x_coor_size = BN_num_bytes(big_num_x);
    size_t y_coor_size = BN_num_bytes(big_num_y);

    aws_byte_buf_init(&key_impl->key_pair.pub_x, allocator, x_coor_size);
    aws_byte_buf_init(&key_impl->key_pair.pub_y, allocator, y_coor_size);

    BN_bn2bin(big_num_x, key_impl->key_pair.pub_x.buffer);
    BN_bn2bin(big_num_y, key_impl->key_pair.pub_y.buffer);

    key_impl->key_pair.pub_x.len = x_coor_size;
    key_impl->key_pair.pub_y.len = y_coor_size;
    BN_free(big_num_x);
    BN_free(big_num_y);

    const BIGNUM *private_key_num = EC_KEY_get0_private_key(key_impl->ec_key);
    size_t priv_key_size = BN_num_bytes(private_key_num);
    aws_byte_buf_init(&key_impl->key_pair.priv_d, allocator, priv_key_size);
    BN_bn2bin(private_key_num, key_impl->key_pair.priv_d.buffer);

    return &key_impl->key_pair;
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

    int ret_val = 0;
    if (!pub_key_point) {
        EC_POINT *point = EC_POINT_new(group);
        ret_val = EC_POINT_mul(group, point, private_key_num, NULL, NULL, NULL);
        EC_KEY_set_public_key(key_impl->ec_key, point);
        pub_key_point = point;
    }

    BIGNUM *big_num_x = BN_new();
    BIGNUM *big_num_y = BN_new();
    ret_val = EC_POINT_get_affine_coordinates(group, pub_key_point, big_num_x, big_num_y, NULL);

    (void)ret_val;

    size_t x_coor_size = BN_num_bytes(big_num_x);
    size_t y_coor_size = BN_num_bytes(big_num_y);

    aws_byte_buf_init(&key_impl->key_pair.pub_x, allocator, x_coor_size);
    aws_byte_buf_init(&key_impl->key_pair.pub_y, allocator, y_coor_size);

    BN_bn2bin(big_num_x, key_impl->key_pair.pub_x.buffer);
    BN_bn2bin(big_num_y, key_impl->key_pair.pub_y.buffer);

    key_impl->key_pair.pub_x.len = x_coor_size;
    key_impl->key_pair.pub_y.len = y_coor_size;
    BN_free(big_num_x);
    BN_free(big_num_y);

    return &key_impl->key_pair;
}

struct libcrypto_ecc_signer {
    struct aws_ecc_signer signer;
    ECDSA_SIG *ec_sig;
    EC_KEY *ec_key;
};

static int s_sign_payload_fn(
    const struct aws_ecc_signer *signer,
    const struct aws_byte_cursor *hash,
    struct aws_byte_buf *signature_output) {
    struct libcrypto_ecc_signer *libcrypto_signer = signer->impl;

    unsigned int signature_size = signature_output->capacity - signature_output->len;
    ECDSA_sign(
        0,
        hash->ptr,
        hash->len,
        signature_output->buffer + signature_output->len,
        &signature_size,
        libcrypto_signer->ec_key);
    signature_output->len += signature_size;

    return AWS_OP_SUCCESS;
}

static int s_verify_payload_fn(
    const struct aws_ecc_signer *signer,
    const struct aws_byte_cursor *hash,
    const struct aws_byte_cursor *signature) {
    struct libcrypto_ecc_signer *libcrypto_signer = signer->impl;

    return ECDSA_verify(0, hash->ptr, hash->len, signature->ptr, signature->len, libcrypto_signer->ec_key) == 1
               ? AWS_OP_SUCCESS
               : AWS_OP_ERR;
}

static size_t s_signature_length_fn(const struct aws_ecc_signer *signer) {
    struct libcrypto_ecc_signer *libcrypto_signer = signer->impl;

    return ECDSA_size(libcrypto_signer->ec_key);
}

static void s_signer_destroy_fn(struct aws_ecc_signer *signer) {
    struct libcrypto_ecc_signer *libcrypto_signer = signer->impl;
    EC_KEY_free(libcrypto_signer->ec_key);
    ECDSA_SIG_free(libcrypto_signer->ec_sig);
    aws_mem_release(libcrypto_signer->signer.allocator, libcrypto_signer);
}

static struct aws_ecc_signer_vtable s_signer_vtable = {
    .sign_payload_fn = s_sign_payload_fn,
    .verify_payload_fn = s_verify_payload_fn,
    .destroy_fn = s_signer_destroy_fn,
    .signature_max_length_fn = s_signature_length_fn,
};

struct aws_ecc_signer *aws_ecc_signer_new(struct aws_allocator *allocator, const struct aws_ecc_key_pair *key_pair) {
    struct libcrypto_ecc_signer *signer_impl = aws_mem_calloc(allocator, 1, sizeof(struct libcrypto_ecc_signer));
    struct libcrypto_ecc_key *key_impl = key_pair->impl;

    signer_impl->ec_sig = ECDSA_SIG_new();
    signer_impl->signer.impl = signer_impl;
    signer_impl->signer.allocator = allocator;
    EC_KEY_up_ref(key_impl->ec_key);
    signer_impl->ec_key = key_impl->ec_key;
    signer_impl->signer.vtable = &s_signer_vtable;

    return &signer_impl->signer;
}
