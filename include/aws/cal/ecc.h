#ifndef AWS_CAL_ECC_H
#define AWS_CAL_ECC_H
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
#include <aws/cal/exports.h>

#include <aws/common/byte_buf.h>
#include <aws/common/common.h>

enum aws_ecc_curve_name {
    AWS_CAL_ECDSA_P256,
    AWS_CAL_ECDSA_P384,
    AWS_CAL_ECDSA_P521,
};

struct aws_ecc_key_pair;

typedef void(aws_ecc_key_pair_destroy_fn)(struct aws_ecc_key_pair *key_pair);

struct aws_ecc_key_pair_vtable {
    aws_ecc_key_pair_destroy_fn *destroy_fn;
};

struct aws_ecc_key_pair {
    struct aws_allocator *allocator;
    enum aws_ecc_curve_name curve_name;
    struct aws_byte_buf pub_x;
    struct aws_byte_buf pub_y;
    struct aws_byte_buf priv_d;
    struct aws_ecc_key_pair_vtable *vtable;
    void *impl;
};

struct aws_ecc_signer;

typedef int(aws_ecc_signer_sign_payload_fn)(
    const struct aws_ecc_signer *signer,
    const struct aws_byte_cursor *hash,
    struct aws_byte_buf *signature_output);
typedef int(aws_ecc_signer_verify_payload_fn)(
    const struct aws_ecc_signer *signer,
    const struct aws_byte_cursor *hash,
    const struct aws_byte_cursor *signature);
typedef size_t(aws_ecc_signer_signature_length_fn)(const struct aws_ecc_signer *signer);
typedef void(aws_ecc_signer_destroy_fn)(struct aws_ecc_signer *signer);

struct aws_ecc_signer_vtable {
    aws_ecc_signer_sign_payload_fn *sign_payload_fn;
    aws_ecc_signer_verify_payload_fn *verify_payload_fn;
    aws_ecc_signer_destroy_fn *destroy_fn;
    aws_ecc_signer_signature_length_fn *signature_max_length_fn;
};

struct aws_ecc_signer {
    struct aws_allocator *allocator;
    struct aws_ecc_signer_vtable *vtable;
    void *impl;
};

AWS_EXTERN_C_BEGIN

AWS_CAL_API struct aws_ecc_key_pair *aws_ecc_key_pair_new_derived_from_private_key(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *priv_key);
AWS_CAL_API struct aws_ecc_key_pair *aws_ecc_key_pair_new(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name);
AWS_CAL_API struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_public_key(
    struct aws_allocator *allocator,
    enum aws_ecc_curve_name curve_name,
    const struct aws_byte_cursor *public_key_x,
    const struct aws_byte_cursor *public_key_y);
AWS_CAL_API struct aws_ecc_key_pair *aws_ecc_key_pair_new_from_asn1(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *encoded_keys);
AWS_CAL_API void aws_ecc_key_pair_destroy(struct aws_ecc_key_pair *key_pair);

AWS_CAL_API struct aws_ecc_signer *aws_ecc_signer_new(
    struct aws_allocator *allocator,
    const struct aws_ecc_key_pair *key_pair);
AWS_CAL_API void aws_ecc_signer_destroy(struct aws_ecc_signer *signer);
AWS_CAL_API int aws_ecc_signer_sign_hash(
    struct aws_ecc_signer *signer,
    const struct aws_byte_cursor *hash,
    struct aws_byte_buf *signature);
AWS_CAL_API int aws_ecc_signer_verify_signature(
    struct aws_ecc_signer *signer,
    const struct aws_byte_cursor *hash,
    const struct aws_byte_cursor *signature);
AWS_CAL_API size_t aws_ecc_signer_max_signature_length(struct aws_ecc_signer *signer);

AWS_EXTERN_C_END

#endif /* AWS_CAL_ECC_H */
