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
