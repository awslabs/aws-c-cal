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

void aws_ecc_signer_destroy(struct aws_ecc_signer *signer) {
    AWS_FATAL_ASSERT(signer->vtable->destroy_fn && "ECC Signer destroy function must be included on the vtable");
    signer->vtable->destroy_fn(signer);
}

int aws_ecc_signer_sign_hash(
    struct aws_ecc_signer *signer,
    const struct aws_byte_cursor *hash,
    struct aws_byte_buf *signature) {
    AWS_FATAL_ASSERT(signer->vtable->sign_payload_fn && "ECC Signer sign hash function must be included on the vtable");
    return signer->vtable->sign_payload_fn(signer, hash, signature);
}

int aws_ecc_signer_verify_signature(
    struct aws_ecc_signer *signer,
    const struct aws_byte_cursor *hash,
    const struct aws_byte_cursor *signature) {
    AWS_FATAL_ASSERT(signer->vtable->verify_payload_fn && "ECC Signer verify function must be included on the vtable");
    return signer->vtable->verify_payload_fn(signer, hash, signature);
}

size_t aws_ecc_signer_max_signature_length(struct aws_ecc_signer *signer) {
    AWS_FATAL_ASSERT(signer->vtable->signature_max_length_fn && "ECC Signer max length must be included on the vtable");
    return signer->vtable->signature_max_length_fn(signer);
}
