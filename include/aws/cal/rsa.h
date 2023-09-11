#ifndef AWS_CAL_RSA_H
#define AWS_CAL_RSA_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/cal.h>
#include <aws/common/byte_buf.h>

AWS_PUSH_SANE_WARNING_LEVEL

struct aws_rsa_key_pair;

enum aws_rsa_encryption_algorithm {
    AWS_CAL_RSA_ENCRYPTION_PKCS1_5,
    AWS_CAL_RSA_ENCRYPTION_OAEP_SHA256,
    AWS_CAL_RSA_ENCRYPTION_OAEP_SHA512
};

enum aws_rsa_signing_algorithm {
    AWS_CAL_RSA_SIGNATURE_PKCS1_5_SHA256,
    AWS_CAL_RSA_SIGNATURE_PSS_SHA256
};

enum {
    AWS_CAL_RSA_MIN_SUPPORTED_KEY_SIZE = 1024,
    AWS_CAL_RSA_MAX_SUPPORTED_KEY_SIZE = 4096,
};

AWS_EXTERN_C_BEGIN

/**
 * Creates an RSA public/private key pair that can be used for signing and verifying.
 * Returns a new instance of aws_ecc_key_pair if the key was successfully built.
 * Otherwise returns NULL.
 */
AWS_CAL_API struct aws_rsa_key_pair *aws_rsa_key_pair_new_generate_random(
    struct aws_allocator *allocator,
    size_t key_size_in_bits);

AWS_CAL_API struct aws_rsa_key_pair *aws_rsa_key_pair_new_from_public_key_pkcs1(
    struct aws_allocator *allocator,
    struct aws_byte_cursor key);

AWS_CAL_API struct aws_rsa_key_pair *aws_rsa_key_pair_new_from_private_key_pkcs1(
    struct aws_allocator *allocator,
    struct aws_byte_cursor key);

/**
 * Adds one to an RSA key pair's ref count.
 */
AWS_CAL_API struct aws_rsa_key_pair *aws_rsa_key_pair_acquire(struct aws_rsa_key_pair *key_pair);

/**
 * Subtracts one from an RSA key pair's ref count. If ref count reaches zero, the key pair is destroyed.
 */
AWS_CAL_API struct aws_rsa_key_pair *aws_rsa_key_pair_release(struct aws_rsa_key_pair *key_pair);

AWS_CAL_API size_t aws_rsa_key_pair_max_encrypt_plaintext_size(struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_encryption_algorithm algorithm);

AWS_CAL_API int aws_rsa_key_pair_encrypt(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_encryption_algorithm algorithm,
    struct aws_byte_cursor plaintext,
    struct aws_byte_buf *out);

AWS_CAL_API int aws_rsa_key_pair_decrypt(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_encryption_algorithm algorithm,
    struct aws_byte_cursor ciphertext,
    struct aws_byte_buf *out);

AWS_CAL_API size_t aws_rsa_key_pair_block_length(struct aws_rsa_key_pair *key_pair);

AWS_CAL_API int aws_rsa_key_pair_sign_message(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_signing_algorithm algorithm,
    struct aws_byte_cursor message,
    struct aws_byte_buf *out);

AWS_CAL_API int aws_rsa_key_pair_verify_signature(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_signing_algorithm algorithm,
    struct aws_byte_cursor message,
    struct aws_byte_cursor signature);


AWS_CAL_API size_t aws_rsa_key_pair_signature_length(struct aws_rsa_key_pair *key_pair);

AWS_CAL_API int aws_rsa_key_pair_get_public_key(
    const struct aws_rsa_key_pair *key_pair,
    struct aws_byte_cursor *out);

AWS_CAL_API int aws_rsa_key_pair_get_private_key(
    const struct aws_rsa_key_pair *key_pair,
    struct aws_byte_cursor *out);

AWS_EXTERN_C_END

AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_CAL_RSA_H */
