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

enum aws_rsa_signing_algorithm { AWS_CAL_RSA_SIGNATURE_PKCS1_5_SHA256, AWS_CAL_RSA_SIGNATURE_PSS_SHA256 };

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

/**
 * Creates an RSA public key from RSAPublicKey as defined in rfc 8017 (aka PKCS1).
 * Returns a new instance of aws_rsa_key_pair if the key was successfully built.
 * Otherwise returns NULL.
 */
AWS_CAL_API struct aws_rsa_key_pair *aws_rsa_key_pair_new_from_public_key_pkcs1(
    struct aws_allocator *allocator,
    struct aws_byte_cursor key);

/**
 * Creates an RSA private key from RSAPrivateKey as defined in rfc 8017 (aka PKCS1).
 * Returns a new instance of aws_rsa_key_pair if the key was successfully built.
 * Otherwise returns NULL.
 */
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

/**
 * Max plaintext size that can be encrypted by the key (i.e. max data size
 * supported by the key - bytes needed for padding).
 */
AWS_CAL_API size_t aws_rsa_key_pair_max_encrypt_plaintext_size(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_encryption_algorithm algorithm);

/*
 * Uses the key_pair's private key to encrypt the plaintext. The output will be
 * in out. out must be large enough to to hold the ciphertext. Check
 * aws_rsa_key_pair_block_length() for output upper bound.
 */
AWS_CAL_API int aws_rsa_key_pair_encrypt(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_encryption_algorithm algorithm,
    struct aws_byte_cursor plaintext,
    struct aws_byte_buf *out);

/*
 * Uses the key_pair's private key to decrypt the ciphertext. The output will be
 * in out. out must be large enough to to hold the ciphertext. Check
 * aws_rsa_key_pair_block_length() for output upper bound.
 */
AWS_CAL_API int aws_rsa_key_pair_decrypt(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_encryption_algorithm algorithm,
    struct aws_byte_cursor ciphertext,
    struct aws_byte_buf *out);

/*
 * Max size for a block supported by a given key pair.
 */
AWS_CAL_API size_t aws_rsa_key_pair_block_length(struct aws_rsa_key_pair *key_pair);

/**
 * Uses the key_pair's private key to sign message. The output will be in out. out must be large enough
 * to hold the signature. Check aws_rsa_key_pair_signature_length() for the appropriate size.
 *
 * It is the callers job to make sure message is the appropriate cryptographic digest for this operation. It's usually
 * something like a SHA256.
 */
AWS_CAL_API int aws_rsa_key_pair_sign_message(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_signing_algorithm algorithm,
    struct aws_byte_cursor digest,
    struct aws_byte_buf *out);

/**
 * Uses the key_pair's public key to verify signature of message.
 *
 * It is the callers job to make sure message is the appropriate cryptographic digest for this operation. It's usually
 * something like a SHA256.
 *
 * returns AWS_OP_SUCCESS if the signature is valid.
 */
AWS_CAL_API int aws_rsa_key_pair_verify_signature(
    struct aws_rsa_key_pair *key_pair,
    enum aws_rsa_signing_algorithm algorithm,
    struct aws_byte_cursor digest,
    struct aws_byte_cursor signature);

/*
 * Max size for a signature supported by a given key pair.
 */
AWS_CAL_API size_t aws_rsa_key_pair_signature_length(struct aws_rsa_key_pair *key_pair);

/*
 * Get pkcs1 encoded public key for the key pair.
 */
AWS_CAL_API int aws_rsa_key_pair_get_public_key(const struct aws_rsa_key_pair *key_pair, struct aws_byte_cursor *out);

/*
 * Get pkcs1 private key for the key pair.
 */
AWS_CAL_API int aws_rsa_key_pair_get_private_key(const struct aws_rsa_key_pair *key_pair, struct aws_byte_cursor *out);

AWS_EXTERN_C_END

AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_CAL_RSA_H */
