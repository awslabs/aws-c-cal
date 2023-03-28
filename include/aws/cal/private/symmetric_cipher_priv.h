#ifndef AWS_CAL_SYMMETRIC_CIPHER_PRIV_H
#define AWS_CAL_SYMMETRIC_CIPHER_PRIV_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/symmetric_cipher.h>

struct aws_symmetric_cipher;

struct aws_symmetric_cipher_vtable {
    const char *alg_name;
    const char *provider;
    void (*destroy)(struct aws_symmetric_cipher *cipher);
    /* reset the cipher to being able to start another encrypt or decrypt operation.
       The original IV, Key, Tag etc... will be restored to the current cipher. */
    int (*reset)(struct aws_symmetric_cipher *cipher);
    int (*encrypt)(
        struct aws_symmetric_cipher *cipher,
        const struct aws_byte_cursor to_encrypt,
        struct aws_byte_buf *out);
    int (*decrypt)(
        struct aws_symmetric_cipher *cipher,
        const struct aws_byte_cursor to_encrypt,
        struct aws_byte_buf *out);

    int (*finalize_encryption)(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out);
    int (*finalize_decryption)(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out);
};

struct aws_symmetric_cipher {
    struct aws_allocator *allocator;
    struct aws_symmetric_cipher_vtable *vtable;
    struct aws_byte_buf iv;
    struct aws_byte_buf key;
    struct aws_byte_buf aad;
    struct aws_byte_buf tag;
    size_t block_size;
    size_t key_length_bits;
    bool good;
    void *impl;
};

AWS_EXTERN_C_BEGIN

/**
 * Generates a secure random initialization vector of length len_bytes. If is_counter_mode is set, the final 4 bytes
 * will be reserved as a counter and initialized to 1 in big-endian byte-order.
 *
 * out is appended dynamically and will automatically expand the buffer if it needs to. If you need to optimize with
 * stack allocated arrays or something, make sure it's at least as large as len_bytes.
 *
 * returns AWS_OP_SUCCESS on success. Call aws_last_error() to determine the failure cause if it returns
 * AWS_OP_ERR;
 */
AWS_CAL_API int aws_symmetric_cipher_generate_initialization_vector(
    size_t len_bytes,
    bool is_counter_mode,
    struct aws_byte_buf *out);

/**
 * Generates a secure random symmetric key of length len_bytes.
 *
 * out is appended dynamically and will automatically expand the buffer if it needs to. If you need to optimize with
 * stack allocated arrays or something, make sure it's at least as large as len_bytes.
 *
 * returns AWS_OP_SUCCESS on success. Call aws_last_error() to determine the failure cause if it returns
 * AWS_OP_ERR;
 */
AWS_CAL_API int aws_symmetric_cipher_generate_key(size_t keyLengthBytes, struct aws_byte_buf *out);
AWS_EXTERN_C_END

#endif /* AWS_CAL_SYMMETRIC_CIPHER_PRIV_H */
