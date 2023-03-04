#ifndef AWS_CAL_SYMMETRIC_CIPHER_H
#define AWS_CAL_SYMMETRIC_CIPHER_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/cal.h>
#include <aws/common/byte_buf.h>

#define AWS_AES_256_CIPHER_BLOCK_SIZE 16
#define AWS_AES_256_KEY_BIT_LEN 256
#define AWS_AES_256_KEY_BYTE_LEN (AWS_AES_256_KEY_BIT_LEN / 8)

struct aws_symmetric_cipher;

struct aws_symmetric_cipher_vtable {
    const char *alg_name;
    const char *provider;
    void (*destroy)(struct aws_symmetric_cipher *cipher);
    int (*encrypt)(
        struct aws_symmetric_cipher *cipher,
        const struct aws_byte_cursor *to_encrypt,
        struct aws_byte_buf *out);
    int (*decrypt)(
        struct aws_symmetric_cipher *cipher,
        const struct aws_byte_cursor *to_encrypt,
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

struct aws_symmetric_cipher *aws_aes_cbc_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv);
struct aws_symmetric_cipher *aws_aes_ctr_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv);
struct aws_symmetric_cipher *aws_aes_gcm_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv,
    const struct aws_byte_cursor *aad);

void aws_symmetric_cipher_destroy(struct aws_symmetric_cipher *cipher);
int aws_symmetric_cipher_encrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_encrypt,
    struct aws_byte_buf *out);
int aws_symmetric_cipher_decrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_encrypt,
    struct aws_byte_buf *out);

int aws_symmetric_cipher_finalize_encryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out);
int aws_symmetric_cipher_finalize_decryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out);

int aws_symmetric_cipher_get_tag(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out);
int aws_symmetric_cipher_get_initialization_vector(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out);

int aws_symmetric_cipher_generate_initialization_vector(
    size_t len_bytes,
    bool is_counter_mode,
    struct aws_byte_buf *out);
int aws_symmetric_cipher_generate_key(size_t keyLengthBytes, struct aws_byte_buf *out);
AWS_EXTERN_C_END

#endif /* AWS_CAL_SYMMETRIC_CIPHER_H */
