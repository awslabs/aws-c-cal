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
    /* reset the cipher to being able to start another encrypt or decrypt operation.
       The original IV, Key, Tag etc... will be restored to the current cipher. */
    int (*reset)(struct aws_symmetric_cipher *cipher);
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

/**
 * Creates an instance of AES CBC with 256-bit key.
 * If key and iv are NULL, they will be generated internally.
 * You can get the generated key and iv back by calling:
 *
 * aws_symmetric_cipher_get_key() and
 * aws_symmetric_cipher_get_initialization_vector()
 *
 * respectively.
 *
 * If they are set, that key and iv will be copied internally and used by the cipher.
 *
 * Returns NULL on failure. You can check aws_last_error() to get the error code indicating the failure cause.
 */
struct aws_symmetric_cipher *aws_aes_cbc_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv);

/**
 * Creates an instance of AES CTR with 256-bit key.
 * If key and iv are NULL, they will be generated internally.
 * You can get the generated key and iv back by calling:
 *
 * aws_symmetric_cipher_get_key() and
 * aws_symmetric_cipher_get_initialization_vector()
 *
 * respectively.
 *
 * If they are set, that key and iv will be copied internally and used by the cipher.
 *
 * Returns NULL on failure. You can check aws_last_error() to get the error code indicating the failure cause.
 */
struct aws_symmetric_cipher *aws_aes_ctr_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv);

/**
 * Creates an instance of AES GCM with 256-bit key.
 * If key, iv are NULL, they will be generated internally.
 * You can get the generated key and iv back by calling:
 *
 * aws_symmetric_cipher_get_key() and
 * aws_symmetric_cipher_get_initialization_vector()
 *
 * respectively.
 *
 * If they are set, that key and iv will be copied internally and used by the cipher.
 *
 * If tag and aad are set they will be copied internally and used by the cipher.
 * decryption_tag would most likely be used for a decrypt operation to detect tampering or corruption.
 * The Tag for the most recent encrypt operation will be available in:
 *
 * aws_symmetric_cipher_get_tag()
 *
 * If aad is set it will be copied and applied to the cipher.
 *
 * Returns NULL on failure. You can check aws_last_error() to get the error code indicating the failure cause.
 */
struct aws_symmetric_cipher *aws_aes_gcm_256_new(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv,
    const struct aws_byte_cursor *aad,
    const struct aws_byte_cursor *decryption_tag);

/**
 * Cleans up internal resources and state for cipher and then deallocates it.
 */
void aws_symmetric_cipher_destroy(struct aws_symmetric_cipher *cipher);

/**
 * Encrypts the value in to_encrypt and writes the encrypted data into out.
 * If out is dynamic it will be expanded. If it is not, and out is not large enough to handle
 * the encrypted output, the call will fail. If you're trying to optimize to use a stack based array
 * or something, make sure it's at least as large as the size of to_encrypt + an extra BLOCK to account for
 * padding etc...
 *
 * returns AWS_OP_SUCCESS on success. Call aws_last_error() to determine the failure cause if it returns
 * AWS_OP_ERR;
 */
int aws_symmetric_cipher_encrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_encrypt,
    struct aws_byte_buf *out);

/**
 * Decrypts the value in to_decrypt and writes the decrypted data into out.
 * If out is dynamic it will be expanded. If it is not, and out is not large enough to handle
 * the decrypted output, the call will fail. If you're trying to optimize to use a stack based array
 * or something, make sure it's at least as large as the size of to_decrypt + an extra BLOCK to account for
 * padding etc...
 *
 * returns AWS_OP_SUCCESS on success. Call aws_last_error() to determine the failure cause if it returns
 * AWS_OP_ERR;
 */
int aws_symmetric_cipher_decrypt(
    struct aws_symmetric_cipher *cipher,
    const struct aws_byte_cursor *to_decrypt,
    struct aws_byte_buf *out);

/**
 * Encrypts any remaining data that was reserved for final padding, loads GMACs etc... and if there is any
 * writes any remaining encrypted data to out. If out is dynamic it will be expanded. If it is not, and
 * out is not large enough to handle the decrypted output, the call will fail. If you're trying to optimize
 *  to use a stack based array or something, make sure it's at least as large as the size of 2 BLOCKs to account for
 * padding etc...
 *
 * After invoking this function, you MUST call aws_symmetric_cipher_reset() before invoking any encrypt/decrypt
 * operations on this cipher again.
 *
 * returns AWS_OP_SUCCESS on success. Call aws_last_error() to determine the failure cause if it returns
 * AWS_OP_ERR;
 */
int aws_symmetric_cipher_finalize_encryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out);

/**
 * Decrypts any remaining data that was reserved for final padding, loads GMACs etc... and if there is any
 * writes any remaining decrypted data to out. If out is dynamic it will be expanded. If it is not, and
 * out is not large enough to handle the decrypted output, the call will fail. If you're trying to optimize
 * to use a stack based array or something, make sure it's at least as large as the size of 2 BLOCKs to account for
 * padding etc...
 *
 * After invoking this function, you MUST call aws_symmetric_cipher_reset() before invoking any encrypt/decrypt
 * operations on this cipher again.
 *
 * returns AWS_OP_SUCCESS on success. Call aws_last_error() to determine the failure cause if it returns
 * AWS_OP_ERR;
 */
int aws_symmetric_cipher_finalize_decryption(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out);

/**
 * Resets the cipher state for starting a new encrypt or decrypt operation. Note encrypt/decrypt cannot be mixed on the
 * same cipher without a call to reset in between them. However, this leaves the key, iv etc... materials setup for
 * immediate reuse.
 *
 * returns AWS_OP_SUCCESS on success. Call aws_last_error() to determine the failure cause if it returns
 * AWS_OP_ERR;
 */
int aws_symmetric_cipher_reset(struct aws_symmetric_cipher *cipher);

/**
 * Gets the current GMAC tag. If not AES GCM, this function will just copy an empty buffer over.
 * You would typically call this function after calling aws_symmetric_cipher_finalize_encryption()
 * to fetch the tag for transmitting it in a cryptographic protocol.
 *
 * returns AWS_OP_SUCCESS on success. Call aws_last_error() to determine the failure cause if it returns
 * AWS_OP_ERR;
 */
int aws_symmetric_cipher_get_tag(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out);

/**
 * Gets the original intialization vector.
 *
 * returns AWS_OP_SUCCESS on success. Call aws_last_error() to determine the failure cause if it returns
 * AWS_OP_ERR;
 */
int aws_symmetric_cipher_get_initialization_vector(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out);

/**
 * Gets the original ke.
 *
 * returns AWS_OP_SUCCESS on success. Call aws_last_error() to determine the failure cause if it returns
 * AWS_OP_ERR;
 */
int aws_symmetric_cipher_get_key(struct aws_symmetric_cipher *cipher, struct aws_byte_buf *out);

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
int aws_symmetric_cipher_generate_initialization_vector(
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
int aws_symmetric_cipher_generate_key(size_t keyLengthBytes, struct aws_byte_buf *out);
AWS_EXTERN_C_END

#endif /* AWS_CAL_SYMMETRIC_CIPHER_H */
