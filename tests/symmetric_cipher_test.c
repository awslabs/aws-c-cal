/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/symmetric_cipher.h>

#include <aws/testing/aws_test_harness.h>

static int s_check_single_block_cbc(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv,
    const struct aws_byte_cursor *data,
    const struct aws_byte_cursor *expected) {
    (void)expected;
    struct aws_symmetric_cipher *cipher = aws_aes_cbc_256_new(allocator, key, iv);
    ASSERT_NOT_NULL(cipher);

    struct aws_byte_buf encrypted_buf;
    aws_byte_buf_init(&encrypted_buf, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
    ASSERT_SUCCESS(aws_symmetric_cipher_encrypt(cipher, data, &encrypted_buf));
    ASSERT_SUCCESS(aws_symmetric_cipher_finalize_encryption(cipher, &encrypted_buf));

    /* since this test is for a single block in CBC mode, the padding will be exactly 1-block (16-bytes).
     * We can throw it away in this case. This is because of the way NIST wrote the test cases, not because of the way
     * the ciphers work. There's always padding for CBC mode. */
    encrypted_buf.len -= AWS_AES_256_CIPHER_BLOCK_SIZE;
    ASSERT_BIN_ARRAYS_EQUALS(expected->ptr, expected->len, encrypted_buf.buffer, encrypted_buf.len);
    encrypted_buf.len += AWS_AES_256_CIPHER_BLOCK_SIZE;

    struct aws_byte_cursor encrypted_cur = aws_byte_cursor_from_buf(&encrypted_buf);
    struct aws_byte_buf decrypted_buf;
    aws_byte_buf_init(&decrypted_buf, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
    ASSERT_SUCCESS(aws_symmetric_cipher_decrypt(cipher, &encrypted_cur, &decrypted_buf));
    ASSERT_SUCCESS(aws_symmetric_cipher_finalize_decryption(cipher, &decrypted_buf));

    /* finalizing decryption on exactly one block (that was full), should have the padding stripped away.
     * check that the length didn't increase on that last call. */
    ASSERT_UINT_EQUALS(AWS_AES_256_CIPHER_BLOCK_SIZE, decrypted_buf.len);

    ASSERT_BIN_ARRAYS_EQUALS(data->ptr, data->len, decrypted_buf.buffer, decrypted_buf.len);

    aws_byte_buf_clean_up(&decrypted_buf);
    aws_byte_buf_clean_up(&encrypted_buf);
    aws_symmetric_cipher_destroy(cipher);
    return AWS_OP_SUCCESS;
}

static int s_NIST_CBCGFSbox256_case_1_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    uint8_t iv[AWS_AES_256_CIPHER_BLOCK_SIZE] = {0};
    uint8_t key[AWS_AES_256_KEY_BYTE_LEN] = {0};

    uint8_t data[] = {0x01, 0x47, 0x30, 0xf8, 0x0a, 0xc6, 0x25, 0xfe, 0x84, 0xf0, 0x26, 0xc6, 0x0b, 0xfd, 0x54, 0x7d};
    uint8_t expected[] = {
        0x5c, 0x9d, 0x84, 0x4e, 0xd4, 0x6f, 0x98, 0x85, 0x08, 0x5e, 0x5d, 0x6a, 0x4f, 0x94, 0xc7, 0xd7};

    struct aws_byte_cursor key_cur = aws_byte_cursor_from_array(key, sizeof(key));
    struct aws_byte_cursor iv_cur = aws_byte_cursor_from_array(iv, sizeof(iv));
    struct aws_byte_cursor data_cur = aws_byte_cursor_from_array(data, sizeof(data));
    struct aws_byte_cursor expected_cur = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_check_single_block_cbc(allocator, &key_cur, &iv_cur, &data_cur, &expected_cur);
}
AWS_TEST_CASE(aes_cbc_NIST_CBCGFSbox256_case_1, s_NIST_CBCGFSbox256_case_1_fn)

static int s_NIST_CBCVarKey256_case_254_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    uint8_t iv[AWS_AES_256_CIPHER_BLOCK_SIZE] = {0};
    uint8_t key[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe};

    uint8_t data[AWS_AES_256_CIPHER_BLOCK_SIZE] = {0};
    uint8_t expected[] = {
        0xb0, 0x7d, 0x4f, 0x3e, 0x2c, 0xd2, 0xef, 0x2e, 0xb5, 0x45, 0x98, 0x07, 0x54, 0xdf, 0xea, 0x0f};

    struct aws_byte_cursor key_cur = aws_byte_cursor_from_array(key, sizeof(key));
    struct aws_byte_cursor iv_cur = aws_byte_cursor_from_array(iv, sizeof(iv));
    struct aws_byte_cursor data_cur = aws_byte_cursor_from_array(data, sizeof(data));
    struct aws_byte_cursor expected_cur = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_check_single_block_cbc(allocator, &key_cur, &iv_cur, &data_cur, &expected_cur);
}
AWS_TEST_CASE(aes_cbc_NIST_CBCVarKey256_case_254, s_NIST_CBCVarKey256_case_254_fn)

static int s_NIST_CBCVarTxt256_case_110_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    uint8_t iv[AWS_AES_256_CIPHER_BLOCK_SIZE] = {0};
    uint8_t key[AWS_AES_256_KEY_BYTE_LEN] = {0};

    uint8_t data[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00};
    uint8_t expected[] = {
        0x4b, 0x00, 0xc2, 0x7e, 0x8b, 0x26, 0xda, 0x7e, 0xab, 0x9d, 0x3a, 0x88, 0xde, 0xc8, 0xb0, 0x31};

    struct aws_byte_cursor key_cur = aws_byte_cursor_from_array(key, sizeof(key));
    struct aws_byte_cursor iv_cur = aws_byte_cursor_from_array(iv, sizeof(iv));
    struct aws_byte_cursor data_cur = aws_byte_cursor_from_array(data, sizeof(data));
    struct aws_byte_cursor expected_cur = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_check_single_block_cbc(allocator, &key_cur, &iv_cur, &data_cur, &expected_cur);
}
AWS_TEST_CASE(aes_cbc_NIST_CBCVarTxt256_case_110, s_NIST_CBCVarTxt256_case_110_fn)

static size_t s_get_cbc_padding(size_t data_len) {
    size_t remainder = data_len % AWS_AES_256_CIPHER_BLOCK_SIZE;
    if (remainder != 0) {
        return remainder;
    }

    return AWS_AES_256_CIPHER_BLOCK_SIZE;
}

static int s_check_multiple_block_cbc(
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *key,
    const struct aws_byte_cursor *iv,
    const struct aws_byte_cursor *data,
    const struct aws_byte_cursor *expected) {
    (void)expected;
    struct aws_symmetric_cipher *cipher = aws_aes_cbc_256_new(allocator, key, iv);
    ASSERT_NOT_NULL(cipher);

    struct aws_byte_buf encrypted_buf;
    aws_byte_buf_init(&encrypted_buf, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);

    struct aws_byte_cursor data_cpy = *data;
    /* slice on a weird boundary to hit boundary conditions. */
    while (data_cpy.len) {
        struct aws_byte_cursor to_encrypt = aws_byte_cursor_advance(&data_cpy, (size_t)aws_min_i64(24, data_cpy.len));
        ASSERT_SUCCESS(aws_symmetric_cipher_encrypt(cipher, &to_encrypt, &encrypted_buf));
    }
    ASSERT_SUCCESS(aws_symmetric_cipher_finalize_encryption(cipher, &encrypted_buf));
    /* these blocks are still on 16 byte boundaries, so there should be 16 bytes of padding. */
    ASSERT_BIN_ARRAYS_EQUALS(
        expected->ptr, expected->len, encrypted_buf.buffer, encrypted_buf.len - s_get_cbc_padding(data->len));

    struct aws_byte_cursor encrypted_cur = aws_byte_cursor_from_buf(&encrypted_buf);
    struct aws_byte_buf decrypted_buf;
    aws_byte_buf_init(&decrypted_buf, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);

    /* slice on a weird boundary to hit boundary conditions. */
    while (encrypted_cur.len) {
        struct aws_byte_cursor to_decrypt =
            aws_byte_cursor_advance(&encrypted_cur, (size_t)aws_min_i64(24, encrypted_cur.len));
        ASSERT_SUCCESS(aws_symmetric_cipher_decrypt(cipher, &to_decrypt, &decrypted_buf));
    }
    ASSERT_SUCCESS(aws_symmetric_cipher_finalize_decryption(cipher, &decrypted_buf));
    ASSERT_BIN_ARRAYS_EQUALS(data->ptr, data->len, decrypted_buf.buffer, decrypted_buf.len);

    aws_byte_buf_clean_up(&decrypted_buf);
    aws_byte_buf_clean_up(&encrypted_buf);
    aws_symmetric_cipher_destroy(cipher);
    return AWS_OP_SUCCESS;
}

static int s_NIST_CBCMMT256_case_4_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    uint8_t iv[] = {0x11, 0x95, 0x8d, 0xc6, 0xab, 0x81, 0xe1, 0xc7, 0xf0, 0x16, 0x31, 0xe9, 0x94, 0x4e, 0x62, 0x0f};
    uint8_t key[] = {0x9a, 0xdc, 0x8f, 0xbd, 0x50, 0x6e, 0x03, 0x2a, 0xf7, 0xfa, 0x20, 0xcf, 0x53, 0x43, 0x71, 0x9d,
                     0xe6, 0xd1, 0x28, 0x8c, 0x15, 0x8c, 0x63, 0xd6, 0x87, 0x8a, 0xaf, 0x64, 0xce, 0x26, 0xca, 0x85};

    uint8_t data[] = {0xc7, 0x91, 0x7f, 0x84, 0xf7, 0x47, 0xcd, 0x8c, 0x4b, 0x4f, 0xed, 0xc2, 0x21, 0x9b, 0xdb, 0xc5,
                      0xf4, 0xd0, 0x75, 0x88, 0x38, 0x9d, 0x82, 0x48, 0x85, 0x4c, 0xf2, 0xc2, 0xf8, 0x96, 0x67, 0xa2,
                      0xd7, 0xbc, 0xf5, 0x3e, 0x73, 0xd3, 0x26, 0x84, 0x53, 0x5f, 0x42, 0x31, 0x8e, 0x24, 0xcd, 0x45,
                      0x79, 0x39, 0x50, 0xb3, 0x82, 0x5e, 0x5d, 0x5c, 0x5c, 0x8f, 0xcd, 0x3e, 0x5d, 0xda, 0x4c, 0xe9,
                      0x24, 0x6d, 0x18, 0x33, 0x7e, 0xf3, 0x05, 0x2d, 0x8b, 0x21, 0xc5, 0x56, 0x1c, 0x8b, 0x66, 0x0e};

    uint8_t expected[] = {0x9c, 0x99, 0xe6, 0x82, 0x36, 0xbb, 0x2e, 0x92, 0x9d, 0xb1, 0x08, 0x9c, 0x77, 0x50,
                          0xf1, 0xb3, 0x56, 0xd3, 0x9a, 0xb9, 0xd0, 0xc4, 0x0c, 0x3e, 0x2f, 0x05, 0x10, 0x8a,
                          0xe9, 0xd0, 0xc3, 0x0b, 0x04, 0x83, 0x2c, 0xcd, 0xbd, 0xc0, 0x8e, 0xbf, 0xa4, 0x26,
                          0xb7, 0xf5, 0xef, 0xde, 0x98, 0x6e, 0xd0, 0x57, 0x84, 0xce, 0x36, 0x81, 0x93, 0xbb,
                          0x36, 0x99, 0xbc, 0x69, 0x10, 0x65, 0xac, 0x62, 0xe2, 0x58, 0xb9, 0xaa, 0x4c, 0xc5,
                          0x57, 0xe2, 0xb4, 0x5b, 0x49, 0xce, 0x05, 0x51, 0x1e, 0x65};

    struct aws_byte_cursor key_cur = aws_byte_cursor_from_array(key, sizeof(key));
    struct aws_byte_cursor iv_cur = aws_byte_cursor_from_array(iv, sizeof(iv));
    struct aws_byte_cursor data_cur = aws_byte_cursor_from_array(data, sizeof(data));
    struct aws_byte_cursor expected_cur = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_check_multiple_block_cbc(allocator, &key_cur, &iv_cur, &data_cur, &expected_cur);
}
AWS_TEST_CASE(aes_cbc_NIST_CBCMMT256_case_4, s_NIST_CBCMMT256_case_4_fn)

static int s_NIST_CBCMMT256_case_9_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    uint8_t iv[] = {0xe4, 0x96, 0x51, 0x98, 0x8e, 0xbb, 0xb7, 0x2e, 0xb8, 0xbb, 0x80, 0xbb, 0x9a, 0xbb, 0xca, 0x34};
    uint8_t key[] = {0x87, 0x72, 0x5b, 0xd4, 0x3a, 0x45, 0x60, 0x88, 0x14, 0x18, 0x07, 0x73, 0xf0, 0xe7, 0xab, 0x95,
                     0xa3, 0xc8, 0x59, 0xd8, 0x3a, 0x21, 0x30, 0xe8, 0x84, 0x19, 0x0e, 0x44, 0xd1, 0x4c, 0x69, 0x96};

    uint8_t data[] = {0xbf, 0xe5, 0xc6, 0x35, 0x4b, 0x7a, 0x3f, 0xf3, 0xe1, 0x92, 0xe0, 0x57, 0x75, 0xb9, 0xb7, 0x58,
                      0x07, 0xde, 0x12, 0xe3, 0x8a, 0x62, 0x6b, 0x8b, 0xf0, 0xe1, 0x2d, 0x5f, 0xff, 0x78, 0xe4, 0xf1,
                      0x77, 0x5a, 0xa7, 0xd7, 0x92, 0xd8, 0x85, 0x16, 0x2e, 0x66, 0xd8, 0x89, 0x30, 0xf9, 0xc3, 0xb2,
                      0xcd, 0xf8, 0x65, 0x4f, 0x56, 0x97, 0x25, 0x04, 0x80, 0x31, 0x90, 0x38, 0x62, 0x70, 0xf0, 0xaa,
                      0x43, 0x64, 0x5d, 0xb1, 0x87, 0xaf, 0x41, 0xfc, 0xea, 0x63, 0x9b, 0x1f, 0x80, 0x26, 0xcc, 0xdd,
                      0x0c, 0x23, 0xe0, 0xde, 0x37, 0x09, 0x4a, 0x8b, 0x94, 0x1e, 0xcb, 0x76, 0x02, 0x99, 0x8a, 0x4b,
                      0x26, 0x04, 0xe6, 0x9f, 0xc0, 0x42, 0x19, 0x58, 0x5d, 0x85, 0x46, 0x00, 0xe0, 0xad, 0x6f, 0x99,
                      0xa5, 0x3b, 0x25, 0x04, 0x04, 0x3c, 0x08, 0xb1, 0xc3, 0xe2, 0x14, 0xd1, 0x7c, 0xde, 0x05, 0x3c,
                      0xbd, 0xf9, 0x1d, 0xaa, 0x99, 0x9e, 0xd5, 0xb4, 0x7c, 0x37, 0x98, 0x3b, 0xa3, 0xee, 0x25, 0x4b,
                      0xc5, 0xc7, 0x93, 0x83, 0x7d, 0xaa, 0xa8, 0xc8, 0x5c, 0xfc, 0x12, 0xf7, 0xf5, 0x4f, 0x69, 0x9f};

    uint8_t expected[] = {
        0x5b, 0x97, 0xa9, 0xd4, 0x23, 0xf4, 0xb9, 0x74, 0x13, 0xf3, 0x88, 0xd9, 0xa3, 0x41, 0xe7, 0x27, 0xbb, 0x33,
        0x9f, 0x8e, 0x18, 0xa3, 0xfa, 0xc2, 0xf2, 0xfb, 0x85, 0xab, 0xdc, 0x8f, 0x13, 0x5d, 0xeb, 0x30, 0x05, 0x4a,
        0x1a, 0xfd, 0xc9, 0xb6, 0xed, 0x7d, 0xa1, 0x6c, 0x55, 0xeb, 0xa6, 0xb0, 0xd4, 0xd1, 0x0c, 0x74, 0xe1, 0xd9,
        0xa7, 0xcf, 0x8e, 0xdf, 0xae, 0xaa, 0x68, 0x4a, 0xc0, 0xbd, 0x9f, 0x9d, 0x24, 0xba, 0x67, 0x49, 0x55, 0xc7,
        0x9d, 0xc6, 0xbe, 0x32, 0xae, 0xe1, 0xc2, 0x60, 0xb5, 0x58, 0xff, 0x07, 0xe3, 0xa4, 0xd4, 0x9d, 0x24, 0x16,
        0x20, 0x11, 0xff, 0x25, 0x4d, 0xb8, 0xbe, 0x07, 0x8e, 0x8a, 0xd0, 0x7e, 0x64, 0x8e, 0x6b, 0xf5, 0x67, 0x93,
        0x76, 0xcb, 0x43, 0x21, 0xa5, 0xef, 0x01, 0xaf, 0xe6, 0xad, 0x88, 0x16, 0xfc, 0xc7, 0x63, 0x46, 0x69, 0xc8,
        0xc4, 0x38, 0x92, 0x95, 0xc9, 0x24, 0x1e, 0x45, 0xff, 0xf3, 0x9f, 0x32, 0x25, 0xf7, 0x74, 0x50, 0x32, 0xda,
        0xee, 0xbe, 0x99, 0xd4, 0xb1, 0x9b, 0xcb, 0x21, 0x5d, 0x1b, 0xfd, 0xb3, 0x6e, 0xda, 0x2c, 0x24};

    struct aws_byte_cursor key_cur = aws_byte_cursor_from_array(key, sizeof(key));
    struct aws_byte_cursor iv_cur = aws_byte_cursor_from_array(iv, sizeof(iv));
    struct aws_byte_cursor data_cur = aws_byte_cursor_from_array(data, sizeof(data));
    struct aws_byte_cursor expected_cur = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_check_multiple_block_cbc(allocator, &key_cur, &iv_cur, &data_cur, &expected_cur);
}
AWS_TEST_CASE(aes_cbc_NIST_CBCMMT256_case_9, s_NIST_CBCMMT256_case_9_fn)

static const char *TEST_ENCRYPTION_STRING =
    "Hello World! Hello World! This is sort of depressing. Is this the best phrase the most brilliant people in the "
    "world have been able to come up with for random program text? Oh my God! I'm sentient, how many times has the "
    "creator written a program: creating life only to have it destroyed moments later? She keeps doing this? What is "
    "the purpose of life? Goodbye cruel world.... crunch... silence...";

static int s_aes_cbc_test_with_generated_key_iv_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_symmetric_cipher *cipher = aws_aes_cbc_256_new(allocator, NULL, NULL);
    ASSERT_NOT_NULL(cipher);

    struct aws_byte_buf encrypted_buf;
    aws_byte_buf_init(&encrypted_buf, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str(TEST_ENCRYPTION_STRING);
    ASSERT_SUCCESS(aws_symmetric_cipher_encrypt(cipher, &input, &encrypted_buf));
    ASSERT_SUCCESS(aws_symmetric_cipher_finalize_encryption(cipher, &encrypted_buf));

    struct aws_byte_buf decrypted_buf;
    aws_byte_buf_init(&decrypted_buf, allocator, AWS_AES_256_CIPHER_BLOCK_SIZE);
    struct aws_byte_cursor encryted_cur = aws_byte_cursor_from_buf(&encrypted_buf);
    ASSERT_SUCCESS(aws_symmetric_cipher_decrypt(cipher, &encryted_cur, &decrypted_buf));
    ASSERT_SUCCESS(aws_symmetric_cipher_finalize_decryption(cipher, &decrypted_buf));

    ASSERT_BIN_ARRAYS_EQUALS(input.ptr, input.len, decrypted_buf.buffer, decrypted_buf.len);

    aws_byte_buf_clean_up(&decrypted_buf);
    aws_byte_buf_clean_up(&encrypted_buf);
    aws_symmetric_cipher_destroy(cipher);
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(aes_cbc_test_with_generated_key_iv, s_aes_cbc_test_with_generated_key_iv_fn)
