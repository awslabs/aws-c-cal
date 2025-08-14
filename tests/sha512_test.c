/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/hash.h>
#include <aws/common/byte_buf.h>
#include <aws/testing/aws_test_harness.h>

#include "test_case_helper.h"
/*
 * these are the NIST test vectors, as compiled here:
 * https://www.di-mgt.com.au/sha_testvectors.html
 */

static int s_sha512_nist_test_case_1_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("abc");
    uint8_t expected[] = {
        0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, 0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e, 0x08,
        0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d, 0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e, 0x10, 0xe1,
        0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9, 0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40, 0x57, 0x34, 0x0b,
        0x4c, 0xf4, 0x08, 0xd5, 0xa5, 0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0

    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_hash_test_case(allocator, &input, &expected_buf, aws_sha512_new);
}

AWS_TEST_CASE(sha512_nist_test_case_1, s_sha512_nist_test_case_1_fn)

static int s_sha512_nist_test_case_2_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("");
    uint8_t expected[] = {0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6,
                          0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4,
                          0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2,
                          0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd,
                          0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e};
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_hash_test_case(allocator, &input, &expected_buf, aws_sha512_new);
}

AWS_TEST_CASE(sha512_nist_test_case_2, s_sha512_nist_test_case_2_fn)

static int s_sha512_nist_test_case_3_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input =
        aws_byte_cursor_from_c_str("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    uint8_t expected[] = {
        0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16, 0x57,
        0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35, 0x96, 0xfd,
        0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9, 0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0, 0x31, 0xad, 0x85,
        0xc7, 0xa7, 0x1d, 0xd7, 0x03, 0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45

    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_hash_test_case(allocator, &input, &expected_buf, aws_sha512_new);
}

AWS_TEST_CASE(sha512_nist_test_case_3, s_sha512_nist_test_case_3_fn)

static int s_sha512_nist_test_case_4_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("abcdefghbcdefghicdefghijdefghijkefghijklfghij"
                                                              "klmghijklmnhijklmnoijklmnopjklmnopqklm"
                                                              "nopqrlmnopqrsmnopqrstnopqrstu");
    uint8_t expected[] = {0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14,
                          0xfc, 0x14, 0x3f, 0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99,
                          0xae, 0xad, 0xb6, 0x88, 0x90, 0x18, 0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7,
                          0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a, 0xc7, 0xd3, 0x29, 0xee,
                          0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09};
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_hash_test_case(allocator, &input, &expected_buf, aws_sha512_new);
}

AWS_TEST_CASE(sha512_nist_test_case_4, s_sha512_nist_test_case_4_fn)

static int s_sha512_nist_test_case_5_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_cal_library_test_init(allocator);

    struct aws_hash *hash = aws_sha512_new(allocator);
    ASSERT_NOT_NULL(hash);
    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("a");

    for (size_t i = 0; i < 1000000; ++i) {
        ASSERT_SUCCESS(aws_hash_update(hash, &input));
    }

    uint8_t output[AWS_SHA512_LEN] = {0};
    struct aws_byte_buf output_buf = aws_byte_buf_from_array(output, sizeof(output));
    output_buf.len = 0;
    ASSERT_SUCCESS(aws_hash_finalize(hash, &output_buf, 0));

    uint8_t expected[] = {
        0xe7, 0x18, 0x48, 0x3d, 0x0c, 0xe7, 0x69, 0x64, 0x4e, 0x2e, 0x42, 0xc7, 0xbc, 0x15, 0xb4, 0x63, 0x8e,
        0x1f, 0x98, 0xb1, 0x3b, 0x20, 0x44, 0x28, 0x56, 0x32, 0xa8, 0x03, 0xaf, 0xa9, 0x73, 0xeb, 0xde, 0x0f,
        0xf2, 0x44, 0x87, 0x7e, 0xa6, 0x0a, 0x4c, 0xb0, 0x43, 0x2c, 0xe5, 0x77, 0xc3, 0x1b, 0xeb, 0x00, 0x9c,
        0x5c, 0x2c, 0x49, 0xaa, 0x2e, 0x4e, 0xad, 0xb2, 0x17, 0xad, 0x8c, 0xc0, 0x9b

    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));
    ASSERT_BIN_ARRAYS_EQUALS(expected_buf.ptr, expected_buf.len, output_buf.buffer, output_buf.len);

    aws_hash_destroy(hash);

    aws_cal_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sha512_nist_test_case_5, s_sha512_nist_test_case_5_fn)

static int s_sha512_nist_test_case_5_truncated_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_cal_library_test_init(allocator);

    struct aws_hash *hash = aws_sha512_new(allocator);
    ASSERT_NOT_NULL(hash);
    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("a");

    for (size_t i = 0; i < 1000000; ++i) {
        ASSERT_SUCCESS(aws_hash_update(hash, &input));
    }

    uint8_t expected[] = {
        0xe7, 0x18, 0x48, 0x3d, 0x0c, 0xe7, 0x69, 0x64, 0x4e, 0x2e, 0x42, 0xc7, 0xbc, 0x15, 0xb4, 0x63,
        0x8e, 0x1f, 0x98, 0xb1, 0x3b, 0x20, 0x44, 0x28, 0x56, 0x32, 0xa8, 0x03, 0xaf, 0xa9, 0x73, 0xeb,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));
    uint8_t output[AWS_SHA512_LEN] = {0};
    struct aws_byte_buf output_buf = aws_byte_buf_from_array(output, expected_buf.len);
    output_buf.len = 0;
    ASSERT_SUCCESS(aws_hash_finalize(hash, &output_buf, 32));

    ASSERT_BIN_ARRAYS_EQUALS(expected_buf.ptr, expected_buf.len, output_buf.buffer, output_buf.len);

    aws_hash_destroy(hash);

    aws_cal_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sha512_nist_test_case_5_truncated, s_sha512_nist_test_case_5_truncated_fn)

static int s_sha512_nist_test_case_6_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_cal_library_test_init(allocator);

    struct aws_hash *hash = aws_sha512_new(allocator);
    ASSERT_NOT_NULL(hash);
    struct aws_byte_cursor input =
        aws_byte_cursor_from_c_str("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");

    for (size_t i = 0; i < 16777216; ++i) {
        ASSERT_SUCCESS(aws_hash_update(hash, &input));
    }

    uint8_t output[AWS_SHA512_LEN] = {0};
    struct aws_byte_buf output_buf = aws_byte_buf_from_array(output, sizeof(output));
    output_buf.len = 0;
    ASSERT_SUCCESS(aws_hash_finalize(hash, &output_buf, 0));

    uint8_t expected[] = {0xb4, 0x7c, 0x93, 0x34, 0x21, 0xea, 0x2d, 0xb1, 0x49, 0xad, 0x6e, 0x10, 0xfc,
                          0xe6, 0xc7, 0xf9, 0x3d, 0x07, 0x52, 0x38, 0x01, 0x80, 0xff, 0xd7, 0xf4, 0x62,
                          0x9a, 0x71, 0x21, 0x34, 0x83, 0x1d, 0x77, 0xbe, 0x60, 0x91, 0xb8, 0x19, 0xed,
                          0x35, 0x2c, 0x29, 0x67, 0xa2, 0xe2, 0xd4, 0xfa, 0x50, 0x50, 0x72, 0x3c, 0x96,
                          0x30, 0x69, 0x1f, 0x1a, 0x05, 0xa7, 0x28, 0x1d, 0xbe, 0x6c, 0x10, 0x86};

    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));
    ASSERT_BIN_ARRAYS_EQUALS(expected_buf.ptr, expected_buf.len, output_buf.buffer, output_buf.len);

    aws_hash_destroy(hash);

    aws_cal_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sha512_nist_test_case_6, s_sha512_nist_test_case_6_fn)

static int s_sha512_test_invalid_buffer_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_cal_library_test_init(allocator);

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("abcdefghbcdefghicdefghijdefghijkefghijklfghij"
                                                              "klmghijklmnhijklmnoijklmnopjklmnopqklm"
                                                              "nopqrlmnopqrsmnopqrstnopqrstu");
    uint8_t output[AWS_SHA512_LEN] = {0};
    struct aws_byte_buf output_buf = aws_byte_buf_from_array(output, sizeof(output));
    output_buf.len = 1;

    ASSERT_ERROR(AWS_ERROR_SHORT_BUFFER, aws_sha512_compute(allocator, &input, &output_buf, 0));

    aws_cal_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sha512_test_invalid_buffer, s_sha512_test_invalid_buffer_fn)

static int s_sha512_test_oneshot_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_cal_library_test_init(allocator);

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("abcdefghbcdefghicdefghijdefghijkefghijklfghij"
                                                              "klmghijklmnhijklmnoijklmnopjklmnopqklm"
                                                              "nopqrlmnopqrsmnopqrstnopqrstu");
    uint8_t expected[] = {0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14,
                          0xfc, 0x14, 0x3f, 0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99,
                          0xae, 0xad, 0xb6, 0x88, 0x90, 0x18, 0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7,
                          0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a, 0xc7, 0xd3, 0x29, 0xee,
                          0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09};

    uint8_t output[AWS_SHA512_LEN] = {0};
    struct aws_byte_buf output_buf = aws_byte_buf_from_array(output, sizeof(output));
    output_buf.len = 0;

    ASSERT_SUCCESS(aws_sha512_compute(allocator, &input, &output_buf, 0));
    ASSERT_BIN_ARRAYS_EQUALS(expected, sizeof(expected), output_buf.buffer, output_buf.len);

    aws_cal_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sha512_test_oneshot, s_sha512_test_oneshot_fn)

static int s_sha512_test_invalid_state_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_cal_library_test_init(allocator);

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("abcdefghbcdefghicdefghijdefghijkefghijklfghij"
                                                              "klmghijklmnhijklmnoijklmnopjklmnopqklm"
                                                              "nopqrlmnopqrsmnopqrstnopqrstu");

    struct aws_hash *hash = aws_sha512_new(allocator);
    ASSERT_NOT_NULL(hash);

    uint8_t output[AWS_SHA512_LEN] = {0};
    struct aws_byte_buf output_buf = aws_byte_buf_from_array(output, sizeof(output));
    output_buf.len = 0;

    ASSERT_SUCCESS(aws_hash_update(hash, &input));
    ASSERT_SUCCESS(aws_hash_finalize(hash, &output_buf, 0));
    ASSERT_ERROR(AWS_ERROR_INVALID_STATE, aws_hash_update(hash, &input));
    ASSERT_ERROR(AWS_ERROR_INVALID_STATE, aws_hash_finalize(hash, &output_buf, 0));

    aws_hash_destroy(hash);

    aws_cal_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(sha512_test_invalid_state, s_sha512_test_invalid_state_fn)

static int s_sha512_test_extra_buffer_space_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_cal_library_test_init(allocator);

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("123456789012345678901234567890123456789012345"
                                                              "67890123456789012345678901234567890");

    struct aws_byte_buf digest_size_buf;
    struct aws_byte_buf super_size_buf;

    aws_byte_buf_init(&digest_size_buf, allocator, AWS_SHA512_LEN);
    aws_byte_buf_init(&super_size_buf, allocator, AWS_SHA512_LEN + 100);

    aws_sha512_compute(allocator, &input, &digest_size_buf, 0);
    aws_sha512_compute(allocator, &input, &super_size_buf, 0);

    ASSERT_TRUE(aws_byte_buf_eq(&digest_size_buf, &super_size_buf));
    ASSERT_TRUE(super_size_buf.len == AWS_SHA512_LEN);

    aws_byte_buf_clean_up(&digest_size_buf);
    aws_byte_buf_clean_up(&super_size_buf);

    aws_cal_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(sha512_test_extra_buffer_space, s_sha512_test_extra_buffer_space_fn)
