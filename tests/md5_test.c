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
#include <aws/cal/hash.h>
#include <aws/testing/aws_test_harness.h>

#include <test_case_helper.h>

/*
 * these are the rfc1321 test vectors
 */

static int s_md5_rfc1321_test_case_1_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("");
    uint8_t expected[] = {
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_hash_test_case(allocator, &input, &expected_buf, aws_md5_new);
}

AWS_TEST_CASE(md5_rfc1321_test_case_1, s_md5_rfc1321_test_case_1_fn)

static int s_md5_rfc1321_test_case_2_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input = aws_byte_cursor_from_c_str("a");
    uint8_t expected[] = {
            0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_hash_test_case(allocator, &input, &expected_buf, aws_md5_new);
}

AWS_TEST_CASE(md5_rfc1321_test_case_2, s_md5_rfc1321_test_case_2_fn)

static int s_md5_rfc1321_test_case_3_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input =
        aws_byte_cursor_from_c_str("abc");
    uint8_t expected[] = {
            0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_hash_test_case(allocator, &input, &expected_buf, aws_md5_new);
}

AWS_TEST_CASE(md5_rfc1321_test_case_3, s_md5_rfc1321_test_case_3_fn)

static int s_md5_rfc1321_test_case_4_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input =
        aws_byte_cursor_from_c_str("message digest");
    uint8_t expected[] = {
            0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_hash_test_case(allocator, &input, &expected_buf, aws_md5_new);
}

AWS_TEST_CASE(md5_rfc1321_test_case_4, s_md5_rfc1321_test_case_4_fn)

static int s_md5_rfc1321_test_case_5_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input =
            aws_byte_cursor_from_c_str("abcdefghijklmnopqrstuvwxyz");
    uint8_t expected[] = {
            0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_hash_test_case(allocator, &input, &expected_buf, aws_md5_new);
}

AWS_TEST_CASE(md5_rfc1321_test_case_5, s_md5_rfc1321_test_case_5_fn)

static int s_md5_rfc1321_test_case_6_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input =
            aws_byte_cursor_from_c_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    uint8_t expected[] = {
            0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41, 0x9d, 0x9f,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_hash_test_case(allocator, &input, &expected_buf, aws_md5_new);
}

AWS_TEST_CASE(md5_rfc1321_test_case_6, s_md5_rfc1321_test_case_6_fn)

static int s_md5_rfc1321_test_case_7_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input =
            aws_byte_cursor_from_c_str("12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    uint8_t expected[] = {
            0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 0xac, 0x49, 0xda, 0x2e, 0x21, 0x07, 0xb6, 0x7a,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_hash_test_case(allocator, &input, &expected_buf, aws_md5_new);
}

AWS_TEST_CASE(md5_rfc1321_test_case_7, s_md5_rfc1321_test_case_7_fn)

static int s_md5_rfc1321_test_case_7_truncated_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_byte_cursor input =
            aws_byte_cursor_from_c_str("12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    uint8_t expected[] = {
            0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55,
    };
    struct aws_byte_cursor expected_buf = aws_byte_cursor_from_array(expected, sizeof(expected));

    return s_verify_hash_test_case(allocator, &input, &expected_buf, aws_md5_new);
}

AWS_TEST_CASE(md5_rfc1321_test_case_7_truncated, s_md5_rfc1321_test_case_7_truncated_fn)
