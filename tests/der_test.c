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

#include <aws/cal/der.h>

#include <aws/testing/aws_test_harness.h>

/* note that this int is unsigned, with the high bit set, so needs to be encoded specially */
static uint8_t s_bigint[] = {
    0x8f, 0xe2, 0x41, 0x2a, 0x08, 0xe8, 0x51, 0xa8, 0x8c, 0xb3, 0xe8, 0x53, 0xe7, 0xd5, 0x49, 0x50, 0xb3, 0x27, 0x8a,
    0x2b, 0xcb, 0xea, 0xb5, 0x42, 0x73, 0xea, 0x02, 0x57, 0xcc, 0x65, 0x33, 0xee, 0x88, 0x20, 0x61, 0xa1, 0x17, 0x56,
    0xc1, 0x24, 0x18, 0xe3, 0xa8, 0x08, 0xd3, 0xbe, 0xd9, 0x31, 0xf3, 0x37, 0x0b, 0x94, 0xb8, 0xcc, 0x43, 0x08, 0x0b,
    0x70, 0x24, 0xf7, 0x9c, 0xb1, 0x8d, 0x5d, 0xd6, 0x6d, 0x82, 0xd0, 0x54, 0x09, 0x84, 0xf8, 0x9f, 0x97, 0x01, 0x75,
    0x05, 0x9c, 0x89, 0xd4, 0xd5, 0xc9, 0x1e, 0xc9, 0x13, 0xd7, 0x2a, 0x6b, 0x30, 0x91, 0x19, 0xd6, 0xd4, 0x42, 0xe0,
    0xc4, 0x9d, 0x7c, 0x92, 0x71, 0xe1, 0xb2, 0x2f, 0x5c, 0x8d, 0xee, 0xf0, 0xf1, 0x17, 0x1e, 0xd2, 0x5f, 0x31, 0x5b,
    0xb1, 0x9c, 0xbc, 0x20, 0x55, 0xbf, 0x3a, 0x37, 0x42, 0x45, 0x75, 0xdc, 0x90, 0x65,
};

static uint8_t s_encoded_bigint[] = {
    0x02 /* INTEGER */,
    0x81 /* 1 byte length */,
    0x81 /* 0x81 bytes */,
    0x00 /* unsigned */,
    0x8f,
    0xe2,
    0x41,
    0x2a,
    0x08,
    0xe8,
    0x51,
    0xa8,
    0x8c,
    0xb3,
    0xe8,
    0x53,
    0xe7,
    0xd5,
    0x49,
    0x50,
    0xb3,
    0x27,
    0x8a,
    0x2b,
    0xcb,
    0xea,
    0xb5,
    0x42,
    0x73,
    0xea,
    0x02,
    0x57,
    0xcc,
    0x65,
    0x33,
    0xee,
    0x88,
    0x20,
    0x61,
    0xa1,
    0x17,
    0x56,
    0xc1,
    0x24,
    0x18,
    0xe3,
    0xa8,
    0x08,
    0xd3,
    0xbe,
    0xd9,
    0x31,
    0xf3,
    0x37,
    0x0b,
    0x94,
    0xb8,
    0xcc,
    0x43,
    0x08,
    0x0b,
    0x70,
    0x24,
    0xf7,
    0x9c,
    0xb1,
    0x8d,
    0x5d,
    0xd6,
    0x6d,
    0x82,
    0xd0,
    0x54,
    0x09,
    0x84,
    0xf8,
    0x9f,
    0x97,
    0x01,
    0x75,
    0x05,
    0x9c,
    0x89,
    0xd4,
    0xd5,
    0xc9,
    0x1e,
    0xc9,
    0x13,
    0xd7,
    0x2a,
    0x6b,
    0x30,
    0x91,
    0x19,
    0xd6,
    0xd4,
    0x42,
    0xe0,
    0xc4,
    0x9d,
    0x7c,
    0x92,
    0x71,
    0xe1,
    0xb2,
    0x2f,
    0x5c,
    0x8d,
    0xee,
    0xf0,
    0xf1,
    0x17,
    0x1e,
    0xd2,
    0x5f,
    0x31,
    0x5b,
    0xb1,
    0x9c,
    0xbc,
    0x20,
    0x55,
    0xbf,
    0x3a,
    0x37,
    0x42,
    0x45,
    0x75,
    0xdc,
    0x90,
    0x65,
};

static int s_der_encode_integer(struct aws_allocator *allocator, void *ctx) {
    struct aws_der_encoder encoder;
    ASSERT_SUCCESS(aws_der_encoder_init(&encoder, allocator, 1024));
    struct aws_byte_cursor bigint_cur = aws_byte_cursor_from_array(s_bigint, AWS_ARRAY_SIZE(s_bigint));
    ASSERT_SUCCESS(aws_der_encoder_write_integer(&encoder, bigint_cur));
    struct aws_byte_cursor encoded_cur;
    ASSERT_SUCCESS(aws_der_encoder_get_contents(&encoder, &encoded_cur));

    ASSERT_BIN_ARRAYS_EQUALS(s_encoded_bigint, AWS_ARRAY_SIZE(s_encoded_bigint), encoded_cur.ptr, encoded_cur.len);
    return 0;
}

AWS_TEST_CASE(der_encode_integer, s_der_encode_integer)

static int s_der_encode_boolean(struct aws_allocator *allocator, void *ctx) {
    return 0;
}

AWS_TEST_CASE(der_encode_boolean, s_der_encode_boolean)

static int s_der_encode_null(struct aws_allocator *allocator, void *ctx) {
    return 0;
}

AWS_TEST_CASE(der_encode_null, s_der_encode_null)

static int s_der_encode_bit_string(struct aws_allocator *allocator, void *ctx) {
    return 0;
}

AWS_TEST_CASE(der_encode_bit_string, s_der_encode_bit_string)

static int s_der_encode_octet_string(struct aws_allocator *allocator, void *ctx) {
    return 0;
}

AWS_TEST_CASE(der_encode_octet_string, s_der_encode_octet_string)

static int s_der_encode_sequence(struct aws_allocator *allocator, void *ctx) {
    return 0;
}

AWS_TEST_CASE(der_encode_sequence, s_der_encode_sequence)

static int s_der_encode_set(struct aws_allocator *allocator, void *ctx) {
    return 0;
}

AWS_TEST_CASE(der_encode_set, s_der_encode_set)

static int s_der_decode_integer(struct aws_allocator *allocator, void *ctx) {
    const size_t encoded_size = AWS_ARRAY_SIZE(s_encoded_bigint);
    const size_t decoded_size = AWS_ARRAY_SIZE(s_bigint);
    struct aws_byte_buf buffer = aws_byte_buf_from_array(s_encoded_bigint, encoded_size);
    struct aws_der_decoder decoder;
    ASSERT_SUCCESS(aws_der_decoder_init(&decoder, allocator, &buffer));
    ASSERT_SUCCESS(aws_der_decoder_parse(&decoder));
    ASSERT_TRUE(aws_der_decoder_next(&decoder));

    /* note that the decoded bigint will have a prepended 0 byte to indicate unsigned */
    ASSERT_INT_EQUALS(DER_INTEGER, aws_der_decoder_tlv_type(&decoder));
    ASSERT_INT_EQUALS(decoded_size+1, aws_der_decoder_tlv_length(&decoder));
    struct aws_byte_buf decoded;
    ASSERT_SUCCESS(aws_byte_buf_init(&decoded, allocator, encoded_size));
    ASSERT_SUCCESS(aws_der_decoder_tlv_integer(&decoder, &decoded));
    ASSERT_BIN_ARRAYS_EQUALS(s_bigint, decoded_size, decoded.buffer+1, decoded.len-1);

    return 0;
}

AWS_TEST_CASE(der_decode_integer, s_der_decode_integer)

static int s_der_decode_boolean(struct aws_allocator *allocator, void *ctx) {
    return 0;
}

AWS_TEST_CASE(der_decode_boolean, s_der_decode_boolean)

static int s_der_decode_null(struct aws_allocator *allocator, void *ctx) {
    return 0;
}

AWS_TEST_CASE(der_decode_null, s_der_decode_null)

static int s_der_decode_bit_string(struct aws_allocator *allocator, void *ctx) {
    return 0;
}

AWS_TEST_CASE(der_decode_bit_string, s_der_decode_bit_string)

static int s_der_decode_octet_string(struct aws_allocator *allocator, void *ctx) {
    return 0;
}

AWS_TEST_CASE(der_decode_octet_string, s_der_decode_octet_string)

static int s_der_decode_sequence(struct aws_allocator *allocator, void *ctx) {
    return 0;
}

AWS_TEST_CASE(der_decode_sequence, s_der_decode_sequence)

static int s_der_decode_set(struct aws_allocator *allocator, void *ctx) {
    return 0;
}

AWS_TEST_CASE(der_decode_set, s_der_decode_set)
