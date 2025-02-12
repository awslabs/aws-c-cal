/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/ed25519.h>

#include <aws/testing/aws_test_harness.h>

#include "test_case_helper.h"

static int s_ed25519_key_pair_generate_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_cal_library_test_init(allocator);

    struct aws_ed25519_key_pair *pair = aws_ed25519_key_pair_new_generate(allocator);

    struct aws_byte_buf buf_pub;
    aws_byte_buf_init(
        &buf_pub, allocator, aws_ed25519_key_pair_get_public_key_size(AWS_CAL_ED25519_KEY_EXPORT_OPENSSH_B64));

    ASSERT_SUCCESS(aws_ed25519_key_pair_get_public_key(pair, AWS_CAL_ED25519_KEY_EXPORT_OPENSSH_B64, &buf_pub));

    struct aws_byte_buf buf_priv;
    aws_byte_buf_init(
        &buf_priv, allocator, aws_ed25519_key_pair_get_private_key_size(AWS_CAL_ED25519_KEY_EXPORT_OPENSSH_B64));

    ASSERT_SUCCESS(aws_ed25519_key_pair_get_private_key(pair, AWS_CAL_ED25519_KEY_EXPORT_OPENSSH_B64, &buf_priv));

    ASSERT_NOT_NULL(pair);
    aws_ed25519_key_pair_release(pair);

    aws_byte_buf_clean_up(&buf_pub);
    aws_byte_buf_clean_up(&buf_priv);

    aws_cal_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(ed25519_key_pair_generate_test, s_ed25519_key_pair_generate_test)
