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

    ASSERT_NOT_NULL(pair);
    aws_ed25519_key_pair_release(pair);

    aws_cal_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(ed25519_key_pair_generate_test, s_ed25519_key_pair_generate_test)
