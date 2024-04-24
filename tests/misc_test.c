/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/cal.h>

static int s_cal_reinit(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_cal_library_init(allocator);

    aws_cal_library_clean_up();

    aws_cal_library_init(allocator);
    CRYPTO_get_thread_local(1);
    aws_cal_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(cal_reinit, s_cal_reinit);