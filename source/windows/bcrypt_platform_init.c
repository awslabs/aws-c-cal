/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/allocator.h>

#if defined(AWS_USE_LIBCRYPTO_TO_SUPPORT_ED25519_EVERYWHERE)
#    include <aws/cal/private/opensslcrypto_common.h>
#endif

void aws_cal_platform_init(struct aws_allocator *allocator) {
#if defined(AWS_USE_LIBCRYPTO_TO_SUPPORT_ED25519_EVERYWHERE)
    aws_validate_libcrypto_linkage();
#endif
    (void)allocator;
}

void aws_cal_platform_clean_up(void) {}

void aws_cal_platform_thread_clean_up(void) {}
