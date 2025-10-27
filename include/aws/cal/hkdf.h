#ifndef AWS_CAL_ECC_H
#define AWS_CAL_ECC_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/exports.h>
#include <aws/common/byte_buf.h>
#include <aws/common/common.h>

AWS_PUSH_SANE_WARNING_LEVEL

AWS_EXTERN_C_BEGIN

enum aws_hkdf_hash_type { HKDF_HMAC_SHA512 };

AWS_CAL_API int aws_hkdf(
    struct aws_allocator *allocator,
    enum aws_hkdf_hash_type hash_type,
    struct aws_byte_cursor ikm,
    struct aws_byte_cursor salt,
    struct aws_byte_cursor info,
    struct aws_byte_buf *out_buf,
    size_t length);

typedef int(aws_hkdf_fn)(
    struct aws_allocator *allocator,
    enum aws_hkdf_hash_type hash_type,
    struct aws_byte_cursor ikm,
    struct aws_byte_cursor salt,
    struct aws_byte_cursor info,
    struct aws_byte_buf *out_buf,
    size_t length);

AWS_CAL_API void aws_set_hkdf_fn(aws_hkdf_fn *fn);

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_CAL_ECC_H */
