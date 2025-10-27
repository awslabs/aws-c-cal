/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/hkdf.h>

#ifndef BYO_CRYPTO

extern int aws_hkdf_derive_impl(
    struct aws_allocator *allocator,
    enum aws_hkdf_hash_type,
    struct aws_byte_cursor ikm,
    struct aws_byte_cursor salt,
    struct aws_byte_cursor info,
    struct aws_byte_buf *out_buf,
    size_t length);

#else /* BYO_CRYPTO */

struct int aws_hkdf_derive_impl(
    struct aws_allocator *allocator,
    enum aws_hkdf_hash_type,
    struct aws_byte_cursor ikm,
    struct aws_byte_cursor salt,
    struct aws_byte_cursor info,
    struct aws_byte_buf *out_buf,
    size_t length) {
    (void)allocator;
    (void)curve_name;
    (void)public_key_x;
    (void)public_key_y;
    abort();
}

#endif /* BYO_CRYPTO */

static aws_hkdf_fn *s_hkdf_impl_fn = aws_hkdf_derive_impl;

AWS_CAL_API void aws_set_hkdf_fn(aws_hkdf_fn *fn) {
    s_hkdf_impl_fn = fn;
}

int aws_hkdf(
    struct aws_allocator *allocator,
    enum aws_hkdf_hash_type hash_type,
    struct aws_byte_cursor ikm,
    struct aws_byte_cursor salt,
    struct aws_byte_cursor info,
    struct aws_byte_buf *out_buf,
    size_t length) {

    AWS_ERROR_PRECONDITION(allocator);
    AWS_ERROR_PRECONDITION(hash_type == HKDF_HMAC_SHA512); /* only one supported right now */
    AWS_ERROR_PRECONDITION(ikm.len != 0);
    AWS_ERROR_PRECONDITION(out_buf);

    return s_hkdf_impl_fn(allocator, hash_type, ikm, salt, info, out_buf, length);
}
