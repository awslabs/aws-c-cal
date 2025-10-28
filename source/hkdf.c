/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/hkdf.h>

#ifndef BYO_CRYPTO

extern int aws_hkdf_derive_impl(
    struct aws_allocator *allocator,
    enum aws_hkdf_hmac_type hmac_type,
    struct aws_byte_cursor ikm,
    struct aws_byte_cursor salt,
    struct aws_byte_cursor info,
    struct aws_byte_buf *out_buf,
    size_t length);

#else /* BYO_CRYPTO */

int aws_hkdf_derive_impl(
    struct aws_allocator *allocator,
    enum aws_hkdf_hmac_type hmac_type,
    struct aws_byte_cursor ikm,
    struct aws_byte_cursor salt,
    struct aws_byte_cursor info,
    struct aws_byte_buf *out_buf,
    size_t length) {
    (void)allocator;
    (void)hmac_type;
    (void)ikm;
    (void)salt;
    (void)info;
    (void)out_buf;
    (void)length;
    abort();
}

#endif /* BYO_CRYPTO */

static aws_hkdf_fn *s_hkdf_impl_fn = aws_hkdf_derive_impl;

AWS_CAL_API void aws_set_hkdf_fn(aws_hkdf_fn *fn) {
    s_hkdf_impl_fn = fn;
}

int aws_hkdf_derive(
    struct aws_allocator *allocator,
    enum aws_hkdf_hmac_type hmac_type,
    struct aws_byte_cursor ikm,
    struct aws_byte_cursor salt,
    struct aws_byte_cursor info,
    struct aws_byte_buf *out_buf,
    size_t length) {

    AWS_ERROR_PRECONDITION(allocator);
    AWS_ERROR_PRECONDITION(hmac_type == HKDF_HMAC_SHA512); /* only one supported right now */
    AWS_ERROR_PRECONDITION(ikm.len != 0);
    AWS_ERROR_PRECONDITION(out_buf);

    return s_hkdf_impl_fn(allocator, hmac_type, ikm, salt, info, out_buf, length);
}
