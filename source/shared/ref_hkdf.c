/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/cal.h>

#include <aws/cal/hkdf.h>
#include <aws/cal/hmac.h>

/*
 * Note: mac only provides hkdf starting in cryptokit (swift only)
 * and windows added convoluted api to generate hkdf starting with win 10+.
 * in rfc5869.
 */

enum { MAX_HMAC_SIZE = 64 };

static int s_hkdf_extract(
    struct aws_allocator *allocator,
    enum aws_hkdf_hmac_type hmac_type,
    struct aws_byte_cursor ikm,
    struct aws_byte_cursor salt,
    struct aws_byte_buf *out_prk_buf) {
    (void)hmac_type;
    static size_t zero_salt[64] = {0};

    if (salt.len == 0) {
        salt = aws_byte_cursor_from_array(zero_salt, 64);
    }

    /* PRK = HMAC-Hash(salt, IKM) */
    return aws_sha512_hmac_compute(allocator, &salt, &ikm, out_prk_buf, 0);
}

static int s_hkdf_expand(
    struct aws_allocator *allocator,
    enum aws_hkdf_hmac_type hmac_type,
    struct aws_byte_cursor prk,
    struct aws_byte_cursor info,
    struct aws_byte_buf *out_okm_buf,
    size_t length) {
    (void)hmac_type;
    static size_t hmac_length = 64; /* sha512 hmac */

    /*
     * Follows rfc implementation.
     * N = ceil(L/HashLen)
     * T = T(1) | T(2) | T(3) | ... | T(N) (i.e. concat of successive T(x))
     * OKM = first L octets of T
     * where:
     * T(0) = empty string (zero length)
     * T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
     * T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
     * T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
     * ...
     * Note: each T hmac has a single byte of counter appended to data, which increases on every iteration.
     */

    size_t num_iterations = (length + hmac_length - 1) / hmac_length; /* round up */

    if (num_iterations > 255) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct aws_byte_buf ret_buf;
    /* the approach is to append successive hmacs until we get over required length and then truncate.
     * so overallocate here */
    aws_byte_buf_init(&ret_buf, allocator, length + hmac_length);

    struct aws_byte_cursor prev_cur = {0};

    struct aws_hmac *hmac = NULL;

    for (uint8_t counter = 1; counter <= num_iterations; ++counter) {

        hmac = aws_sha512_hmac_new(allocator, &prk);
        if (!hmac) {
            goto on_error;
        }

        if (aws_hmac_update(hmac, &prev_cur)) {
            goto on_error;
        }

        if (info.len > 0) {
            if (aws_hmac_update(hmac, &info)) {
                goto on_error;
            }
        }

        struct aws_byte_cursor counter_cur = {
            .ptr = &counter,
            .len = 1,
        };

        if (aws_hmac_update(hmac, &counter_cur)) {
            goto on_error;
        }

        if (aws_hmac_finalize(hmac, &ret_buf, 0)) {
            goto on_error;
        }

        prev_cur = (struct aws_byte_cursor){
            .ptr = ret_buf.buffer + (counter - 1) * hmac_length,
            .len = hmac_length,
        };
        aws_hmac_destroy(hmac);
        hmac = NULL;
    }

    struct aws_byte_cursor ret_cur = aws_byte_cursor_from_buf(&ret_buf);
    ret_cur.len = length; /* truncate to required length */

    if (aws_byte_buf_append(out_okm_buf, &ret_cur)) {
        goto on_error;
    }

    aws_byte_buf_clean_up(&ret_buf);
    return AWS_OP_SUCCESS;

on_error:
    aws_byte_buf_clean_up(&ret_buf);
    aws_hmac_destroy(hmac);
    return AWS_OP_ERR;
}

int aws_hkdf_derive_impl(
    struct aws_allocator *allocator,
    enum aws_hkdf_hmac_type hmac_type,
    struct aws_byte_cursor ikm,
    struct aws_byte_cursor salt,
    struct aws_byte_cursor info,
    struct aws_byte_buf *out_buf,
    size_t length) {

    AWS_PRECONDITION(hmac_type == HKDF_HMAC_SHA512);

    uint8_t prk[MAX_HMAC_SIZE] = {0};
    struct aws_byte_buf prk_buf = aws_byte_buf_from_empty_array(prk, MAX_HMAC_SIZE);

    if (s_hkdf_extract(allocator, hmac_type, ikm, salt, &prk_buf)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor prk_cur = aws_byte_cursor_from_buf(&prk_buf);

    return s_hkdf_expand(allocator, hmac_type, prk_cur, info, out_buf, length);
}
