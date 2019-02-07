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
#include <aws/cal/hmac.h>

#ifndef AWS_BYO_CRYPTO
extern struct aws_hmac *aws_sha256_hmac_default_new(struct aws_allocator *allocator, struct aws_byte_cursor *secret);
static aws_hmac_new_fn *s_sha256_hmac_new_fn = aws_sha256_hmac_default_new;
#else
static struct aws_hmac *aws_hmac_new_abort(struct aws_allocator *allocator, struct aws_byte_cursor *secret) {
    (void)allocator;
    (void)secret;
    abort();
}

static aws_hmac_new_fn *s_sha256_hmac_new_fn = aws_hmac_new_abort;
#endif

struct aws_hmac *aws_sha256_hmac_new(struct aws_allocator *allocator, struct aws_byte_cursor *secret) {
    return s_sha256_hmac_new_fn(allocator, secret);
}

void aws_set_sha256_hmac_new_fn(aws_hmac_new_fn *fn) {
    s_sha256_hmac_new_fn = fn;
}

void aws_hmac_destroy(struct aws_hmac *hmac) {
    hmac->vtable->destroy(hmac);
}

int aws_hmac_update(struct aws_hmac *hmac, struct aws_byte_cursor *to_hmac) {
    return hmac->vtable->update(hmac, to_hmac);
}

int aws_hmac_finalize(struct aws_hmac *hmac, struct aws_byte_buf *output) {
    size_t available_buffer = output->capacity - output->len;

    if (available_buffer < hmac->digest_size) {
        uint8_t tmp_output[128] = {0};
        assert(sizeof(tmp_output) >= hmac->digest_size);

        struct aws_byte_buf tmp_out_buf = aws_byte_buf_from_array(tmp_output, sizeof(tmp_output));
        tmp_out_buf.len = 0;

        if (hmac->vtable->finalize(hmac, &tmp_out_buf)) {
            return AWS_OP_ERR;
        }

        memcpy(output->buffer + output->len, tmp_output, available_buffer);
        output->len += available_buffer;
        return AWS_OP_SUCCESS;
    }

    return hmac->vtable->finalize(hmac, output);
}

int aws_sha256_hmac_compute(struct aws_allocator *allocator, struct aws_byte_cursor *secret, struct aws_byte_cursor *to_hash, struct aws_byte_buf *output) {
    struct aws_hmac *hmac = aws_sha256_hmac_new(allocator, secret);

    if (!hmac) {
        return AWS_OP_ERR;
    }

    if (aws_hmac_update(hmac, to_hash)) {
        return AWS_OP_ERR;
    }

    if (aws_hmac_finalize(hmac, output)) {
        return AWS_OP_ERR;
    }

    aws_hmac_destroy(hmac);
    return AWS_OP_SUCCESS;
}