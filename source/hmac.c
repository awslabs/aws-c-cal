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
    return hmac->vtable->finalize(hmac, output);
}
