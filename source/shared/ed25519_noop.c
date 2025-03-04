/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

struct aws_ed25519_key_pair_impl;

static void aws_ed25519_key_pair_destroy_impl(struct aws_ed25519_key_pair_impl *key_pair) {
    AWS_FATAL_ASSERT(key_pair == NULL);
    return;
}

struct aws_ed25519_key_pair *aws_ed25519_key_pair_new_generate_impl(struct aws_allocator *allocator) {
    (void)allocator;
    aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
    return NULL;
}

int aws_ed25519_key_pair_get_public_key_impl(
    const struct aws_ed25519_key_pair_impl *key_pair,
    enum aws_ed25519_key_export_format format,
    struct aws_byte_buf *out) {
    (void)key_pair;
    (void)format;
    (void)out;
    return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
}

size_t aws_ed25519_key_pair_get_public_key_size_impl(enum aws_ed25519_key_export_format format) {
    (void)format;
    AWS_FATAL_ASSERT(0);
    return 0;
}

int aws_ed25519_key_pair_get_private_key_impl(
    const struct aws_ed25519_key_pair_impl *key_pair,
    enum aws_ed25519_key_export_format format,
    struct aws_byte_buf *out) {
    (void)key_pair;
    (void)format;
    (void)out;
    return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
}

size_t aws_ed25519_key_pair_get_private_key_size_impl(enum aws_ed25519_key_export_format format) {
    (void)format;
    AWS_FATAL_ASSERT(0);
    return 0;
}
