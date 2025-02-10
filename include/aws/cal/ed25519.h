#ifndef AWS_CAL_ED25519_H
#define AWS_CAL_ED25519_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/cal/cal.h>
#include <aws/common/byte_buf.h>

AWS_PUSH_SANE_WARNING_LEVEL

struct aws_ed25519_key_pair;

AWS_EXTERN_C_BEGIN

AWS_CAL_API struct aws_ed25519_key_pair *aws_ed25519_key_pair_new_generate(struct aws_allocator *allocator);

AWS_CAL_API struct aws_ed25519_key_pair *aws_ed25519_key_pair_acquire(struct aws_ed25519_key_pair *key_pair);

AWS_CAL_API struct aws_ed25519_key_pair *aws_ed25519_key_pair_release(struct aws_ed25519_key_pair *key_pair);

enum aws_ed25519_key_export_format {
    AWS_CAL_ED25519_KEY_EXPORT_SSH,
};

/*
 * Get public key for the key pair.
 * Inits out to a copy of key.
 * Any encoding on top of that (ex. b64) is left up to user.
 */
AWS_CAL_API int aws_ed25519_key_pair_get_public_key(
    const struct aws_ed25519_key_pair *key_pair,
    enum aws_ed25519_key_export_format format,
    struct aws_byte_buf *out);

/*
 * Get private key for the key pair.
 * Inits out to a copy of key.
 * Any encoding on top of that (ex. b64) is left up to user.
 */
AWS_CAL_API int aws_ed25519_key_pair_get_private_key(
    const struct aws_ed25519_key_pair *key_pair,
    enum aws_ed25519_key_export_format format,
    struct aws_byte_buf *out);

AWS_EXTERN_C_END

AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_CAL_ED25519_H */
