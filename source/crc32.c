#include <aws/cal/crc32.h>
#include <aws/cal/hash.h>
#include <aws/checksums/crc.h>
#include <aws/common/byte_buf.h>
#include <stdint.h>

static int s_crc32_update(struct aws_hash *hash, const struct aws_byte_cursor *to_hash);
static int s_crc32c_update(struct aws_hash *hash, const struct aws_byte_cursor *to_hash);
static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output);
static void s_destroy(struct aws_hash *hash) {
    aws_mem_release(hash->allocator, hash);
}

static struct aws_hash_vtable crc32_vtable = {
    .destroy = s_destroy,
    .update = s_crc32_update,
    .finalize = s_finalize,
    .alg_name = "CRC32",
    .provider = "AWS",
};

static struct aws_hash_vtable crc32c_vtable = {
    .destroy = s_destroy,
    .update = s_crc32c_update,
    .finalize = s_finalize,
    .alg_name = "CRC32C",
    .provider = "AWS",
};

static struct aws_hash *s_crc32_common_init(struct aws_allocator *allocator, struct aws_hash_vtable *vtable) {
    struct aws_hash *hash = aws_mem_acquire(allocator, sizeof(struct aws_hash));

    if (!hash) {
        return NULL;
    }

    hash->allocator = allocator;
    hash->vtable = vtable;
    hash->impl = 0;
    hash->digest_size = AWS_CRC32C_LEN;
    hash->good = true;

    return hash;
}

struct aws_hash *aws_crc32_default_new(struct aws_allocator *allocator) {
    return s_crc32_common_init(allocator, &crc32_vtable);
}

struct aws_hash *aws_crc32c_default_new(struct aws_allocator *allocator) {
    return s_crc32_common_init(allocator, &crc32c_vtable);
}

static int s_crc32_common_update(
    struct aws_hash *hash,
    const struct aws_byte_cursor *to_hash,
    uint32_t (*aws_checksums)(const uint8_t *, int, uint32_t)) {

    if (!hash->good) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    uintptr_t crc_value = (uintptr_t)hash->impl;
    uint32_t crc = (uint32_t)crc_value;

    /* hash->impl has type (void *) to match the rest of the API, but we are storing as a uintptr, and using it as an
     * int to avoid mem allocation */
    uintptr_t new_crc = aws_checksums(to_hash->ptr, (int)to_hash->len, crc);
    hash->impl = (void *)new_crc;
    return AWS_OP_SUCCESS;
}

static int s_crc32_update(struct aws_hash *hash, const struct aws_byte_cursor *to_hash) {
    return s_crc32_common_update(hash, to_hash, aws_checksums_crc32);
}

static int s_crc32c_update(struct aws_hash *hash, const struct aws_byte_cursor *to_hash) {
    return s_crc32_common_update(hash, to_hash, aws_checksums_crc32c);
}

static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output) {
    if (!hash->good) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    size_t buffer_len = output->capacity - output->len;

    if (buffer_len < AWS_CRC32C_LEN) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    hash->good = false;
    uintptr_t crc_value = (uintptr_t)hash->impl;
    const uint32_t crc = (uint32_t)crc_value;
    return aws_byte_buf_write(output, (uint8_t *)&crc, sizeof(uint32_t));
}
