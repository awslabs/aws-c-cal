#include <aws/cal/crc32.h>
#include <aws/cal/hash.h>
// #include <aws/checksums/crc.h>

static void s_destroy(struct aws_hash *hash);
static int s_update(struct aws_hash *hash, const struct aws_byte_cursor *to_hash);
static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output);
// should the above be shared in a header file?

static struct aws_hash_vtable s_vtable = {
    .destroy = s_destroy,
    .update = s_update,
    .finalize = s_finalize,
    .alg_name = "CRC32",
    .provider = "AWS", // is this right?
};
// should the above be abstracted into a constructor shared by multiple files?

struct aws_hash *aws_crc32_default_new(struct aws_allocator *allocator) {
    struct crc32_hash *crc32_hash = aws_mem_acquire(allocator, sizeof(struct crc32_hash));

    if (!crc32_hash) {
        return NULL;
    }

    crc32_hash->hash.allocator = allocator;
    crc32_hash->hash.vtable = &s_vtable;
    crc32_hash->hash.impl = crc32_hash; // this cicular reference feels like a red flag to me
    crc32_hash->hash.digest_size = 0;   // what should the digest size be?
    crc32_hash->hash.good = true;
    crc32_hash->crc32_hash = 0;

    return &crc32_hash->hash;
}

// reordered from destroy update finalize to update finalize destroy, this order makes more sense to me
static int s_update(struct aws_hash *hash, const struct aws_byte_cursor *to_hash) {
    if (!hash->good) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    // struct crc32_hash *ctx = hash->impl;

    // should checksums be refactored to use a byte cursor instead?
    // ctx.crc32_hash = aws_checksums_crc32(to_hash->ptr, to_hash->len,  ctx.crc32_hash.crc32_ctx);
    // CC_SHA256_Update(&ctx->cc_hash, to_hash->ptr, (CC_LONG)to_hash->len);
    return AWS_OP_SUCCESS;
}

static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output) {
    if (!hash->good) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    // struct crc32_hash *ctx = hash->impl; // why is this line here?

    size_t buffer_len = output->capacity - output->len;

    if (buffer_len < AWS_SHA256_LEN) { // what should I replace this constant with
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    // CC_SHA256_Final(output->buffer + output->len, &ctx->cc_hash); // what does this line do?
    hash->good = false;
    output->len += buffer_len;
    return AWS_OP_SUCCESS;
}

static void s_destroy(struct aws_hash *hash) {
    struct crc32_hash *ctx = hash->impl; // why is this line here?
    aws_mem_release(hash->allocator, ctx);
}
