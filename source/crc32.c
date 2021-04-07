#include <aws/cal/crc32.h>
#include <aws/cal/hash.h>
#include <aws/checksums/crc.h>

/* hash is object, vtable is methods, hash properties (not vtable) are data?*/

static void s_destroy(struct aws_hash *hash);
static int s_update(struct aws_hash *hash, const struct aws_byte_cursor *to_hash);
static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output);
/* why do we need to define and implement the functions separatly? */
/* can we reuse some of these as defaults defined in hash.c?*/

/* does this have to be defined globaly? I'd like to use a different update function depending on a parameter */
static struct aws_hash_vtable s_vtable = {
    .destroy = s_destroy,
    .update = s_update,
    .finalize = s_finalize,
    .alg_name = "CRC32",
    .provider = "AWS", /* is this right? */
};


struct aws_hash *aws_crc32_default_new(struct aws_allocator *allocator) {
    struct aws_hash *hash = aws_mem_acquire(allocator, sizeof(struct aws_hash));

    if (!hash) {
        return NULL;
    }

    hash->allocator = allocator;
    hash->vtable = &s_vtable; /*could make to vtables, and pass an argument to default new*/
    hash->impl = 0;
    hash->digest_size = AWS_CRC32C_LEN; 
    hash->good = true;

    return hash;
}

/* reordered from destroy update finalize to update finalize destroy, this order makes more sense to me */
static int s_update(struct aws_hash *hash, const struct aws_byte_cursor *to_hash) {
    if (!hash->good) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    uint32_t crc = (uint32_t)hash->impl;

    /* should checksums be refactored to use a byte cursor instead? */
    *((uintptr_t*)&(hash->impl)) = aws_checksums_crc32(to_hash->ptr, to_hash->len, crc);
    return AWS_OP_SUCCESS;
}

static int s_finalize(struct aws_hash *hash, struct aws_byte_buf *output) {
    if (!hash->good) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    size_t buffer_len = output->capacity - output->len;

    if (buffer_len < AWS_CRC32C_LEN) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    /* CC_SHA256_Final(output->buffer + output->len, &ctx->cc_hash); crc doesn't need this line because the intermediat
       is the same as the final correct? How do I follow function to implementaiton?*/
    hash->good = false;
    output->len += buffer_len;
    return AWS_OP_SUCCESS;
}

static void s_destroy(struct aws_hash *hash) {
    /* uint32_t ctx = hash->impl; */
    aws_mem_release(hash->allocator, hash->impl);
}
