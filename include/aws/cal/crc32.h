#include <stdint.h>
#include <aws/cal/hash.h>

typedef uint32_t crc32_ctx;

struct crc32_hash {
    struct aws_hash hash;
    crc32_ctx crc32_hash;
};

struct aws_hash *aws_crc32_default_new(struct aws_allocator *allocator);
