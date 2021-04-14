#include <aws/cal/hash.h>
#include <aws/common/byte_buf.h>
#include <aws/testing/aws_test_harness.h>

static const uint8_t DATA_32_ZEROS[32] = {0};
static const uint32_t KNOWN_CRC32_32_ZEROES = 0x190A55AD;
static const uint32_t KNOWN_CRC32C_32_ZEROES = 0x8A9136AA;

static const uint8_t DATA_32_VALUES[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                                           16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
static const uint32_t KNOWN_CRC32_32_VALUES = 0x91267E8A;
static const uint32_t KNOWN_CRC32C_32_VALUES = 0x46DD794E;

static const uint8_t TEST_VECTOR[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
static const uint32_t KNOWN_CRC32_TEST_VECTOR = 0xCBF43926;
static const uint32_t KNOWN_CRC32C_TEST_VECTOR = 0xE3069283;

typedef struct aws_hash *(crc_fn)(struct aws_allocator *);

/* Makes sure that the specified crc function produces the expected results for known input and output*/
static int s_test_known_crc(
    const char *func_name,
    crc_fn *func,
    const char *data_name,
    const struct aws_byte_cursor *input,
    uint32_t expected,
    struct aws_allocator *allocator) {

    uint8_t len = (uint8_t)input->len;
    struct aws_hash *crc = func(allocator);
    aws_hash_update(crc, input);
    uintptr_t result = (uintptr_t)crc->impl;
    ASSERT_HEX_EQUALS(expected, result, "%s(%s)", func_name, data_name);

    /* chain the crc computation so 2 calls each operate on about 1/2 of the buffer*/
    const struct aws_byte_cursor input_first_half = {
        .len = (int)(len / 2),
        .ptr = input->ptr,
    };
    const struct aws_byte_cursor input_second_half = {
        .len = (int)(len - len / 2),
        .ptr = (input->ptr) + (len / 2),
    };
    struct aws_hash *crc1 = func(allocator);
    aws_hash_update(crc1, &input_first_half);
    aws_hash_update(crc1, &input_second_half);
    uintptr_t result1 = (uintptr_t)crc1->impl;
    ASSERT_HEX_EQUALS(expected, result1, "chaining %s(%s)", func_name, data_name);

    struct aws_hash *crc2 = func(allocator);
    for (size_t i = 0; i < len; ++i) {
        const struct aws_byte_cursor input_i = {
            .len = 1,
            .ptr = input->ptr + i,
        };
        aws_hash_update(crc2, &input_i);
    }
    uintptr_t result2 = (uintptr_t)crc2->impl;
    ASSERT_HEX_EQUALS(expected, result2, "one byte at a time %s(%s)", func_name, data_name);
    aws_hash_destroy(crc);
    aws_hash_destroy(crc1);
    aws_hash_destroy(crc2);
    return AWS_OP_SUCCESS;
}

/* helper function that groups crc32 tests*/
static int s_test_known_crc32(const char *func_name, crc_fn *func, struct aws_allocator *allocator) {
    int res = 0;
    uint8_t *mut_DATA_32_ZEROS = (uint8_t *)DATA_32_ZEROS;
    uint8_t *mut_DATA_32_VALUES = (uint8_t *)DATA_32_VALUES;
    uint8_t *mut_TEST_VECTOR = (uint8_t *)TEST_VECTOR;
    const struct aws_byte_cursor input = {
        .len = sizeof(DATA_32_ZEROS),
        .ptr = mut_DATA_32_ZEROS,
    };
    const struct aws_byte_cursor input1 = {
        .len = sizeof(DATA_32_VALUES),
        .ptr = mut_DATA_32_VALUES,
    };
    const struct aws_byte_cursor input2 = {
        .len = sizeof(TEST_VECTOR),
        .ptr = mut_TEST_VECTOR,
    };
    res |= s_test_known_crc(func_name, func, "DATA_32_ZEROS", &input, KNOWN_CRC32_32_ZEROES, allocator);
    res |= s_test_known_crc(func_name, func, "DATA_32_VALUES", &input1, KNOWN_CRC32_32_VALUES, allocator);
    res |= s_test_known_crc(func_name, func, "TEST_VECTOR", &input2, KNOWN_CRC32_TEST_VECTOR, allocator);
    return res;
}

/* helper function that groups crc32c tests*/
static int s_test_known_crc32c(const char *func_name, crc_fn *func, struct aws_allocator *allocator) {
    int res = 0;
    uint8_t *mut_DATA_32_ZEROS = (uint8_t *)DATA_32_ZEROS;
    uint8_t *mut_DATA_32_VALUES = (uint8_t *)DATA_32_VALUES;
    uint8_t *mut_TEST_VECTOR = (uint8_t *)TEST_VECTOR;
    const struct aws_byte_cursor input = {
        .len = sizeof(DATA_32_ZEROS),
        .ptr = mut_DATA_32_ZEROS,
    };
    const struct aws_byte_cursor input1 = {
        .len = sizeof(DATA_32_VALUES),
        .ptr = mut_DATA_32_VALUES,
    };
    const struct aws_byte_cursor input2 = {
        .len = sizeof(TEST_VECTOR),
        .ptr = mut_TEST_VECTOR,
    };
    res |= s_test_known_crc(func_name, func, "DATA_32_ZEROS", &input, KNOWN_CRC32C_32_ZEROES, allocator);
    res |= s_test_known_crc(func_name, func, "DATA_32_VALUES", &input1, KNOWN_CRC32C_32_VALUES, allocator);
    res |= s_test_known_crc(func_name, func, "TEST_VECTOR", &input2, KNOWN_CRC32C_TEST_VECTOR, allocator);

    /*this tests three things, first it tests the case where we aren't 8-byte aligned*/
    /*second, it tests that reads aren't performed before start of buffer*/
    /*third, it tests that writes aren't performed after the end of the buffer.*/
    /*if any of those things happen, then the checksum will be wrong and the assertion will fail */
    uint8_t *s_non_mem_aligned_vector;
    s_non_mem_aligned_vector = malloc(sizeof(DATA_32_VALUES) + 6);
    memset(s_non_mem_aligned_vector, 1, sizeof(DATA_32_VALUES) + 6);
    memcpy(s_non_mem_aligned_vector + 3, DATA_32_VALUES, sizeof(DATA_32_VALUES));

    const struct aws_byte_cursor input3 = {
        .len = sizeof(DATA_32_VALUES),
        .ptr = s_non_mem_aligned_vector + 3,
    };
    res |= s_test_known_crc(func_name, func, "non_mem_aligned_vector", &input3, KNOWN_CRC32C_32_VALUES, allocator);
    free(s_non_mem_aligned_vector);
    return res;
}

/**
 * Quick sanity check of some known CRC values for known input.
 * The reference functions are included in these tests to verify that they aren't obviously broken.
 */
static int s_test_crc32c(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int res = 0;

    res |= s_test_known_crc32c("aws_crc32c_new", aws_crc32c_new, allocator);

    return res;
}
AWS_TEST_CASE(test_crc32c, s_test_crc32c)

static int s_test_crc32(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    int res = 0;
    res |= s_test_known_crc32("aws_crc32_new", aws_crc32_new, allocator);

    return res;
}

AWS_TEST_CASE(test_crc32, s_test_crc32)
