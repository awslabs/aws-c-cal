/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/crc.h>
#include <aws/common/byte_buf.h>
#include <aws/common/clock.h>
#include <aws/common/device_random.h>

#include <inttypes.h>

// Welfords online algorithm
void update_summay(uint64_t count, double *mean, double *M2, uint64_t *min, uint64_t *max, uint64_t new_value) {
    double n_v = (double)new_value;
    double delta = n_v - *mean;
    *mean += delta / count;
    double delta2 = n_v - *mean;
    *M2 += delta * delta2;
    *min = aws_min_u64(*min, new_value);
    *max = aws_max_u64(*max, new_value);
}

void finalize_summary(uint64_t count, double *M2) {
    *M2 = *M2 / (double)count;
}

void print_stats(
    double *mean,
    double *variance,
    uint64_t *min,
    uint64_t *max,
    uint32_t *chunk_sizes,
    size_t num_chunks,
    size_t size) {
    (void)size;
    fprintf(stdout, "chunks\n");
    for (size_t i = 0; i < num_chunks; i++) {
        fprintf(
            stdout,
            "chunk size: %" PRIu32 ", min: %" PRIu64 ", max: %" PRIu64 ", mean: %f, variance: %f",
            chunk_sizes[i],
            min[i],
            max[i],
            mean[i],
            variance[i]);
    }
    fprintf(stdout, "\n");
}

static void profile_sequence_chunks(
    struct aws_byte_cursor to_hash,
    uint32_t chunk_size,
    uint32_t iterations,
    double *variance,
    double *avg,
    uint64_t *min,
    uint64_t *max,
    uint32_t (*checksum_fn)(const uint8_t *, int, uint32_t)) {
    for (uint32_t i = 0; i < iterations; i++) {
        uint64_t start = 0;
        uint32_t output = 0;
        AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&start) && "clock get ticks failed.");
        struct aws_byte_cursor to_hash_seeked = to_hash;
        while (to_hash_seeked.len) {
            size_t remaining = (size_t)chunk_size > to_hash_seeked.len ? to_hash_seeked.len : (size_t)chunk_size;

            struct aws_byte_cursor chunk_to_process = aws_byte_cursor_advance(&to_hash_seeked, remaining);
            output = checksum_fn(chunk_to_process.ptr, chunk_to_process.len, output);
        }
        uint64_t end = 0;
        AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&end) && "clock get ticks failed");
        update_summay(i + 1, avg, variance, min, max, end - start);
    }
}

static void profile_sequence(
    struct aws_byte_cursor to_hash,
    uint32_t *chunk_sizes,
    size_t num_chunks,
    uint32_t iterations_per_sequence,
    double *times,
    double *variance,
    uint64_t *min,
    uint64_t *max,
    uint32_t (*checksum_fn)(const uint8_t *, int, uint32_t)) {
    for (size_t i = 0; i < num_chunks; i++) {
        // load code into cache, to get consistent measure of "hot" performance;
        double tmp_v = 0;
        double tmp_e = 0;
        uint64_t tmp_min = 0;
        uint64_t tmp_max = 0;
        profile_sequence_chunks(to_hash, chunk_sizes[i], 1, &tmp_v, &tmp_e, &tmp_min, &tmp_max, checksum_fn);
        profile_sequence_chunks(
            to_hash, chunk_sizes[i], iterations_per_sequence, &variance[i], &times[i], &min[i], &max[i], checksum_fn);
    }
}

static void profile(
    struct aws_allocator *allocator,
    size_t size,
    uint32_t *chunk_sizes,
    size_t num_chunks,
    uint32_t num_sequences,
    uint32_t iterations_per_sequence,
    uint32_t (*checksum_fn)(const uint8_t *, int, uint32_t)) {

    double *total_mean = aws_mem_calloc(allocator, num_chunks, sizeof(double));
    double *total_variance = aws_mem_calloc(allocator, num_chunks, sizeof(double));
    uint64_t *total_min = aws_mem_calloc(allocator, num_chunks, sizeof(uint64_t));
    for (size_t j = 0; j < num_chunks; j++) {
        total_min[j] = UINT64_MAX;
    }
    uint64_t *total_max = aws_mem_calloc(allocator, num_chunks, sizeof(uint64_t));

    uint64_t start = 0;
    uint64_t end = 0;
    AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&start) && "clock get ticks failed.");
    for (uint32_t i = 0; i < num_sequences; i++) {
        double *means = aws_mem_calloc(allocator, num_chunks, sizeof(double));
        double *variance = aws_mem_calloc(allocator, num_chunks, sizeof(double));
        uint64_t *mins = aws_mem_calloc(allocator, num_chunks, sizeof(uint64_t));
        for (size_t j = 0; j < num_chunks; j++) {
            mins[j] = UINT64_MAX;
        }
        uint64_t *maxs = aws_mem_calloc(allocator, num_chunks, sizeof(uint64_t));

        struct aws_byte_buf to_hash;
        AWS_FATAL_ASSERT(!aws_byte_buf_init(&to_hash, allocator, size) && "failed to allocate buffer for hashing");
        AWS_FATAL_ASSERT(!aws_device_random_buffer(&to_hash) && "reading random data failed");

        struct aws_byte_cursor to_hash_cur = aws_byte_cursor_from_buf(&to_hash);
        profile_sequence(
            to_hash_cur, chunk_sizes, num_chunks, iterations_per_sequence, means, variance, mins, maxs, checksum_fn);
        for (size_t j = 0; j < num_chunks; j++) {
            update_summay(i + 1, &total_mean[j], &total_variance[j], &total_min[j], &total_max[j], means[j]);
        }
        if (i % 100 == 0) {
            AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&end) && "clock get ticks failed.");
            fprintf(stdout, "count: %d: %" PRIu64 "\n", i, end - start);
            start = end;
        }
        aws_byte_buf_clean_up(&to_hash);
        aws_mem_release(allocator, means);
        aws_mem_release(allocator, variance);
        aws_mem_release(allocator, mins);
        aws_mem_release(allocator, maxs);
    }
    for (size_t j = 0; j < num_chunks; j++) {
        finalize_summary(num_sequences, &total_variance[j]);
    }
    fprintf(stdout, "crc32\n");
    print_stats(total_mean, total_variance, total_min, total_max, chunk_sizes, num_chunks, size);
    aws_mem_release(allocator, total_mean);
    aws_mem_release(allocator, total_variance);
    aws_mem_release(allocator, total_min);
    aws_mem_release(allocator, total_max);
}

int main(void) {
    struct aws_allocator *allocator = aws_default_allocator();
    uint32_t chunks[] = {1 << 22, 1 << 20, 1 << 10, 1 << 9, 1 << 8, 1 << 7};
    profile(allocator, 1 << 22, chunks, 6, 1000, 1, aws_checksums_crc32c);
    // uint32_t chunks[] = {1 << 19, 1 << 9, 1 << 8, 1 << 7};
    // profile(allocator, 1 << 19, chunks, 4, 10000, 1, aws_checksums_crc32);
    return 0;
}
