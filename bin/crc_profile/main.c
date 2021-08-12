/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/checksums/crc.h>
#include <aws/common/byte_buf.h>
#include <aws/common/clock.h>
#include <aws/common/device_random.h>

#include <inttypes.h>

static void s_profile_streaming_hash_at_chunk_size(
    struct aws_byte_cursor to_hash,
    size_t chunk_size,
    size_t alignment,
    bool print,
    uint32_t (*checksum_fn)(const uint8_t *, int, uint32_t)) {

    uint32_t output = 0;
    struct aws_byte_cursor to_hash_seeked = to_hash;

    uint64_t start = 0;
    AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&start) && "clock get ticks failed.");

    if (alignment) {
        size_t alignment_miss = (uintptr_t)to_hash_seeked.ptr % alignment;
        struct aws_byte_cursor unaligned_chunk = aws_byte_cursor_advance(&to_hash_seeked, alignment_miss);

        output = checksum_fn(unaligned_chunk.ptr, unaligned_chunk.len, output);
    }

    while (to_hash_seeked.len) {
        size_t remaining = chunk_size > to_hash_seeked.len ? to_hash_seeked.len : chunk_size;

        struct aws_byte_cursor chunk_to_process = aws_byte_cursor_advance(&to_hash_seeked, remaining);
        output = checksum_fn(chunk_to_process.ptr, chunk_to_process.len, output);
    }
    uint64_t end = 0;
    AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&end) && "clock get ticks failed");
    if (print) {
        fprintf(stdout, "CRC streaming computation took %" PRIu64 "ns\n", end - start);
    }
}

static void s_profile_oneshot_hash(
    struct aws_byte_cursor to_hash,
    bool print,
    uint32_t (*checksum_fn)(const uint8_t *, int, uint32_t)) {

    uint32_t output = 0;
    uint64_t start = 0;
    AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&start) && "clock get ticks failed.");
    output = checksum_fn(to_hash.ptr, to_hash.len, output);
    uint64_t end = 0;
    AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&end) && "clock get ticks failed");
    if (print) {
        fprintf(stdout, "CRC oneshot computation took %" PRIu64 "ns\n", end - start);
    }
}

static void s_run_profiles(
    struct aws_allocator *allocator,
    size_t to_hash_size,
    const char *profile_name,
    const char *function_name,
    uint32_t (*checksum_fn)(const uint8_t *, int, uint32_t)) {
    fprintf(
        stdout,
        "********************* %s Profile %s ************************************\n\n",
        function_name,
        profile_name);

    struct aws_byte_buf to_hash;
    AWS_FATAL_ASSERT(!aws_byte_buf_init(&to_hash, allocator, to_hash_size) && "failed to allocate buffer for hashing");
    AWS_FATAL_ASSERT(!aws_device_random_buffer(&to_hash) && "reading random data failed");
    struct aws_byte_cursor to_hash_cur = aws_byte_cursor_from_buf(&to_hash);

    /* To load the code into the cache, and get a fair comparison we first run without printing timing, and then
        run again with times printed */
    fprintf(stdout, "********************* Chunked/Alignment Runs *********************************\n\n");
    fprintf(stdout, "****** 128 byte chunks ******\n\n");
    fprintf(stdout, "0-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 128, 0, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 128, 0, true, checksum_fn);
    fprintf(stdout, "8-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 128, 8, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 128, 8, true, checksum_fn);
    fprintf(stdout, "16-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 128, 16, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 128, 16, true, checksum_fn);
    fprintf(stdout, "64-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 128, 64, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 128, 64, true, checksum_fn);
    fprintf(stdout, "128-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 128, 128, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 128, 128, true, checksum_fn);
    fprintf(stdout, "\n****** 256 byte chunks ******\n\n");
    fprintf(stdout, "0-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 256, 0, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 256, 0, true, checksum_fn);
    fprintf(stdout, "8-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 256, 8, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 256, 8, true, checksum_fn);
    fprintf(stdout, "16-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 256, 16, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 256, 16, true, checksum_fn);
    fprintf(stdout, "64-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 256, 64, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 256, 64, true, checksum_fn);
    fprintf(stdout, "128-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 256, 128, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 256, 128, true, checksum_fn);

    fprintf(stdout, "\n******* 512 byte chunks *****\n\n");
    fprintf(stdout, "0-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 512, 0, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 512, 0, true, checksum_fn);
    fprintf(stdout, "8-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 512, 8, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 512, 8, true, checksum_fn);
    fprintf(stdout, "16-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 512, 16, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 512, 16, true, checksum_fn);
    fprintf(stdout, "64-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 512, 64, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 512, 64, true, checksum_fn);
    fprintf(stdout, "128-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 512, 128, false, checksum_fn);
    s_profile_streaming_hash_at_chunk_size(to_hash_cur, 512, 128, true, checksum_fn);

    fprintf(stdout, "\n********************** Oneshot Run *******************************************\n\n");
    s_profile_oneshot_hash(to_hash_cur, false, checksum_fn);
    s_profile_oneshot_hash(to_hash_cur, true, checksum_fn);
    fprintf(stdout, "\n\n");
}

int main(void) {
    struct aws_allocator *allocator = aws_default_allocator();

    fprintf(stdout, "Starting profile run for Crc32 using implementation \n\n");
    s_run_profiles(allocator, 1024, "1 KB", "CRC32", aws_checksums_crc32);
    s_run_profiles(allocator, 1024 * 64, "64 KB", "CRC32", aws_checksums_crc32);
    s_run_profiles(allocator, 1024 * 128, "128 KB", "CRC32", aws_checksums_crc32);
    s_run_profiles(allocator, 1024 * 512, "512 KB", "CRC32", aws_checksums_crc32);

    fprintf(stdout, "\n\nStarting profile run for Crc32C using implementation \n\n");
    s_run_profiles(allocator, 1024, "1 KB", "CRC32C", aws_checksums_crc32c);
    s_run_profiles(allocator, 1024 * 64, "64 KB", "CRC32C", aws_checksums_crc32c);
    s_run_profiles(allocator, 1024 * 128, "128 KB", "CRC32C", aws_checksums_crc32c);
    s_run_profiles(allocator, 1024 * 512, "512 KB", "CRC32C", aws_checksums_crc32c);

    return 0;
}
