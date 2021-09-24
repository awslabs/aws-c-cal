/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/cal/cal.h>
#include <aws/cal/hash.h>

#include <aws/common/clock.h>
#include <aws/common/device_random.h>

#include <inttypes.h>

static void s_profile_streaming_hash_at_chunk_size(
    struct aws_allocator *allocator,
    struct aws_byte_cursor to_hash,
    size_t chunk_size,
    size_t alignment) {
    struct aws_hash *hash_impl = aws_sha256_new(allocator);
    AWS_FATAL_ASSERT(hash_impl);

    struct aws_byte_buf output_buf;
    AWS_FATAL_ASSERT(
        !aws_byte_buf_init(&output_buf, allocator, AWS_SHA256_LEN) && "allocation of output buffer failed!");

    struct aws_byte_cursor to_hash_seeked = to_hash;

    uint64_t start = 0;
    AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&start) && "clock get ticks failed.");

    if (alignment) {
        size_t alignment_miss = (uintptr_t)to_hash_seeked.ptr % alignment;
        struct aws_byte_cursor unaligned_chunk = aws_byte_cursor_advance(&to_hash_seeked, alignment_miss);
        AWS_FATAL_ASSERT(!aws_hash_update(hash_impl, &unaligned_chunk) && "hash compute of unaligned chunk failed");
    }

    while (to_hash_seeked.len) {
        size_t remaining = chunk_size > to_hash_seeked.len ? to_hash_seeked.len : chunk_size;

        struct aws_byte_cursor chunk_to_process = aws_byte_cursor_advance(&to_hash_seeked, remaining);
        AWS_FATAL_ASSERT(!aws_hash_update(hash_impl, &chunk_to_process) && "hash compute of chunk failed");
    }

    AWS_FATAL_ASSERT(!aws_hash_finalize(hash_impl, &output_buf, 0) && "hash finalize failed");
    uint64_t end = 0;
    AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&end) && "clock get ticks failed");
    fprintf(stdout, "SHA256 streaming computation took %" PRIu64 "ns\n", end - start);

    aws_byte_buf_clean_up(&output_buf);
    aws_hash_destroy(hash_impl);
}

static void s_profile_oneshot_hash(struct aws_allocator *allocator, struct aws_byte_cursor to_hash) {
    struct aws_byte_buf output_buf;

    AWS_FATAL_ASSERT(
        !aws_byte_buf_init(&output_buf, allocator, AWS_SHA256_LEN) && "allocation of output buffer failed!");

    uint64_t start = 0;
    AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&start) && "clock get ticks failed.");
    AWS_FATAL_ASSERT(!aws_sha256_compute(allocator, &to_hash, &output_buf, 0) && "Hash computation failed");
    uint64_t end = 0;
    AWS_FATAL_ASSERT(!aws_high_res_clock_get_ticks(&end) && "clock get ticks failed");
    fprintf(stdout, "SHA256 oneshot computation took %" PRIu64 "ns\n", end - start);
    aws_byte_buf_clean_up(&output_buf);
}

static void s_run_profiles(struct aws_allocator *allocator, size_t to_hash_size, const char *profile_name) {
    fprintf(stdout, "********************* SHA256 Profile %s ************************************\n\n", profile_name);

    struct aws_byte_buf to_hash;
    AWS_FATAL_ASSERT(!aws_byte_buf_init(&to_hash, allocator, to_hash_size) && "failed to allocate buffer for hashing");
    AWS_FATAL_ASSERT(!aws_device_random_buffer(&to_hash) && "reading random data failed");
    struct aws_byte_cursor to_hash_cur = aws_byte_cursor_from_buf(&to_hash);

    fprintf(stdout, "********************* Chunked/Alignment Runs *********************************\n\n");
    fprintf(stdout, "****** 128 byte chunks ******\n\n");
    fprintf(stdout, "8-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 128, 8);
    fprintf(stdout, "16-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 128, 16);
    fprintf(stdout, "64-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 128, 64);
    fprintf(stdout, "128-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 128, 128);
    fprintf(stdout, "\n****** 256 byte chunks ******\n\n");
    fprintf(stdout, "8-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 256, 8);
    fprintf(stdout, "16-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 256, 16);
    fprintf(stdout, "64-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 256, 64);
    fprintf(stdout, "128-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 256, 128);

    fprintf(stdout, "\n******* 512 byte chunks *****\n\n");
    fprintf(stdout, "8-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 512, 8);
    fprintf(stdout, "16-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 512, 16);
    fprintf(stdout, "64-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 512, 64);
    fprintf(stdout, "128-byte alignment:\n");
    s_profile_streaming_hash_at_chunk_size(allocator, to_hash_cur, 512, 128);

    fprintf(stdout, "\n********************** Oneshot Run *******************************************\n\n");
    s_profile_oneshot_hash(allocator, to_hash_cur);
    fprintf(stdout, "\n\n");
    aws_byte_buf_clean_up(&to_hash);
}

int main(void) {
    struct aws_allocator *allocator = aws_default_allocator();
    aws_cal_library_init(allocator);

    struct aws_hash *hash_impl = aws_sha256_new(allocator);
    fprintf(stdout, "Starting profile run for Sha256 using implementation %s\n\n", hash_impl->vtable->provider);
    s_run_profiles(allocator, 1024, "1 KB");
    s_run_profiles(allocator, 1024 * 64, "64 KB");
    s_run_profiles(allocator, 1024 * 128, "128 KB");
    s_run_profiles(allocator, 1024 * 512, "512 KB");

    aws_hash_destroy(hash_impl);
    aws_cal_library_clean_up();
    return 0;
}
