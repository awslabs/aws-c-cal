/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/cal/cal.h>
#include <aws/cal/ecc.h>
#include <aws/cal/hash.h>

#include <aws/common/command_line_parser.h>
#include <aws/common/encoding.h>
#include <aws/common/file.h>
#include <aws/common/string.h>

#include <inttypes.h>

struct run_corpus_ctx {
    struct aws_allocator *allocator;
    const char *root_path;
};

static struct aws_cli_option s_long_options[] = {
    {"corpus-path", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'o'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    /* Per getopt(3) the last element of the array has to be filled with all zeros */
    {NULL, AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 0},
};

static void s_usage(int exit_code) {

    fprintf(stderr, "usage: run_x_platform_fuzz_corpus [options]\n");
    fprintf(stderr, "\n Options:\n\n");
    fprintf(
        stderr,
        "      --corpus-path DIRECTORY: path to scan for corpus files default is the current working directory.\n");
    fprintf(stderr, "  -h, --help\n");
    fprintf(stderr, "            Display this message and quit.\n");
    exit(exit_code);
}

static void s_parse_options(int argc, char **argv, struct run_corpus_ctx *ctx) {
    while (true) {
        int option_index = 0;
        int c = aws_cli_getopt_long(argc, argv, "o:h", s_long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                /* getopt_long() returns 0 if an option.flag is non-null */
                break;
            case 'o':
                ctx->root_path = aws_cli_optarg;
                break;
            case 'h':
                s_usage(0);
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                s_usage(1);
        }
    }
}

/**
 * Attempts to load a corpus directory. If it's successful, it loads each platform's ECDSA corpus, and makes sure
 * it can actually verify the signatures in it provided the same key and message to sign are used as those used
 * to produce the signature.
 */
int main(int argc, char *argv[]) {
    struct aws_allocator *allocator = aws_default_allocator();
    aws_cal_library_init(allocator);

    struct run_corpus_ctx ctx = {
        .allocator = allocator,
    };

    s_parse_options(argc, argv, &ctx);

    uint8_t x[] = {
        0x1c, 0xcb, 0xe9, 0x1c, 0x07, 0x5f, 0xc7, 0xf4, 0xf0, 0x33, 0xbf, 0xa2, 0x48, 0xdb, 0x8f, 0xcc,
        0xd3, 0x56, 0x5d, 0xe9, 0x4b, 0xbf, 0xb1, 0x2f, 0x3c, 0x59, 0xff, 0x46, 0xc2, 0x71, 0xbf, 0x83,
    };

    uint8_t y[] = {
        0xce, 0x40, 0x14, 0xc6, 0x88, 0x11, 0xf9, 0xa2, 0x1a, 0x1f, 0xdb, 0x2c, 0x0e, 0x61, 0x13, 0xe0,
        0x6d, 0xb7, 0xca, 0x93, 0xb7, 0x40, 0x4e, 0x78, 0xdc, 0x7c, 0xcd, 0x5c, 0xa8, 0x9a, 0x4c, 0xa9,
    };

    struct aws_byte_cursor pub_x = aws_byte_cursor_from_array(x, sizeof(x));
    struct aws_byte_cursor pub_y = aws_byte_cursor_from_array(y, sizeof(y));

    struct aws_ecc_key_pair *verifying_key =
        aws_ecc_key_pair_new_from_public_key(allocator, AWS_CAL_ECDSA_P256, &pub_x, &pub_y);

    struct aws_byte_buf scan_path;
    aws_byte_buf_init(&scan_path, allocator, 1024);

    if (ctx.root_path) {
        struct aws_byte_cursor root_path = aws_byte_cursor_from_c_str(ctx.root_path);
        aws_byte_buf_append_dynamic(&scan_path, &root_path);

        /* if (root_path.ptr[root_path.len - 1] != AWS_PATH_DELIM) {
            aws_byte_buf_append_byte_dynamic(&scan_path, (uint8_t)AWS_PATH_DELIM);
        }*/
    }

    struct aws_string *scan_path_str = aws_string_new_from_buf(allocator, &scan_path);
    struct aws_directory_iterator *dir_iter = aws_directory_entry_iterator_new(allocator, scan_path_str);

    if (!dir_iter) {
        fprintf(stderr, "Unable to load fuzz corpus from %s\n", aws_string_c_str(scan_path_str));
        exit(-1);
    }

    struct aws_byte_cursor corpus_file_name = aws_byte_cursor_from_c_str("p256_sig_corpus.txt");
    size_t corpus_runs = 0;
    const struct aws_directory_entry *entry = aws_directory_entry_iterator_get_value(dir_iter);
    while (entry) {
        struct aws_string *corpus_file = NULL;

        if (entry->file_type & AWS_FILE_TYPE_DIRECTORY) {
            struct aws_string *potential_corpus_path = aws_string_new_from_cursor(allocator, &entry->path);
            struct aws_directory_iterator *potential_corpus_dir =
                aws_directory_entry_iterator_new(allocator, potential_corpus_path);

            if (potential_corpus_dir) {
                const struct aws_directory_entry *corpus_file_candidate =
                    aws_directory_entry_iterator_get_value(potential_corpus_dir);

                while (corpus_file_candidate) {
                    struct aws_byte_cursor find_unused;
                    if (aws_byte_cursor_find_exact(
                            &corpus_file_candidate->relative_path, &corpus_file_name, &find_unused) == AWS_OP_SUCCESS) {
                        corpus_file = aws_string_new_from_cursor(allocator, &corpus_file_candidate->path);
                        break;
                    }

                    if (aws_directory_entry_iterator_next(potential_corpus_dir) != AWS_OP_SUCCESS) {
                        break;
                    }

                    corpus_file_candidate = aws_directory_entry_iterator_get_value(potential_corpus_dir);
                }

                aws_directory_entry_iterator_destroy(potential_corpus_dir);
            }

            aws_string_destroy(potential_corpus_path);
        }

        if (corpus_file) {
            corpus_runs++;
            fprintf(stdout, "Running corpus file found at %s:\n\n", aws_string_c_str(corpus_file));
            struct aws_string *mode = aws_string_new_from_c_str(allocator, "r");
            FILE *corpus_input_file = aws_fopen_safe(corpus_file, mode);

            if (!corpus_input_file) {
                fprintf(stderr, "Unable to open file at %s\n", aws_string_c_str(corpus_file));
                exit(-1);
            }

            struct aws_byte_buf hex_decoded_buf;
            aws_byte_buf_init(&hex_decoded_buf, allocator, 1024);

            struct aws_byte_cursor to_append = aws_byte_cursor_from_c_str("a");
            struct aws_byte_buf signed_value;
            aws_byte_buf_init(&signed_value, allocator, AWS_SHA256_LEN);

            struct aws_byte_buf to_hash;
            aws_byte_buf_init(&to_hash, allocator, 1024);

            char line_buf[1024];
            AWS_ZERO_ARRAY(line_buf);
            size_t signatures_processed = 0;
            size_t signatures_failed = 0;

            while (fgets(line_buf, 1024, corpus_input_file)) {

                /* -1 to strip off the newline delimiter */
                struct aws_byte_cursor line_cur = aws_byte_cursor_from_c_str(line_buf);
                line_cur.len -= 1;

                if (aws_hex_decode(&line_cur, &hex_decoded_buf) != AWS_OP_SUCCESS) {
                    fprintf(
                        stderr,
                        "Invalid line in file detected. Could not hex decode.\n Line is " PRInSTR "\n",
                        AWS_BYTE_CURSOR_PRI(line_cur));
                    exit(-1);
                }

                struct aws_byte_cursor to_hash_cur = aws_byte_cursor_from_buf(&to_hash);
                aws_sha256_compute(allocator, &to_hash_cur, &signed_value, 0);

                struct aws_byte_cursor signed_value_cur = aws_byte_cursor_from_buf(&signed_value);
                struct aws_byte_cursor signature_cur = aws_byte_cursor_from_buf(&hex_decoded_buf);

                if (aws_ecc_key_pair_verify_signature(verifying_key, &signed_value_cur, &signature_cur)) {
                    struct aws_byte_buf hex_encoded_sha;
                    aws_byte_buf_init(&hex_encoded_sha, allocator, 1024);

                    aws_hex_encode(&signed_value_cur, &hex_encoded_sha);
                    struct aws_byte_cursor failed_sha = aws_byte_cursor_from_buf(&hex_encoded_sha);

                    fprintf(
                        stderr,
                        "Failed to validate signature\n signature: " PRInSTR "\n message_signed: " PRInSTR "\n\n",
                        AWS_BYTE_CURSOR_PRI(line_cur),
                        AWS_BYTE_CURSOR_PRI(failed_sha));
                    signatures_failed++;
                    aws_byte_buf_clean_up(&hex_encoded_sha);
                }

                aws_byte_buf_reset(&hex_decoded_buf, true);
                aws_byte_buf_reset(&signed_value, true);

                aws_byte_buf_append_dynamic(&to_hash, &to_append);
                AWS_ZERO_ARRAY(line_buf);
                signatures_processed++;
            }
            fprintf(
                stdout,
                "Corpus %d verification complete with %d failures out of %d signatures processed\n\n",
                (int)corpus_runs,
                (int)signatures_failed,
                (int)signatures_processed);

            aws_byte_buf_clean_up(&hex_decoded_buf);
            aws_byte_buf_clean_up(&to_hash);
            aws_byte_buf_clean_up(&signed_value);

            fclose(corpus_input_file);
            aws_string_destroy(mode);
        }

        aws_string_destroy(corpus_file);

        if (aws_directory_entry_iterator_next(dir_iter)) {
            break;
        }

        entry = aws_directory_entry_iterator_get_value(dir_iter);
    }
    aws_directory_entry_iterator_destroy(dir_iter);
    aws_string_destroy(scan_path_str);

    aws_byte_buf_clean_up(&scan_path);

    aws_ecc_key_pair_release(verifying_key);

    aws_cal_library_clean_up();
    return 0;
}
