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

struct produce_corpus_ctx {
    struct aws_allocator *allocator;
    const char *root_path;
};

static struct aws_cli_option s_long_options[] = {
    {"output-path", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'o'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    /* Per getopt(3) the last element of the array has to be filled with all zeros */
    {NULL, AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 0},
};

static void s_usage(int exit_code) {

    fprintf(stderr, "usage: produce_x_platform_fuzz_corpus [options]\n");
    fprintf(stderr, "\n Options:\n\n");
    fprintf(
        stderr, "      --output-path DIRECTORY: path to output corpus to, default is the current working directory.\n");
    fprintf(stderr, "  -h, --help\n");
    fprintf(stderr, "            Display this message and quit.\n");
    exit(exit_code);
}

static void s_parse_options(int argc, char **argv, struct produce_corpus_ctx *ctx) {
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
 * Runs thousands of ECDSA signatures, and dumps them out to a file. This assumes the same public key and
 * message to sign scheme is used by the verifying program.
 */
int main(int argc, char *argv[]) {
    struct aws_allocator *allocator = aws_default_allocator();
    aws_cal_library_init(allocator);

    struct produce_corpus_ctx ctx = {
        .allocator = allocator,
    };

    s_parse_options(argc, argv, &ctx);

    struct aws_byte_buf output_path;
    aws_byte_buf_init(&output_path, allocator, 1024);
    struct aws_byte_cursor sub_dir_cur;

    if (ctx.root_path) {
        struct aws_byte_cursor root_path = aws_byte_cursor_from_c_str(ctx.root_path);
        aws_byte_buf_append_dynamic(&output_path, &root_path);

        if (root_path.ptr[root_path.len - 1] != AWS_PATH_DELIM) {
            aws_byte_buf_append_byte_dynamic(&output_path, (uint8_t)AWS_PATH_DELIM);
        }
    }

#ifdef _WIN32
    sub_dir_cur = aws_byte_cursor_from_c_str("windows\\");
#elif __APPLE__
    sub_dir_cur = aws_byte_cursor_from_c_str("darwin/");
#else
    sub_dir_cur = aws_byte_cursor_from_c_str("unix/");
#endif

    aws_byte_buf_append_dynamic(&output_path, &sub_dir_cur);
    struct aws_string *directory = aws_string_new_from_buf(allocator, &output_path);
    aws_directory_create(directory);
    aws_string_destroy(directory);

    struct aws_byte_cursor file_name = aws_byte_cursor_from_c_str("p256_sig_corpus.txt");
    aws_byte_buf_append_dynamic(&output_path, &file_name);

    struct aws_string *path = aws_string_new_from_buf(allocator, &output_path);
    struct aws_string *mode = aws_string_new_from_c_str(allocator, "w");
    FILE *output_file = aws_fopen_safe(path, mode);

    if (!output_file) {
        fprintf(
            stderr,
            "Error %s, while opening file to: %s\n",
            aws_error_debug_str(aws_last_error()),
            aws_string_c_str(path));
        exit(-1);
    }

    aws_string_destroy(mode);
    aws_string_destroy(path);
    aws_byte_buf_clean_up(&output_path);

    /* use pre-built private/pub key pairs, we'll fuzz via the input. */
    uint8_t d[] = {
        0x51, 0x9b, 0x42, 0x3d, 0x71, 0x5f, 0x8b, 0x58, 0x1f, 0x4f, 0xa8, 0xee, 0x59, 0xf4, 0x77, 0x1a,
        0x5b, 0x44, 0xc8, 0x13, 0x0b, 0x4e, 0x3e, 0xac, 0xca, 0x54, 0xa5, 0x6d, 0xda, 0x72, 0xb4, 0x64,
    };

    struct aws_byte_cursor private_key = aws_byte_cursor_from_array(d, sizeof(d));

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

    struct aws_ecc_key_pair *signing_key =
        aws_ecc_key_pair_new_from_private_key(allocator, AWS_CAL_ECDSA_P256, &private_key);
    struct aws_ecc_key_pair *verifying_key =
        aws_ecc_key_pair_new_from_public_key(allocator, AWS_CAL_ECDSA_P256, &pub_x, &pub_y);

    struct aws_byte_buf raw_buf;
    aws_byte_buf_init(&raw_buf, allocator, 1024);

    size_t max_iterations = 10000;
    size_t count = 0;

    struct aws_byte_cursor to_append = aws_byte_cursor_from_c_str("a");
    struct aws_byte_buf to_sign;
    aws_byte_buf_init(&to_sign, allocator, AWS_SHA256_LEN);

    struct aws_byte_buf signature_output;
    aws_byte_buf_init(&signature_output, allocator, aws_ecc_key_pair_signature_length(signing_key));

    struct aws_byte_buf hex_buf;
    aws_byte_buf_init(&hex_buf, allocator, 1024);

    for (; count < max_iterations; ++count) {
        struct aws_byte_cursor hash_input = aws_byte_cursor_from_buf(&raw_buf);

        aws_sha256_compute(allocator, &hash_input, &to_sign, 0);
        struct aws_byte_cursor signing_cur = aws_byte_cursor_from_buf(&to_sign);

        int signing_val = aws_ecc_key_pair_sign_message(signing_key, &signing_cur, &signature_output);
        (void)signing_val;

        struct aws_byte_cursor signature_cur = aws_byte_cursor_from_buf(&signature_output);
        int verify_val = aws_ecc_key_pair_verify_signature(verifying_key, &signing_cur, &signature_cur);

        aws_hex_encode(&signature_cur, &hex_buf);
        struct aws_byte_cursor hex_encoded_cur = aws_byte_cursor_from_buf(&hex_buf);

        if (verify_val != AWS_OP_SUCCESS) {
            fprintf(
                stderr,
                "Signature: \"" PRInSTR "\" was produced but could not be verified\n",
                AWS_BYTE_CURSOR_PRI(hex_encoded_cur));
        }

        fprintf(output_file, PRInSTR "\n", AWS_BYTE_CURSOR_PRI(hex_encoded_cur));

        aws_byte_buf_append_dynamic(&raw_buf, &to_append);
        aws_byte_buf_reset(&hex_buf, true);
        aws_byte_buf_reset(&to_sign, true);
        aws_byte_buf_reset(&signature_output, true);
    }

    aws_byte_buf_clean_up(&hex_buf);
    aws_byte_buf_clean_up(&signature_output);
    aws_byte_buf_clean_up(&raw_buf);

    aws_ecc_key_pair_release(verifying_key);
    aws_ecc_key_pair_release(signing_key);

    fclose(output_file);

    aws_cal_library_clean_up();
    return 0;
}
