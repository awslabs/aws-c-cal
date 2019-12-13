#ifndef AWS_C_CAL_DER_H
#define AWS_C_CAL_DER_H
/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */


#include <aws/common/array_list.h>
#include <aws/common/byte_buf.h>

struct aws_der_encoder {
    struct aws_allocator *allocator;
    struct aws_byte_buf storage;
    struct aws_byte_buf *buffer; /* buffer being written to, might be storage, might be a sequence/set buffer */
    struct aws_array_list stack;
};

struct aws_der_decoder {
    struct aws_allocator *allocator;
    struct aws_array_list tlvs; /* index to elements after parsing */
    int tlv_idx;
    struct aws_byte_buf *buffer;
};

enum aws_der_type {
    /* Primitives */
    DER_BOOLEAN = 0x01,
    DER_INTEGER = 0x02,
    DER_BIT_STRING = 0x03,
    DER_OCTET_STRING = 0x04,
    DER_NULL = 0x05,
    DER_OBJECT_IDENTIFIER = 0x06,
    DER_BMPString = 0x1e,
    DER_UNICODE_STRING = DER_BMPString,
    DER_IA5String = 0x16, /* Unsupported */
    DER_PrintableString = 0x13,
    DER_TeletexString = 0x14, /* Unsupported */
    DER_SEQUENCE = 0x30,
    DER_SEQUENCE_OF = DER_SEQUENCE,
    DER_SET = 0x31,
    DER_SET_OF = DER_SET,

    /* Constructed types */
    DER_UTF8_STRING = 0x0c,
};

/**
 * Initializes a DER encoder
 * @param encoder The encoder to initialize
 * @param allocator The allocator to use for all allocations within the encoder
 * @param capacity The capacity of the encoder scratch buffer (the max size of all encoded TLVs)
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
int aws_der_encoder_init(struct aws_der_encoder *encoder, struct aws_allocator *allocator, size_t capacity);
/**
 * Cleans up a DER encoder
 * @param encoder The encoder to clean up
 *
 * Note that this destroys the encoder buffer, invalidating any references to the contents given via get_contents()
 */
void aws_der_encoder_clean_up(struct aws_der_encoder *encoder);

/**
 * Writes an arbitrarily sized integer to the DER stream
 * @param encoder The encoder to use
 * @param integer A cursor pointing to the integer's memory
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
int aws_der_encoder_write_integer(struct aws_der_encoder *encoder, struct aws_byte_cursor integer);
/**
 * Writes a boolean to the DER stream
 * @param encoder The encoder to use
 * @param boolean The boolean to write
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
int aws_der_encoder_write_boolean(struct aws_der_encoder *encoder, bool boolean);

/**
 * Writes a NULL token to the stream
 * @param encoder The encoder to write to
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
int aws_der_encoder_write_null(struct aws_der_encoder *encoder);

/**
 * Writes a BIT_STRING to the stream
 * @param encoder The encoder to use
 * @param bit_string The bit string to encode
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
int aws_der_encoder_write_bit_string(struct aws_der_encoder *encoder, struct aws_byte_cursor bit_string);

/**
 * Writes a string to the stream
 * @param encoder The encoder to use
 * @param octet_string The string to encode
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
int aws_der_encoder_write_octet_string(struct aws_der_encoder *encoder, struct aws_byte_cursor octet_string);

int aws_der_encoder_begin_sequence(struct aws_der_encoder *encoder);
int aws_der_encoder_end_sequence(struct aws_der_encoder *encoder);

int aws_der_encoder_begin_set(struct aws_der_encoder *encoder);
int aws_der_encoder_end_set(struct aws_der_encoder *encoder);

/**
 * Retrieves the contents of the deocoder stream buffer
 * @param encoder The encoder to read from
 * @param cursor The cursor to point at the stream buffer
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
int aws_der_encoder_get_contents(struct aws_der_encoder *encoder, struct aws_byte_cursor *cursor);

/**
 * Initializes an DER decoder
 * @param decoder The decoder to initialize
 * @param buffer The DER formatted buffer to parse
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
int aws_der_decoder_init(struct aws_der_decoder *decoder, struct aws_byte_buf *buffer);

/**
 * Cleans up a DER encoder
 * @param decoder The encoder to clean up
 */
void aws_der_decoder_clean_up(struct aws_der_decoder *decoder);

/**
 * Parses the internal buffer into a TLV or sequence/set of TLVs
 * @param decoder The decoder to parse
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
int aws_der_decoder_parse(struct aws_der_decoder *decoder);

/**
 * Allows for iteration over the decoded TLVs.
 * @param decoder The decoder to iterate over
 * @return true if there is a tlv to read after advancing, false when done
 */
bool aws_der_decoder_next(struct aws_der_decoder *decoder);

/**
 * The type of the current TLV
 * @param decoder The decoder to inspect
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
enum aws_der_type aws_der_tlv_type(struct aws_der_decoder *decoder);

/**
 * The size of the current TLV
 * @param decoder The decoder to inspect
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
size_t aws_der_tlv_size(struct aws_der_decoder *decoder);

/**
 * Extracts the current TLV string value (BIT_STRING, OCTET_STRING)
 * @param decoder The decoder to extract from
 * @param string The buffer to store the string into
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
int aws_der_decoder_tlv_string(struct aws_der_decoder *decoder, struct aws_byte_buf *string);

/**
 * Extracts the current TLV INTEGER value (INTEGER)
 * @param decoder The decoder to extract from
 * @param integer The buffer to store the integer into
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
int aws_der_decoder_tlv_integer(struct aws_der_decoder *decoder, struct aws_byte_buf *integer);

/**
 * Extracts the current TLV BOOLEAN value (BOOLEAN)
 * @param decoder The decoder to extract from
 * @param boolean The boolean to store the value into
 * @return AWS_OP_ERR if an error occurs, otherwise AWS_OP_SUCCESS
 */
int aws_der_decoder_tlv_boolean(struct aws_der_decoder *decoder, bool *boolean);

#endif
