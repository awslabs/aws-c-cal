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

#include <aws/cal/der.h>

#include <aws/common/byte_buf.h>

struct der_tlv {
    uint8_t tag;
    uint32_t length;
    uint32_t count; /* SEQUENCE or SET element count */
    uint8_t *value;
};

static void s_decode_tlv(struct der_tlv *tlv) {
    if (tlv->tag == DER_INTEGER) {
        uint8_t first_byte = tlv->value[0];
        /* if the first byte is 0, it just denotes unsigned and should be removed */
        if (first_byte == 0x00) {
            tlv->length -= 1;
            tlv->value += 1;
        }
    } else if (tlv->tag == DER_BIT_STRING) {
        /* skip over the trailing skipped bit count */
        tlv->length -= 1;
        tlv->value += 1;
    }
}

static int s_der_read_tlv(struct aws_byte_cursor *cur, struct der_tlv *tlv) {
    uint8_t tag = 0;
    uint8_t len_bytes = 0;
    uint32_t len = 0;
    if (!aws_byte_cursor_read_u8(cur, &tag)) {
        return AWS_OP_ERR;
    }
    if (!aws_byte_cursor_read_u8(cur, &len_bytes)) {
        return AWS_OP_ERR;
    }
    /* if the sign bit is set, then the first byte is the number of bytes required to store
     * the length */
    if (len_bytes & 0x80) {
        len_bytes &= 0x7f;
        AWS_FATAL_ASSERT(len_bytes <= 4 && "Only 32-bit sizes of DER TLV elements are supported");
        if (len_bytes == 1) {
            if (!aws_byte_cursor_read_u8(cur, (uint8_t*)&len)) {
                return AWS_OP_ERR;
            }
        } else if (len_bytes == 2) {
            if (!aws_byte_cursor_read_be16(cur, (uint16_t *)&len)) {
                return AWS_OP_ERR;
            }
        } else if (len_bytes == 4) {
            if (!aws_byte_cursor_read_be32(cur, &len)) {
                return AWS_OP_ERR;
            }
        } else {
            AWS_FATAL_ASSERT(len_bytes == 1 || len_bytes == 2 || len_bytes == 4);
        }

    } else {
        len = len_bytes;
    }

    tlv->tag = tag;
    tlv->length = len;
    /* skip over any prepended encoding bytes */
    tlv->value = (tag == DER_NULL) ? NULL : cur->ptr;
    s_decode_tlv(tlv);
    aws_byte_cursor_advance(cur, len);

    return AWS_OP_SUCCESS;
}

static uint32_t s_encoded_len(struct der_tlv *tlv) {
    if (tlv->tag == DER_INTEGER) {
        uint8_t first_byte = tlv->value[0];
        /* if the first byte has the high bit set, a 0 will be prepended to denote unsigned */
        return tlv->length + ((first_byte & 0x80) != 0);
    } else if (tlv->tag == DER_BIT_STRING) {
        return tlv->length + 1; /* needs a byte to denote how many trailing skipped bits */
    }

    return tlv->length;
}

static int s_der_write_tlv(struct der_tlv *tlv, struct aws_byte_buf *buf) {
    if (!aws_byte_buf_write_u8(buf, tlv->tag)) {
        return AWS_OP_ERR;
    }
    uint32_t len = s_encoded_len(tlv);
    if (len > UINT16_MAX) {
        /* write the high bit plus 4 byte length */
        if (!aws_byte_buf_write_u8(buf, 0x84)) {
            return AWS_OP_ERR;
        }
        if (!aws_byte_buf_write_be32(buf, len)) {
            return AWS_OP_ERR;
        }
    } else if (len > UINT8_MAX) {
        /* write the high bit plus 2 byte length */
        if (!aws_byte_buf_write_u8(buf, 0x82)) {
            return AWS_OP_ERR;
        }
        if (!aws_byte_buf_write_be16(buf, len)) {
            return AWS_OP_ERR;
        }
    } else if (len > INT8_MAX) {
        /* Write the high bit + 1 byte length */
        if (!aws_byte_buf_write_u8(buf, 0x81)) {
            return AWS_OP_ERR;
        }
        if (!aws_byte_buf_write_u8(buf, len)) {
            return AWS_OP_ERR;
        }
    } else {
        if (!aws_byte_buf_write_u8(buf, len)) {
            return AWS_OP_ERR;
        }
    }

    switch (tlv->tag) {
        case DER_INTEGER: {
            /* if the first byte has the sign bit set, insert an extra 0x00 byte to indicate unsigned */
            uint8_t first_byte = tlv->value[0];
            if (first_byte & 0x80) {
                if (!aws_byte_buf_write_u8(buf, 0)) {
                    return AWS_OP_ERR;
                }
            }
            if (!aws_byte_buf_write(buf, tlv->value, tlv->length)) {
                return AWS_OP_ERR;
            }
        } break;
        case DER_BOOLEAN:
            if (!aws_byte_buf_write_u8(buf, (*tlv->value) ? 0xff : 0x00)) {
                return AWS_OP_ERR;
            }
            break;
        case DER_BIT_STRING:
            /* Write that there are 0 skipped bits */
            if (!aws_byte_buf_write_u8(buf, 0)) {
                return AWS_OP_ERR;
            }
            /* FALLTHROUGH */
        case DER_BMPString:
        case DER_IA5String:
        case DER_PrintableString:
        case DER_UTF8_STRING:
        case DER_OBJECT_IDENTIFIER:
        case DER_OCTET_STRING:
        case DER_SEQUENCE:
        case DER_SET:
            if (!aws_byte_buf_write(buf, tlv->value, tlv->length)) {
                return AWS_OP_ERR;
            }
            break;
        case DER_NULL:
            /* No value bytes */
            break;
        default:
            AWS_FATAL_ASSERT(!"TLV tag is not a supported encoding type");
            return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_der_encoder_init(struct aws_der_encoder *encoder, struct aws_allocator *allocator, size_t capacity) {
    encoder->allocator = allocator;
    if (aws_byte_buf_init(&encoder->storage, encoder->allocator, capacity)) {
        return AWS_OP_ERR;
    }
    if (aws_array_list_init_dynamic(&encoder->stack, encoder->allocator, 4, sizeof(struct der_tlv))) {
        return AWS_OP_ERR;
    }

    encoder->buffer = &encoder->storage;

    return AWS_OP_SUCCESS;
}

void aws_der_encoder_clean_up(struct aws_der_encoder *encoder) {
    aws_byte_buf_clean_up_secure(&encoder->storage);
    aws_array_list_clean_up(&encoder->stack);
}

int aws_der_encoder_write_integer(struct aws_der_encoder *encoder, struct aws_byte_cursor integer) {
    struct der_tlv tlv = {
        .tag = DER_INTEGER,
        .length = integer.len,
        .value = integer.ptr,
    };

    return s_der_write_tlv(&tlv, encoder->buffer);
}

int aws_der_encoder_write_boolean(struct aws_der_encoder *encoder, bool boolean) {
    struct der_tlv tlv = {.tag = DER_BOOLEAN, .length = 1, .value = (uint8_t *)&boolean};

    return s_der_write_tlv(&tlv, encoder->buffer);
}

int aws_der_encoder_write_null(struct aws_der_encoder *encoder) {
    struct der_tlv tlv = {
        .tag = DER_NULL,
        .length = 0,
        .value = NULL,
    };

    return s_der_write_tlv(&tlv, encoder->buffer);
}

int aws_der_encoder_write_bit_string(struct aws_der_encoder *encoder, struct aws_byte_cursor bit_string) {
    struct der_tlv tlv = {
        .tag = DER_BIT_STRING,
        .length = bit_string.len,
        .value = bit_string.ptr,
    };

    return s_der_write_tlv(&tlv, encoder->buffer);
}

int aws_der_encoder_write_octet_string(struct aws_der_encoder *encoder, struct aws_byte_cursor octet_string) {
    struct der_tlv tlv = {
        .tag = DER_OCTET_STRING,
        .length = octet_string.len,
        .value = octet_string.ptr,
    };

    return s_der_write_tlv(&tlv, encoder->buffer);
}

static int s_der_encoder_begin_container(struct aws_der_encoder *encoder, enum aws_der_type type) {
    struct aws_byte_buf *seq_buf = aws_mem_acquire(encoder->allocator, sizeof(struct aws_byte_buf));
    AWS_FATAL_ASSERT(seq_buf);
    if (aws_byte_buf_init(seq_buf, encoder->allocator, encoder->storage.capacity)) {
        return AWS_OP_ERR;
    }
    struct der_tlv tlv_seq = {
        .tag = type,
        .length = 0, /* not known yet, will update later */
        .value = (void *)seq_buf,
    };
    if (aws_array_list_push_back(&encoder->stack, &tlv_seq)) {
        aws_byte_buf_clean_up(seq_buf);
        return AWS_OP_ERR;
    }
    encoder->buffer = seq_buf;
    return AWS_OP_SUCCESS;
}

static int s_der_encoder_end_container(struct aws_der_encoder *encoder) {
    struct der_tlv tlv;
    if (aws_array_list_back(&encoder->stack, &tlv)) {
        return AWS_OP_ERR;
    }
    aws_array_list_pop_back(&encoder->stack);
    /* update the buffer to point at the next container on the stack */
    if (encoder->stack.length > 0) {
        struct der_tlv outer;
        if (aws_array_list_back(&encoder->stack, &outer)) {
            return AWS_OP_ERR;
        }
        encoder->buffer = (struct aws_byte_buf *)outer.value;
    } else {
        encoder->buffer = &encoder->storage;
    }

    struct aws_byte_buf *seq_buf = (struct aws_byte_buf *)tlv.value;
    tlv.length = seq_buf->len;
    tlv.value = seq_buf->buffer;
    int result = s_der_write_tlv(&tlv, encoder->buffer);
    aws_byte_buf_clean_up_secure(seq_buf);
    aws_mem_release(encoder->allocator, seq_buf);
    return result;
}

int aws_der_encoder_begin_sequence(struct aws_der_encoder *encoder) {
    return s_der_encoder_begin_container(encoder, DER_SEQUENCE);
}

int aws_der_encoder_end_sequence(struct aws_der_encoder *encoder) {
    return s_der_encoder_end_container(encoder);
}

int aws_der_encoder_begin_set(struct aws_der_encoder *encoder) {
    return s_der_encoder_begin_container(encoder, DER_SET);
}

int aws_der_encoder_end_set(struct aws_der_encoder *encoder) {
    return s_der_encoder_end_container(encoder);
}

int aws_der_encoder_get_contents(struct aws_der_encoder *encoder, struct aws_byte_cursor *contents) {
    if (encoder->storage.len == 0) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
    if (encoder->buffer != &encoder->storage) {
        /* someone forgot to end a sequence or set */
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
    *contents = aws_byte_cursor_from_buf(&encoder->storage);
    return AWS_OP_SUCCESS;
}

int aws_der_decoder_init(struct aws_der_decoder *decoder, struct aws_allocator *allocator, struct aws_byte_buf *buffer) {
    decoder->allocator = allocator;
    decoder->buffer = buffer;
    decoder->tlv_idx = -1;
    if (aws_array_list_init_dynamic(&decoder->tlvs, decoder->allocator, 16, sizeof(struct der_tlv))) {
        return AWS_OP_ERR;
    }

    if (aws_array_list_init_dynamic(&decoder->stack, decoder->allocator, 4, sizeof(struct der_tlv))) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

void aws_der_decoder_clean_up(struct aws_der_decoder *decoder) {
    aws_array_list_clean_up(&decoder->tlvs);
    aws_array_list_clean_up(&decoder->stack);
}

int s_parse_cursor(struct aws_der_decoder *decoder, struct aws_byte_cursor cur) {
    while (cur.len) {
        struct der_tlv tlv = {0};
        if (s_der_read_tlv(&cur, &tlv)) {
            return AWS_OP_ERR;
        }
        aws_array_list_push_back(&decoder->tlvs, &tlv);
    }
    return AWS_OP_SUCCESS;
}

int aws_der_decoder_parse(struct aws_der_decoder *decoder) {
    struct aws_byte_cursor cur = aws_byte_cursor_from_buf(decoder->buffer);
    if (s_parse_cursor(decoder, cur)) {
        return AWS_OP_ERR;
    }
    /* If the last thing parsed was a container, continually parse until all containers are expanded */
    struct der_tlv *tlv = NULL;
    while (!aws_array_list_get_at_ptr(&decoder->tlvs, (void**)&tlv, decoder->tlvs.length - 1) &&
        (tlv->tag == DER_SEQUENCE || tlv->tag == DER_SET)) {
        size_t prev_count = decoder->tlvs.length;
        cur = aws_byte_cursor_from_array(tlv->value, tlv->length);
        s_parse_cursor(decoder, cur);
        /* update the number of inner objects */
        tlv->count = decoder->tlvs.length - prev_count;
    }
    return AWS_OP_SUCCESS;
}

bool aws_der_decoder_next(struct aws_der_decoder *decoder) {
    return (++decoder->tlv_idx < decoder->tlvs.length);
}

static struct der_tlv s_decoder_tlv(struct aws_der_decoder *decoder) {
    AWS_FATAL_ASSERT(decoder->tlv_idx < decoder->tlvs.length);
    struct der_tlv tlv = {0};
    aws_array_list_get_at(&decoder->tlvs, &tlv, decoder->tlv_idx);
    return tlv;
}

enum aws_der_type aws_der_decoder_tlv_type(struct aws_der_decoder *decoder) {
    struct der_tlv tlv = s_decoder_tlv(decoder);
    return tlv.tag;
}

size_t aws_der_decoder_tlv_length(struct aws_der_decoder *decoder) {
    struct der_tlv tlv = s_decoder_tlv(decoder);
    return tlv.length;
}

size_t aws_der_decoder_tlv_sequence_count(struct aws_der_decoder *decoder) {
    struct der_tlv tlv = s_decoder_tlv(decoder);
    AWS_FATAL_ASSERT(tlv.tag == DER_SEQUENCE);
    return tlv.count;
}

size_t aws_der_decoder_tlv_set_count(struct aws_der_decoder *decoder) {
    struct der_tlv tlv = s_decoder_tlv(decoder);
    AWS_FATAL_ASSERT(tlv.tag == DER_SET);
    return tlv.count;
}

int aws_der_decoder_tlv_string(struct aws_der_decoder *decoder, struct aws_byte_buf *string) {
    struct der_tlv tlv = s_decoder_tlv(decoder);
    AWS_FATAL_ASSERT(tlv.tag == DER_OCTET_STRING || tlv.tag == DER_BIT_STRING);
    struct aws_byte_cursor from = aws_byte_cursor_from_array(tlv.value, tlv.length);
    return aws_byte_buf_append(string, &from);
}

int aws_der_decoder_tlv_integer(struct aws_der_decoder *decoder, struct aws_byte_buf *integer) {
    struct der_tlv tlv = s_decoder_tlv(decoder);
    AWS_FATAL_ASSERT(tlv.tag == DER_INTEGER);
    struct aws_byte_cursor from = aws_byte_cursor_from_array(tlv.value, tlv.length);
    return aws_byte_buf_append(integer, &from);
}

int aws_der_decoder_tlv_boolean(struct aws_der_decoder *decoder, bool *boolean) {
    struct der_tlv tlv = s_decoder_tlv(decoder);
    AWS_FATAL_ASSERT(tlv.tag == DER_BOOLEAN);
    *boolean = *tlv.value != 0;
    return AWS_OP_SUCCESS;
}
