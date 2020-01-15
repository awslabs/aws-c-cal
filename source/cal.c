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
#include <aws/cal/cal.h>
#include <aws/common/common.h>
#include <aws/common/error.h>

#define AWS_DEFINE_ERROR_INFO_CAL(CODE, STR) [(CODE)-0x1C00] = AWS_DEFINE_ERROR_INFO(CODE, STR, "aws-c-cal")

static struct aws_error_info s_errors[] = {
    AWS_DEFINE_ERROR_INFO_CAL(AWS_ERROR_CAL_SIGNATURE_VALIDATION_FAILED, "Verify on a cryptographic signature failed."),
    AWS_DEFINE_ERROR_INFO_CAL(
        AWS_ERROR_CAL_MISSING_REQUIRED_KEY_COMPONENT,
        "An attempt was made to perform an "
        "Asymmetric cryptographic operation with the"
        "wrong key component. For example, attempt to"
        "verify a signature with a private key or "
        "sign a message with a public key."),
    AWS_DEFINE_ERROR_INFO_CAL(
        AWS_ERROR_CAL_INVALID_KEY_LENGTH_FOR_ALGORITHM,
        "A key length was used for an algorithm that needs a different key length"),
    AWS_DEFINE_ERROR_INFO_CAL(
        AWS_ERROR_CAL_UNKNOWN_OBJECT_IDENTIFIER,
        "An ASN.1 OID was encountered that wasn't expected or understood. Most likely, an unsupported algorithm was "
        "encountered."),
    AWS_DEFINE_ERROR_INFO_CAL(
        AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED,
        "An ASN.1 DER decoding operation failed on malformed input."),
    AWS_DEFINE_ERROR_INFO_CAL(
        AWS_ERROR_CAL_MISMATCHED_DER_TYPE,
        "An invalid DER type was requested during encoding/decoding"),
    AWS_DEFINE_ERROR_INFO_CAL(
        AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM,
        "The specified algorithim is unsupported on this platform."),
};

static struct aws_error_info_list s_list = {
    .error_list = s_errors,
    .count = AWS_ARRAY_SIZE(s_errors),
};

static bool s_cal_library_initialized = false;

void aws_cal_library_init(struct aws_allocator *allocator) {
    if (!s_cal_library_initialized) {
        aws_common_library_init(allocator);
        aws_register_error_info(&s_list);
        s_cal_library_initialized = true;
    }
}
void aws_cal_library_clean_up(void) {
    if (s_cal_library_initialized) {
        s_cal_library_initialized = false;
        aws_unregister_error_info(&s_list);
        aws_common_library_clean_up();
    }
}
