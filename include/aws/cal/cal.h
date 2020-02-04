#ifndef AWS_CAL_CAL_H
#define AWS_CAL_CAL_H
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

#include <aws/common/common.h>

#include <aws/cal/exports.h>

struct aws_allocator;

#define AWS_C_CAL_PACKAGE_ID 7

enum aws_cal_errors {
    AWS_ERROR_CAL_SIGNATURE_VALIDATION_FAILED = AWS_ERROR_ENUM_BEGIN_RANGE(AWS_C_CAL_PACKAGE_ID),
    AWS_ERROR_CAL_MISSING_REQUIRED_KEY_COMPONENT,
    AWS_ERROR_CAL_INVALID_KEY_LENGTH_FOR_ALGORITHM,
    AWS_ERROR_CAL_UNKNOWN_OBJECT_IDENTIFIER,
    AWS_ERROR_CAL_MALFORMED_ASN1_ENCOUNTERED,
    AWS_ERROR_CAL_MISMATCHED_DER_TYPE,
    AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM,

    AWS_ERROR_CAL_END_RANGE = AWS_ERROR_ENUM_END_RANGE(AWS_C_CAL_PACKAGE_ID)
};

AWS_EXTERN_C_BEGIN

AWS_CAL_API void aws_cal_library_init(struct aws_allocator *allocator);
AWS_CAL_API void aws_cal_library_clean_up(void);

AWS_EXTERN_C_END

#endif /* AWS_CAL_CAL_H */
