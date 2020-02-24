#ifndef AWS_C_CAL_PRIVATE_ECC_H
#define AWS_C_CAL_PRIVATE_ECC_H
/*
 * Copyright 2010-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/common/byte_buf.h>

struct aws_der_decoder;

AWS_EXTERN_C_BEGIN

AWS_CAL_API int aws_der_decoder_load_ecc_key_pair(
    struct aws_der_decoder *decoder,
    struct aws_byte_cursor *out_public_x_coor,
    struct aws_byte_cursor *out_public_y_coor,
    struct aws_byte_cursor *out_private_d,
    enum aws_ecc_curve_name *out_curve_name);

AWS_EXTERN_C_END

#endif /* AWS_C_CAL_PRIVATE_ECC_H */
