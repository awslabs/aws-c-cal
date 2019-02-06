#ifndef AWS_CAL_EXPORTS_H
#define AWS_CAL_EXPORTS_H
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
#if defined(AWS_C_RT_USE_WINDOWS_DLL_SEMANTICS) || defined(WIN32)
#    ifdef AWS_CAL_USE_IMPORT_EXPORT
#        ifdef AWS_CAL_EXPORTS
#            define AWS_CAL_API __declspec(dllexport)
#        else
#            define AWS_CAL_API __declspec(dllimport)
#        endif /* AWS_CAL_EXPORTS */
#    else
#        define AWS_CAL_API
#    endif /* AWS_CAL_USE_IMPORT_EXPORT */

#else /* defined (AWS_C_RT_USE_WINDOWS_DLL_SEMANTICS) || defined (WIN32) */

#    if ((__GNUC__ >= 4) || defined(__clang__)) && defined(AWS_CAL_USE_IMPORT_EXPORT) && defined(AWS_CAL_EXPORTS)
#        define AWS_CAL_API __attribute__((visibility("default")))
#    else
#        define AWS_CAL_API
#    endif /* __GNUC__ >= 4 || defined(__clang__) */

#endif /* defined (AWS_C_RT_USE_WINDOWS_DLL_SEMANTICS) || defined (WIN32) */

#endif /* AWS_CAL_EXPORTS_H */
