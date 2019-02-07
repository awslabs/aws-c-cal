# Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

cmake_minimum_required(VERSION 3.0)
project(aws-c-cal LANGUAGES C VERSION 0.1.0)

option(BYO_CRYPTO "Set this if you want to provide your own cryptography implementation. This will cause the defaults to not be compiled." OFF)

if (UNIX AND NOT APPLE)
    include(GNUInstallDirs)
elseif(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/modules")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_PREFIX_PATH}/${CMAKE_INSTALL_LIBDIR}/cmake")

include(AwsCFlags)
include(AwsSharedLibSetup)
include(AwsSanitizers)

file(GLOB AWS_CAL_HEADERS
        "include/aws/cal/*.h"
)

file(GLOB AWS_CAL_SRC
        "source/*.c"
)

if (WIN32)

    if (NOT BYO_CRYPTO)
        file(GLOB AWS_CAL_OS_SRC
            "source/bcrypt/*.c"
        )
        set(PLATFORM_LIBS BCrypt)
    endif()

    if (MSVC)
        source_group("Header Files\\aws\\cal" FILES ${AWS_CAL_HEADERS})
        source_group("Source Files" FILES ${AWS_CAL_SRC})
        source_group("Source Files\\bcrypt" FILES ${AWS_CAL_OS_SRC})
    endif ()

elseif (APPLE)
    if (NOT BYO_CRYPTO)
        file(GLOB AWS_CAL_OS_SRC
        "source/commoncrypto/*.c"
        )
        find_library(SECURITY_LIB Security)
        if (NOT SECURITY_LIB)
           message(FATAL_ERROR "Security Framework not found")
        endif ()

        set(PLATFORM_LIBS ${SECURITY_LIB})
    endif()
else ()
    if (NOT BYO_CRYPTO)
        file(GLOB AWS_CAL_OS_SRC
            "source/opensslcrypto/*.c"
        )
        find_package(LibCrypto REQUIRED)
        set(PLATFORM_LIBS LibCrypto::Crypto)
    endif()
endif()

file(GLOB CAL_HEADERS
        ${AWS_CAL_HEADERS}
)

file(GLOB CAL_SRC
        ${AWS_CAL_SRC}
        ${AWS_CAL_OS_SRC}
)

add_library(${CMAKE_PROJECT_NAME} ${CAL_SRC})
aws_set_common_properties(${CMAKE_PROJECT_NAME} NO_WEXTRA)
aws_prepare_symbol_visibility_args(${CMAKE_PROJECT_NAME} "AWS_CAL")
aws_add_sanitizers(${CMAKE_PROJECT_NAME} BLACKLIST "sanitizer-blacklist.txt")

find_package(aws-c-common REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} PUBLIC AWS::aws-c-common ${PLATFORM_LIBS})

if (BYO_CRYPTO)
    target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE -DAWS_BYO_CRYPTO)
elseif (NOT WIN32 AND NOT APPLE)
    target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE $<TARGET_PROPERTY:LibCrypto::Crypto,INTERFACE_INCLUDE_DIRECTORIES>)
endif()

# Our ABI is not yet stable
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES VERSION 1.0.0)
set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES SOVERSION 0unstable)

target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)
# When we install, the generated header will be at the INSTALL_INTERFACE:include location,
# but at build time we need to explicitly include this here
target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${GENERATED_INCLUDE_DIR}>)

aws_prepare_shared_lib_exports(${CMAKE_PROJECT_NAME})

configure_file("cmake/${CMAKE_PROJECT_NAME}-config.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_PROJECT_NAME}-config.cmake"
  @ONLY)

install(EXPORT "${CMAKE_PROJECT_NAME}-targets"
    DESTINATION "${LIBRARY_DIRECTORY}/${CMAKE_PROJECT_NAME}/cmake"
    NAMESPACE AWS::
    COMPONENT Development)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_PROJECT_NAME}-config.cmake"
    DESTINATION "${LIBRARY_DIRECTORY}/${CMAKE_PROJECT_NAME}/cmake"
    COMPONENT Development)

list(APPEND EXPORT_MODULES
    "cmake/modules/FindLibCrypto.cmake"
    )

install(FILES ${EXPORT_MODULES}
        DESTINATION "${LIBRARY_DIRECTORY}/cmake"
        COMPONENT Development)

if (NOT CMAKE_CROSSCOMPILING AND NOT BYO_CRYPTO)
    include(CTest)
    add_subdirectory(tests)
endif()