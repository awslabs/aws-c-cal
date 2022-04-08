include(CMakeFindDependencyMacro)

find_dependency(aws-c-common)

if (BUILD_SHARED_LIBS)
    include(${CMAKE_CURRENT_LIST_DIR}/shared/@PROJECT_NAME@-targets.cmake)
else()
    include(${CMAKE_CURRENT_LIST_DIR}/static/@PROJECT_NAME@-targets.cmake)
endif()

if (NOT BYO_CRYPTO AND NOT WIN32 AND NOT APPLE)
    get_target_property(AWS_C_CAL_DEPS AWS::aws-c-cal INTERFACE_LINK_LIBRARIES)
    # pre-cmake 3.3 IN_LIST search approach
    list (FIND AWS_C_CAL_DEPS "OpenSSL::Crypto" _index)
    if (${_index} GREATER -1) # if USE_OPENSSL AND NOT ANDROID
        find_dependency(OpenSSL REQUIRED)
        find_dependency(Threads REQUIRED)
    else()
        list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/modules")
        find_dependency(crypto)
    endif()
endif()
