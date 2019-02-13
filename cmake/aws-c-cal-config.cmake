include(CMakeFindDependencyMacro)

if (NOT BYO_CRYPTO AND NOT WIN32 AND NOT APPLE)
    find_dependency(LibCrypto)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/@CMAKE_PROJECT_NAME@-targets.cmake)
