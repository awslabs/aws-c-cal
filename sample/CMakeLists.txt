cmake_minimum_required(VERSION 3.10)
project(ReproSample)

if(POLICY CMP0069)
    cmake_policy(SET CMP0069 NEW) # Enable LTO/IPO if available in the compiler, see AwsCFlags
endif()

find_library(COREFOUNDATION_LIBRARY CoreFoundation)
find_library(SECURITY_LIBRARY Security)

add_executable(ReproSample main.c)

target_link_libraries(ReproSample ${COREFOUNDATION_LIBRARY} ${SECURITY_LIBRARY})
