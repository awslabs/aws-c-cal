include(AwsLibFuzzer)
include(AwsTestHarness)
enable_testing()

file(GLOB TEST_HDRS "*.h")
file(GLOB TEST_SRC "*.c")

file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})

add_test_case(sha256_nist_test_case_1)
add_test_case(sha256_nist_test_case_2)
add_test_case(sha256_nist_test_case_3)
add_test_case(sha256_nist_test_case_4)
add_test_case(sha256_nist_test_case_5)
add_test_case(sha256_nist_test_case_6)
add_test_case(sha256_invalid_buffer_size)

add_test_case(md5_rfc1321_test_case_1)
add_test_case(md5_rfc1321_test_case_2)
add_test_case(md5_rfc1321_test_case_3)
add_test_case(md5_rfc1321_test_case_4)
add_test_case(md5_rfc1321_test_case_5)
add_test_case(md5_rfc1321_test_case_6)
add_test_case(md5_rfc1321_test_case_7)
add_test_case(md5_invalid_buffer_size)

add_test_case(sha256_hmac_rfc4231_test_case_1)
add_test_case(sha256_hmac_rfc4231_test_case_2)
add_test_case(sha256_hmac_rfc4231_test_case_3)
add_test_case(sha256_hmac_rfc4231_test_case_4)
#test case 5 is deliberately left out. It deals with truncation behavior.
add_test_case(sha256_hmac_rfc4231_test_case_6)
add_test_case(sha256_hmac_rfc4231_test_case_7)
add_test_case(sha256_hmac_invalid_buffer_size)

generate_test_driver(${CMAKE_PROJECT_NAME}-tests)

