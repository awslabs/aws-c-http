include(AwsTestHarness)
enable_testing()

file(GLOB TEST_HDRS "*.h")
file(GLOB TEST_SRC "*.c")
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})

add_test_case(http_parse_lots_of_headers)

generate_test_driver(${CMAKE_PROJECT_NAME}-tests)
