include(CTest)
enable_testing()

file(GLOB TEST_SRC "main.c")
file(GLOB TEST_HDRS "*.h")
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})

set(TEST_BINARY_NAME ${CMAKE_PROJECT_NAME}-tests)

add_executable(${TEST_BINARY_NAME} ${TESTS})
aws_set_common_properties(${TEST_BINARY_NAME})
aws_add_sanitizers(${TEST_BINARY_NAME} SANITIZERS ${${CMAKE_PROJECT_NAME}_SANITIZERS})
target_link_libraries(${TEST_BINARY_NAME} PRIVATE ${CMAKE_PROJECT_NAME})
target_compile_definitions(${TEST_BINARY_NAME} PRIVATE AWS_UNSTABLE_TESTING_API=1)
target_include_directories(${TEST_BINARY_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR})

add_test(http_parse_lots_of_headers ${TEST_BINARY_NAME} http_parse_lots_of_headers)
add_test(http_parse_and_lookup_header ${TEST_BINARY_NAME} http_parse_and_lookup_header)
add_test(http_parse_bad_or_empty_input ${TEST_BINARY_NAME} http_parse_bad_or_empty_input)
