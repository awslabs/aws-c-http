include(AwsTestHarness)
enable_testing()

file(GLOB TEST_HDRS "*.h")
file(GLOB TEST_SRC "*.c")
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})

add_test_case(http_test_queue_typical_usecase)
add_test_case(http_test_queue_static)
add_test_case(http_test_queue_overflow)
add_test_case(http_test_queue_resize)

add_test_case(http_test_get_version)
add_test_case(http_test_get_uri)
add_test_case(http_test_get_status_code)
add_test_case(http_test_overflow_scratch_space)
add_test_case(http_test_receive_request_headers)
add_test_case(http_test_receive_response_headers)
add_test_case(http_test_get_transfer_encoding_flags)
add_test_case(http_test_body_unchunked)
add_test_case(http_test_body_chunked)
add_test_case(http_decode_trailers)
add_test_case(http_decode_one_byte_at_a_time)
add_test_case(http_decode_messages_at_random_intervals)
add_test_case(http_decode_bad_messages_and_assert_failure)
add_test_case(http_test_extraneous_buffer_data_ensure_not_processed)
add_test_case(http_test_ignore_transfer_extensions)
add_test_case(http_test_ignore_chunk_extensions)

add_test_case(http_test_connection)

set(TEST_BINARY_NAME ${CMAKE_PROJECT_NAME}-tests)
generate_test_driver(${TEST_BINARY_NAME})

#SSL certificates to use for testing.
add_custom_command(TARGET ${TEST_BINARY_NAME} PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/resources ${CMAKE_CURRENT_BINARY_DIR})
