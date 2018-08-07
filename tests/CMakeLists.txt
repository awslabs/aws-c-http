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

add_test(huffman_symbol_encoder ${TEST_BINARY_NAME} huffman_symbol_encoder)
add_test(huffman_encoder ${TEST_BINARY_NAME} huffman_encoder)
add_test(huffman_encoder_all_code_points ${TEST_BINARY_NAME} huffman_encoder_all_code_points)
add_test(huffman_encoder_partial_output ${TEST_BINARY_NAME} huffman_encoder_partial_output)

add_test(huffman_symbol_decoder ${TEST_BINARY_NAME} huffman_symbol_decoder)
add_test(huffman_decoder ${TEST_BINARY_NAME} huffman_decoder)
add_test(huffman_decoder_all_code_points ${TEST_BINARY_NAME} huffman_decoder_all_code_points)
add_test(huffman_decoder_partial_input ${TEST_BINARY_NAME} huffman_decoder_partial_input)
add_test(huffman_decoder_partial_output ${TEST_BINARY_NAME} huffman_decoder_partial_output)

add_test(huffman_transitive ${TEST_BINARY_NAME} huffman_transitive)
add_test(huffman_transitive_all_code_points ${TEST_BINARY_NAME} huffman_transitive_all_code_points)


add_test(hpack_encode_integer ${TEST_BINARY_NAME} hpack_encode_integer)