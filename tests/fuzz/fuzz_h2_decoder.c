/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/http/private/h2_decoder.h>

#include <aws/testing/aws_test_harness.h>

#include <aws/common/logging.h>

AWS_EXTERN_C_BEGIN

AWS_TEST_ALLOCATOR_INIT(fuzz_h2_decoder)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    /* Setup allocator and parameters */
    struct aws_allocator *allocator = &fuzz_h2_decoder_allocator;
    struct memory_test_allocator *alloc_impl = &fuzz_h2_decoder_alloc_impl;
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(data, size);

    /* Reset the allocator's leak checker */
    alloc_impl->allocated = 0;
    alloc_impl->freed = 0;

    /* Enable logging */
    struct aws_logger logger;
    struct aws_logger_standard_options log_options = {
        .level = AWS_LL_TRACE,
        .file = stdout,
    };
    aws_logger_init_standard(&logger, allocator, &log_options);
    aws_logger_set(&logger);

    /* Init HTTP */
    aws_http_library_init(allocator);

    /* Create the decoder */
    struct aws_h2_decoder_params decoder_params = {
        .alloc = allocator,
    };
    struct aws_h2_decoder *decoder = aws_h2_decoder_new(&decoder_params);

    /* Decode whatever we got */
    aws_h2_decode(decoder, &to_decode);

    /* Clean up */
    aws_h2_decoder_destroy(decoder);
    aws_http_library_clean_up();
    aws_logger_set(NULL);
    aws_logger_clean_up(&logger);

    /* Check for leaks */
    AWS_FATAL_ASSERT(alloc_impl->allocated == alloc_impl->freed);

    return 0;
}

AWS_EXTERN_C_END
