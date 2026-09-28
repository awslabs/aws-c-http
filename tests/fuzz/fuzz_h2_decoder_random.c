/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/private/h2_decoder.h>

#include <aws/testing/aws_test_harness.h>

#include <aws/common/allocator.h>
#include <aws/common/logging.h>

static struct aws_mutex s_fuzz_lock = AWS_MUTEX_INIT;
static bool s_fuzz_test_initialized = false;
static struct aws_allocator *s_tracing_allocator = NULL;
static struct aws_logger s_logger;

static void s_clean_up_fuzz_test(void) {
    aws_http_library_clean_up();

    aws_logger_set(NULL);
    aws_logger_clean_up(&s_logger);
}

static void s_init_fuzz_test(void) {
    aws_mutex_lock(&s_fuzz_lock);
    if (s_fuzz_test_initialized) {
        goto done;
    }

    s_fuzz_test_initialized = true;

    s_tracing_allocator = aws_default_allocator();

    /* Enable logging */

    struct aws_logger_standard_options log_options = {
        .level = AWS_LL_TRACE,
        .file = stdout,
    };
    aws_logger_init_standard(&s_logger, s_tracing_allocator, &log_options);
    aws_logger_set(&s_logger);

    /* Init HTTP (s2n init is weird, so don't do this under the tracer) */
    aws_http_library_init(aws_default_allocator());

    atexit(s_clean_up_fuzz_test);

done:

    aws_mutex_unlock(&s_fuzz_lock);
}

AWS_EXTERN_C_BEGIN

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    s_init_fuzz_test();

    /* Setup allocator and parameters */
    struct aws_allocator *allocator = s_tracing_allocator;
    struct aws_byte_cursor to_decode = aws_byte_cursor_from_array(data, size);

    /* Create the decoder */
    struct aws_h2_decoder_vtable decoder_vtable = {0};
    struct aws_h2_decoder_params decoder_params = {
        .alloc = allocator,
        .vtable = &decoder_vtable,
        .skip_connection_preface = true,
    };
    struct aws_h2_decoder *decoder = aws_h2_decoder_new(&decoder_params);

    /* Decode whatever we got */
    aws_h2_decode(decoder, &to_decode);

    /* Clean up */
    aws_h2_decoder_destroy(decoder);

    return 0;
}

AWS_EXTERN_C_END
