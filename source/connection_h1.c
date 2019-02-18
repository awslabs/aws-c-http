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

#include <aws/http/private/connection_impl.h>

static int s_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message);

static int s_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message);

static int s_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size);

static int s_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately);

static size_t s_handler_initial_window_size(struct aws_channel_handler *handler);
static size_t s_handler_message_overhead(struct aws_channel_handler *handler);
static void s_handler_destroy(struct aws_channel_handler *handler);

static struct aws_http_connection_vtable s_vtable = {
    .channel_handler_vtable =
        {
            .process_read_message = s_handler_process_read_message,
            .process_write_message = s_handler_process_write_message,
            .increment_read_window = s_handler_increment_read_window,
            .shutdown = s_handler_shutdown,
            .initial_window_size = s_handler_initial_window_size,
            .message_overhead = s_handler_message_overhead,
            .destroy = s_handler_destroy,
        },
};

struct h1_connection {
    struct aws_http_connection base;
};

struct aws_http_connection *aws_http_connection_new_http1_1_server(
    const struct aws_http_server_connection_impl_options *options) {

    struct h1_connection *impl = aws_mem_acquire(options->alloc, sizeof(struct h1_connection));
    if (!impl) {
        return NULL;
    }
    AWS_ZERO_STRUCT(*impl);

    impl->base.vtable = &s_vtable;
    impl->base.alloc = options->alloc;
    impl->base.channel_handler.vtable = &s_vtable.channel_handler_vtable;
    impl->base.channel_handler.impl = impl;
    impl->base.http_version = AWS_HTTP_VERSION_1_1;
    impl->base.server_data = &impl->base.client_or_server_data.server;

    return &impl->base;
}

struct aws_http_connection *aws_http_connection_new_http1_1_client(
    const struct aws_http_client_connection_impl_options *options) {

    (void)options;
    aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
    return NULL;
}

static void s_handler_destroy(struct aws_channel_handler *handler) {
    struct h1_connection *impl = handler->impl;

    aws_mem_release(impl->base.alloc, impl);
}

static int s_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    (void)handler;
    (void)slot;
    (void)message;
    /* TODO: implement function */
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}

static int s_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    (void)handler;
    (void)slot;
    (void)message;
    assert(false); /* Should not be called until websocket stuff comes along. */
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}

static int s_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {

    (void)handler;
    (void)slot;
    (void)size;
    assert(false); /* Should not be called until websocket stuff comes along. */
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}

static int s_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    /* TODO: implement function */
    (void)handler;

    aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
    return AWS_OP_SUCCESS;
}

static size_t s_handler_initial_window_size(struct aws_channel_handler *handler) {
    struct h1_connection *impl = handler->impl;
    return impl->base.initial_window_size;
}

static size_t s_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;
    return 0;
}
