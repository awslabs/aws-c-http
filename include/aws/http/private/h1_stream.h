#ifndef AWS_HTTP_H1_STREAM_H
#define AWS_HTTP_H1_STREAM_H
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

#include <aws/http/private/h1_encoder.h>
#include <aws/http/private/http_impl.h>
#include <aws/http/private/request_response_impl.h>

struct aws_h1_stream {
    struct aws_http_stream base;

    struct aws_linked_list_node node;

    /* Message (derived from outgoing request or response) to be submitted to encoder */
    struct aws_h1_encoder_message encoder_message;

    bool is_outgoing_message_done;

    bool is_incoming_message_done;
    bool is_incoming_head_done;

    /* If true, this is the last stream the connection should process.
     * See RFC-7230 Section 6: Connection Management. */
    bool is_final_stream;

    /* Buffer for incoming data that needs to stick around. */
    struct aws_byte_buf incoming_storage_buf;

    /* Any thread may touch this data, but the lock must be held */
    struct {
        /* Whether a "request handler" stream has a response to send. */
        bool has_outgoing_response;
    } synced_data;
};

AWS_EXTERN_C_BEGIN

AWS_HTTP_API
struct aws_h1_stream *aws_h1_stream_new_request(
    struct aws_http_connection *client_connection,
    const struct aws_http_make_request_options *options);

AWS_HTTP_API
struct aws_h1_stream *aws_h1_stream_new_request_handler(const struct aws_http_request_handler_options *options);

AWS_EXTERN_C_END

/* we don't want this exported. We just want it to have external linkage between h1_stream and h1_connection compilation
 * units. it is defined in h1_connection.c */
int aws_h1_stream_activate(struct aws_http_stream *stream);

#endif /* AWS_HTTP_H1_STREAM_H */
