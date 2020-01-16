#ifndef AWS_HTTP_H2_DECODER_H
#define AWS_HTTP_H2_DECODER_H

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

#include <aws/http/private/h2_frames.h>
#include <aws/http/private/http_impl.h>

struct aws_h2_decoder_vtable {

    int (*on_header)(
        uint32_t stream_id,
        const struct aws_http_header *header,
        enum aws_h2_header_field_hpack_behavior hpack_behavior,
        void *userdata);
    int (*on_end_headers)(uint32_t stream_id, void *userdata);

    int (*on_data)(uint32_t stream_id, const struct aws_byte_cursor *data, void *userdata);

    int (*on_rst_stream)(uint32_t stream_id, uint32_t error_code, void *userdata);

    int (*on_push_promise)(uint32_t stream_id, uint32_t promised_stream_id, void *userdata);

    int (*on_ping)(bool ack, uint8_t opaque_data[8], void *userdata);
    int (*on_setting)(uint16_t setting, uint32_t value, void *userdata);
    int (*on_settings_ack)(void *userdata);
    int (*on_goaway)(uint32_t last_stream, uint32_t error_code, uint32_t debug_data_length, void *userdata);
    int (*on_goaway_debug_data)(const struct aws_byte_cursor *data, void *userdata);
};

/**
 * Structure used to initialize an `aws_h2_decoder`.
 */
struct aws_h2_decoder_params {
    struct aws_allocator *alloc;
    struct aws_h2_decoder_vtable vtable;
    void *userdata;
    void *logging_id;
};

struct aws_h2_decoder;

AWS_EXTERN_C_BEGIN

AWS_HTTP_API struct aws_h2_decoder *aws_h2_decoder_new(struct aws_h2_decoder_params *params);
AWS_HTTP_API void aws_h2_decoder_destroy(struct aws_h2_decoder *decoder);
AWS_HTTP_API int aws_h2_decode(struct aws_h2_decoder *decoder, struct aws_byte_cursor *data);

AWS_EXTERN_C_END

#endif /* AWS_HTTP_H2_DECODER_H */
