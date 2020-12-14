/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/http/proxy_strategy.h>

#include <aws/common/encoding.h>
#include <aws/common/string.h>

struct aws_http_proxy_strategy *aws_http_proxy_strategy_acquire(struct aws_http_proxy_strategy *proxy_strategy) {
    if (proxy_strategy != NULL) {
        aws_ref_count_acquire(&proxy_strategy->ref_count);
    }

    return proxy_strategy;
}

void aws_http_proxy_strategy_release(struct aws_http_proxy_strategy *proxy_strategy) {
    if (proxy_strategy != NULL) {
        aws_ref_count_release(&proxy_strategy->ref_count);
    }
}

struct aws_http_proxy_strategy *aws_http_proxy_strategy_factory_create_strategy(
    struct aws_http_proxy_strategy_factory *factory,
    struct aws_allocator *allocator) {
    if (factory == NULL || allocator == NULL) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    return factory->vtable->create_strategy(factory, allocator);
}

struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_acquire(
    struct aws_http_proxy_strategy_factory *proxy_strategy_factory) {
    if (proxy_strategy_factory != NULL) {
        aws_ref_count_acquire(&proxy_strategy_factory->ref_count);
    }

    return proxy_strategy_factory;
}

void aws_http_proxy_strategy_factory_release(struct aws_http_proxy_strategy_factory *proxy_strategy_factory) {
    if (proxy_strategy_factory != NULL) {
        aws_ref_count_release(&proxy_strategy_factory->ref_count);
    }
}

/******************************************************************************************************************/

enum proxy_strategy_connect_state {
    AWS_PSCS_READY,
    AWS_PSCS_IN_PROGRESS,
    AWS_PSCS_SUCCESS,
    AWS_PSCS_FAILURE,
};

struct aws_http_proxy_strategy_factory_basic_auth {
    struct aws_allocator *allocator;

    struct aws_string *user_name;
    struct aws_string *password;

    struct aws_http_proxy_strategy_factory factory_base;
};

static void s_destroy_basic_auth_factory(struct aws_http_proxy_strategy_factory *proxy_strategy_factory) {
    struct aws_http_proxy_strategy_factory_basic_auth *basic_auth_factory = proxy_strategy_factory->impl;

    aws_string_destroy(basic_auth_factory->user_name);
    aws_string_destroy(basic_auth_factory->password);

    aws_mem_release(basic_auth_factory->allocator, basic_auth_factory);
}

struct aws_http_proxy_strategy_basic_auth {
    struct aws_allocator *allocator;

    struct aws_http_proxy_strategy_factory *factory;

    enum proxy_strategy_connect_state connect_state;

    struct aws_http_proxy_strategy strategy_base;
};

static void s_destroy_basic_auth_strategy(struct aws_http_proxy_strategy *proxy_strategy) {
    struct aws_http_proxy_strategy_basic_auth *basic_auth_strategy = proxy_strategy->impl;

    aws_http_proxy_strategy_factory_release(basic_auth_strategy->factory);

    aws_mem_release(basic_auth_strategy->allocator, basic_auth_strategy);
}

AWS_STATIC_STRING_FROM_LITERAL(s_proxy_authorization_header_name, "Proxy-Authorization");
AWS_STATIC_STRING_FROM_LITERAL(s_proxy_authorization_header_basic_prefix, "Basic ");

/*
 * Adds a proxy authentication header based on the basic authentication mode, rfc7617
 */
static int s_add_basic_proxy_authentication_header(
    struct aws_allocator *allocator,
    struct aws_http_message *request,
    struct aws_http_proxy_strategy_basic_auth *basic_auth_strategy) {

    struct aws_byte_buf base64_input_value;
    AWS_ZERO_STRUCT(base64_input_value);

    struct aws_byte_buf header_value;
    AWS_ZERO_STRUCT(header_value);

    int result = AWS_OP_ERR;

    struct aws_http_proxy_strategy_factory_basic_auth *factory = basic_auth_strategy->factory->impl;

    if (aws_byte_buf_init(&base64_input_value, allocator, factory->user_name->len + factory->password->len + 1)) {
        goto done;
    }

    /* First build a buffer with "username:password" in it */
    struct aws_byte_cursor username_cursor = aws_byte_cursor_from_string(factory->user_name);
    if (aws_byte_buf_append(&base64_input_value, &username_cursor)) {
        goto done;
    }

    struct aws_byte_cursor colon_cursor = AWS_BYTE_CUR_INIT_FROM_STRING_LITERAL(":");
    if (aws_byte_buf_append(&base64_input_value, &colon_cursor)) {
        goto done;
    }

    struct aws_byte_cursor password_cursor = aws_byte_cursor_from_string(factory->password);
    if (aws_byte_buf_append(&base64_input_value, &password_cursor)) {
        goto done;
    }

    struct aws_byte_cursor base64_source_cursor =
        aws_byte_cursor_from_array(base64_input_value.buffer, base64_input_value.len);

    /* Figure out how much room we need in our final header value buffer */
    size_t required_size = 0;
    if (aws_base64_compute_encoded_len(base64_source_cursor.len, &required_size)) {
        goto done;
    }

    required_size += s_proxy_authorization_header_basic_prefix->len + 1;
    if (aws_byte_buf_init(&header_value, allocator, required_size)) {
        goto done;
    }

    /* Build the final header value by appending the authorization type and the base64 encoding string together */
    struct aws_byte_cursor basic_prefix = aws_byte_cursor_from_string(s_proxy_authorization_header_basic_prefix);
    if (aws_byte_buf_append_dynamic(&header_value, &basic_prefix)) {
        goto done;
    }

    if (aws_base64_encode(&base64_source_cursor, &header_value)) {
        goto done;
    }

    struct aws_http_header header = {
        .name = aws_byte_cursor_from_string(s_proxy_authorization_header_name),
        .value = aws_byte_cursor_from_array(header_value.buffer, header_value.len),
    };

    if (aws_http_message_add_header(request, header)) {
        goto done;
    }

    result = AWS_OP_SUCCESS;

done:

    aws_byte_buf_clean_up(&header_value);
    aws_byte_buf_clean_up(&base64_input_value);

    return result;
}

int s_basic_auth_forward_add_header(struct aws_http_proxy_strategy *proxy_strategy, struct aws_http_message *message) {
    struct aws_http_proxy_strategy_basic_auth *basic_auth_strategy = proxy_strategy->impl;

    return s_add_basic_proxy_authentication_header(basic_auth_strategy->allocator, message, basic_auth_strategy);
}

void s_basic_auth_tunnel_add_header(
    struct aws_http_proxy_strategy *proxy_strategy,
    struct aws_http_message *message,
    aws_http_proxy_strategy_terminate_fn *strategy_termination_callback,
    aws_http_proxy_strategy_http_request_forward_fn *strategy_http_request_forward_callback,
    void *internal_proxy_user_data) {

    struct aws_http_proxy_strategy_basic_auth *basic_auth_strategy = proxy_strategy->impl;
    if (basic_auth_strategy->connect_state != AWS_PSCS_READY) {
        strategy_termination_callback(message, AWS_ERROR_INVALID_STATE, internal_proxy_user_data);
        return;
    }

    basic_auth_strategy->connect_state = AWS_PSCS_IN_PROGRESS;

    if (s_add_basic_proxy_authentication_header(basic_auth_strategy->allocator, message, basic_auth_strategy)) {
        strategy_termination_callback(message, aws_last_error(), internal_proxy_user_data);
        return;
    }

    strategy_http_request_forward_callback(message, internal_proxy_user_data);
}

static int s_basic_auth_on_connect_status(
    struct aws_http_proxy_strategy *proxy_strategy,
    enum aws_http_status_code status_code) {
    struct aws_http_proxy_strategy_basic_auth *basic_auth_strategy = proxy_strategy->impl;

    if (basic_auth_strategy->connect_state == AWS_PSCS_IN_PROGRESS) {
        if (AWS_HTTP_STATUS_CODE_200_OK != status_code) {
            basic_auth_strategy->connect_state = AWS_PSCS_FAILURE;
        } else {
            basic_auth_strategy->connect_state = AWS_PSCS_SUCCESS;
        }
    }

    return AWS_OP_SUCCESS;
}

static struct aws_http_proxy_strategy_forwarding_vtable s_basic_auth_proxy_forwarding_vtable = {
    .forward_request_transform = s_basic_auth_forward_add_header,
};

static struct aws_http_proxy_strategy_tunnelling_vtable s_basic_auth_proxy_tunneling_vtable = {
    .on_status_callback = s_basic_auth_on_connect_status,
    .connect_request_transform = s_basic_auth_tunnel_add_header,
};

static struct aws_http_proxy_strategy *s_create_basic_auth_strategy(
    struct aws_http_proxy_strategy_factory *proxy_strategy_factory,
    struct aws_allocator *allocator) {
    if (proxy_strategy_factory == NULL || allocator == NULL) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_http_proxy_strategy_basic_auth *basic_auth_strategy =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_strategy_basic_auth));
    if (basic_auth_strategy == NULL) {
        return NULL;
    }

    basic_auth_strategy->allocator = allocator;
    basic_auth_strategy->connect_state = AWS_PSCS_READY;
    basic_auth_strategy->strategy_base.impl = basic_auth_strategy;
    aws_ref_count_init(
        &basic_auth_strategy->strategy_base.ref_count,
        &basic_auth_strategy->strategy_base,
        (aws_simple_completion_callback *)s_destroy_basic_auth_strategy);

    if (proxy_strategy_factory->proxy_connection_type == AWS_HPCT_HTTP_FORWARD) {
        basic_auth_strategy->strategy_base.strategy_vtable.forwarding_vtable = &s_basic_auth_proxy_forwarding_vtable;
    } else {
        basic_auth_strategy->strategy_base.strategy_vtable.tunnelling_vtable = &s_basic_auth_proxy_tunneling_vtable;
    }

    basic_auth_strategy->factory = aws_ref_count_acquire(&proxy_strategy_factory->ref_count);

    return &basic_auth_strategy->strategy_base;
}

static struct aws_http_proxy_strategy_factory_vtable s_basic_auth_factory_vtable = {
    .create_strategy = s_create_basic_auth_strategy,
};

struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_new_basic_auth(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_factory_basic_auth_config *config) {
    if (config == NULL || allocator == NULL) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    if (config->proxy_connection_type != AWS_HPCT_HTTP_FORWARD &&
        config->proxy_connection_type != AWS_HPCT_HTTP_TUNNEL) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_http_proxy_strategy_factory_basic_auth *basic_auth_factory =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_strategy_factory_basic_auth));
    if (basic_auth_factory == NULL) {
        return NULL;
    }

    basic_auth_factory->factory_base.impl = basic_auth_factory;
    basic_auth_factory->factory_base.vtable = &s_basic_auth_factory_vtable;
    basic_auth_factory->allocator = allocator;
    basic_auth_factory->factory_base.proxy_connection_type = config->proxy_connection_type;
    aws_ref_count_init(
        &basic_auth_factory->factory_base.ref_count,
        &basic_auth_factory->factory_base,
        (aws_simple_completion_callback *)s_destroy_basic_auth_factory);

    basic_auth_factory->user_name = aws_string_new_from_cursor(allocator, &config->user_name);
    if (basic_auth_factory->user_name == NULL) {
        goto on_error;
    }

    basic_auth_factory->password = aws_string_new_from_cursor(allocator, &config->password);
    if (basic_auth_factory->password == NULL) {
        goto on_error;
    }

    return &basic_auth_factory->factory_base;

on_error:

    aws_http_proxy_strategy_factory_release(&basic_auth_factory->factory_base);

    return NULL;
}

/******************************************************************************************************************/

struct aws_http_proxy_strategy_factory_one_time_identity {
    struct aws_allocator *allocator;

    struct aws_http_proxy_strategy_factory factory_base;
};

struct aws_http_proxy_strategy_one_time_identity {
    struct aws_allocator *allocator;

    enum proxy_strategy_connect_state connect_state;

    struct aws_http_proxy_strategy strategy_base;
};

static void s_destroy_one_time_identity_strategy(struct aws_http_proxy_strategy *proxy_strategy) {
    struct aws_http_proxy_strategy_one_time_identity *identity_strategy = proxy_strategy->impl;

    aws_mem_release(identity_strategy->allocator, identity_strategy);
}

void s_one_time_identity_connect_transform(
    struct aws_http_proxy_strategy *proxy_strategy,
    struct aws_http_message *message,
    aws_http_proxy_strategy_terminate_fn *strategy_termination_callback,
    aws_http_proxy_strategy_http_request_forward_fn *strategy_http_request_forward_callback,
    void *internal_proxy_user_data) {

    struct aws_http_proxy_strategy_one_time_identity *one_time_identity_strategy = proxy_strategy->impl;
    if (one_time_identity_strategy->connect_state != AWS_PSCS_READY) {
        strategy_termination_callback(message, AWS_ERROR_INVALID_STATE, internal_proxy_user_data);
        return;
    }

    one_time_identity_strategy->connect_state = AWS_PSCS_IN_PROGRESS;
    strategy_http_request_forward_callback(message, internal_proxy_user_data);
}

static int s_one_time_identity_on_connect_status(
    struct aws_http_proxy_strategy *proxy_strategy,
    enum aws_http_status_code status_code) {
    struct aws_http_proxy_strategy_one_time_identity *one_time_identity_strategy = proxy_strategy->impl;

    if (one_time_identity_strategy->connect_state == AWS_PSCS_IN_PROGRESS) {
        if (AWS_HTTP_STATUS_CODE_200_OK != status_code) {
            one_time_identity_strategy->connect_state = AWS_PSCS_FAILURE;
        } else {
            one_time_identity_strategy->connect_state = AWS_PSCS_SUCCESS;
        }
    }

    return AWS_OP_SUCCESS;
}

static struct aws_http_proxy_strategy_tunnelling_vtable s_one_time_identity_proxy_tunneling_vtable = {
    .on_status_callback = s_one_time_identity_on_connect_status,
    .connect_request_transform = s_one_time_identity_connect_transform,
};

static struct aws_http_proxy_strategy *s_create_one_time_identity_strategy(
    struct aws_http_proxy_strategy_factory *proxy_strategy_factory,
    struct aws_allocator *allocator) {
    if (proxy_strategy_factory == NULL || allocator == NULL) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_http_proxy_strategy_one_time_identity *identity_strategy =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_strategy_one_time_identity));
    if (identity_strategy == NULL) {
        return NULL;
    }

    identity_strategy->allocator = allocator;
    identity_strategy->connect_state = AWS_PSCS_READY;
    identity_strategy->strategy_base.impl = identity_strategy;
    aws_ref_count_init(
        &identity_strategy->strategy_base.ref_count,
        &identity_strategy->strategy_base,
        (aws_simple_completion_callback *)s_destroy_one_time_identity_strategy);

    identity_strategy->strategy_base.strategy_vtable.tunnelling_vtable = &s_one_time_identity_proxy_tunneling_vtable;

    return &identity_strategy->strategy_base;
}

static struct aws_http_proxy_strategy_factory_vtable s_one_time_identity_factory_vtable = {
    .create_strategy = s_create_one_time_identity_strategy,
};

static void s_destroy_one_time_identity_factory(struct aws_http_proxy_strategy_factory *proxy_strategy_factory) {
    struct aws_http_proxy_strategy_factory_one_time_identity *identity_factory = proxy_strategy_factory->impl;

    aws_mem_release(identity_factory->allocator, identity_factory);
}

struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_new_tunneling_one_time_identity(
    struct aws_allocator *allocator) {
    if (allocator == NULL) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_http_proxy_strategy_factory_one_time_identity *identity_factory =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_strategy_factory_one_time_identity));
    if (identity_factory == NULL) {
        return NULL;
    }

    identity_factory->factory_base.impl = identity_factory;
    identity_factory->factory_base.vtable = &s_one_time_identity_factory_vtable;
    identity_factory->factory_base.proxy_connection_type = AWS_HPCT_HTTP_TUNNEL;
    identity_factory->allocator = allocator;

    aws_ref_count_init(
        &identity_factory->factory_base.ref_count,
        &identity_factory->factory_base,
        (aws_simple_completion_callback *)s_destroy_one_time_identity_factory);

    return &identity_factory->factory_base;
}

/******************************************************************************************************************/

struct aws_http_proxy_strategy_factory_forwarding_identity {
    struct aws_allocator *allocator;

    struct aws_http_proxy_strategy_factory factory_base;
};

struct aws_http_proxy_strategy_forwarding_identity {
    struct aws_allocator *allocator;

    enum proxy_strategy_connect_state connect_state;

    struct aws_http_proxy_strategy strategy_base;
};

static void s_destroy_forwarding_identity_strategy(struct aws_http_proxy_strategy *proxy_strategy) {
    struct aws_http_proxy_strategy_forwarding_identity *identity_strategy = proxy_strategy->impl;

    aws_mem_release(identity_strategy->allocator, identity_strategy);
}

int s_forwarding_identity_connect_transform(
    struct aws_http_proxy_strategy *proxy_strategy,
    struct aws_http_message *message) {

    (void)message;
    (void)proxy_strategy;

    return AWS_OP_SUCCESS;
}

static struct aws_http_proxy_strategy_forwarding_vtable s_forwarding_identity_proxy_tunneling_vtable = {
    .forward_request_transform = s_forwarding_identity_connect_transform,
};

static struct aws_http_proxy_strategy *s_create_forwarding_identity_strategy(
    struct aws_http_proxy_strategy_factory *proxy_strategy_factory,
    struct aws_allocator *allocator) {
    if (proxy_strategy_factory == NULL || allocator == NULL) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_http_proxy_strategy_forwarding_identity *identity_strategy =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_strategy_forwarding_identity));
    if (identity_strategy == NULL) {
        return NULL;
    }

    identity_strategy->allocator = allocator;
    identity_strategy->connect_state = AWS_PSCS_READY;
    identity_strategy->strategy_base.impl = identity_strategy;
    aws_ref_count_init(
        &identity_strategy->strategy_base.ref_count,
        &identity_strategy->strategy_base,
        (aws_simple_completion_callback *)s_destroy_forwarding_identity_strategy);

    identity_strategy->strategy_base.strategy_vtable.forwarding_vtable = &s_forwarding_identity_proxy_tunneling_vtable;

    return &identity_strategy->strategy_base;
}

static struct aws_http_proxy_strategy_factory_vtable s_forwarding_identity_factory_vtable = {
    .create_strategy = s_create_forwarding_identity_strategy,
};

static void s_destroy_forwarding_identity_factory(struct aws_http_proxy_strategy_factory *proxy_strategy_factory) {
    struct aws_http_proxy_strategy_factory_forwarding_identity *identity_factory = proxy_strategy_factory->impl;

    aws_mem_release(identity_factory->allocator, identity_factory);
}

struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_new_forwarding_identity(
    struct aws_allocator *allocator) {
    if (allocator == NULL) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_http_proxy_strategy_factory_forwarding_identity *identity_factory =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_strategy_factory_forwarding_identity));
    if (identity_factory == NULL) {
        return NULL;
    }

    identity_factory->factory_base.impl = identity_factory;
    identity_factory->factory_base.vtable = &s_forwarding_identity_factory_vtable;
    identity_factory->factory_base.proxy_connection_type = AWS_HPCT_HTTP_FORWARD;
    identity_factory->allocator = allocator;

    aws_ref_count_init(
        &identity_factory->factory_base.ref_count,
        &identity_factory->factory_base,
        (aws_simple_completion_callback *)s_destroy_forwarding_identity_factory);

    return &identity_factory->factory_base;
}

/******************************************************************************************************************/

struct aws_http_proxy_strategy_factory_tunneling_chain {
    struct aws_allocator *allocator;

    struct aws_http_proxy_strategy_factory factory_base;

    struct aws_array_list strategy_factories;
};

struct aws_http_proxy_strategy_tunneling_chain {
    struct aws_allocator *allocator;

    struct aws_array_list strategies;
    size_t current_strategy_transform_index;
    void *original_internal_proxy_user_data;
    aws_http_proxy_strategy_terminate_fn *original_strategy_termination_callback;
    aws_http_proxy_strategy_http_request_forward_fn *original_strategy_http_request_forward_callback;

    struct aws_http_proxy_strategy strategy_base;
};

static void s_chain_tunnel_try_next_strategy(
    struct aws_http_proxy_strategy *proxy_strategy,
    struct aws_http_message *message);

static void s_chain_tunnel_iteration_termination_callback(
    struct aws_http_message *message,
    int error_code,
    void *user_data) {

    (void)error_code; /* TODO: log */

    struct aws_http_proxy_strategy *proxy_strategy = user_data;
    struct aws_http_proxy_strategy_tunneling_chain *chain_strategy = proxy_strategy->impl;

    chain_strategy->current_strategy_transform_index++;

    s_chain_tunnel_try_next_strategy(proxy_strategy, message);
}

static void s_chain_tunnel_iteration_forward_callback(struct aws_http_message *message, void *user_data) {
    struct aws_http_proxy_strategy *proxy_strategy = user_data;
    struct aws_http_proxy_strategy_tunneling_chain *chain_strategy = proxy_strategy->impl;

    chain_strategy->original_strategy_http_request_forward_callback(
        message, chain_strategy->original_internal_proxy_user_data);
}

static void s_chain_tunnel_try_next_strategy(
    struct aws_http_proxy_strategy *proxy_strategy,
    struct aws_http_message *message) {
    struct aws_http_proxy_strategy_tunneling_chain *chain_strategy = proxy_strategy->impl;

    size_t strategy_count = aws_array_list_length(&chain_strategy->strategies);
    if (chain_strategy->current_strategy_transform_index >= strategy_count) {
        goto on_error;
    }

    struct aws_http_proxy_strategy *current_strategy = NULL;
    if (aws_array_list_get_at(
            &chain_strategy->strategies, &current_strategy, chain_strategy->current_strategy_transform_index)) {
        goto on_error;
    }

    current_strategy->strategy_vtable.tunnelling_vtable->connect_request_transform(
        current_strategy,
        message,
        s_chain_tunnel_iteration_termination_callback,
        s_chain_tunnel_iteration_forward_callback,
        chain_strategy);
    return;

on_error:

    chain_strategy->original_strategy_termination_callback(
        message, AWS_ERROR_HTTP_PROXY_STRATEGY_TRANSFORM_FAILED, chain_strategy->original_internal_proxy_user_data);
}

static void s_chain_tunnel_transform_connect(
    struct aws_http_proxy_strategy *proxy_strategy,
    struct aws_http_message *message,
    aws_http_proxy_strategy_terminate_fn *strategy_termination_callback,
    aws_http_proxy_strategy_http_request_forward_fn *strategy_http_request_forward_callback,
    void *internal_proxy_user_data) {

    struct aws_http_proxy_strategy_tunneling_chain *chain_strategy = proxy_strategy->impl;

    chain_strategy->current_strategy_transform_index = 0;
    chain_strategy->original_internal_proxy_user_data = internal_proxy_user_data;
    chain_strategy->original_strategy_termination_callback = strategy_termination_callback;
    chain_strategy->original_strategy_http_request_forward_callback = strategy_http_request_forward_callback;

    s_chain_tunnel_try_next_strategy(proxy_strategy, message);
}

static int s_chain_on_incoming_headers(
    struct aws_http_proxy_strategy *proxy_strategy,
    enum aws_http_header_block header_block,
    const struct aws_http_header *header_array,
    size_t num_headers) {

    struct aws_http_proxy_strategy_tunneling_chain *chain_strategy = proxy_strategy->impl;
    size_t strategy_count = aws_array_list_length(&chain_strategy->strategies);
    for (size_t i = 0; i < strategy_count; ++i) {
        struct aws_http_proxy_strategy *strategy = NULL;
        if (aws_array_list_get_at(&chain_strategy->strategies, &strategy, i)) {
            continue;
        }

        aws_http_proxy_strategy_connect_on_incoming_headers_fn *on_incoming_headers =
            strategy->strategy_vtable.tunnelling_vtable->on_incoming_headers_callback;
        if (on_incoming_headers != NULL) {
            (*on_incoming_headers)(strategy, header_block, header_array, num_headers);
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_chain_on_connect_status(
    struct aws_http_proxy_strategy *proxy_strategy,
    enum aws_http_status_code status_code) {

    struct aws_http_proxy_strategy_tunneling_chain *chain_strategy = proxy_strategy->impl;
    size_t strategy_count = aws_array_list_length(&chain_strategy->strategies);
    for (size_t i = 0; i < strategy_count; ++i) {
        struct aws_http_proxy_strategy *strategy = NULL;
        if (aws_array_list_get_at(&chain_strategy->strategies, &strategy, i)) {
            continue;
        }

        aws_http_proxy_strategy_connect_status_fn *on_status =
            strategy->strategy_vtable.tunnelling_vtable->on_status_callback;
        if (on_status != NULL) {
            (*on_status)(strategy, status_code);
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_chain_on_incoming_body(
    struct aws_http_proxy_strategy *proxy_strategy,
    const struct aws_byte_cursor *data) {

    struct aws_http_proxy_strategy_tunneling_chain *chain_strategy = proxy_strategy->impl;
    size_t strategy_count = aws_array_list_length(&chain_strategy->strategies);
    for (size_t i = 0; i < strategy_count; ++i) {
        struct aws_http_proxy_strategy *strategy = NULL;
        if (aws_array_list_get_at(&chain_strategy->strategies, &strategy, i)) {
            continue;
        }

        aws_http_proxy_strategy_connect_on_incoming_body_fn *on_incoming_body =
            strategy->strategy_vtable.tunnelling_vtable->on_incoming_body_callback;
        if (on_incoming_body != NULL) {
            (*on_incoming_body)(strategy, data);
        }
    }

    return AWS_OP_SUCCESS;
}

static struct aws_http_proxy_strategy_tunnelling_vtable s_tunneling_chain_proxy_tunneling_vtable = {
    .on_incoming_body_callback = s_chain_on_incoming_body,
    .on_incoming_headers_callback = s_chain_on_incoming_headers,
    .on_status_callback = s_chain_on_connect_status,
    .connect_request_transform = s_chain_tunnel_transform_connect,
};

static void s_destroy_tunneling_chain_strategy(struct aws_http_proxy_strategy *proxy_strategy) {
    struct aws_http_proxy_strategy_tunneling_chain *chain_strategy = proxy_strategy->impl;

    size_t strategy_count = aws_array_list_length(&chain_strategy->strategies);
    for (size_t i = 0; i < strategy_count; ++i) {
        struct aws_http_proxy_strategy *strategy = NULL;
        if (aws_array_list_get_at(&chain_strategy->strategies, &strategy, i)) {
            continue;
        }

        aws_http_proxy_strategy_release(strategy);
    }

    aws_array_list_clean_up(&chain_strategy->strategies);

    aws_mem_release(chain_strategy->allocator, chain_strategy);
}

static struct aws_http_proxy_strategy *s_create_tunneling_chain_strategy(
    struct aws_http_proxy_strategy_factory *proxy_strategy_factory,
    struct aws_allocator *allocator) {
    if (proxy_strategy_factory == NULL || allocator == NULL) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_http_proxy_strategy_tunneling_chain *chain_strategy =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_strategy_tunneling_chain));
    if (chain_strategy == NULL) {
        return NULL;
    }

    chain_strategy->allocator = allocator;
    chain_strategy->strategy_base.impl = chain_strategy;
    aws_ref_count_init(
        &chain_strategy->strategy_base.ref_count,
        &chain_strategy->strategy_base,
        (aws_simple_completion_callback *)s_destroy_tunneling_chain_strategy);

    chain_strategy->strategy_base.strategy_vtable.tunnelling_vtable = &s_tunneling_chain_proxy_tunneling_vtable;

    struct aws_http_proxy_strategy_factory_tunneling_chain *chain_factory = proxy_strategy_factory->impl;
    size_t strategy_count = aws_array_list_length(&chain_factory->strategy_factories);

    if (aws_array_list_init_dynamic(
            &chain_strategy->strategies, allocator, strategy_count, sizeof(struct aws_http_proxy_strategy *))) {
        goto on_error;
    }

    for (size_t i = 0; i < strategy_count; ++i) {
        struct aws_http_proxy_strategy_factory *factory = NULL;
        if (aws_array_list_get_at(&chain_factory->strategy_factories, &factory, i)) {
            goto on_error;
        }

        struct aws_http_proxy_strategy *strategy = aws_http_proxy_strategy_factory_create_strategy(factory, allocator);
        if (strategy == NULL) {
            goto on_error;
        }

        if (aws_array_list_push_back(&chain_strategy->strategies, &strategy)) {
            aws_http_proxy_strategy_release(strategy);
            goto on_error;
        }
    }

    return &chain_strategy->strategy_base;

on_error:

    aws_http_proxy_strategy_release(&chain_strategy->strategy_base);

    return NULL;
}

static struct aws_http_proxy_strategy_factory_vtable s_tunneling_chain_factory_vtable = {
    .create_strategy = s_create_tunneling_chain_strategy,
};

static void s_destroy_tunneling_chain_factory(struct aws_http_proxy_strategy_factory *proxy_strategy_factory) {
    struct aws_http_proxy_strategy_factory_tunneling_chain *chain_factory = proxy_strategy_factory->impl;

    size_t factory_count = aws_array_list_length(&chain_factory->strategy_factories);
    for (size_t i = 0; i < factory_count; ++i) {
        struct aws_http_proxy_strategy_factory *factory = NULL;
        if (aws_array_list_get_at(&chain_factory->strategy_factories, &factory, i)) {
            continue;
        }

        aws_http_proxy_strategy_factory_release(factory);
    }

    aws_array_list_clean_up(&chain_factory->strategy_factories);

    aws_mem_release(chain_factory->allocator, chain_factory);
}

struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_new_tunneling_chain(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_factory_tunneling_chain_options *config) {

    if (allocator == NULL || config == NULL) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_http_proxy_strategy_factory_tunneling_chain *chain_factory =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_http_proxy_strategy_factory_tunneling_chain));
    if (chain_factory == NULL) {
        return NULL;
    }

    chain_factory->factory_base.impl = chain_factory;
    chain_factory->factory_base.vtable = &s_tunneling_chain_factory_vtable;
    chain_factory->factory_base.proxy_connection_type = AWS_HPCT_HTTP_TUNNEL;
    chain_factory->allocator = allocator;

    aws_ref_count_init(
        &chain_factory->factory_base.ref_count,
        &chain_factory->factory_base,
        (aws_simple_completion_callback *)s_destroy_tunneling_chain_factory);

    if (aws_array_list_init_dynamic(
            &chain_factory->strategy_factories,
            allocator,
            config->factory_count,
            sizeof(struct aws_http_proxy_strategy_factory *))) {
        goto on_error;
    }

    for (size_t i = 0; i < config->factory_count; ++i) {
        struct aws_http_proxy_strategy_factory *factory = config->factories[i];

        if (aws_array_list_push_back(&chain_factory->strategy_factories, &factory)) {
            goto on_error;
        }

        aws_http_proxy_strategy_factory_acquire(factory);
    }

    return &chain_factory->factory_base;

on_error:

    aws_http_proxy_strategy_factory_release(&chain_factory->factory_base);

    return NULL;
}

/******************************************************************************************************************/

AWS_HTTP_API
struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_new_tunneling_adaptive_test(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_factory_tunneling_adaptive_test_options *config) {

    if (allocator == NULL || config == NULL) {
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_http_proxy_strategy_factory *bad_basic_factory = NULL;
    struct aws_http_proxy_strategy_factory *good_basic_factory = NULL;
    struct aws_http_proxy_strategy_factory *adaptive_factory = NULL;

    struct aws_http_proxy_strategy_factory_basic_auth_config bad_config = {
        .proxy_connection_type = AWS_HPCT_HTTP_TUNNEL,
        .password = aws_byte_cursor_from_c_str("NotAUsername"),
        .user_name = aws_byte_cursor_from_c_str("NotAPassword"),
    };

    bad_basic_factory = aws_http_proxy_strategy_factory_new_basic_auth(allocator, &bad_config);
    if (bad_basic_factory == NULL) {
        goto on_error;
    }

    struct aws_http_proxy_strategy_factory_basic_auth_config good_config = {
        .proxy_connection_type = AWS_HPCT_HTTP_TUNNEL,
        .password = config->password,
        .user_name = config->user_name,
    };

    good_basic_factory = aws_http_proxy_strategy_factory_new_basic_auth(allocator, &good_config);
    if (good_basic_factory == NULL) {
        goto on_error;
    }

    struct aws_http_proxy_strategy_factory *factories[2] = {
        bad_basic_factory,
        good_basic_factory,
    };

    struct aws_http_proxy_strategy_factory_tunneling_chain_options chain_config = {
        .factories = factories,
        .factory_count = 2,
    };

    adaptive_factory = aws_http_proxy_strategy_factory_new_tunneling_chain(allocator, &chain_config);
    if (adaptive_factory == NULL) {
        goto on_error;
    }

    return adaptive_factory;

on_error:

    aws_http_proxy_strategy_factory_release(bad_basic_factory);
    aws_http_proxy_strategy_factory_release(good_basic_factory);
    aws_http_proxy_strategy_factory_release(adaptive_factory);

    return NULL;
}
