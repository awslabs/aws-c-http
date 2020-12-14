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

#ifdef NEVER

struct aws_http_proxy_strategy_factory *aws_http_proxy_strategy_factory_new_tunneling_chain(
    struct aws_allocator *allocator,
    struct aws_http_proxy_strategy_factory_tunneling_chain_options *config) {}
#endif
