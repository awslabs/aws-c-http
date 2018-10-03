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

#include <aws/http/queue.h>

#include <aws/common/error.h>

int aws_queue_init(struct aws_queue *queue, size_t initial_size, struct aws_allocator *alloc) {
    queue->alloc = alloc;
    queue->memory = (uint8_t*)aws_mem_acquire(alloc, initial_size);
    if (!queue->memory) {
        return AWS_OP_ERR;
    }
    queue->index0 = 0;
    queue->index1 = 0;
    queue->capacity = initial_size;
    queue->bytes_remaining = initial_size;
    return AWS_OP_SUCCESS;
}

int aws_queue_init_static(struct aws_queue *queue, void *memory, size_t size) {
    queue->alloc = NULL;
    queue->memory = (uint8_t*)memory;
    queue->index0 = 0;
    queue->index1 = 0;
    queue->capacity = size;
    queue->bytes_remaining = size;
    return AWS_OP_SUCCESS;
}

void aws_queue_clean_up(struct aws_queue *queue) {
    if (queue->alloc) {
        aws_mem_release(queue->alloc, queue->memory);
    }
    AWS_ZERO_STRUCT(*queue);
}

int aws_queue_push(struct aws_queue *queue, const void *data, size_t size) {
    if (size > queue->bytes_remaining) {
        return aws_raise_error(AWS_ERROR_DEST_COPY_TOO_SMALL);
    }

    size_t i0 = queue->index0;
    size_t i1 = queue->index1;
    size_t capacity = queue->capacity;
    bool can_wrap = i0 <= i1;
    bool would_wrap = i1 + size > capacity;

    if (can_wrap && would_wrap) {
        size_t first_size = capacity - i1;
        size_t second_size = size - first_size;
        memcpy(queue->memory + i1, data, first_size);
        memcpy(queue->memory, (uint8_t *)data + first_size, second_size);
        queue->index1 = second_size;
    } else {
        memcpy(queue->memory + i1, data, size);
        queue->index1 += size;
    }

    queue->bytes_remaining -= size;

    return AWS_OP_SUCCESS;
}

int aws_queue_pull(struct aws_queue *queue, void *data, size_t size) {
    if (size > (queue->capacity - queue->bytes_remaining)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    size_t i0 = queue->index0;
    size_t i1 = queue->index1;

    if (i0 < i1) {
        memcpy(data, queue->memory + i0, size);
        queue->index0 += size;
    } else {
        size_t first_size = queue->capacity - i0;
        size_t second_size = size - first_size;
        memcpy(data, queue->memory + i0, first_size);
        memcpy((uint8_t *)data + first_size, queue->memory, second_size);
        queue->index0 = second_size;
    }

    queue->bytes_remaining += size;

    return AWS_OP_SUCCESS;
}

int aws_queue_resize(struct aws_queue *queue, size_t new_size) {
    size_t current_data_size = queue->capacity - queue->bytes_remaining;
    if (current_data_size > new_size) {
        return aws_raise_error(AWS_ERROR_DEST_COPY_TOO_SMALL);
    }

    uint8_t *new_memory = (uint8_t *)aws_mem_acquire(queue->alloc, new_size);
    if (!new_memory) {
        return AWS_OP_ERR;
    }

    size_t i0 = queue->index0;
    size_t i1 = queue->index1;

    if (i0 < i1) {
        memcpy(new_memory, queue->memory + i0, current_data_size);
    } else {
        size_t first_size = queue->capacity - i0;
        size_t second_size = current_data_size - first_size;
        memcpy(new_memory, queue->memory + i0, first_size);
        memcpy(new_memory + first_size, queue->memory, second_size);
    }

    aws_mem_release(queue->alloc, queue->memory);
    queue->memory = new_memory;
    queue->index0 = 0;
    queue->index1 = current_data_size;
    queue->capacity = new_size;
    queue->bytes_remaining = new_size - current_data_size;

    return AWS_OP_SUCCESS;
}

bool aws_queue_is_empty(struct aws_queue *queue) {
    return queue->bytes_remaining == queue->capacity;
}
