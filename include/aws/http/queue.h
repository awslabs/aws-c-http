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

#ifndef AWS_RING_BUFFER
#define AWS_RING_BUFFER

#include <aws/http/exports.h>
#include <aws/common/common.h>

struct aws_allocator;

/**
 * Basic FIFO queue ADT implemented via ring buffer.
 */
struct aws_queue {
    struct aws_allocator *alloc;
    uint8_t *memory;
    size_t index0;
    size_t index1;
    size_t capacity;
    size_t bytes_remaining;
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initializes a queue with a new memory block of `initial_size`.
 */
AWS_HTTP_API int aws_queue_init(struct aws_queue *queue, size_t initial_size, struct aws_allocator *alloc);

/**
 * Initializes a queue from an array `memory` of size `initial_size`. Does not own `memory` and performs
 * no memory allocations/deallocations.
 */
AWS_HTTP_API int aws_queue_init_static(struct aws_queue *queue, void *memory, size_t size);

/**
 * Cleans up any memory owned by the queue, and clears the queue to zero.
 */
AWS_HTTP_API void aws_queue_clean_up(struct aws_queue *queue);

/**
 * Queue up and store `size` bytes at the `data` pointer.
 */
AWS_HTTP_API int aws_queue_push(struct aws_queue *queue, const void *data, size_t size);

/**
 * Copy `size` bytes out of the queue and into the `data` pointer.
 */
AWS_HTTP_API int aws_queue_pull(struct aws_queue *queue, void *data, size_t size);

/**
 * Resizes the internal dynamically allocated buffer to `new_size`, retaining any previously stored data. Does
 * nothing if the queue was statically initialized with `aws_queue_init_static` and will return `AWS_OP_ERR`.
 * Will raise the error `AWS_ERROR_DEST_COPY_TOO_SMALL` if the new size is not large enough to store data
 * currently stored within the queue.
 */
AWS_HTTP_API int aws_queue_resize(struct aws_queue *queue, size_t new_size);

/**
 * Returns trues if the queue has no data within it.
 */
AWS_HTTP_API bool aws_queue_is_empty(struct aws_queue *queue);

#ifdef __cplusplus
}
#endif

#endif /* AWS_RING_BUFFER */
