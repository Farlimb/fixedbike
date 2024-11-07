/******************************************************************************
 * BIKE -- Bit Flipping Key Encapsulation
 *
 * Copyright (c) 2021 Nir Drucker, Shay Gueron, Rafael Misoczki, Tobias Oder,
 * Tim Gueneysu, Jan Richter-Brockmann.
 * Contact: drucker.nir@gmail.com, shay.gueron@gmail.com,
 * rafaelmisoczki@google.com, tobias.oder@rub.de, tim.gueneysu@rub.de,
 * jan.richter-brockmann@rub.de.
 *
 * Permission to use this code BIKE is granted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * * The names of the contributors may not be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS CORPORATION OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "ring_buffer.h"

ring_buffer_t rb_alloc(size_t size) {
    ring_buffer_t rb = (ring_buffer_t) malloc(sizeof(struct ring_buffer));
    if (rb == NULL)
        return NULL;
    rb->length = 0;
    rb->size = size;
    rb->raw_ptr_index = (index_t *) malloc(size * sizeof(index_t));
    if (rb->raw_ptr_index == NULL)
        return NULL;
    rb->raw_ptr_position = (index_t *) malloc(size * sizeof(index_t));
    if (rb->raw_ptr_position == NULL)
        return NULL;
    rb->raw_ptr_extra = (int *) malloc(size * sizeof(int));
    if (rb->raw_ptr_extra == NULL)
        return NULL;
    rb->start_idx = 0;
    rb->start_ptr_index = rb->raw_ptr_index;
    rb->start_ptr_position = rb->raw_ptr_position;
    rb->start_ptr_extra = rb->raw_ptr_extra;

    return rb;
}

void rb_free(ring_buffer_t rb) {
    free(rb->raw_ptr_index);
    free(rb->raw_ptr_position);
    free(rb->raw_ptr_extra);
    free(rb);
}

void rb_prepend(ring_buffer_t rb, index_t index, index_t position, int extra) {
    size_t pos = (rb->start_idx - 1 + rb->size) % rb->size;
    rb->start_idx = pos;
    rb->start_ptr_index = rb->raw_ptr_index + pos;
    rb->start_ptr_position = rb->raw_ptr_position + pos;
    rb->start_ptr_extra = rb->raw_ptr_extra + pos;
    rb->raw_ptr_index[pos] = index;
    rb->raw_ptr_position[pos] = position;
    rb->raw_ptr_extra[pos] = extra;
    rb->length += 1;
}

void rb_append(ring_buffer_t rb, index_t index, index_t position, int extra) {
    size_t pos = (rb->start_idx + rb->length) % rb->size;
    rb->raw_ptr_index[pos] = index;
    rb->raw_ptr_position[pos] = position;
    rb->raw_ptr_extra[pos] = extra;
    rb->length += 1;
}

void rb_get_first(ring_buffer_t rb, index_t *index, index_t *position,
                  int *extra) {
    *index = rb->start_ptr_index[0];
    *position = rb->start_ptr_position[0];
    if (extra)
        *extra = rb->start_ptr_extra[0];
}

void rb_get(ring_buffer_t rb, size_t i, index_t *index, index_t *position,
            int *extra) {
    size_t pos = (rb->start_idx + (i % rb->length)) % rb->size;
    *index = rb->raw_ptr_index[pos];
    *position = rb->raw_ptr_position[pos];
    if (extra)
        *extra = rb->raw_ptr_extra[pos];
}

void rb_remove_first(ring_buffer_t rb) {
    size_t pos = (rb->start_idx + 1) % rb->size;
    rb->start_idx = pos;
    rb->start_ptr_index = rb->raw_ptr_index + pos;
    rb->start_ptr_position = rb->raw_ptr_position + pos;
    rb->start_ptr_extra = rb->raw_ptr_extra + pos;
    rb->length -= 1;
}

void rb_put(ring_buffer_t rb, size_t i, index_t index, index_t position,
            int extra) {
    if (i == 0) {
        rb_prepend(rb, index, position, extra);
    }
    else if (i == rb->length) {
        rb_append(rb, index, position, extra);
    }
    else {
        rb->length += 1;
        for (size_t k = rb->length - 2; k >= i; --k) {
            size_t pos = (rb->start_idx + (k % rb->length)) % rb->size;
            size_t pos_next =
                (rb->start_idx + ((k + 1) % rb->length)) % rb->size;
            rb->raw_ptr_index[pos_next] = rb->raw_ptr_index[pos];
            rb->raw_ptr_position[pos_next] = rb->raw_ptr_position[pos];
            rb->raw_ptr_extra[pos_next] = rb->raw_ptr_extra[pos];
        }
        size_t pos = (rb->start_idx + i) % rb->size;
        rb->raw_ptr_index[pos] = index;
        rb->raw_ptr_position[pos] = position;
        rb->raw_ptr_extra[pos] = extra;
    }
}

void rb_remove(ring_buffer_t rb, size_t i) {
    if (i == 0)
        rb_remove_first(rb);
    else {
        for (size_t k = i; k < rb->length; ++k) {
            size_t pos = (rb->start_idx + (k % rb->length)) % rb->size;
            size_t pos_next =
                (rb->start_idx + ((k + 1) % rb->length)) % rb->size;
            rb->raw_ptr_index[pos] = rb->raw_ptr_index[pos_next];
            rb->raw_ptr_position[pos] = rb->raw_ptr_position[pos_next];
            rb->raw_ptr_extra[pos] = rb->raw_ptr_extra[pos_next];
        }
        rb->length -= 1;
    }
}
