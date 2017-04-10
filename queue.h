/*
MIT License

Copyright (c) 2017 MH Lim

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef MQTT_CLIENT_QUEUE_H
#define MQTT_CLIENT_QUEUE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct queue_s queue_s;

queue_s *queue_create(void);
void queue_destroy(queue_s *q);
void queue_delete_data(void *data);

int queue_push_front(queue_s *q, const void *data, size_t data_length, void (*cleanup)(void *data));
int queue_push_back(queue_s *q, const void *data, size_t data_length, void (*cleanup)(void *data));

size_t queue_pop_front(queue_s *q, void **pdata);
size_t queue_pop_back(queue_s *q, void **pdata);

size_t queue_get_size(queue_s *q);

#ifdef __cplusplus
}
#endif

#endif
