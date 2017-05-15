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

#include "queue.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*cleanup_fptr)(void *);

#ifdef __cplusplus
}
#endif

typedef struct node_s
{
	struct node_s *prev;
	struct node_s *next;
	void *data;
	size_t len;
	cleanup_fptr cleanup;	
} node_s;

struct queue_s
{
	node_s *first;
	node_s *last;
	size_t count;
	pthread_mutex_t mutex;
};

static void *queue_malloc(size_t size)
{
	return malloc(size);
}

static void queue_free(void *mem)
{
	free(mem);
}

queue_s *queue_create(void)
{
	queue_s *q = (queue_s*) queue_malloc(sizeof(queue_s));
	if (q) {
		q->first = q->last = NULL;
		q->count = 0;
		if (0 != pthread_mutex_init(&q->mutex, NULL)) {
			queue_free(q);
			q = NULL;
		}
	}
	return q;
}

void queue_clear(queue_s *q)
{
	node_s *node, *this_node;
	pthread_mutex_lock(&q->mutex);
	node = q->first;
	while (node) {
		void *data = node->data;
		if (node->cleanup)
			node->cleanup(data);
		queue_delete_data(data);
		this_node = node;
		node = node->next;
		queue_free(this_node);
	}
	q->first = q->last = NULL;
	q->count = 0;
	pthread_mutex_unlock(&q->mutex);
}

void queue_destroy(queue_s *q)
{
	queue_clear(q);
	pthread_mutex_destroy(&q->mutex);
	free(q);
}

void queue_delete_data(void *data)
{
	queue_free(data);
}

static node_s *queue_create_node(const void *data, size_t data_length)
{
	node_s *node;
	void *p = queue_malloc(data_length);
	if (!p)
		return NULL;
	memcpy(p, data, data_length);

	node = (node_s*) queue_malloc(sizeof(node_s));
	if (!node) {
		free(p);
		return NULL;
	}

	node->prev = NULL;
	node->next = NULL;
	node->data = (void*) p;
	node->len = data_length;
	node->cleanup = NULL;
	return node;
}

int queue_push_front(queue_s *q, const void *data, size_t data_length, void (*cleanup)(void *data))
{
	node_s *node = queue_create_node(data, data_length);
	if (!node)
		return -1;

	node->cleanup = cleanup;
	pthread_mutex_lock(&q->mutex);
	if (NULL == q->first) {
		q->first = q->last = node;
	} else {
		node->next = q->first;
		q->first->prev = node;
		q->first = node;
	}
	q->count++;
	pthread_mutex_unlock(&q->mutex);
	return 0;
}

int queue_push_back(queue_s *q, const void *data, size_t data_length, void (*cleanup)(void *data))
{
	node_s *node = queue_create_node(data, data_length);
	if (!node)
		return -1;

	node->cleanup = cleanup;
	pthread_mutex_lock(&q->mutex);
	if (NULL == q->last) {
		q->first = q->last = node;
	} else {
		q->last->next = node;
		node->prev = q->last;
		q->last = node;
	}
	q->count++;
	pthread_mutex_unlock(&q->mutex);
	return 0;
}

size_t queue_pop_front(queue_s *q, void **pdata)
{
	node_s *node;
	size_t len;
	if (!pdata)
		return 0;

	pthread_mutex_lock(&q->mutex);
	if (q->first) {
		node = q->first;
		if (node->next)
			node->next->prev = NULL;
		q->first = node->next;
		*pdata = node->data;
		len = node->len;
	} else {
		node = NULL;
		*pdata = NULL;
		len = 0;
	}

	if (node) {
		queue_free(node);
		q->count--;
		if (0 == q->count)
			q->last = NULL;
	}
	pthread_mutex_unlock(&q->mutex);
	return len;
}

size_t queue_pop_back(queue_s *q, void **pdata)
{
	node_s *node;
	size_t len;
	if (!pdata)
		return 0;

	pthread_mutex_lock(&q->mutex);
	if (q->last) {
		node = q->last;
		if (node->prev)
			node->prev->next = NULL;
		q->last = node->prev;
		*pdata = node->data;
		len = node->len;
	} else {
		node = NULL;
		*pdata = NULL;
		len = 0;
	}

	if (node) {
		queue_free(node);
		q->count--;
		if (0 == q->count)
			q->first = NULL;
	}
	pthread_mutex_unlock(&q->mutex);
	return len;
}

size_t queue_get_size(queue_s *q)
{
	size_t size;
	pthread_mutex_lock(&q->mutex);
	size = q->count;
	pthread_mutex_unlock(&q->mutex);
	return size;
}
