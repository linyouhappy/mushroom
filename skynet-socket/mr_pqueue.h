#ifndef mr_pqueue_h
#define mr_pqueue_h

#include <stdint.h>

// #define HPQKEY int

struct mr_pqueue_node{
	uint32_t key;
	uint32_t idx;
};

struct mr_pqueue {
    uint32_t size;
    uint32_t cap;
    struct mr_pqueue_node** buffer;
};


#define mr_pqueue_init(node) (node)->idx = -1
#define mr_pqueue_peek(queue) (queue)->buffer[0]
#define mr_pqueue_size(queue) (queue)->size

// static inline void mr_pqueue_init(struct mr_pqueue_node* node) {
// 	node->idx = -1;
// }

// static inline struct mr_pqueue_node* mr_pqueue_peek(struct mr_pqueue* queue) {
// 	return queue->buffer[0];
// }

// static inline void mr_pqueue_size(struct mr_pqueue* queue) {
// 	return queue->size;
// }

struct mr_pqueue* mr_pqueue_create(void);
void mr_pqueue_free(struct mr_pqueue* queue);
// void mr_pqueue_swim(struct mr_pqueue* queue, int idx, struct mr_pqueue_node* node);
void mr_pqueue_push(struct mr_pqueue* queue, struct mr_pqueue_node* node);
// void mr_pqueue_sink(struct mr_pqueue* queue, int idx, struct mr_pqueue_node* node);
struct mr_pqueue_node* mr_pqueue_pop(struct mr_pqueue* queue);
int mr_pqueue_remove(struct mr_pqueue* queue, struct mr_pqueue_node* node);
// void mr_pqueue_sort(struct mr_pqueue* queue);

#endif

