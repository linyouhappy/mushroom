

#include "mr_pqueue.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

struct mr_pqueue* mr_pqueue_create(void) {
	struct mr_pqueue* queue = (struct mr_pqueue*)malloc(sizeof(struct mr_pqueue));
	queue->size = 0;
	queue->cap = 64;
	queue->buffer = (struct mr_pqueue_node**)malloc(sizeof(struct mr_pqueue_node*)*queue->cap);
	memset(queue->buffer, 0, sizeof(struct mr_pqueue_node*)*queue->cap);
	return queue;
}

void mr_pqueue_free(struct mr_pqueue* queue) {
	assert(queue);
	free(queue);
}

void mr_pqueue_swim(struct mr_pqueue* queue, uint32_t idx, struct mr_pqueue_node* node) {
	uint32_t pidx;
	struct mr_pqueue_node* pnode;
	while(idx > 0){
		pidx = (idx-1) >> 1;
		pnode = queue->buffer[pidx];
		if (node->key < pnode->key){
			assert(queue->buffer[idx] == NULL);
			queue->buffer[pidx] = NULL;

			queue->buffer[idx] = pnode;
			pnode->idx = idx;
			idx = pidx;
		}
		else {
			break;
		}
	}
	assert(queue->buffer[idx] == NULL);
	queue->buffer[idx] = node;
	node->idx = idx;
}

void mr_pqueue_push(struct mr_pqueue* queue, struct mr_pqueue_node* node) {
	if (node->idx != -1){
		fprintf(stderr, "mr_pqueue_push node no init key = %d\n",node->key);
	}
	if (queue->size >= queue->cap){
		queue->cap *= 2;
		struct mr_pqueue_node** nbuffer = (struct mr_pqueue_node**)malloc(sizeof(struct mr_pqueue_node*)*queue->cap);
		memset(nbuffer, 0, sizeof(struct mr_pqueue_node*)*queue->cap);
		memcpy(nbuffer, queue->buffer, queue->size);
		free(queue->buffer);
		queue->buffer = nbuffer;
	}
	uint32_t idx = queue->size++;
	assert(queue->buffer[idx] == NULL);
	if (idx == 0){
		queue->buffer[idx] = node;
		node->idx = idx;
	}else{
		mr_pqueue_swim(queue, idx, node);
	}
}

void mr_pqueue_sink(struct mr_pqueue* queue, uint32_t idx, struct mr_pqueue_node* node) {
	uint32_t half_idx = queue->size >> 1;
	uint32_t cidx, ridx;
	struct mr_pqueue_node* cnode;
	struct mr_pqueue_node* rnode;
    while(idx < half_idx){
        cidx = (idx << 1) + 1;
        cnode = queue->buffer[cidx];
        ridx = cidx + 1;
        if(ridx < queue->size){
        	rnode = queue->buffer[ridx];
        	if (rnode->key < cnode->key){
        		cidx = ridx;
        		cnode = rnode;
        	}
        }
        if(cnode->key < node->key){
        	assert(queue->buffer[idx] == NULL);
            queue->buffer[cidx] = NULL;

        	queue->buffer[idx] = cnode;
        	cnode->idx = idx;
        	idx = cidx;
		}
		else{
			break;
		}
    }
    assert(queue->buffer[idx] == NULL);
    queue->buffer[idx] = node;
    node->idx = idx;
}

struct mr_pqueue_node* mr_pqueue_pop(struct mr_pqueue* queue) {
	if (queue->size == 0){
		return NULL;
	}
    uint32_t idx = --queue->size;
   	struct mr_pqueue_node* rnode = queue->buffer[0];
   	queue->buffer[0] = NULL;
    struct mr_pqueue_node* node = queue->buffer[idx];
    if (idx > 0)
        mr_pqueue_sink(queue, 0, node);

    mr_pqueue_init(rnode);
	return rnode;
}

uint32_t mr_pqueue_remove(struct mr_pqueue* queue, struct mr_pqueue_node* node){
	if (node->idx < 0 || node->idx >= queue->size){
		fprintf(stderr, "mr_pqueue_remove node no in queue key = %d\n", node->key);
		mr_pqueue_init(node);
		return -1;
	}
	uint32_t idx = node->idx;
	if (queue->buffer[idx] != node){
		fprintf(stderr, "mr_pqueue_remove node error key = %d\n", node->key);
		mr_pqueue_init(node);
		return -1;
	}
	uint32_t midx = --queue->size;
	if (midx == idx){
		queue->buffer[midx] = NULL;
	}else{
		 struct mr_pqueue_node* mnode = queue->buffer[midx];
		 queue->buffer[midx] = NULL;
		 queue->buffer[idx] = NULL;
		 mr_pqueue_sink(queue, idx, mnode);
	}
	mr_pqueue_init(node);
	return 0;
}

void mr_pqueue_sort(struct mr_pqueue* queue){
	uint32_t cidx, ridx, idx;
	uint32_t hidx;
	struct mr_pqueue_node* cnode;
	struct mr_pqueue_node* rnode;
	struct mr_pqueue_node* node;
	uint32_t len = queue->size;
	while(len > 1){
		len--;
		node = queue->buffer[len];
		queue->buffer[0]->idx = len;
		queue->buffer[len] = queue->buffer[0];
		queue->buffer[0] = NULL;

		hidx = len >> 1;
		idx = 0;
		while(idx < hidx){
	        cidx = (idx << 1) + 1;
	        cnode = queue->buffer[cidx];
	        ridx = cidx + 1;
	        if(ridx < len){
	        	rnode = queue->buffer[ridx];
	        	if (rnode->key < cnode->key){
	        		cidx = ridx;
	        		cnode = rnode;
	        	}
	        }
	        if(cnode->key < node->key){
	        	assert(queue->buffer[idx] == NULL);
	            queue->buffer[cidx] = NULL;

	        	queue->buffer[idx] = cnode;
	        	cnode->idx = idx;
	        	idx = cidx;
			}
			else{
				break;
			}
	    }
	    assert(queue->buffer[idx] == NULL);
	    queue->buffer[idx] = node;
	    node->idx = idx;
	}
}



void mr_pqueue_test(){
	 struct mr_pqueue* queue = mr_pqueue_create();
    int i = 0;

    struct mr_pqueue_node* node;

	//1, 2, 5, 7, 12, 17, 19, 22, 25, 28, 36, 46, 92, 99
    int array[14] = {99, 5, 36, 17, 46, 12, 2, 19, 25, 28, 92, 22, 7, 1};
    for (; i < 14; ++i)
    {
        node = (struct mr_pqueue_node*)malloc(sizeof(struct mr_pqueue_node));
        mr_pqueue_init(node);
        node->key = array[i];
        mr_pqueue_push(queue, node);
    }

    mr_pqueue_sort(queue);
    mr_pqueue_remove(queue, node);

    node = (struct mr_pqueue_node*)malloc(sizeof(struct mr_pqueue_node));
    mr_pqueue_init(node);
    node->key = 38;
    mr_pqueue_push(queue, node);

    // struct mr_pqueue_node* node;
    while((node = mr_pqueue_pop(queue))){
        printf(" %d", node->key);
    }
	printf("\n");
}