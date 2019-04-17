
#include "mr_buffer.h"
#include <assert.h>
#include <string.h>

#define MALLOC malloc
#define FREE free

#define MIN_PACK 256


struct mr_buffer_node {
	char* msg;
	size_t sz;
	struct mr_buffer_node *next;
};

struct mr_buffer* mr_buffer_create(int head_len){
	struct mr_buffer* buffer = (struct mr_buffer*)MALLOC(sizeof(struct mr_buffer));
	memset(buffer, 0, sizeof(struct mr_buffer));

    buffer->pack_cap = MIN_PACK;
	buffer->pack_data = MALLOC(buffer->pack_cap);

	if (head_len > 4 || head_len < 1)
		buffer->head_len = 2;
	else
		buffer->head_len = head_len;

	return buffer;
}

void mr_buffer_free(struct mr_buffer* buffer){
	struct mr_buffer_node* bnode;
	while(buffer->head != NULL){
		bnode = buffer->head;
		buffer->head = bnode->next;

		FREE(bnode->msg);
		FREE(bnode);
	}
	FREE(buffer);
}

int mr_buffer_push(struct mr_buffer* buffer, char* msg, size_t len){
	if (msg == NULL || len <= 0){
		return -1;
	}
	struct mr_buffer_node* bnode = (struct mr_buffer_node*)MALLOC(sizeof(struct mr_buffer_node));
	bnode->msg = (char*)MALLOC(len);
	memcpy(bnode->msg, msg, len);
	bnode->sz = len;
	bnode->next = NULL;

	if (buffer->head == NULL) {
		assert(buffer->tail == NULL);
		buffer->head = buffer->tail = bnode;
	} else {
		buffer->tail->next = bnode;
		buffer->tail = bnode;
	}
	buffer->size += len;
	return (int)buffer->size;
}

static inline void mr_buffer_pop_buffer_node(struct mr_buffer* buffer){
	struct mr_buffer_node* bnode = buffer->head;
	buffer->size -= bnode->sz-buffer->offset;
	buffer->offset = 0;
	buffer->head = bnode->next;
	if (buffer->head == NULL) {
		buffer->tail = NULL;
	}
	FREE(bnode->msg);
	FREE(bnode);
}

int mr_buffer_read_header(struct mr_buffer* buffer, size_t len) {
	if (len > 4 || len < 1) return -2;
	if (len > buffer->size) return -1;

	int sz = 0;
	struct mr_buffer_node * bnode = buffer->head;
	const uint8_t* ptr = (const uint8_t*)bnode->msg+buffer->offset;
	size_t i = 0;
	for (; i < len; i++) {
		sz <<= 8;
		sz |= *ptr;
		buffer->offset++;
		if (bnode->sz - buffer->offset == 0){
			mr_buffer_pop_buffer_node(buffer);
			if(i < len){
				break;
			}
			bnode = buffer->head;
			assert(bnode);
			ptr = (const uint8_t*)bnode->msg+buffer->offset;
		}else{
			ptr++;
		}
	}
	buffer->size -= len;
	return sz;
}

int mr_buffer_read(struct mr_buffer* buffer, char* data, int len) {
	if (data == NULL) return -2;
	if(len > buffer->size) return -1;

	struct mr_buffer_node* bnode = buffer->head;
	size_t size;
	size_t rd_len = len;
	do{
		size = bnode->sz - buffer->offset;
		if (rd_len >= size){
			memcpy(data, bnode->msg + buffer->offset, size);
			mr_buffer_pop_buffer_node(buffer);
			bnode = buffer->head;
			rd_len -= size;
			data += size;
		}else{
			memcpy(data, bnode->msg + buffer->offset, rd_len);
			buffer->offset += rd_len;
			buffer->size -= rd_len;
			rd_len = 0;
		}
	}while(rd_len > 0);
	return len;
}


static inline void mr_buffer_adjust_pack(struct mr_buffer* buffer, int len)
{
    if (len >= buffer->pack_cap) {
    	while(len >= buffer->pack_cap) 
    		buffer->pack_cap *= 2;
        
        FREE(buffer->pack_data);
        buffer->pack_data = MALLOC(buffer->pack_cap);
    }
    else if (buffer->pack_cap > MIN_PACK && buffer->pack_cap > len*2) 
    {
        buffer->pack_cap /= 2;
        FREE(buffer->pack_data);
        buffer->pack_data = MALLOC(buffer->pack_cap);
    }
}

int mr_buffer_read_pack(struct mr_buffer* buffer) {
	int rlen = buffer->read_len;
	if (rlen <= 0){
		rlen = mr_buffer_read_header(buffer, buffer->head_len);
		if (rlen <= 0){
			return -1;
		}
		buffer->read_len = rlen;
	}
	if(rlen > buffer->size) return -1;
	buffer->read_len = 0;

	buffer->pack_len = rlen;
	mr_buffer_adjust_pack(buffer, rlen);

	mr_buffer_read(buffer, buffer->pack_data, rlen);
	return rlen;
}

int mr_buffer_write_pack(struct mr_buffer* buffer, char* data, size_t len) {
	int max_len = 0;
	int head_len = buffer->head_len;
	switch(head_len){
		case 1:
			max_len = 0xff;
		break;
		case 2:
			max_len = 0xffff;
		break;
		case 4:
			max_len = 0xffffffff;
		break;
		default:
			return -1;
		break;
	}
	if (len > max_len){
		assert(0);
		return -1;
	}

	int wlen = head_len+(int)len;
	buffer->pack_len = wlen;
	if (data == buffer->pack_data){
		// assert(0);
		char* tmp_data = MALLOC(len);
		memcpy(tmp_data, data, len);
		data = tmp_data;
		mr_buffer_adjust_pack(buffer, wlen);
		memcpy(buffer->pack_data+head_len, data, len);
	}else{
		mr_buffer_adjust_pack(buffer, wlen);
		memcpy(buffer->pack_data+head_len, data, len);
	}
	char* pdata = buffer->pack_data;
	int i = head_len-1;
	for (; i >= 0; i--) {
		*(pdata+i) = len & 0xff;
		len >>= 8;
	}
	return buffer->pack_len;
}


void mr_buffer_test(){
	struct mr_buffer* buffer = mr_buffer_create(4);

	char test_data1[32] = {6,2};
	mr_buffer_push(buffer, test_data1, strlen(test_data1));

	char test_data2[32] = {1, 2, 3, 4,'1','2','3','4','5','6'};
	mr_buffer_push(buffer, test_data2, strlen(test_data2));

	char test_data3[32] = {'a','b','c','d','e','f'};
	mr_buffer_push(buffer, test_data3, strlen(test_data3));

	char test_data4[32] = {'g','h','i','j','k','l'};
	mr_buffer_push(buffer, test_data4, strlen(test_data4));

	int byte3 = mr_buffer_read_header(buffer, 3);
	int byte2 = mr_buffer_read_header(buffer, 2);
	int byte1 = mr_buffer_read_header(buffer, 1);
	assert(byte1 == 4);

	char read_data[19] = {0};
	mr_buffer_read(buffer, read_data, 15);

	mr_buffer_read(buffer, read_data, 3);
	assert(mr_buffer_size(buffer) == 0);

	char test_data[64] = {'1','2','3','4','5','6'};
	mr_buffer_write_pack(buffer, test_data, (int)strlen(test_data));
	mr_buffer_push(buffer, buffer->pack_data, buffer->pack_len);
	mr_buffer_read_pack(buffer);
	assert(memcmp(test_data, buffer->pack_data, buffer->pack_len) == 0);
}