#ifndef _mr_rbtree_h_
#define _mr_rbtree_h_

#include <stdint.h>

#define RED   0
#define BLACK 1

struct mr_rbtree_node {
	unsigned char color;
	uintptr_t key;
	uintptr_t value;
	struct mr_rbtree_node *left;
	struct mr_rbtree_node *right;
	struct mr_rbtree_node *parent;
};

struct mr_rbtree_root {
	struct mr_rbtree_node *node;
	unsigned int key_len;
};

struct mr_rbtree_root* mr_rbtree_create(unsigned int key_len);
void mr_rbtree_destroy(struct mr_rbtree_root *root);
int mr_rbtree_insert(struct mr_rbtree_root *root, uintptr_t key, uintptr_t value);
void mr_rbtree_remove(struct mr_rbtree_root *root, uintptr_t key);
uintptr_t mr_rbtree_search(struct mr_rbtree_root *root, uintptr_t key);
void mr_rbtree_each(struct mr_rbtree_root *root, void(*func)(struct mr_rbtree_root*, uintptr_t, uintptr_t));


#endif