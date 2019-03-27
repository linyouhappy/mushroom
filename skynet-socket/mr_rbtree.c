
#include <stdio.h>
#include <stdlib.h>
#include "mr_rbtree.h"

#define rb_parent(r)   ((r)->parent)
#define rb_color(r) ((r)->color)
#define rb_is_red(r)   ((r)->color==RED)
#define rb_is_black(r)  ((r)->color==BLACK)
#define rb_set_black(r)  do { (r)->color = BLACK; } while (0)
#define rb_set_red(r)  do { (r)->color = RED; } while (0)
#define rb_set_parent(r,p)  do { (r)->parent = (p); } while (0)
#define rb_set_color(r,c)  do { (r)->color = (c); } while (0)


struct mr_rbtree_root* mr_rbtree_create(unsigned int key_len){
	struct mr_rbtree_root *root = (struct mr_rbtree_root *)malloc(sizeof(struct mr_rbtree_root));
	root->node = NULL;
	root->key_len = key_len;
	return root;
}

static inline struct mr_rbtree_node* search(struct mr_rbtree_node* x, uintptr_t key, unsigned int key_len){
	if (x == NULL) return NULL;

	int ret = memcmp(x->key, key, key_len);
	if (ret == 0)
		return x;

	while(x != NULL){
		ret = memcmp(key, x->key, key_len);
		if (ret < 0)
			x = x->left;
		else if (ret > 0)
			x = x->right;
		else
			return x;
	}
	return NULL;
}

uintptr_t mr_rbtree_search(struct mr_rbtree_root *root, uintptr_t key){
	if (root){
		struct mr_rbtree_node* x = search(root->node, key, root->key_len);
		if (x) return x->value;
	}
	return 0;
}

static void rbtree_left_rotate(struct mr_rbtree_root *root, struct mr_rbtree_node *x){
	struct mr_rbtree_node *y = x->right;
	x->right = y->left;
	if (y->left != NULL)
		y->left->parent = x;

	y->parent = x->parent;
	if (x->parent == NULL){
		root->node = y;
	}
	else{
		if (x->parent->left == x)
			x->parent->left = y;
		else
			x->parent->right = y;
	}
	y->left = x;
	x->parent = y;
}

static void rbtree_right_rotate(struct mr_rbtree_root *root, struct mr_rbtree_node *y){
	struct mr_rbtree_node *x = y->left;
	y->left = x->right;
	if (x->right != NULL)
		x->right->parent = y;

	x->parent = y->parent;
	if (y->parent == NULL){
		root->node = x;
	}else{
		if (y == y->parent->right)
			y->parent->right = x;
		else
			y->parent->left = x;
	}
	x->right = y;
	y->parent = x;
}

static void rbtree_insert_fixup(struct mr_rbtree_root *root, struct mr_rbtree_node *node){
	struct mr_rbtree_node *parent, *gparent;
	while ((parent = rb_parent(node)) && rb_is_red(parent)){
		gparent = rb_parent(parent);
		if (parent == gparent->left){
			{
				struct mr_rbtree_node *uncle = gparent->right;
				if (uncle && rb_is_red(uncle)){
					rb_set_black(uncle);
					rb_set_black(parent);
					rb_set_red(gparent);
					node = gparent;
					continue;
				}
			}
			if (parent->right == node){
				struct mr_rbtree_node *tmp;
				rbtree_left_rotate(root, parent);
				tmp = parent;
				parent = node;
				node = tmp;
			}
			rb_set_black(parent);
			rb_set_red(gparent);
			rbtree_right_rotate(root, gparent);
		}else{
			{
				struct mr_rbtree_node *uncle = gparent->left;
				if (uncle && rb_is_red(uncle)){
					rb_set_black(uncle);
					rb_set_black(parent);
					rb_set_red(gparent);
					node = gparent;
					continue;
				}
			}
			if (parent->left == node){
				struct mr_rbtree_node *tmp;
				rbtree_right_rotate(root, parent);
				tmp = parent;
				parent = node;
				node = tmp;
			}
			rb_set_black(parent);
			rb_set_red(gparent);
			rbtree_left_rotate(root, gparent);
		}
	}
	rb_set_black(root->node);
}

static void insert_rbtree(struct mr_rbtree_root *root, struct mr_rbtree_node *node){
	struct mr_rbtree_node *y = NULL;
	struct mr_rbtree_node *x = root->node;

	unsigned int key_len = root->key_len;
	int ret;
	while (x != NULL){
		y = x;
		ret = memcmp(node->key, x->key, key_len);
		if (ret < 0)
			x = x->left;
		else
			x = x->right;
	}
	rb_parent(node) = y;
	if (y != NULL){
		ret = memcmp(node->key, y->key, key_len);
		if (ret < 0)
			y->left = node;
		else
			y->right = node;
	}
	else{
		root->node = node;
	}
	node->color = RED;
	rbtree_insert_fixup(root, node);
}

static inline struct mr_rbtree_node* create_rbtree_node(uintptr_t key, uintptr_t value){
	struct mr_rbtree_node* p = (struct mr_rbtree_node *)malloc(sizeof(struct mr_rbtree_node));
	if (p == NULL)
		return NULL;

	p->key = key;
	p->value = value;
	p->left = NULL;
	p->right = NULL;
	p->parent = NULL;
	p->color = BLACK;
	return p;
}

int mr_rbtree_insert(struct mr_rbtree_root *root, uintptr_t key, uintptr_t value){
	if (search(root->node, key, root->key_len) != NULL)
		return -1;

	struct mr_rbtree_node *node = create_rbtree_node(key, value);
	if (node == NULL)
		return -1;

	insert_rbtree(root, node);
	return 0;
}

static void rbtree_remove_fixup(struct mr_rbtree_root *root, struct mr_rbtree_node *node, struct mr_rbtree_node *parent){
	struct mr_rbtree_node *other;
	while ((!node || rb_is_black(node)) && node != root->node){
		if (parent->left == node){
			other = parent->right;
			if (rb_is_red(other)){
				rb_set_black(other);
				rb_set_red(parent);
				rbtree_left_rotate(root, parent);
				other = parent->right;
			}
			if ((!other->left || rb_is_black(other->left)) &&
				(!other->right || rb_is_black(other->right))){
				rb_set_red(other);
				node = parent;
				parent = rb_parent(node);
			}
			else{
				if (!other->right || rb_is_black(other->right)){
					rb_set_black(other->left);
					rb_set_red(other);
					rbtree_right_rotate(root, other);
					other = parent->right;
				}
				rb_set_color(other, rb_color(parent));
				rb_set_black(parent);
				rb_set_black(other->right);
				rbtree_left_rotate(root, parent);
				node = root->node;
				break;
			}
		}
		else{
			other = parent->left;
			if (rb_is_red(other)){
				rb_set_black(other);
				rb_set_red(parent);
				rbtree_right_rotate(root, parent);
				other = parent->left;
			}
			if ((!other->left || rb_is_black(other->left)) &&
				(!other->right || rb_is_black(other->right))){
				rb_set_red(other);
				node = parent;
				parent = rb_parent(node);
			}
			else{
				if (!other->left || rb_is_black(other->left)){
					rb_set_black(other->right);
					rb_set_red(other);
					rbtree_left_rotate(root, other);
					other = parent->left;
				}
				rb_set_color(other, rb_color(parent));
				rb_set_black(parent);
				rb_set_black(other->left);
				rbtree_right_rotate(root, parent);
				node = root->node;
				break;
			}
		}
	}
	if (node)
		rb_set_black(node);
}

void remove_rbtree(struct mr_rbtree_root *root, struct mr_rbtree_node *node){
	struct mr_rbtree_node *child, *parent;
	int color;
	if ((node->left != NULL) && (node->right != NULL)){
		struct mr_rbtree_node *replace = node;
		replace = replace->right;
		while (replace->left != NULL)
			replace = replace->left;

		if (rb_parent(node)){
			if (rb_parent(node)->left == node)
				rb_parent(node)->left = replace;
			else
				rb_parent(node)->right = replace;
		}
		else
			root->node = replace;

		child = replace->right;
		parent = rb_parent(replace);
		color = rb_color(replace);
		if (parent == node){
			parent = replace;
		}
		else{
			if (child)
				rb_set_parent(child, parent);

			parent->left = child;
			replace->right = node->right;
			rb_set_parent(node->right, replace);
		}
		replace->parent = node->parent;
		replace->color = node->color;
		replace->left = node->left;
		node->left->parent = replace;

		if (color == BLACK)
			rbtree_remove_fixup(root, child, parent);

		free(node);
		return;
	}

	if (node->left != NULL)
		child = node->left;
	else
		child = node->right;

	parent = node->parent;
	color = node->color;

	if (child)
		child->parent = parent;

	if (parent){
		if (parent->left == node)
			parent->left = child;
		else
			parent->right = child;
	}
	else
		root->node = child;

	if (color == BLACK)
		rbtree_remove_fixup(root, child, parent);
	free(node);
}

void mr_rbtree_remove(struct mr_rbtree_root *root, uintptr_t key){
	struct mr_rbtree_node *z = search(root->node, key, root->key_len);
	if (z != NULL)
		remove_rbtree(root, z);
}

static void destroy_rbtree(struct mr_rbtree_node* tree){
	if (tree == NULL)
		return;

	if (tree->left != NULL)
		destroy_rbtree(tree->left);
	if (tree->right != NULL)
		destroy_rbtree(tree->right);

	free(tree);
}

void mr_rbtree_destroy(struct mr_rbtree_root *root){
	if (root != NULL)
		destroy_rbtree(root->node);

	free(root);
}


void mr_rbtree_test(void){
	
	struct mr_rbtree_root* rbtree = mr_rbtree_create(8);
	char key1[8] = {0};
	memset(key1, 97, sizeof(key1));
	int value1 = 1;

	char key2[8] = {0};
	memset(key2, 98, sizeof(key2));
	int value2 = 2;

	char key3[8] = {0};
	memset(key3, 99, sizeof(key3));
	int value3 = 3;

	char key4[8] = {0};
	memset(key4, 100, sizeof(key4));
	int value4 = 3;

	mr_rbtree_insert(rbtree, key1, &value1);
	mr_rbtree_insert(rbtree, key2, &value2);
	mr_rbtree_insert(rbtree, key3, &value3);
	mr_rbtree_insert(rbtree, key4, &value4);

}


