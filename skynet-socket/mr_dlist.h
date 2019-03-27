// #ifndef slist_h
// #define slist_h


// struct list_node 
// {
//     struct list_node* next;
// };

// struct slist 
// {
//     struct list_node head;
//     struct list_node *tail;
// };

// static inline struct list_node* list_clear(struct slist *list) {
//     struct list_node * ret = list->head.next;
//     list->head.next = 0;
//     list->tail = &(list->head);
//     return ret;
// }

// static inline void list_link(struct slist *list, struct list_node *node) {
//     list->tail->next = node;
//     list->tail = node;
//     node->next=0;
// }


// #endif

