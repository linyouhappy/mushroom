#ifndef mr_queue_h
#define mr_queue_h

struct mr_queue
{
	struct mr_queue *next, *prev;
};

#define mr_queue_init(ptr) \
	((ptr)->next = (ptr), (ptr)->prev = (ptr))

#define MROFFSETOF(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#define MRCONTAINEROF(ptr, type, member) ( \
		(type*)( ((char*)((type*)ptr)) - MROFFSETOF(type, member)) )
#define mr_queue_entry(ptr, type, member) MRCONTAINEROF(ptr, type, member)

#define mr_queue_cast(ptr, type) ((type*)ptr)

#define mr_queue_add(node, head) \
	((node)->prev = (head), (node)->next = (head)->next, \
	(head)->next->prev = (node), (head)->next = (node))

#define mr_queue_add_tail(node, head) \
	((node)->prev = (head)->prev, (node)->next = (head), \
	(head)->prev->next = (node), (head)->prev = (node))

#define mr_queue_del(entry) \
	((entry)->next->prev = (entry)->prev, \
	(entry)->prev->next = (entry)->next, \
	(entry)->next = 0, (entry)->prev = 0)

#define mr_queue_del_init(entry) do { \
	mr_queue_del(entry); mr_queue_init(entry); } while (0)

#define mr_queue_is_empty(entry) ((entry) == (entry)->next)

// #define MRQUEUE_ASSIGN_INIT(lhead, rhead) do { \
// 		assert(!mr_queue_is_empty((rhead))); \
// 		(lhead)->next = (rhead)->next; \
// 	    (rhead)->next->prev = (lhead); \
// 	    (lhead)->prev = (rhead)->prev; \
// 	    (rhead)->prev->next = (lhead); \
// 		mr_queue_init((rhead)); \
// 	} while (0)
	



#endif
