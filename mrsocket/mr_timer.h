#ifndef mr_timer_h
#define mr_timer_h

#include <stdint.h>
#include "mr_slist.h"

#define TIME_NEAR_SHIFT 8
#define TIME_NEAR 0x100
#define TIME_LEVEL_SHIFT 6
#define TIME_LEVEL 0x40
#define TIME_NEAR_MASK 0xff
#define TIME_LEVEL_MASK 0x3f

#undef near


struct mr_timer_node {
   	struct mr_slist queue;
    uint32_t time;
};

struct mr_timer {
    struct mr_timer_node near[TIME_NEAR];
    struct mr_timer_node t[4][TIME_LEVEL];
    uint32_t time;
};

struct mr_timer* mr_timer_create(void);
void mr_timer_free(struct mr_timer* timer);
void mr_timer_add(struct mr_timer* timer, struct mr_slist_node* skt, uint32_t time);
void mr_timer_shift(struct mr_timer* timer);
void mr_timer_execute(struct mr_timer* timer, void(*func)(struct mr_timer*, void*));

#endif
