
#include "mr_timer.h"
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "mr_config.h"

struct mr_timer* mr_timer_create(void){
    struct mr_timer* timer = (struct mr_timer*)MALLOC(sizeof(struct mr_timer));
    memset(timer, 0, sizeof(struct mr_timer));
    int i, j;
    for (i=0;i<TIME_NEAR;i++) {
        mr_slist_clear(&timer->near[i].queue);
    }
    for (i=0;i<4;i++) {
        for (j=0;j<TIME_LEVEL;j++) {
            mr_slist_clear(&timer->t[i][j].queue);
        }
    }
    return timer;
}

// 111111 111111 111111 111111 |11111111
void mr_timer_free(struct mr_timer* timer){
    FREE(timer);
}

static inline void mr_timer_link(struct mr_timer_node* node, struct mr_slist_node* skt, uint32_t time){
    mr_slist_link(&node->queue, skt);
    node->time = time;
}

void mr_timer_add(struct mr_timer* timer, struct mr_slist_node* skt, uint32_t time){
    uint32_t cur_time = timer->time;
    //level equal near
    if ((time|TIME_NEAR_MASK) == (cur_time|TIME_NEAR_MASK)) {
        mr_timer_link(&timer->near[time&TIME_NEAR_MASK], skt, time);
    } else {
        int i = 0;
        uint32_t mask = TIME_NEAR << TIME_LEVEL_SHIFT;
        for (;i<3;i++) {
            if ((time|(mask-1))==(cur_time|(mask-1))) {
                break;
            }
            mask <<= TIME_LEVEL_SHIFT;
        }
        mr_timer_link(&timer->t[i][((time>>(TIME_NEAR_SHIFT + i*TIME_LEVEL_SHIFT)) & TIME_LEVEL_MASK)], skt, time);    
    }
}

void mr_timer_move_list(struct mr_timer* timer, int level, int idx) {
    struct mr_timer_node* tnode = &timer->t[level][idx];
    struct mr_slist_node* skt = mr_slist_clear(&tnode->queue);
    struct mr_slist_node* temp;
    while (skt) {
        temp = skt->next;
        mr_timer_add(timer, skt, tnode->time);
        skt = temp;
    }
}

void mr_timer_shift(struct mr_timer* timer) {
    int mask = TIME_NEAR;
    uint32_t cur_time = ++timer->time;
    if (cur_time == 0){
        mr_timer_move_list(timer, 3, 0);
    }else{
        uint32_t time = cur_time >> TIME_NEAR_SHIFT;
        int i = 0;
        while ((cur_time & (mask-1)) == 0) {
            int idx = time & TIME_LEVEL_MASK;
            if (idx != 0) {
                mr_timer_move_list(timer, i, idx);
                break;              
            }
            mask <<= TIME_LEVEL_SHIFT;
            time >>= TIME_LEVEL_SHIFT;
            ++i;
        }
    }
}

void mr_timer_execute(struct mr_timer* timer, void(*func)(struct mr_timer*, void*)) {
    assert(func);
    uint32_t cur_time = timer->time;
    struct mr_timer_node* tnode = &timer->near[cur_time & TIME_NEAR_MASK];
    struct mr_slist_node* skt = mr_slist_clear(&tnode->queue);
    if (skt){
        assert((tnode->time & TIME_NEAR_MASK) == (cur_time & TIME_NEAR_MASK));
        tnode->time = 0;
        struct mr_slist_node* temp;
        while (skt) {
            temp = skt->next;
            func(timer, (void*)skt);
            skt = temp;
        }
    }else{
        assert(tnode->time == 0);
    }
}

