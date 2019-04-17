#ifndef mr_timer_h
#define mr_timer_h

#include "mr_queue.h"
#include <stdint.h>

#define TIME_NEAR_SHIFT 8
#define TIME_NEAR 0x100
#define TIME_LEVEL_SHIFT 6
#define TIME_LEVEL 0x40
#define TIME_NEAR_MASK 0xff
#define TIME_LEVEL_MASK 0x3f

#undef near

struct mr_timer_node {
    struct mr_queue queue;
    uint32_t time;
};

struct mr_timer {
    struct mr_timer_node near[TIME_NEAR];
    struct mr_timer_node t[4][TIME_LEVEL];
    uint32_t time;
};


struct mr_timer* mr_timer_create(void){
    struct mr_timer* timer = (struct mr_timer*)malloc(sizeof(struct mr_timer));
    memset(timer, 0, sizeof(struct mr_timer));
    int i, j;
    for (i=0;i<TIME_NEAR;i++) {
        mr_queue_init(&timer->near[i].queue);
    }
    for (i=0;i<4;i++) {
        for (j=0;j<TIME_LEVEL;j++) {
            mr_queue_init(&timer->t[i][j].queue);
        }
    }
    return timer;
}

void mr_timer_free(struct mr_timer* timer){
    free(timer);
}

static inline void mr_timer_link(struct mr_timer_node* node, struct mr_queue* skt, uint32_t time){
    mr_queue_add_tail(skt, &node->queue);
    node->time = time;
}

static void mr_timer_add(struct mr_timer* timer, struct mr_queue* skt, uint32_t time){
    uint32_t cur_time = timer->time;
    // skt->next_ts = time;
    if ((time|TIME_NEAR_MASK) == (cur_time|TIME_NEAR_MASK)) {
        mr_timer_link(&timer->near[time&TIME_NEAR_MASK], skt, time);
    } else {
        // assert(0);
        int i;
        uint32_t mask = TIME_NEAR << TIME_LEVEL_SHIFT;
        for (i=0;i<3;i++) {
            if ((time|(mask-1))==(cur_time|(mask-1))) {
                break;
            }
            mask <<= TIME_LEVEL_SHIFT;
        }
        mr_timer_link(&timer->t[i][((time>>(TIME_NEAR_SHIFT + i*TIME_LEVEL_SHIFT)) & TIME_LEVEL_MASK)], skt, time);    
    }
}

static void mr_timer_change(struct mr_timer* timer, struct mr_queue* skt, uint32_t time){
    if (!mr_queue_is_empty(skt)){
    	mr_queue_del_init(skt);
    }
    mr_timer_add(timer, skt, time);
}

static void mr_timer_remove(struct mr_timer* timer, struct mr_queue* skt){
    if (!mr_queue_is_empty(skt)){
        mr_queue_del_init(skt);
    }
}

static void mr_timer_move_list(struct mr_timer* timer, int level, int idx) {
    struct mr_timer_node* tnode = &timer->t[level][idx];
    if (!mr_queue_is_empty(&tnode->queue)){
        struct mr_queue* skt;
        struct mr_queue *p;
        for (p = tnode->queue.next; p != &tnode->queue;) {
            skt = p;
            p = p->next;
            mr_timer_change(timer, skt, tnode->time);
        }
    }
}

static void mr_timer_shift(struct mr_timer* timer) {
    int mask = TIME_NEAR;
    uint32_t cur_time = ++timer->time;
    if (cur_time == 0){
        mr_timer_move_list(timer, 3, 0);
    }else{
        uint32_t time = cur_time >> TIME_NEAR_SHIFT;
        int i=0;
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

// static void mr_timer_execute(struct mr_timer* timer) {
//     uint32_t cur_time = timer->time;
//     struct mr_timer_node* tnode = &timer->near[cur_time & TIME_NEAR_MASK];
//     // if (!mr_queue_is_empty(&tnode->queue)){
//     //     struct mr_queue* skt;
//     //     struct mr_queue *p;
//     //     uint32_t update_ts;
//     //     for (p = tnode->queue.next; p != &tnode->queue;) {
//     //         skt = p;
//     //         p = p->next;
//     //         do{
//     //             ikcp_update(skt->kcp, cur_time);
//     //             update_ts = ikcp_check(skt->kcp, cur_time);
//     //         }while(update_ts <= cur_time);
//     //         timer_remove(timer, skt);
//     //         if (ikcp_waitsnd(skt->kcp) > 0)
//     //             timer_add(timer, skt, update_ts);
//     //     }
//     // }
// }



#endif
