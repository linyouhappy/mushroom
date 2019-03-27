#include "mr_socket_kcp.h"
#include "ikcp.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)

#include "win/winport.h"
#include "win/atomic.h"
#include "win/spinlock.h"

#else

#include <pthread.h>
#include "spinlock.h"
#include "atomic.h"

#endif

#include "mr_slist.h"
#include "mr_rbtree.h"
#include "mr_time.h"
// #include "mr_pqueue.h"
#include "mr_timer.h"
#include "socket_server.h"


#define MALLOC malloc
#define FREE free

#define MAX_SOCKET_P 16
#define MAX_SOCKET (1<<MAX_SOCKET_P)

#define UDP_ADDRESS_SIZE 19	// ipv6 128bit + port 16bit + 1 byte type


#define SOCKET_TYPE_INVALID 0
#define SOCKET_TYPE_RESERVE 1
// #define SOCKET_TYPE_LISTEN 2
#define SOCKET_TYPE_CONNECTED 3
#define SOCKET_TYPE_ACCEPT 4

#define HASH_ID(id) (((unsigned)id) % MAX_SOCKET)

// #define PROTOCOL_TCP 0
#define PROTOCOL_UDP 1
#define PROTOCOL_UDPv6 2
#define PROTOCOL_UNKNOWN 255


struct mr_message {
	struct mr_slist_node node;
	// int type;
	int fd;
	int kcp_fd;
	uintptr_t uid;
	char* buffer;
	int ud;
	char* option;
};

struct mr_kcp_socket {
	struct mr_queue node;
	int fd;
	int kcp_fd;
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
	int type;
	int udpconnecting;
#else
	uint8_t type;
	uint16_t udpconnecting;
#endif
	int link_time;
	int recent_time;
	uint8_t udp_address[UDP_ADDRESS_SIZE];
	uint8_t udp_addr_sz;
	uintptr_t opaque;
	ikcpcb *kcp;
	struct spinlock dw_lock;
	char udp_addr[128];


};

struct mr_kcp_server {
	struct mr_timer* timer;

	struct mr_slist rd_list;
	struct spinlock rd_lock;
	struct mr_slist wt_list;
	struct spinlock wt_lock;

	struct mr_rbtree_root* rbtree;
	int addr_len;

	struct mr_kcp_socket slot[MAX_SOCKET];
	int alloc_id;
};


union sockaddr_all {
	struct sockaddr s;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

static struct mr_kcp_server* MR_KCP_SERVER = NULL;
static struct socket_server * SOCKET_SERVER = NULL;



static int gen_udp_address(int protocol, union sockaddr_all *sa, uint8_t* udp_address) {
	int addrsz = 1;
	udp_address[0] = (uint8_t)protocol;
	if (protocol == PROTOCOL_UDP) {
		memcpy(udp_address+addrsz, &sa->v4.sin_port, sizeof(sa->v4.sin_port));
		addrsz += sizeof(sa->v4.sin_port);
		memcpy(udp_address+addrsz, &sa->v4.sin_addr, sizeof(sa->v4.sin_addr));
		addrsz += sizeof(sa->v4.sin_addr);
	} else {
		memcpy(udp_address+addrsz, &sa->v6.sin6_port, sizeof(sa->v6.sin6_port));
		addrsz += sizeof(sa->v6.sin6_port);
		memcpy(udp_address+addrsz, &sa->v6.sin6_addr, sizeof(sa->v6.sin6_addr));
		addrsz += sizeof(sa->v6.sin6_addr);
	}
	return addrsz;
}

static int convert_udp_address(const char* addr, int port, uint8_t* udp_address){
	struct addrinfo ai_hints;
	memset(&ai_hints, 0, sizeof(ai_hints));
	ai_hints.ai_family = AF_UNSPEC;
	ai_hints.ai_socktype = SOCK_DGRAM;
	ai_hints.ai_protocol = IPPROTO_UDP;

	struct addrinfo *ai_list = NULL;
	char portstr[16];
	snprintf(portstr, sizeof(portstr), "%d", port);
	getaddrinfo(addr, portstr, &ai_hints, &ai_list);
	int protocol;
	if (ai_list->ai_family == AF_INET) {
		protocol = PROTOCOL_UDP;
	} else if (ai_list->ai_family == AF_INET6) {
		protocol = PROTOCOL_UDPv6;
	} else {
		freeaddrinfo(ai_list);
		return -1;
	}
	int addrsz = gen_udp_address(protocol, (union sockaddr_all*)ai_list->ai_addr, udp_address);
	freeaddrinfo(ai_list);
	return addrsz;
}

static socklen_t udp_socket_address(int protocol, const uint8_t udp_address[UDP_ADDRESS_SIZE], union sockaddr_all *sa) {
	int type = (uint8_t)udp_address[0];
	if (type != protocol)
		return 0;
	uint16_t port = 0;
	memcpy(&port, udp_address+1, sizeof(uint16_t));
	switch (protocol) {
		case PROTOCOL_UDP:
			memset(&sa->v4, 0, sizeof(sa->v4));
			sa->s.sa_family = AF_INET;
			sa->v4.sin_port = port;
			// ipv4 address is 32 bits
			memcpy(&sa->v4.sin_addr, udp_address + 1 + sizeof(uint16_t), sizeof(sa->v4.sin_addr));
			return sizeof(sa->v4);
		case PROTOCOL_UDPv6:
			memset(&sa->v6, 0, sizeof(sa->v6));
			sa->s.sa_family = AF_INET6;
			sa->v6.sin6_port = port;
			// ipv6 address is 128 bits
			memcpy(&sa->v6.sin6_addr, udp_address + 1 + sizeof(uint16_t), sizeof(sa->v6.sin6_addr));
			return sizeof(sa->v6);
	}
	return 0;
}

void mr_socket_kcp_init(void){
	assert(MR_KCP_SERVER == NULL);
	struct mr_kcp_server* kcp_svr = (struct mr_kcp_server*)MALLOC(sizeof(struct mr_kcp_server));
	memset(kcp_svr, 0, sizeof(struct mr_kcp_server));
	MR_KCP_SERVER = kcp_svr;

	mr_slist_clear(&kcp_svr->rd_list);
	spinlock_init(&kcp_svr->rd_lock);
	mr_slist_clear(&kcp_svr->wt_list);
	spinlock_init(&kcp_svr->wt_lock);

	int i;
	struct mr_kcp_socket* skt;
	for (i=0; i<MAX_SOCKET; i++) {
		skt = &kcp_svr->slot[i];
		skt->type = SOCKET_TYPE_INVALID;
	}
	kcp_svr->alloc_id = 0;

	assert(!SOCKET_SERVER);
	SOCKET_SERVER = socket_server_create(0);

	uint8_t udp_address[UDP_ADDRESS_SIZE];
	const char* addr = "0.0.0.0";
	int port = 80;
	int addrsz = convert_udp_address(addr, port, udp_address);
	assert(addrsz >= 7);
	kcp_svr->addr_len = addrsz;
	kcp_svr->rbtree = mr_rbtree_create(addrsz);

	kcp_svr->timer = mr_timer_create();
}

void mr_socket_kcp_exit(void){

}

void mr_socket_kcp_free(void){
	assert(MR_KCP_SERVER != NULL);
	FREE(MR_KCP_SERVER);
	MR_KCP_SERVER = NULL;
}

static int kcp_output(const char *buf, int len, ikcpcb *kcp, void *user){
    struct mr_kcp_socket* skt = (struct mr_kcp_socket*)user;
    // int ret = sendto(skt->fd, buf, len, 0, (struct sockaddr *)&skt->sockaddr, sizeof(skt->sockaddr));

 //   char* sbuffer = (char*)MALLOC(len);
	//memcpy(sbuffer, buf, len);
	//int ret = socket_server_udp_send(SOCKET_SERVER, skt->fd, (const struct socket_udp_address*)address, sbuffer, sz);

 //  	// int ret = mr_socket_udp_send(skt->fd, skt->udp_address, buf, len);
	//if (ret<0){
 //       assert(0);
 //   }
    return 0;
}

static inline void kcp_log(const char *log, struct IKCPCB *kcp, void *user){
    struct mr_kcp_socket* skt = (struct mr_kcp_socket*)user;
	int clock_time = mr_clock();
    printf("KCP[%d] LOG[%d]: %s\n", skt->kcp_fd, clock_time, log);
}

static inline void kcp_create(struct mr_kcp_socket* skt){
    ikcpcb *kcp = ikcp_create(0x11223344, (void*)skt);
    kcp->output = kcp_output;
    kcp->writelog = kcp_log;
    // kcp->logmask = -1
    // kcp->stream = 1;
    ikcp_wndsize(kcp, 128, 128);
    // ikcp_nodelay(kcp, 0, 10, 0, 0);
    // ikcp_nodelay(kcp, 0, 10, 0, 1);
    ikcp_nodelay(kcp, 1, 2, 10, 1);
    skt->kcp = kcp;
}

static inline void kcp_free(struct mr_kcp_socket* skt){
    if (skt->kcp){
        free(skt->kcp);
        skt->kcp = NULL;
    }
}

static int reserve_id(struct mr_kcp_server* kcp_svr) {
	int i;
	for (i=0;i<MAX_SOCKET;i++) {
		int id = ATOM_INC(&(kcp_svr->alloc_id));
		if (id < 0) {
			id = ATOM_AND(&(kcp_svr->alloc_id), 0x7fffffff);
		}
		struct mr_kcp_socket* skt = &kcp_svr->slot[HASH_ID(id)];
		if (skt->type == SOCKET_TYPE_INVALID) {
			if (ATOM_CAS(&skt->type, SOCKET_TYPE_INVALID, SOCKET_TYPE_RESERVE)) {
				skt->kcp_fd = id;
				skt->fd = -1;
				spinlock_init(&skt->dw_lock);
				kcp_create(skt);
				mr_queue_init(&skt->node);
				return id;
			} else {
				--i;
			}
		}
	}
	return -1;
}

int mr_socket_kcp(uintptr_t uid, const char* addr, int port){
	int kcp_fd = reserve_id(MR_KCP_SERVER);
	if(kcp_fd < 0){
		return -1;
	}
	int fd = socket_server_udp(SOCKET_SERVER, kcp_fd, addr, port);
	if (fd < 0){
		return -1;
	}
	struct mr_kcp_socket* skt = &MR_KCP_SERVER->slot[HASH_ID(kcp_fd)];
	skt->opaque = uid;
	skt->fd = fd;
	return kcp_fd;
}

int mr_socket_kcp_connect(int kcp_fd, const char* addr, int port){
	printf("mr_socket_kcp_connect kcp_fd=%d port=%d\n", kcp_fd, port);
	struct mr_kcp_socket* skt = &MR_KCP_SERVER->slot[HASH_ID(kcp_fd)];
	if (skt->kcp_fd != kcp_fd || skt->type == SOCKET_TYPE_INVALID) {
		return -1;
	}
	if (skt->type != SOCKET_TYPE_RESERVE){
		return -1;
	}
	struct mr_message* msg = (struct mr_message*)MALLOC(sizeof(struct mr_message));
	msg->fd = 0;
	msg->kcp_fd = kcp_fd;
	msg->uid = 1;

	char* buffer = (char*)MALLOC(UDP_ADDRESS_SIZE);
	memset(buffer, 0, UDP_ADDRESS_SIZE);
	msg->ud = convert_udp_address(addr, port, buffer);
	msg->buffer = buffer;
	msg->option = NULL;

	spinlock_lock(&MR_KCP_SERVER->wt_lock);
	mr_slist_link(&MR_KCP_SERVER->wt_list, (struct mr_slist_node*)msg);
	spinlock_unlock(&MR_KCP_SERVER->wt_lock);
	return 0;
}

int mr_socket_kcp_send(int kcp_fd, const void* buffer, int sz){
	printf("mr_socket_kcp_send kcp_fd=%d sz=%d\n", kcp_fd, sz);
	struct mr_message* msg = (struct mr_message*)MALLOC(sizeof(struct mr_message));
	msg->fd = 0;
	msg->kcp_fd = kcp_fd;
	msg->uid = 0;

	char* sbuffer = (char*)MALLOC(sz);
	memcpy(sbuffer, buffer, sz);
	msg->buffer = sbuffer;
	msg->ud = sz;
	msg->option = NULL;
	
	spinlock_lock(&MR_KCP_SERVER->wt_lock);
	mr_slist_link(&MR_KCP_SERVER->wt_list, (struct mr_slist_node*)msg);
	spinlock_unlock(&MR_KCP_SERVER->wt_lock);
	return 0;
}

struct mr_kcp_socket* get_kcp_socket(struct mr_message* msg){
	uintptr_t key = (uintptr_t)(msg->option+1);

    struct mr_kcp_server* kcp_svr = MR_KCP_SERVER;
	struct mr_kcp_socket* skt = (struct mr_kcp_socket*)mr_rbtree_search(kcp_svr->rbtree, key);
	// if (skt){
	// 	assert(memcmp(skt->udp_address, msg->option, kcp_svr->add_len) == 0);
	// 	assert(skt->fd == msg->fd);
	// 	return skt;
	// }

	// skt = (struct mr_kcp_socket*)MALLOC(sizeof(struct mr_kcp_socket));
	// skt->fd = msg->fd;
	// skt->kcp_fd = ++kcp_svr->_uid;
	// skt->link_time = mr_clock();
	// memcpy(skt->udp_address, msg->option, UDP_ADDRESS_SIZE);
	// kcp_create(skt);

    // mr_socket_udp_address(skt->udp_address, skt->udp_addr, sizeof(skt->udp_addr));
	return skt;
}


static int kcp_handle_read(struct mr_kcp_server* kcp_svr, struct mr_message* msg){
	struct mr_kcp_socket* skt = get_kcp_socket(msg);
    printf("mr_socket_kcp_handle fd = %d, ud = %d addr:%s \n", msg->fd, msg->ud, (const char*)skt->udp_addr);
    //skt->recent_time = mr_clock();
    int len = ikcp_input(skt->kcp, msg->buffer, msg->ud);
    if (len < 0){
        switch(len){
            case -1:
                printf("[KCP][ERROR]ikcp_input code:%d,:%s \n",len, (const char*)skt->udp_addr);
            break;
            case -2:
                printf("[KCP][ERROR]ikcp_input code:%d,:%s \n",len, (const char*)skt->udp_addr);
            break;
            case -3:
                printf("[KCP][ERROR]ikcp_input code:%d,cmd:%s \n",len, (const char*)skt->udp_addr);
            break;
            default:
                assert(0);
            break;
        }
    }else{
        while(1){
            len = ikcp_peeksize(skt->kcp);
		    if (len < 0){
		        printf("socket_read_kcp==>>\n");
		        break ;
		    }
		    char* rd_data = (char*)MALLOC(len);
		    len = ikcp_recv(skt->kcp, rd_data, len);
		    if (len < 0){
		        switch(len){
		            case -1:
		                printf("socket_read_kcp -1\n");
		                assert(0);
		                break;
		            break;
		            case -2:
		                printf("socket_read_kcp -2\n");
		                assert(0);
		                break;
		            break;
		            case -3:
		                printf("socket_read_kcp -3\n");
		                assert(0);
		            break;
		            default:
		                printf("socket_read_kcp Unknown\n");
		                assert(0);
		            break;
		        }
		    }else{

		    }
        }
    }
    return len;
}

static int kcp_handle_write(struct mr_kcp_socket* skt, struct mr_message* msg){
	printf("kcp_handle_write kcp_fd=%d uid=%lld ud=%d \n", msg->kcp_fd, msg->uid, msg->ud);
	if (skt->type == SOCKET_TYPE_RESERVE){
		assert(msg->uid == 1);
		memcpy(skt->udp_address, msg->buffer, UDP_ADDRESS_SIZE);
		skt->udp_addr_sz = msg->ud;
		skt->type = SOCKET_TYPE_CONNECTED;
		return -1;
	}else{
		assert(msg->uid == 0);
		int ret = ikcp_send(skt->kcp, msg->buffer, msg->ud);
	    if (ret < 0){
	        printf("kcp_handle_write fail! code:%d \n",ret);
	        assert(0);
	        return 0;
	    }
	}
	return 0;
}

// if (ns == NULL) {
// 		close(udp->fd);
// 		ss->slot[HASH_ID(id)].type = SOCKET_TYPE_INVALID;
// 		return;
// 	}
// 	ns->type = SOCKET_TYPE_CONNECTED;


static void mr_timer_execute(struct mr_timer* timer) {
    uint32_t cur_time = timer->time;
    struct mr_timer_node* tnode = &timer->near[cur_time & TIME_NEAR_MASK];
    if (!mr_queue_is_empty(&tnode->queue)){
        struct mr_kcp_socket* skt;
        struct mr_queue *p;
        uint32_t next_ts;
        for (p = tnode->queue.next; p != &tnode->queue;) {
            skt = mr_queue_cast(p, struct mr_kcp_socket);
            p = p->next;
            do{
                ikcp_update(skt->kcp, cur_time);
                next_ts = ikcp_check(skt->kcp, cur_time);
            }while(next_ts <= cur_time);

            mr_timer_remove(timer, (struct mr_queue*)skt);
            if (ikcp_waitsnd(skt->kcp) > 0)
                mr_timer_add(timer, (struct mr_queue*)skt, next_ts);
        }
    }
}


static void *thread_kcp_socket_handle(void* p) {
    struct mr_slist_node* node;
    struct mr_message* msg;
    struct mr_kcp_socket* skt;
    struct mr_kcp_server* kcp_svr = MR_KCP_SERVER;
    uint32_t cur_ts;
    uint32_t next_ts;
    struct mr_timer* timer = kcp_svr->timer;
    timer->time = mr_clock();
    while(1){
    	if(!mr_slist_is_empty(&kcp_svr->rd_list)){
    		spinlock_lock(&kcp_svr->rd_lock);
    		node = mr_slist_clear(&kcp_svr->rd_list);
    		spinlock_unlock(&kcp_svr->rd_lock);

    		cur_ts = mr_clock();
		    while(node){
		    	msg = (struct mr_message*)node;
		    	node = node->next;

				kcp_handle_read(kcp_svr, msg);

				do{
		            ikcp_update(skt->kcp, cur_ts);
		            next_ts = ikcp_check(skt->kcp, cur_ts);
		        }while(next_ts <= cur_ts);
		        mr_timer_change(timer, &skt->node, next_ts);

				if(msg->buffer){
		    		FREE(msg->buffer);
		    	}
		       	FREE(msg);
		    }
    	}

    	if(!mr_slist_is_empty(&kcp_svr->wt_list)){
    		spinlock_lock(&kcp_svr->wt_lock);
    		node = mr_slist_clear(&kcp_svr->wt_list);
    		spinlock_unlock(&kcp_svr->wt_lock);

    		cur_ts = mr_clock();
    		while(node){
		    	msg = (struct mr_message*)node;
		    	node = node->next;

		    	assert(msg->fd == 0);
				skt = &kcp_svr->slot[HASH_ID(msg->kcp_fd)];
				if (skt->kcp_fd == msg->kcp_fd && skt->type != SOCKET_TYPE_INVALID) {
					if(kcp_handle_write(skt, msg) == 0){
			    		do{
				            ikcp_update(skt->kcp, cur_ts);
				            next_ts = ikcp_check(skt->kcp, cur_ts);
				        }while(next_ts <= cur_ts);
				        mr_timer_change(timer, &skt->node, next_ts);
			    	}
				}else{
					assert(0);
				}

		    	if(msg->buffer){
		    		FREE(msg->buffer);
		    	}
		       	FREE(msg);
		    }
    	}

    	cur_ts = mr_clock();
        while(timer->time <= cur_ts){
            mr_timer_execute(timer);
            mr_timer_shift(timer);
        }

        mr_sleep(1);
    }
	return NULL;
}

static void forward_message(struct socket_message * result) {
	struct mr_message* msg = (struct mr_message*)MALLOC(sizeof(struct mr_message));
	msg->fd = result->id;
	msg->kcp_fd = 0;
	msg->uid = result->opaque;

	msg->ud = result->ud;
	msg->buffer = result->data;
	msg->option = msg->buffer + msg->ud;
	
	spinlock_lock(&MR_KCP_SERVER->rd_lock);
	mr_slist_link(&MR_KCP_SERVER->rd_list, (struct mr_slist_node*)msg);
	spinlock_unlock(&MR_KCP_SERVER->rd_lock);
}

int mr_socket_kcp_poll(void) {
	struct socket_server *ss = SOCKET_SERVER;
	assert(ss);
	struct socket_message result;
	int more = 1;
	int type = socket_server_poll(ss, &result, &more);
	switch (type) {
		case SOCKET_EXIT:
			return 0;
		case SOCKET_UDP:
			forward_message(&result);
			break;
		default:
			if (type != -1){
				fprintf(stderr, "Unknown socket message type %d.\n",type);
			}
			return -1;
	}
	if (more) {
		return -1;
	}
	return 1;
}

static void *thread_kcp_socket_poll(void* p) {
	int r;
	for (;;) {
		r = mr_socket_kcp_poll();
		if (r==0) break;
	}
	return NULL;
}

void mr_socket_kcp_run(void){
	pthread_t thread1;
	int ret = pthread_create(&thread1, NULL, (void *)&thread_kcp_socket_poll, NULL);
	if (ret < 0) {
		fprintf(stderr, "mr_socket_kcp_run create poll thread failed");
		exit(1);
	}
	pthread_t thread2;
	ret = pthread_create(&thread2, NULL, (void *)&thread_kcp_socket_handle, NULL);
	if (ret < 0) {
		fprintf(stderr, "mr_socket_kcp_run create handle thread failed");
		exit(1);
	}
}
