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
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#endif

#include "mr_slist.h"
#include "mr_rbtree.h"
#include "mr_time.h"
#include "mr_timer.h"
#include "socket_server.h"
#include "mr_config.h"

#define MAX_SOCKET (1<<MAX_SOCKET_P)

#define UDP_ADDRESS_SIZE 19	// ipv6 128bit + port 16bit + 1 byte type

#define SOCKET_TYPE_INVALID 0
#define SOCKET_TYPE_RESERVE 1
#define SOCKET_TYPE_BIND 2
// #define SOCKET_TYPE_CONNECTED 3
#define SOCKET_TYPE_BACCEPT 4
#define SOCKET_TYPE_CACCEPT 5
// #define SOCKET_TYPE_PACCEPT 5

#define HASH_ID(id) (((unsigned)id) % MAX_SOCKET)

// #define PROTOCOL_TCP 0
#define PROTOCOL_UDP 1
#define PROTOCOL_UDPv6 2
#define PROTOCOL_UNKNOWN 255

#define MR_SOCKET_TYPE_DATA 1
#define MR_SOCKET_TYPE_CLOSE 3
#define MR_SOCKET_TYPE_BACCEPT 4
#define MR_SOCKET_TYPE_CACCEPT 5
#define MR_SOCKET_TYPE_ERROR 6
#define MR_SOCKET_TYPE_WARNING 7
#define MR_SOCKET_TYPE_COUNT 8


struct mr_message {
	struct mr_slist_node node;
	uint8_t type;
	int fd;
	int kcp_fd;
	uintptr_t uid;
	char* buffer;
	int ud;
};

struct mr_kcp_socket {
	struct mr_slist_node node;
	int fd;
	int kcp_fd;
#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
	int type;
#else
	uint8_t type;
#endif
	uint8_t udp_address[UDP_ADDRESS_SIZE];
	uint8_t udp_addr_sz;
	uintptr_t opaque;
	ikcpcb *kcp;
	// struct spinlock dw_lock;
	struct mr_rbtree_root* rbtree;
	uint32_t timer_time;
};

struct mr_kcp_server {
	struct mr_timer* timer;
	uint32_t conv;
	struct mr_slist rd_list;
	struct spinlock rd_lock;
	struct mr_slist wt_list;
	struct spinlock wt_lock;
	
	struct mr_slist msg_list;
	struct spinlock list_lock;

	struct mr_kcp_socket slot[MAX_SOCKET];
	int alloc_id;

	mr_kcp_callback cbs[MR_SOCKET_TYPE_COUNT];
};

union sockaddr_all {
	struct sockaddr s;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

static struct mr_kcp_server* MR_KCP_SERVER = NULL;
static struct socket_server* SOCKET_SERVER = NULL;

// void mr_kcp_set_handle(mr_kcp_callback cb){
// 	assert(MR_KCP_SERVER && cb);
// 	MR_KCP_SERVER->all_cb = cb;
// }

static void mr_kcp_handle_data(uintptr_t uid, int fd, char* data, int size){
    printf("[mr_socket_kcp]mr_kcp_handle_data uid=%d fd=%d size=%d data=%s \n", (int)uid, fd, size, data);
}
static void mr_kcp_handle_connect(uintptr_t uid, int fd, char* data, int size){
	printf("[mr_socket_kcp]mr_kcp_handle_connect uid=%d fd=%d size=%d data=%s \n", (int)uid, fd, size, data);
}
static void mr_kcp_handle_close(uintptr_t uid, int fd, char* data, int size){
    printf("[mr_socket_kcp]mr_kcp_handle_close uid=%d fd=%d size=%d data=%s \n", (int)uid, fd, size, data);
}
static void mr_kcp_handle_baccept(uintptr_t uid, int fd, char* data, int accept_fd){
    printf("[mr_socket_kcp]mr_kcp_handle_baccept uid=%d fd =%d accept_fd=%d data=%s\n", (int)uid, fd, accept_fd, data);
}
static void mr_kcp_handle_caccept(uintptr_t uid, int fd, char* data, int accept_fd){
    printf("[mr_socket_kcp]mr_kcp_handle_caccept uid=%d fd =%d accept_fd=%d data=%s\n", (int)uid, fd, accept_fd, data);
}
static void mr_kcp_handle_error(uintptr_t uid, int fd, char* data, int size){
    printf("[mr_socket_kcp]mr_kcp_handle_error uid=%d fd=%d size=%d data=%s \n", (int)uid, fd, size, data);
}
static void mr_kcp_handle_warning(uintptr_t uid, int fd, char* data, int size){
    printf("[mr_socket_kcp]mr_kcp_handle_warning uid=%d fd=%d size=%d data=%s \n", (int)uid, fd, size, data);
}

void mr_kcp_set_handle_data(mr_kcp_callback cb){
	assert(MR_KCP_SERVER && cb);
	MR_KCP_SERVER->cbs[MR_SOCKET_TYPE_DATA] = cb;
}
void mr_kcp_set_handle_close(mr_kcp_callback cb){
	assert(MR_KCP_SERVER && cb);
	MR_KCP_SERVER->cbs[MR_SOCKET_TYPE_CLOSE] = cb;
}
void mr_kcp_set_handle_baccept(mr_kcp_callback cb){
	assert(MR_KCP_SERVER && cb);
	MR_KCP_SERVER->cbs[MR_SOCKET_TYPE_BACCEPT] = cb;
}
void mr_kcp_set_handle_caccept(mr_kcp_callback cb){
	assert(MR_KCP_SERVER && cb);
	MR_KCP_SERVER->cbs[MR_SOCKET_TYPE_CACCEPT] = cb;
}
void mr_kcp_set_handle_error(mr_kcp_callback cb){
	assert(MR_KCP_SERVER && cb);
	MR_KCP_SERVER->cbs[MR_SOCKET_TYPE_ERROR] = cb;
}
void mr_kcp_set_handle_warning(mr_kcp_callback cb){
	assert(MR_KCP_SERVER && cb);
	MR_KCP_SERVER->cbs[MR_SOCKET_TYPE_WARNING] = cb;
}

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

int mr_socket_kcp_udp_address(const char* address, char* udp_addr, int len){
	if (!address){
		return -1;
	}
	int type = address[0];
	int family;
	switch(type) {
		case PROTOCOL_UDP:
			family = AF_INET;
			break;
		case PROTOCOL_UDPv6:
			family = AF_INET6;
			break;
		default:
			return -1;
	}
	uint16_t port = 0;
    memcpy(&port, address+1, sizeof(uint16_t));
    port = ntohs(port);
    const void * addrptr = address+3;
    char strptr[256] = {0};
    if (!inet_ntop(family, addrptr, strptr, sizeof(strptr))) {
    	return -1;
    }
    snprintf(udp_addr, len, "%s:%d", strptr, port);
    return 0;
}

void mr_socket_kcp_init(uint32_t conv){
	assert(MR_KCP_SERVER == NULL);
	struct mr_kcp_server* kcp_svr = (struct mr_kcp_server*)MALLOC(sizeof(struct mr_kcp_server));
	memset(kcp_svr, 0, sizeof(struct mr_kcp_server));
	MR_KCP_SERVER = kcp_svr;
	kcp_svr->conv = conv;

	mr_slist_clear(&kcp_svr->rd_list);
	spinlock_init(&kcp_svr->rd_lock);
	mr_slist_clear(&kcp_svr->wt_list);
	spinlock_init(&kcp_svr->wt_lock);

	mr_slist_clear(&kcp_svr->msg_list);
	spinlock_init(&kcp_svr->list_lock);

	int i;
	struct mr_kcp_socket* skt;
	for (i = 0; i<MAX_SOCKET; i++) {
		skt = &kcp_svr->slot[i];
		skt->type = SOCKET_TYPE_INVALID;
	}
	kcp_svr->alloc_id = 0;

	assert(SOCKET_SERVER == NULL);
	SOCKET_SERVER = socket_server_create(0);
	kcp_svr->timer = mr_timer_create();

	mr_kcp_callback* cbs = kcp_svr->cbs;
	cbs[MR_SOCKET_TYPE_DATA] = mr_kcp_handle_data;
	cbs[MR_SOCKET_TYPE_CLOSE] = mr_kcp_handle_close;
	cbs[MR_SOCKET_TYPE_BACCEPT] = mr_kcp_handle_baccept;
	cbs[MR_SOCKET_TYPE_CACCEPT] = mr_kcp_handle_caccept;
	cbs[MR_SOCKET_TYPE_ERROR] = mr_kcp_handle_error;
	cbs[MR_SOCKET_TYPE_WARNING] = mr_kcp_handle_warning;
}

void mr_socket_kcp_exit(void){

}

static int kcp_output(const char *buffer, int len, ikcpcb *kcp, void *user){
    struct mr_kcp_socket* skt = (struct mr_kcp_socket*)user;
    assert(skt->type == SOCKET_TYPE_BACCEPT || skt->type == SOCKET_TYPE_CACCEPT);
	char* sbuffer = (char*)MALLOC(len);
	if (!sbuffer){
		fprintf(stderr, "[WARN]kcp_output MALLOC failed!! len= %d\n", len);
		return -1;
	}
	memcpy(sbuffer, buffer, len);
	int ret = socket_server_udp_send(SOCKET_SERVER, skt->fd, (const struct socket_udp_address*)skt->udp_address, sbuffer, len);
	if (ret < 0){
       fprintf(stderr, "[WARN]kcp_output socket_server_udp_send failed!!");
	   return -1;
	}
    return 0;
}

static inline void kcp_log(const char *log, struct IKCPCB *kcp, void *user){
    struct mr_kcp_socket* skt = (struct mr_kcp_socket*)user;
	int clock_time = mr_clock();
    fprintf(stderr, "KCP[%d] LOG[%d]: %s\n", skt->kcp_fd, clock_time, log);
}

static inline void kcp_create(struct mr_kcp_socket* skt){
    ikcpcb *kcp = ikcp_create(MR_KCP_SERVER->conv, (void*)skt);
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
        FREE(skt->kcp);
        skt->kcp = NULL;
    }
}

static inline void list_msg_free(struct mr_slist* msg_list, struct spinlock* list_lock){
	if (!mr_slist_is_empty(msg_list)){
		struct mr_slist_node* node;
	    spinlock_lock(list_lock);
	    node = mr_slist_clear(msg_list);
	    spinlock_unlock(list_lock);

	    struct mr_message* msg;
	     while(node){
			msg = (struct mr_message*)node;
			node = node->next;
	      	if (msg->buffer){
	      		FREE(msg->buffer);
	      	}
	       	FREE(msg);
		}
	}
}

void mr_socket_kcp_clear(void) {
	assert(MR_KCP_SERVER);
	struct mr_kcp_server* kcp_svr = MR_KCP_SERVER;
	list_msg_free(&kcp_svr->msg_list, &kcp_svr->list_lock);
	list_msg_free(&kcp_svr->rd_list, &kcp_svr->rd_lock);
	list_msg_free(&kcp_svr->wt_list, &kcp_svr->wt_lock);
}

void mr_socket_kcp_free(void){
	assert(MR_KCP_SERVER != NULL);

	struct mr_kcp_server* kcp_svr = MR_KCP_SERVER;
	int i;
	struct mr_kcp_socket* skt;
	for (i=0; i<MAX_SOCKET; i++) {
		skt = &kcp_svr->slot[i];
		if (skt->type != SOCKET_TYPE_INVALID) {
			skt->type = SOCKET_TYPE_INVALID;
			kcp_free(skt);
			// spinlock_destroy(&skt->dw_lock);
		}
	}
	mr_socket_kcp_clear();
	spinlock_destroy(&kcp_svr->list_lock);
	spinlock_destroy(&kcp_svr->rd_lock);
	spinlock_destroy(&kcp_svr->wt_lock);

	FREE(MR_KCP_SERVER);
	MR_KCP_SERVER = NULL;

	assert(SOCKET_SERVER);
	socket_server_release(SOCKET_SERVER);
	SOCKET_SERVER = NULL;
}

int mr_socket_kcp_close(int kcp_fd){
	struct mr_kcp_socket* skt = &MR_KCP_SERVER->slot[HASH_ID(kcp_fd)];
	if (skt->kcp_fd != kcp_fd) {
		fprintf(stderr, "[WARN]mr_socket_kcp_close skt->kcp_fd != kcp_fd kcp_fd =%d \n", kcp_fd);
		// assert(0);
		return -1;
	}

	

	return 0;
}

void mr_socket_kcp_shutdown(int kcp_fd){

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
				// spinlock_init(&skt->dw_lock);
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
		fprintf(stderr, "[WARN]mr_socket_kcp kcp_fd < 0   kcp_fd =%d \n", kcp_fd);
		// assert(0);
		return -1;
	}
	int fd = socket_server_udp(SOCKET_SERVER, kcp_fd, addr, port);
	if (fd < 0){
		// assert(0);
		fprintf(stderr, "[WARN]mr_socket_kcp fd < 0   kcp_fd =%d, fd =%d\n", kcp_fd, fd);
		return -1;
	}
	struct mr_kcp_socket* skt = &MR_KCP_SERVER->slot[HASH_ID(kcp_fd)];
	assert(skt->type == SOCKET_TYPE_RESERVE);
	assert(skt->kcp_fd == kcp_fd);
	skt->opaque = uid;
	skt->fd = fd;
	skt->type = SOCKET_TYPE_BIND;
	// printf("mr_socket_kcp kcp_fd=%d, addr=%s, port=%d, fd=%d\n", kcp_fd, addr, port, fd);
	return kcp_fd;
}

int mr_socket_kcp_connect(int kcp_fd, const char* addr, int port){
	struct mr_kcp_socket* skt = &MR_KCP_SERVER->slot[HASH_ID(kcp_fd)];
	if (skt->kcp_fd != kcp_fd || skt->type != SOCKET_TYPE_BIND) {
		fprintf(stderr, "[WARN]mr_socket_kcp_connect skt->kcp_fd != kcp_fd || skt->type != SOCKET_TYPE_BIND kcp_fd =%d \n", kcp_fd);
		// assert(0);
		return -1;
	}
	struct mr_message* msg = (struct mr_message*)MALLOC(sizeof(struct mr_message));
	msg->kcp_fd = kcp_fd;

	char* buffer = (char*)MALLOC(UDP_ADDRESS_SIZE);
	memset(buffer, 0, UDP_ADDRESS_SIZE);
	msg->ud = convert_udp_address(addr, port, buffer);
	msg->buffer = buffer;

	spinlock_lock(&MR_KCP_SERVER->wt_lock);
	mr_slist_link(&MR_KCP_SERVER->wt_list, (struct mr_slist_node*)msg);
	spinlock_unlock(&MR_KCP_SERVER->wt_lock);
	// printf("mr_socket_kcp_connect kcp_fd=%d, addr=%s, port=%d, fd=%d\n", kcp_fd, addr, port, skt->fd);
	return 0;
}

int mr_socket_kcp_send(int kcp_fd, const void* buffer, int sz){
	struct mr_message* msg = (struct mr_message*)MALLOC(sizeof(struct mr_message));
	msg->kcp_fd = kcp_fd;

	char* sbuffer = (char*)MALLOC(sz);
	memcpy(sbuffer, buffer, sz);
	msg->buffer = sbuffer;
	msg->ud = sz;
	// msg->option = NULL;
	
	spinlock_lock(&MR_KCP_SERVER->wt_lock);
	mr_slist_link(&MR_KCP_SERVER->wt_list, (struct mr_slist_node*)msg);
	spinlock_unlock(&MR_KCP_SERVER->wt_lock);
	// printf("mr_socket_kcp_send kcp_fd=%d, sz=%d \n", kcp_fd, sz);
	return 0;
}

static void forward_list_message(struct mr_message* msg) {
	spinlock_lock(&MR_KCP_SERVER->list_lock);
	mr_slist_link(&MR_KCP_SERVER->msg_list, (struct mr_slist_node*)msg);
	spinlock_unlock(&MR_KCP_SERVER->list_lock);
}

static void create_rbtree(struct mr_kcp_socket* bind_skt, const char* udp_address){
	int protocol = (uint8_t)udp_address[0];
	int addrsz = 0;
	union sockaddr_all sa;
	switch (protocol) {
		case PROTOCOL_UDP:
			addrsz = 1+sizeof(sa.v4.sin_port)+sizeof(sa.v4.sin_addr);
			break;
		case PROTOCOL_UDPv6:
			addrsz = 1+sizeof(sa.v6.sin6_port)+sizeof(sa.v6.sin6_addr);
			break;
		default:
			assert(0);
			break;
	}
	bind_skt->rbtree = mr_rbtree_create(addrsz);
	bind_skt->udp_addr_sz = addrsz;
}

static struct mr_kcp_socket* create_accept_socket(struct mr_kcp_socket* bind_skt, const char* udp_address, int skt_type){
	int kcp_fd = reserve_id(MR_KCP_SERVER);
	if(kcp_fd < 0){
		fprintf(stderr, "[WARN]create_accept_socket kcp_fd < 0 bind_skt->kcp_fd=%d, skt_type =%d \n", bind_skt->kcp_fd, skt_type);
		return NULL;
	}

	struct mr_kcp_socket* accept_skt = &MR_KCP_SERVER->slot[HASH_ID(kcp_fd)];
	kcp_create(accept_skt);
	assert(accept_skt->type == SOCKET_TYPE_RESERVE);
	assert(accept_skt->kcp_fd == kcp_fd);
	accept_skt->opaque = bind_skt->opaque;
	accept_skt->fd = bind_skt->fd;
	if (skt_type == SOCKET_TYPE_BACCEPT){
		accept_skt->type = SOCKET_TYPE_BACCEPT;
	}else if (skt_type == SOCKET_TYPE_CACCEPT){
		accept_skt->type = SOCKET_TYPE_CACCEPT;
	}else{
		fprintf(stderr, "[WARN]create_accept_socket bind_skt->kcp_fd=%d, skt_type =%d \n", bind_skt->kcp_fd, skt_type);
		return NULL;
		// assert(0);
	}
	memcpy(accept_skt->udp_address, udp_address, UDP_ADDRESS_SIZE);
	mr_rbtree_insert(bind_skt->rbtree, (uintptr_t)accept_skt->udp_address, (uintptr_t)accept_skt);

	char udp_addr[128];
	mr_socket_kcp_udp_address(accept_skt->udp_address, udp_addr, sizeof(udp_addr));
	// printf("create_accept_socket accept_skt udp_addr =%s \n", udp_addr);
	// printf("create_accept_socket bind_skt->kcp_fd=%d, accept_skt->kcp_fd=%d, accept_skt->type=%d \n", bind_skt->kcp_fd, accept_skt->kcp_fd, accept_skt->type);

	struct mr_message* msg = (struct mr_message*)MALLOC(sizeof(struct mr_message));
	msg->type = accept_skt->type;
	msg->kcp_fd = bind_skt->kcp_fd;
	msg->uid = accept_skt->opaque;
	int len = strlen(udp_addr);
	char* buffer = (char*)MALLOC(len);
	memcpy(buffer, udp_addr, len);
	msg->buffer = buffer;
	msg->ud = kcp_fd;
	forward_list_message(msg);
	return accept_skt;
}

static struct mr_kcp_socket* get_accept_socket(struct mr_kcp_socket* bind_skt, const char* udp_address, int skt_type){
	if (!bind_skt->rbtree){
		create_rbtree(bind_skt, udp_address);
	}
	struct mr_kcp_socket* accept_skt = (struct mr_kcp_socket*)mr_rbtree_search(bind_skt->rbtree, (uintptr_t)udp_address);
	if (accept_skt){
		assert(accept_skt->type == SOCKET_TYPE_CACCEPT || accept_skt->type == SOCKET_TYPE_BACCEPT);
		assert(!memcmp(accept_skt->udp_address, udp_address, bind_skt->udp_addr_sz));
		assert(accept_skt->fd == bind_skt->fd);
		return accept_skt;
	}
	accept_skt = create_accept_socket(bind_skt, udp_address, skt_type);
	return accept_skt;
}

static int handle_bind_write(struct mr_kcp_socket* bind_skt, struct mr_message* msg){
	const char* udp_address = (const char*)msg->buffer;
	struct mr_kcp_socket* accept_skt = get_accept_socket(bind_skt, udp_address, SOCKET_TYPE_BACCEPT);
	if (!accept_skt){
		fprintf(stderr, "[WARN]handle_bind_write accept_skt == NULL, bind_skt->kcp_fd=%d \n", bind_skt->kcp_fd);
		// assert(0);
		return -1;
    }
    return 0;
}

static void kcp_handle_read(struct mr_kcp_socket* accept_skt, struct mr_message* msg){
	// printf("kcp_handle_read accept_skt->kcp_fd=%d,accept_skt->type=%d, uid=%lld, ud=%d \n", accept_skt->kcp_fd, accept_skt->type, msg->uid, msg->ud);
    int len = ikcp_input(accept_skt->kcp, msg->buffer, msg->ud);
    if (len < 0){
        switch(len){
            case -1:
				fprintf(stderr, "[WARN]kcp_handle_read accept_skt->kcp_fd=%d, code:%d\n", accept_skt->kcp_fd, len);
				// assert(0);
            break;
            case -2:
                fprintf(stderr, "[WARN]kcp_handle_read accept_skt->kcp_fd=%d, code:%d\n", accept_skt->kcp_fd, len);
                assert(0);
            break;
            case -3:
               fprintf(stderr, "[WARN]kcp_handle_read accept_skt->kcp_fd=%d, code:%d\n", accept_skt->kcp_fd, len);
               assert(0);
            break;
            default:
                assert(0);
            break;
        }
    }else{
        while(1){
            len = ikcp_peeksize(accept_skt->kcp);
		    if (len < 0){
		        break ;
		    }
		    char* rd_data = (char*)MALLOC(len);
		    len = ikcp_recv(accept_skt->kcp, rd_data, len);
		    if (len < 0){
		    	FREE(rd_data);
		        switch(len){
		            case -1:
		                fprintf(stderr, "[WARN]ikcp_recv -1\n");
		                assert(0);
		                break;
		            break;
		            case -2:
		                fprintf(stderr, "[WARN]ikcp_recv -2\n");
		                assert(0);
		                break;
		            break;
		            case -3:
		                fprintf(stderr, "[WARN]ikcp_recv -3\n");
		                assert(0);
		            break;
		            default:
		                fprintf(stderr, "[WARN]ikcp_recv Unknown\n");
		                assert(0);
		            break;
		        }
		    }else{
		    	struct mr_message* msg = (struct mr_message*)MALLOC(sizeof(struct mr_message));
				msg->type = MR_SOCKET_TYPE_DATA;
				msg->kcp_fd = accept_skt->kcp_fd;
				msg->uid = accept_skt->opaque;
				msg->buffer = rd_data;
				msg->ud = len;
				forward_list_message(msg);
		    }
        }
    }
}

static int handle_accept_write(struct mr_kcp_socket* accept_skt, struct mr_message* msg){
	// printf("handle_accept_write accept_skt->kcp_fd=%d,accept_skt->type=%d, uid=%lld, ud=%d \n", accept_skt->kcp_fd, accept_skt->type, msg->uid, msg->ud);
	assert(accept_skt->kcp_fd ==  msg->kcp_fd);
	assert(accept_skt->type == SOCKET_TYPE_BACCEPT || accept_skt->type == SOCKET_TYPE_CACCEPT);
	int ret = ikcp_send(accept_skt->kcp, msg->buffer, msg->ud);
    if (ret < 0){
        fprintf(stderr, "handle_accept_write fail! code:%d \n",ret);
        assert(0);
        return -1;
    }
	return 0;
}

static inline void kcp_socket_addtimer(struct mr_timer* timer, struct mr_kcp_socket* skt, uint32_t timer_time){
	if (skt->timer_time > 0 && skt->timer_time <= timer_time){
		return;
	}
	skt->timer_time = timer_time;
	mr_timer_add(timer, (struct mr_slist_node*)skt, timer_time);
}

void timer_callback(struct mr_timer* timer, void* args) {
	 uint32_t cur_time = timer->time;
	struct mr_kcp_socket* skt = (struct mr_kcp_socket*)args;
    ikcp_update(skt->kcp, cur_time);
    uint32_t next_time = ikcp_check(skt->kcp, cur_time);
    assert(next_time >= cur_time);
    skt->timer_time = 0;
    if (ikcp_waitsnd(skt->kcp) > 0){
    	kcp_socket_addtimer(timer, skt, next_time);
    }
}

static void *thread_kcp_socket_handle(void* p) {
    struct mr_slist_node* node;
    struct mr_message* msg;
    uint32_t cur_time;
    uint32_t next_time;

    struct mr_kcp_server* kcp_svr = MR_KCP_SERVER;
    struct mr_timer* timer = kcp_svr->timer;
    timer->time = 0;
    cur_time = 0;

    uint32_t start_ts;
    uint32_t tmp_ts;
    uint32_t delta_ts;
    while(1){
    	start_ts = mr_clock();

    	cur_time++;
    	if(!mr_slist_is_empty(&kcp_svr->rd_list)){
    		spinlock_lock(&kcp_svr->rd_lock);
    		node = mr_slist_clear(&kcp_svr->rd_list);
    		spinlock_unlock(&kcp_svr->rd_lock);

    		struct mr_kcp_socket* bind_skt;
    		struct mr_kcp_socket* accept_skt;
		    while(node){
		    	msg = (struct mr_message*)node;
		    	node = node->next;

				bind_skt = &MR_KCP_SERVER->slot[HASH_ID(msg->kcp_fd)];
    			assert(bind_skt->fd == msg->fd && bind_skt->type == SOCKET_TYPE_BIND);
    			accept_skt = get_accept_socket(bind_skt, (const char*)(msg->buffer + msg->ud), SOCKET_TYPE_CACCEPT);
				kcp_handle_read(accept_skt, msg);
	            ikcp_update(accept_skt->kcp, cur_time);
	            next_time = ikcp_check(accept_skt->kcp, cur_time);
		        assert(next_time >= cur_time);

		        kcp_socket_addtimer(timer, accept_skt, next_time);
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

    		struct mr_kcp_socket* skt;
    		while(node){
		    	msg = (struct mr_message*)node;
		    	node = node->next;

				skt = &kcp_svr->slot[HASH_ID(msg->kcp_fd)];
				assert(skt->kcp_fd == msg->kcp_fd);
				if (skt->type == SOCKET_TYPE_BACCEPT || skt->type == SOCKET_TYPE_CACCEPT) {
					if(handle_accept_write(skt, msg) == 0){
				    	ikcp_update(skt->kcp, cur_time);
				       	next_time = ikcp_check(skt->kcp, cur_time);
				       	assert(next_time >= cur_time);
				       	kcp_socket_addtimer(timer, skt, next_time);
			    	}
				}else if(skt->type == SOCKET_TYPE_BIND){
					handle_bind_write(skt, msg);
				}else{
					fprintf(stderr, "[WARN]Unknown socket type = %d.\n", skt->type);
					assert(0);
				}
		    	if(msg->buffer){
		    		FREE(msg->buffer);
		    	}
		       	FREE(msg);
		    }
    	}

        while(timer->time <= cur_time){
            mr_timer_execute(timer, &timer_callback);
            mr_timer_shift(timer);
        }

        tmp_ts = mr_clock();
		delta_ts = tmp_ts - start_ts;
        if (delta_ts <= 0){
        	mr_sleep(1);
        }else{
        	// if (delta_ts >= 2){
        	// 	printf("delta_ts =%d \n", delta_ts);
        	// 	delta_ts = 2;
        	// }
        	cur_time += delta_ts;
        }
    }
	return NULL;
}

static void forward_message(struct socket_message * result) {
	struct mr_message* msg = (struct mr_message*)MALLOC(sizeof(struct mr_message));
	msg->fd = result->id;
	msg->kcp_fd = result->opaque;
	// msg->uid = 0;
	msg->ud = result->ud;
	msg->buffer = result->data;
	
	spinlock_lock(&MR_KCP_SERVER->rd_lock);
	mr_slist_link(&MR_KCP_SERVER->rd_list, (struct mr_slist_node*)msg);
	spinlock_unlock(&MR_KCP_SERVER->rd_lock);
}

static int mr_socket_kcp_poll(void) {
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
				fprintf(stderr, "Unknown socket message type = %d.\n",type);
				assert(0);
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

void mr_socket_kcp_update(void){
	if (mr_slist_is_empty(&MR_KCP_SERVER->msg_list)){
		return;
	}
	struct mr_slist_node* node;
    spinlock_lock(&MR_KCP_SERVER->list_lock);
    node = mr_slist_clear(&MR_KCP_SERVER->msg_list);
    spinlock_unlock(&MR_KCP_SERVER->list_lock);

    assert(node != NULL);
    struct mr_message* msg;
    while(node){
    	msg = (struct mr_message*)node;
    	node = node->next;
      	MR_KCP_SERVER->cbs[msg->type](msg->uid, msg->kcp_fd, msg->buffer, msg->ud);
      	if (msg->buffer){
      		FREE(msg->buffer);
      	}
       	FREE(msg);
    }
}

