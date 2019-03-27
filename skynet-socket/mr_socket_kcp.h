#ifndef mr_socket_kcp_h
#define mr_socket_kcp_h

#include <stdint.h>

void mr_socket_kcp_init(void);
void mr_socket_kcp_exit(void);
void mr_socket_kcp_free(void);

// void mr_socket_kcp_forward(void* msg);

// void mr_socket_kcp_update(void);
void mr_socket_kcp_run(void);


// void mr_socket_kcp_open();


int mr_socket_kcp(uintptr_t uid, const char* addr, int port);
// void mr_socket_kcp_start(uintptr_t uid, int kcp_fd);
int mr_socket_kcp_connect(int kcp_fd, const char* addr, int port);
int mr_socket_kcp_send(int kcp_fd, const void* buffer, int sz);

// int mr_socket_send(int fd, void* buffer, int sz);

#endif
