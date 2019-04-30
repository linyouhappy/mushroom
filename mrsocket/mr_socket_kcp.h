#ifndef mr_socket_kcp_h
#define mr_socket_kcp_h

#include <stdint.h>

typedef void (*mr_kcp_callback4)(uintptr_t, int, char*, int);
typedef void (*mr_kcp_callback5)(uintptr_t, int, char*, int, int);

void mr_socket_kcp_init(uint32_t conv);
//void mr_socket_kcp_exit(void);
 void mr_socket_kcp_free(void);

void mr_kcp_set_handle_data(mr_kcp_callback4 cb);
void mr_kcp_set_handle_close(mr_kcp_callback4 cb);
void mr_kcp_set_handle_connect(mr_kcp_callback5 cb);
void mr_kcp_set_handle_accept(mr_kcp_callback5 cb);
void mr_kcp_set_handle_error(mr_kcp_callback4 cb);
void mr_kcp_set_handle_warning(mr_kcp_callback4 cb);

void mr_socket_kcp_update(void);
void mr_socket_kcp_run(void);

void mr_sokekt_kcp_wndsize(int sndwnd, int rcvwnd);
void mr_sokekt_kcp_nodelay(int nodelay, int interval, int resend, int nc);

int mr_socket_kcp(uintptr_t uid, const char* addr, int port);
// void mr_socket_kcp_start(uintptr_t uid, int kcp_fd);
int mr_socket_kcp_connect(int kcp_fd, const char* addr, int port);
int mr_socket_kcp_send(int kcp_fd, const void* buffer, int sz);
int mr_socket_kcp_start(uintptr_t uid, int kcp_fd);

int mr_socket_kcp_close(int kcp_fd);


#endif
