#ifndef winsocket_h
#define winsocket_h

#include <WinSock2.h>
#include <WS2tcpip.h>



extern int write_extend_socket(int fd, const void *buffer, size_t sz);
extern int read_extend_socket(int fd, void *buffer, size_t sz);
extern int close_extend_socket(int fd);
extern int pipe_socket(int fd[2]);
extern int connect_extend_errno(SOCKET s, const struct sockaddr* name, int namelen);
extern int send_extend_errno(SOCKET s, const char* buffer, int sz, int flag);
extern int recv_extend_errno(SOCKET s, char* buffer, int sz, int flag);
extern int recv_extend_errno(SOCKET s, char* buffer, int sz, int flag);
extern int getsockopt_extend_voidptr(SOCKET s, int level, int optname, void* optval, int* optlen);
extern int setsockopt_extend_voidptr(SOCKET s, int level, int optname, const void* optval, int optlen);
extern int recvfrom_extend_voidptr(SOCKET s, void* buf, int len, int flags, struct sockaddr* from, int* fromlen);

// #ifndef DONOT_USE_IO_EXTEND
// #define write(fd, ptr, sz) write_extend_socket(fd, ptr, sz)
// #define read(fd, ptr, sz)  read_extend_socket(fd, ptr, sz)
// #define close(fd) close_extend_socket(fd)
// #define pipe(fd) pipe_socket(fd)
// #define connect(s, name, namelen) connect_extend_errno(s, name, namelen)
// #define send(s, buffer, sz, flag) send_extend_errno(s, buffer, sz, flag)
// #define recv(s, buffer, sz, flag) recv_extend_errno(s, buffer, sz, flag)
// #define getsockopt(s, level, optname, optval, optlen) getsockopt_extend_voidptr(s, level, optname, optval, optlen)
// #define setsockopt(s, level, optname, optval, optlen) setsockopt_extend_voidptr(s, level, optname, optval, optlen)
// #define recvfrom(s, buf, len, flags, from, fromlen) recvfrom_extend_voidptr(s, buf, len, flags, from, fromlen)
// #endif

// #undef near


#endif