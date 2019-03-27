#ifndef _wininet_H
#define _wininet_H

#include <Winsock2.h>
#include <WS2tcpip.h>

#define O_NONBLOCK 1
#define F_SETFL 0
#define F_GETFL 1

int fcntl(int fd, int cmd, long arg);

const char * inet_ntop(int af, const void *src, char *dst, size_t size);

#endif /* _wininet_H */