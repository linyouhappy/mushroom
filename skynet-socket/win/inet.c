
#include "inet.h"


int fcntl(int fd, int cmd, long arg) {
  if (cmd == F_GETFL)
    return 0;

  if (cmd == F_SETFL && arg == O_NONBLOCK) {
    u_long ulOption = 1;
    ioctlsocket(fd, FIONBIO, &ulOption);
  }
  return 1;
}

const char * inet_ntop(int af, const void *src, char *dst, size_t size) {
  if (af != AF_INET && af != AF_INET6)
    return NULL;

  SOCKADDR_STORAGE address;
  DWORD address_length;

  if (af == AF_INET)
  {
    address_length = sizeof(struct sockaddr_in);
    struct sockaddr_in* ipv4_address = (struct sockaddr_in*)(&address);
    ipv4_address->sin_family = AF_INET;
    ipv4_address->sin_port = 0;
    memcpy(&ipv4_address->sin_addr, src, sizeof(struct in_addr));
  }
  else // AF_INET6
  {
    address_length = sizeof(struct sockaddr_in6);
    struct sockaddr_in6* ipv6_address = (struct sockaddr_in6*)(&address);
    ipv6_address->sin6_family = AF_INET6;
    ipv6_address->sin6_port = 0;
    ipv6_address->sin6_flowinfo = 0;
    // hmmm
    ipv6_address->sin6_scope_id = 0;
    memcpy(&ipv6_address->sin6_addr, src, sizeof(struct in6_addr));
  }

  DWORD string_length = (DWORD)(size);
  int result;
  result = WSAAddressToStringA((struct sockaddr*)(&address), address_length, 0, dst, &string_length);
  // one common reason for this to fail is that ipv6 is not installed

  return result == SOCKET_ERROR ? NULL : dst;
}

