
// #ifdef __STDC__
// #undef __STDC__
// #endif
// #define __STDC__ 1
// #define __STDC_VERSION__ 199409L
// #define __STDC_VERSION__ 199901L

#define _CRT_SECURE_NO_WARNINGS


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "skynet-socket/mr_time.h"
#include "skynet-socket/mr_log.h"
#include "skynet-socket/mr_pqueue.h"
#include "skynet-socket/mr_buffer.h"
#include "skynet-socket/mr_code.h"
#include "skynet-socket/mr_rbtree.h"
#include "skynet-socket/mr_socket.h"
#include "skynet-socket/mr_socket_kcp.h"

#ifdef __cplusplus
}
#endif

struct User
{
    int id;
    int type;
    int fd;
    int snd_id;
    int rcv_id;
    struct mr_buffer* buffer;
};




int main(int argc, char* argv[])
{
    mr_socket_kcp_init();
    mr_socket_kcp_run();

    int port = 8765;
    struct User* suser = (struct User*)malloc(sizeof(struct User));
    suser->type = 0;
    suser->buffer = mr_buffer_create(4);
    int server_fd = mr_socket_kcp((uintptr_t)suser, "0.0.0.0", port);
    if (server_fd < 0)
    {
        printf("mr_socket_kcp faild server_fd = %d\n", server_fd);
    }

   int i = 0;
   for (; i < 1; ++i)
   {
        struct User* cuser = (struct User*)malloc(sizeof(struct User));
        cuser->id = i;
        cuser->type = 1;
        cuser->buffer = mr_buffer_create(4);
        int client_fd = mr_socket_kcp((uintptr_t)cuser, NULL, 0);
        if (client_fd < 0)
        {
            printf("mr_socket_kcp faild client_fd = %d\n", client_fd);
        }
        mr_socket_kcp_connect(client_fd, "127.0.0.1", port);

        char buffer[2048] = {0};
        snprintf(buffer, 2048, "mr_socket_kcp_send send data hello world");
        int ret = mr_socket_kcp_send(client_fd, buffer, (int)strlen(buffer));
        if (ret < 0)
        {
           printf("mr_socket_kcp_send faild ret = %d\n", ret);
        }
    }

    while(1)
    {
       //mr_socket_update();
       mr_sleep(1);
    }
    return 0;
}



