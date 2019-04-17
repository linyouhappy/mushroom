
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

#include "skynet-socket/mr_socket.h"
#include "skynet-socket/mr_time.h"
#include "skynet-socket/mr_log.h"
#include "skynet-socket/mr_pqueue.h"
#include "skynet-socket/mr_buffer.h"
#include "skynet-socket/mr_code.h"
#include "skynet-socket/mr_rbtree.h"

#ifdef __cplusplus
}
#endif

struct User{
    int id;
    int type;
    int fd;
    int snd_id;
    int rcv_id;
    struct mr_buffer* buffer;
};

void handle_data(uintptr_t uid, int fd, char* data, int size)
{
    struct User* user = (struct User*)uid;
    if (user->type == 0){
        // MRLOG("[main][server]handle_data uid=%lld, fd=%d, size=%d\n", uid, fd, size);
        struct mr_buffer* buffer = user->buffer;
        mr_buffer_push(buffer, data, size);
        int ret = mr_buffer_read_pack(buffer);
        if (ret > 0){
            const char* ptr = buffer->pack_data;
            uint32_t id = 0;
            ptr = mr_decode32u(ptr, &id);
            uint32_t time = 0;
            ptr = mr_decode32u(ptr, &time);

            uint32_t cur_time = mr_clock();
            //MRLOG("[server]id = %d, costtime = %d \n", id, cur_time-time);
            assert(id%2 == 0);
            char* enptr = buffer->pack_data;
			enptr = mr_encode32u(enptr, ++id);

            mr_buffer_write_pack(buffer, buffer->pack_data, buffer->pack_len);
            int ret = mr_socket_send(fd, buffer->pack_data, buffer->pack_len);
            if (ret < 0){
                MRERROR("[server]handle_data faild ret = %d\n", ret);
            }
        }
    }else{
        // MRLOG("[main][client]handle_data uid=%lld, fd=%d, size=%d\n", uid, fd, size);
        struct mr_buffer* buffer = user->buffer;
        mr_buffer_push(buffer, data, size);
        int ret = mr_buffer_read_pack(buffer);
        if (ret > 0){
            const char* ptr = buffer->pack_data;
            uint32_t id = 0;
            ptr = mr_decode32u(ptr, &id);
            uint32_t time = 0;
            ptr = mr_decode32u(ptr, &time);
            uint32_t rcv_id = 0;
            ptr = mr_decode32u(ptr, &rcv_id);
            assert(user->rcv_id == rcv_id);
            user->rcv_id++;

            uint32_t cur_time = mr_clock();
            MRLOG("[client]id = %d, rcv_id=%d, costtime = %d \n", id, rcv_id, cur_time-time);
            assert(id%2 == 1);

            char* enptr = buffer->pack_data;
            enptr = mr_encode32u(enptr, ++id);
            enptr = mr_encode32u(enptr, cur_time);
            enptr = mr_encode32u(enptr, (uint32_t)user->snd_id);
            user->snd_id++;

            mr_buffer_write_pack(buffer, buffer->pack_data, buffer->pack_len);
            int ret = mr_socket_send(fd, buffer->pack_data, buffer->pack_len);
            if (ret < 0)
            {
               MRERROR("[client]mr_socket_send faild ret = %d\n", ret);
            }
        }
    }
}

void handle_connect(uintptr_t uid, int fd, char* data, int ud)
{
    struct User* user = (struct User*)uid;
    if (user->type == 0){
       MRLOG("[server]handle_connect uid=%lld fd=%d\n",uid, fd);
    }else{
        MRLOG("[client]handle_connect uid=%lld fd=%d\n", uid, fd);

        user->snd_id = 0;
        user->rcv_id = 0;

        char tmp[1024*100] = {0};
        // snprintf(tmp, 2048, "send data hello world");
        memset(tmp, 97, sizeof(tmp)-1);
        char* ptr = tmp;
        uint32_t uid = 0;
        ptr = mr_encode32u(ptr, uid);
        uint32_t time = mr_clock();
        ptr = mr_encode32u(ptr, time);
        ptr = mr_encode32u(ptr, (uint32_t)user->snd_id);
        user->snd_id++;

       struct mr_buffer* buffer = user->buffer;
       mr_buffer_write_pack(buffer, tmp, sizeof(tmp)-1);

       int ret = mr_socket_send(fd, buffer->pack_data, buffer->pack_len);
       if (ret < 0)
       {
           MRERROR("mr_socket_send faild ret = %d\n", ret);
       }
    }
}

void handle_close(uintptr_t uid, int fd, char* data, int ud)
{
    MRLOG("[main]handle_close uid=%lld\n", uid);
}

void handle_accept(uintptr_t uid, int fd, char* data, int accept_fd)
{
    MRLOG("[main]handle_accept uid=%lld fd =%d accept_fd=%d data=%s\n", uid, fd, accept_fd, data);
    // static _client_uid = 778899;
    mr_socket_start(uid, accept_fd);
}

void handle_error(uintptr_t uid, int fd, char* data, int ud)
{
    MRLOG("[main]handle_error uid = %lld, fd = %d, data = %s \n", uid, fd, data);
}

void handle_warning(uintptr_t uid, int fd, char* data, int ud)
{
    MRLOG("[main]handle_warning uid = %lld, fd = %d, data = %s \n", uid, fd, data);
}

void handle_udp(uintptr_t uid, int fd, char* data, int size, char* address)
{
    struct User* user = (struct User*)uid;
    if (user->type == 0){
        int ret = mr_socket_udp_send(fd, address, data, size);
        if (ret < 0){
            MRERROR("[server]handle_udp faild ret = %d\n", ret);
        }
    }else{
        char udp_addr[256];
        mr_socket_udp_address(address, udp_addr, sizeof(udp_addr));

        char* tmp = (char*)malloc(size+1);
		memset(tmp, 0, size + 1);
        memcpy(tmp, data, size);
        MRLOG("UDP[%s] uid=%lld fd =%d buffer=%s sz=%d ud=%d\n", udp_addr, uid, fd, tmp, (int)strlen(tmp), size);

        mr_sleep(1000);

        static int _sid = 1;
        char sbuffer[2048] = {0};
        snprintf(sbuffer, 2048, "send data hello world sid=%d", _sid++);
        int ret = mr_socket_udp_send(fd, address, sbuffer, (int)strlen(sbuffer));
        if (ret < 0){
            MRERROR("mr_socket_udp_send faild ret = %d\n", ret);
        }
    }
}


int main(int argc, char* argv[])
{
    mr_socket_init();
    mr_socket_run();

    mr_set_handle_data(handle_data);
    mr_set_handle_connect(handle_connect);
    mr_set_handle_close(handle_close);
    mr_set_handle_accept(handle_accept);
    mr_set_handle_error(handle_error);
    mr_set_handle_warning(handle_warning);
    mr_set_handle_udp(handle_udp);

    // int port = 8765;
    // struct User* suser = (struct User*)malloc(sizeof(struct User));
    // suser->type = 0;
    // suser->buffer = mr_buffer_create(4);
    
    // int server_fd = mr_socket_listen((uintptr_t)suser, "0.0.0.0", port, 64);
    // if (server_fd < 0)
    // {
    //    MRERROR("mr_socket_listen faild server_fd = %d\n", server_fd);
    // }
    // MRLOG("[main]start server\n");
    // mr_socket_start((uintptr_t)suser, server_fd);


    // struct User* cuser = (struct User*)malloc(sizeof(struct User));
    // cuser->type = 1;
    // cuser->buffer = mr_buffer_create(4);

    // int client_fd = mr_socket_connect((uintptr_t)cuser, "127.0.0.1", port);
    // if (client_fd < 0)
    // {
    //    printf("mr_socket_connect faild client_fd = %d\n", client_fd);
    // }
    // MRLOG("[main]connect server\n");
   // int i = 0;
   // for (; i < 30; ++i)
   // {
   //    client_uid = 13800+i;
   //    client_fd = mr_socket_connect(client_uid, "127.0.0.1", port);
   //    if (client_fd < 0)
   //    {
   //        printf("mr_socket_connect faild client_fd = %d\n", client_fd);
   //    }
   // }
   
   // MRLOG("[main]start success\n");

    int port = 8765;
    struct User* suser = (struct User*)malloc(sizeof(struct User));
    suser->type = 0;
    suser->buffer = mr_buffer_create(4);
    int server_fd = mr_socket_udp((uintptr_t)suser, "0.0.0.0", port);
    if (server_fd < 0)
    {
        printf("mr_socket_udp faild server_fd = %d\n", server_fd);
    }

   int i = 0;
   for (; i < 1; ++i)
   {
        struct User* cuser = (struct User*)malloc(sizeof(struct User));
        cuser->id = i;
        cuser->type = 1;
        cuser->buffer = mr_buffer_create(4);
        int client_fd = mr_socket_udp((uintptr_t)cuser, NULL, 0);
        if (client_fd < 0)
        {
            printf("mr_socket_udp faild client_fd = %d\n", client_fd);
        }
        mr_socket_udp_connect(client_fd, "127.0.0.1", port);

        char buffer[2048] = {0};
        snprintf(buffer, 2048, "mr_socket_send send data hello world");
        int ret = mr_socket_send(client_fd, buffer, (int)strlen(buffer));
        if (ret < 0)
        {
           printf("mr_socket_send faild ret = %d\n", ret);
        }
    }

    while(1)
    {
       mr_socket_update();
       mr_sleep(1);
    }
    return 0;
}

