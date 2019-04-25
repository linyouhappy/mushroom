
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

#include "mrsocket/mrsocket.h"


struct User{
    int id;
    int type;
    int fd;
    int snd_id;
    int rcv_id;
    struct mr_buffer* buffer;
    int bind_fd;
};



static void handle_kcp_connect(uintptr_t uid, int fd, char* data, int accept_fd){
    struct User* user = (struct User*)uid;
    assert(user->bind_fd == fd);
    if (user->type == 0){
        printf("[main]server handle_kcp_baccept data=%s \n", data);
        assert(0);
    }else if (user->type == 1){
        printf("[main]client handle_kcp_baccept data=%s \n", data);
        mr_socket_kcp_close(accept_fd);
        return;

        user->snd_id = 0;
        user->rcv_id = 0;

        // char tmp[1024*100] = {0};
        char tmp[128] = { 0 };
        // snprintf(tmp, 2048, "send data hello world");
        memset(tmp, 97, sizeof(tmp)-1);
        char* ptr = tmp;
        uint32_t id = 0;
        ptr = mr_encode32u(ptr, id);
        uint32_t time = mr_clock();
        ptr = mr_encode32u(ptr, time);
        ptr = mr_encode32u(ptr, (uint32_t)user->snd_id);
        user->snd_id++;

       struct mr_buffer* buffer = user->buffer;
       mr_buffer_write_pack(buffer, tmp, sizeof(tmp));
       int ret = mr_socket_kcp_send(accept_fd, buffer->write_data, buffer->write_len);
        if (ret < 0){
           printf("handle_kcp_baccept mr_socket_kcp_send faild ret = %d\n", ret);
        }
    }else{
        assert(0);
    }
}

static void handle_kcp_accept(uintptr_t uid, int fd, char* data, int accept_fd){
    struct User* user = (struct User*)uid;
    assert(user->bind_fd == fd);
    if (user->type == 0){
        printf("[main]server handle_kcp_caccept data=%s \n", data);
    }else if (user->type == 1){
        printf("[main]client handle_kcp_caccept data=%s \n", data);
        assert(0);
        user->snd_id = 0;
        user->rcv_id = 0;

        // char tmp[1024*100] = {0};
        char tmp[128] = { 0 };
        // snprintf(tmp, 2048, "send data hello world");
        memset(tmp, 97, sizeof(tmp)-1);
        char* ptr = tmp;
        uint32_t id = 0;
        ptr = mr_encode32u(ptr, id);
        uint32_t time = mr_clock();
        ptr = mr_encode32u(ptr, time);
        ptr = mr_encode32u(ptr, (uint32_t)user->snd_id);
        user->snd_id++;

       struct mr_buffer* buffer = user->buffer;
       mr_buffer_write_pack(buffer, tmp, sizeof(tmp));
       int ret = mr_socket_kcp_send(accept_fd, buffer->write_data, buffer->write_len);
        if (ret < 0){
           printf("handle_kcp_caccept mr_socket_kcp_send faild ret = %d\n", ret);
        }
    }else{
        assert(0);
    }
}

static void handle_kcp_data(uintptr_t uid, int fd, char* data, int size)
{
    struct User* user = (struct User*)uid;
    if (user->type == 0){
        struct mr_buffer* buffer = user->buffer;
        mr_buffer_push(buffer, data, size);
        int ret = mr_buffer_read_pack(buffer);
        if (ret > 0){
            const char* ptr = buffer->read_data;
            int read_len = buffer->read_len;
            uint32_t id = 0;
            ptr = mr_decode32u(ptr, &id);
            uint32_t time = 0;
            ptr = mr_decode32u(ptr, &time);

            uint32_t cur_time = mr_clock();
            //MRLOG("[server]id = %d, costtime = %d \n", id, cur_time-time);
            assert(id%2 == 0);
            char* enptr = buffer->read_data;
            enptr = mr_encode32u(enptr, ++id);

            mr_buffer_write_pack(buffer, buffer->read_data, buffer->read_len);
            int ret = mr_socket_kcp_send(fd, buffer->write_data, buffer->write_len);
            if (ret < 0){
                printf("[server]mr_socket_kcp_send faild ret = %d\n", ret);
            }
        }
    }else{
        // MRLOG("[main]server handle_kcp_data client\n");
        // mr_mem_info();

        struct mr_buffer* buffer = user->buffer;
        mr_buffer_push(buffer, data, size);
        int ret = mr_buffer_read_pack(buffer);
        if (ret > 0){
            const char* ptr = buffer->read_data;
            int read_len = buffer->read_len;

            uint32_t id = 0;
            ptr = mr_decode32u(ptr, &id);
            uint32_t time = 0;
            ptr = mr_decode32u(ptr, &time);
            uint32_t rcv_id = 0;
            ptr = mr_decode32u(ptr, &rcv_id);
            assert(user->rcv_id == rcv_id);
            user->rcv_id++;

            uint32_t cur_time = mr_clock();
            // printf("[client]fd = %d, id = %d, rcv_id=%d,  costtime = %d \n",fd, id, rcv_id, cur_time-time);
            assert(id%2 == 1);

            char* enptr = buffer->read_data;
            enptr = mr_encode32u(enptr, ++id);
            enptr = mr_encode32u(enptr, cur_time);
            enptr = mr_encode32u(enptr, (uint32_t)user->snd_id);
            user->snd_id++;

            mr_buffer_write_pack(buffer, buffer->read_data, buffer->read_len);
            int ret = mr_socket_kcp_send(fd, buffer->write_data, buffer->write_len);
            if (ret < 0)
            {
               printf("[client]mr_socket_kcp_send faild ret = %d\n", ret);
            }
        }
    }
}

int main(int argc, char* argv[])
{
    mr_mem_detect(0xFFFF);
     // mr_mem_check(15);
    // mr_mem_check(22);
    
    mr_socket_kcp_init(0x11223344);
    mr_socket_kcp_run();

    mr_kcp_set_handle_connect(handle_kcp_connect);
    mr_kcp_set_handle_accept(handle_kcp_accept);
    mr_kcp_set_handle_data(handle_kcp_data);

    int port = 8765;
    struct User* suser = (struct User*)malloc(sizeof(struct User));
    suser->type = 0;
    suser->buffer = mr_buffer_create(4);
    int server_fd = mr_socket_kcp((uintptr_t)suser, "0.0.0.0", port);
    if (server_fd < 0){
        printf("mr_socket_kcp faild server_fd = %d\n", server_fd);
        assert(0);
    }
	suser->bind_fd = server_fd;
    mr_socket_kcp_close(server_fd);

   int i = 0;
   for (; i < 1000; ++i){
        struct User* cuser = (struct User*)malloc(sizeof(struct User));
        cuser->id = i;
        cuser->type = 1;
        cuser->buffer = mr_buffer_create(4);

        int port = 8766+i;
        int cbind_fd = mr_socket_kcp((uintptr_t)cuser, "0.0.0.0", port);
        if (cbind_fd < 0){
            printf("mr_socket_kcp faild cbind_fd = %d\n", cbind_fd);
        }
        port = 8765;
        mr_socket_kcp_connect(cbind_fd, "127.0.0.1", port);
        cuser->bind_fd = cbind_fd;
        break;
    }

    while(1){
        mr_socket_kcp_update();
        mr_sleep(1);
        // mr_mem_info();
    }
    return 0;
}



