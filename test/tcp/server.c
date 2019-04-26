
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "mrsocket.h"


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
    struct mr_buffer* buffer = user->buffer;
    mr_buffer_push(buffer, data, size);
    int ret = mr_buffer_read_pack(buffer);
    if (ret > 0){
        const char* ptr = buffer->read_data;
        uint32_t id = 0;
        ptr = mr_decode32u(ptr, &id);
        uint32_t send_time = 0;
        ptr = mr_decode32u(ptr, &send_time);

        uint32_t cur_time = mr_clock();
        printf("[server]id = %d, costtime = %d \n", id, cur_time-send_time);

        assert(id%2 == 0);
        char* enptr = buffer->read_data;
        enptr = mr_encode32u(enptr, ++id);

        mr_buffer_write_pack(buffer, buffer->read_data, buffer->read_len);
        int ret = mr_socket_send(fd, buffer->write_data, buffer->write_len);
        if (ret < 0){
            printf("[server]handle_data faild ret = %d\n", ret);
        }
    }
}

void handle_close(uintptr_t uid, int fd, char* data, int ud)
{
    printf("[main]handle_close uid=%lld\n", uid);
}

void handle_accept(uintptr_t uid, int fd, char* data, int accept_fd)
{
    printf("[main]handle_accept uid=%lld fd =%d accept_fd=%d data=%s\n", uid, fd, accept_fd, data);
    // static _client_uid = 778899;
    mr_socket_start(uid, accept_fd);
}

void handle_error(uintptr_t uid, int fd, char* data, int ud)
{
    printf("[main]handle_error uid = %lld, fd = %d, data = %s \n", uid, fd, data);
}

void handle_warning(uintptr_t uid, int fd, char* data, int ud)
{
    printf("[main]handle_warning uid = %lld, fd = %d, data = %s \n", uid, fd, data);
}

#define TEST_CLIENT_NUM 60
#define TEST_SERVER_IP "0.0.0.0"
#define TEST_SERVER_PORT 8765

int main(int argc, char* argv[])
{
    mr_socket_init();
    mr_socket_run();

    mr_set_handle_data(handle_data);
    mr_set_handle_close(handle_close);
    mr_set_handle_accept(handle_accept);
    mr_set_handle_error(handle_error);
    mr_set_handle_warning(handle_warning);

    struct User* user = (struct User*)malloc(sizeof(struct User));
    user->buffer = mr_buffer_create(4);
    
    int server_fd = mr_socket_listen((uintptr_t)user, TEST_SERVER_IP, TEST_SERVER_PORT, 64);
    if (server_fd < 0)
    {
       printf("mr_socket_listen faild server_fd = %d\n", server_fd);
       assert(0);
    }
    mr_socket_start((uintptr_t)user, server_fd);
    printf("[main]start server\n");
    while(1)
    {
       mr_socket_update();
       mr_sleep(1);
    }
    return 0;
}

