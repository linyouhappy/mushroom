
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
        uint32_t rcv_id = 0;
        ptr = mr_decode32u(ptr, &rcv_id);
        assert(user->rcv_id == rcv_id);
        user->rcv_id++;

        uint32_t cur_time = mr_clock();
        printf("[client]id = %d, rcv_id=%d, costtime = %d \n", id, rcv_id, cur_time-send_time);
        assert(id%2 == 1);

        char* enptr = buffer->read_data;
        enptr = mr_encode32u(enptr, ++id);
        enptr = mr_encode32u(enptr, cur_time);
        enptr = mr_encode32u(enptr, (uint32_t)user->snd_id);
        user->snd_id++;

        mr_buffer_write_pack(buffer, buffer->read_data, buffer->read_len);
        int ret = mr_socket_send(fd, buffer->write_data, buffer->write_len);
        if (ret < 0)
        {
           printf("[client]mr_socket_send faild ret = %d\n", ret);
        }
    }
}

void handle_connect(uintptr_t uid, int fd, char* data, int ud)
{
    struct User* user = (struct User*)uid;
    user->snd_id = 0;
    user->rcv_id = 0;
    //100KB data
    char tmp[1024*100] = {0};
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

   int ret = mr_socket_send(fd, buffer->write_data, buffer->write_len);
   if (ret < 0)
   {
       printf("mr_socket_send faild ret = %d\n", ret);
   }
}


void handle_close(uintptr_t uid, int fd, char* data, int ud)
{
    printf("[main]handle_close uid=%lld\n", uid);
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
// #define TEST_SERVER_IP "127.0.0.1"
#define TEST_SERVER_IP "192.168.188.223"
#define TEST_SERVER_PORT 8765

int main(int argc, char* argv[])
{
    mr_socket_init();
    mr_socket_run();

    mr_set_handle_data(handle_data);
    mr_set_handle_connect(handle_connect);
    mr_set_handle_close(handle_close);
    mr_set_handle_error(handle_error);
    mr_set_handle_warning(handle_warning);

    struct User* users[TEST_CLIENT_NUM] = {0};
    int clent_count = TEST_CLIENT_NUM;
    int i = 0;
    for (i = 0; i < clent_count; ++i)
    {
        struct User* user = (struct User*)malloc(sizeof(struct User));
        user->buffer = mr_buffer_create(4);
        user->id = i;
        uintptr_t uid = (uintptr_t)user;
        int fd = mr_socket_connect(uid, TEST_SERVER_IP, TEST_SERVER_PORT);
        if (fd < 0)
        {
            printf("mr_socket_connect faild fd = %d\n", fd);
            assert(0);
        }
        printf("mr_socket_connect id=%d, uid=%ld, fd =%d \n", user->id, uid, fd);
        user->fd = fd;
        users[i] = user;
    }
    printf("start success\n");
    while(1)
    {
       mr_socket_update();
       mr_sleep(1);
    }
    return 0;
}
