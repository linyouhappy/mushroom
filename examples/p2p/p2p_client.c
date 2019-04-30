
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
    int bind_fd;
};

#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
//60 connections
#define TEST_CLIENT_NUM 2
#else
//1000 connections
#define TEST_CLIENT_NUM 2
//Yes,1000 socket connect sever
#endif
#define TEST_SERVER_IP "127.0.0.1"
// #define TEST_SERVER_IP "192.168.188.224"
#define TEST_SERVER_PORT 8765
struct User* clientUsers[TEST_CLIENT_NUM] = {0};


struct User* create_user(){
    struct User* user = (struct User*)malloc(sizeof(struct User));
    user->buffer = mr_buffer_create(4);
    return user;
}

void destroy_user(struct User* user){
    mr_buffer_free(user->buffer);
    free(user);
}

static void client_handle_kcp_connect(uintptr_t uid, int fd, char* data, int cnt_fd)
{
    printf("client_handle_kcp_connect uid=%d, fd=%d, data=%s, cnt_fd=%d \n", (int)uid, fd, data, cnt_fd);
    struct User* user = (struct User*)uid;
    assert(user->bind_fd == fd);
    if (user->fd != 0){
        printf("client_handle_kcp_connect already connect\n");
    }
    user->fd = cnt_fd;

    user->snd_id = 0;
    user->rcv_id = 0;

    //100KB data
    char tmp[1024*100] = {0};
    // char tmp[128] = { 0 };
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
    int ret = mr_socket_kcp_send(cnt_fd, buffer->write_data, buffer->write_len);
    if (ret < 0){
       printf("client_handle_kcp_connect mr_socket_kcp_send faild ret = %d\n", ret);
    }
}

// static void handle_kcp_accept(uintptr_t uid, int fd, char* data, int apt_fd){
//     printf("other client connect me\n");
// }
static void client_handle_kcp_data(uintptr_t uid, int fd, char* data, int size)
{
    printf("client_handle_kcp_data uid=%d, fd=%d, size=%d \n", (int)uid, fd, size);
    struct User* user = (struct User*)uid;
    assert(user->fd == fd);
    struct mr_buffer* buffer = user->buffer;
    mr_buffer_read_push(buffer, data, size);
    int ret = mr_buffer_read_pack(buffer);
    if (ret > 0){
        const char* ptr = buffer->read_data;
        // int read_len = buffer->read_len;

        uint32_t id = 0;
        ptr = mr_decode32u(ptr, &id);
        uint32_t time = 0;
        ptr = mr_decode32u(ptr, &time);
        uint32_t rcv_id = 0;
        ptr = mr_decode32u(ptr, &rcv_id);
        assert(user->rcv_id == rcv_id);
        user->rcv_id++;

        uint32_t cur_time = mr_clock();
        printf("handle_kcp_data fd = %d, id = %d, rcv_id=%d,  costtime = %d \n",fd, id, rcv_id, cur_time-time);
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
           printf("client_handle_kcp_data mr_socket_kcp_send faild ret = %d\n", ret);
        }
    }
}

static void client_handle_kcp_close(uintptr_t uid, int fd, char* data, int ud){
    // struct User* user = (struct User*)uid;
    printf("client_handle_kcp_close uid=%d, fd=%d \n", (int)uid, fd);
}

int main(int argc, char* argv[])
{
    // mr_mem_detect(0xFFFF);
    mr_socket_kcp_init(0x11223344);
    mr_sokekt_kcp_wndsize(128, 128);
    mr_sokekt_kcp_nodelay(1, 10, 10, 1);
    mr_socket_kcp_run();

    mr_kcp_set_handle_connect(client_handle_kcp_connect);
    mr_kcp_set_handle_accept(handle_kcp_accept);
    mr_kcp_set_handle_data(client_handle_kcp_data);
    mr_kcp_set_handle_close(client_handle_kcp_close);

   int i = 0;
   for (; i < TEST_CLIENT_NUM; ++i){
        struct User* user = create_user();
        user->id = i;

        int port = TEST_SERVER_PORT+i+1
        int bind_fd = mr_socket_kcp((uintptr_t)user, "0.0.0.0", port);
        if (bind_fd < 0){
            printf("mr_socket_kcp faild bind_fd = %d\n", bind_fd);
        }
        mr_socket_kcp_connect(bind_fd, TEST_SERVER_IP, TEST_SERVER_PORT);
        user->bind_fd = bind_fd;
        user->fd = 0;
        clientUsers[i] = user;
		break;
    }

    while(1){
        mr_socket_kcp_update();
        mr_sleep(1);
    }

    i = 0;
    for (; i < TEST_CLIENT_NUM; ++i){
        if (clientUsers[i]){
            destroy_user(clientUsers[i]);
            clientUsers[i] = NULL;
        }
    }
    return 0;
}



