
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

#define TEST_SERVER_IP "0.0.0.0"
#define TEST_SERVER_PORT 8765

struct User* serverUser = NULL;
struct User* clientUsers[0xFFFF] = {0};

struct User* create_user(){
    struct User* user = (struct User*)malloc(sizeof(struct User));
    user->buffer = mr_buffer_create(4);
    return user;
}

void destroy_user(struct User* user){
    mr_buffer_free(user->buffer);
    free(user);
}

static void server_handle_kcp_accept(uintptr_t uid, int fd, char* data, int apt_fd){
    struct User* user = (struct User*)uid;
    assert(user->bind_fd == fd);
    assert(serverUser == user);

    printf("server_handle_kcp_accept uid=%d, fd=%d, data=%s, apt_fd=%d \n", (int)uid, fd, data, apt_fd);
    int i = 0;
    for (; i < 0xFFFF; ++i)
    {
        if (!clientUsers[i])
        {
            struct User* user = create_user();
            clientUsers[i] = user;
            mr_socket_kcp_start((uintptr_t)user, apt_fd);
            return;
        }
    }
}

static void server_handle_kcp_data(uintptr_t uid, int fd, char* data, int size)
{
    struct User* user = (struct User*)uid;
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

        uint32_t cur_time = mr_clock();
        printf("[server]id = %d, costtime = %d \n", id, cur_time-time);
        assert(id%2 == 0);
        char* enptr = buffer->read_data;
        enptr = mr_encode32u(enptr, ++id);

        mr_buffer_write_pack(buffer, buffer->read_data, buffer->read_len);
        int ret = mr_socket_kcp_send(fd, buffer->write_data, buffer->write_len);
        if (ret < 0){
            printf("[server]mr_socket_kcp_send faild ret = %d\n", ret);
        }
    }
}

static void server_handle_kcp_close(uintptr_t uid, int fd, char* data, int ud)
{
    struct User* user = (struct User*)uid;
    printf("[main]server handle_kcp_accept fd=%d \n", fd);
    if (user == serverUser){
        
    }else{
        int i = 0;
        for (; i < 0xffff; ++i)
        {
            if (clientUsers[i] == user)
            {
                clientUsers[i] = NULL;
                destroy_user(user);
                return;
            }
        }
    }
}

int main(int argc, char* argv[])
{
    // mr_mem_detect(0xFFFF);

    mr_socket_kcp_init(0x11223344);
    mr_sokekt_kcp_wndsize(128, 128);
    mr_sokekt_kcp_nodelay(1, 10, 10, 1);
    mr_socket_kcp_run();

    mr_kcp_set_handle_accept(server_handle_kcp_accept);
    mr_kcp_set_handle_data(server_handle_kcp_data);
    mr_kcp_set_handle_close(server_handle_kcp_close);

    struct User* user = create_user();
    int server_fd = mr_socket_kcp((uintptr_t)user, TEST_SERVER_IP, TEST_SERVER_PORT);
    if (server_fd < 0){
        printf("mr_socket_kcp faild server_fd = %d\n", server_fd);
        assert(0);
    }
	user->bind_fd = server_fd;
    serverUser = user;
   
    while(1){
        mr_socket_kcp_update();
        mr_sleep(1);
        // mr_mem_info();
    }

    int i = 0;
    for (; i < 0xffff; ++i){
        if (clientUsers[i]){
            destroy_user(clientUsers[i]);
            clientUsers[i] = NULL;
        }
    }
    destroy_user(user);
    serverUser = NULL;
    
    return 0;
}



