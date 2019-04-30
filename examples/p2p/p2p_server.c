
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
	char address[64];
};

#define TEST_SERVER_IP "0.0.0.0"
#define TEST_SERVER_PORT 8765

#define kMUserNum 0xFF

struct User* bindUser = NULL;
struct User* clientUsers[kMUserNum] = {0};

struct User* create_user(){
    struct User* user = (struct User*)malloc(sizeof(struct User));
    user->buffer = mr_buffer_create(4);
    return user;
}

void destroy_user(struct User* user){
    mr_buffer_free(user->buffer);
    free(user);
}

void remove_user(struct User* user){

}

void add_user(struct User* user){
    int i = 0;
    for (; i < kMUserNum; ++i){
        if (!clientUsers[i]){
            clientUsers[i] = user;
            user->id = i;
            break;
        }
    }
}

struct User* get_user(int apt_fd, char* data, int size){
    struct User* apt_user = NULL;
    int i = 0;
    for (; i < kMUserNum; ++i){
        if (clientUsers[i]){
            if (clientUsers[i]->fd == apt_fd){
                apt_user = clientUsers[i];
                if (memcmp(apt_user->address, data, size) != 0){
                    destroy_user(apt_user);
                    clientUsers[i] = NULL;
                    apt_user = NULL;
                }
                break;
            }
        }
    }
    return apt_user;
}


static void server_handle_kcp_accept(uintptr_t uid, int fd, char* data, int size, int apt_fd)
{
    struct User* user = (struct User*)uid;
    assert(user->bind_fd == fd);
    assert(bindUser == user);
    printf("server_handle_kcp_accept uid=%d, fd=%d, data=%s, apt_fd=%d \n", (int)uid, fd, data, apt_fd);

    struct User* apt_user = NULL;
    int i = 0;
    for (; i < kMUserNum; ++i){
        if (clientUsers[i]){
            if (clientUsers[i]->fd == apt_fd){
                apt_user = clientUsers[i];
                if (memcmp(apt_user->address, data, size) != 0){
                    destroy_user(apt_user);
                    clientUsers[i] = NULL;
                    apt_user = NULL;
                }
                break;
            }
        }
    }
    if (!apt_user){
        int i = 0;
        for (; i < kMUserNum; ++i){
            if (!clientUsers[i]){
                apt_user = create_user();
                clientUsers[i] = apt_user;
                apt_user->fd = apt_fd;
                apt_user->bind_fd = fd;
                memcpy(apt_user->address, data, size);
                mr_socket_kcp_start((uintptr_t)apt_user, apt_fd);
                return;
            }
        }
    }
    printf("too many client.close it\n");
    mr_socket_kcp_close(apt_fd);
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
        uint32_t msg_id = 0;
        ptr = mr_decode32u(ptr, &msg_id);
        if (msg_id == 1001)
        {
            int client_num = 0;
			int i = 0;
            for (; i < kMUserNum; ++i){
                if (clientUsers[i]){
                    client_num++;
                }
            }
            char tmp[128] = {0};
            char* enptr = tmp;

			msg_id = 1002;
			enptr = mr_encode32u(enptr, msg_id);
            enptr = mr_encode32u(enptr, client_num);
            mr_buffer_write_push(buffer, tmp, enptr-tmp);

            struct User* clientUser;
			i = 0;
            for (; i < kMUserNum; ++i){
                if (clientUsers[i]){
                    clientUser = clientUsers[i];
                    char tmp[128] = {0};
                    char* enptr = tmp;
                    enptr = mr_encode32u(enptr, clientUser->id);

                    short txtlen = (short)strlen(clientUser->address);
                    enptr = mr_encode16u(enptr, txtlen);
                    memcpy(enptr, clientUser->address, txtlen);
                    mr_buffer_write_push(buffer, tmp, enptr-tmp+txtlen);
                }
            }

            mr_buffer_write_pack(buffer);
            int ret = mr_socket_kcp_send(fd, buffer->write_data, buffer->write_len);
            if (ret < 0){
                printf("[server]mr_socket_kcp_send faild ret = %d\n", ret);
            }
        }
    }
}

static void server_handle_kcp_close(uintptr_t uid, int fd, char* data, int size)
{
    struct User* user = (struct User*)uid;
    printf("[main]server handle_kcp_accept fd=%d \n", fd);
    if (user == bindUser){
    }else{
        int i = 0;
        for (; i < kMUserNum; ++i)
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
    mr_mem_detect(0xFFFF);

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
    bindUser = user;
   
    while(1){
        mr_socket_kcp_update();
        mr_sleep(1);
        // mr_mem_info();
    }

    int i = 0;
    for (; i < kMUserNum; ++i){
        if (clientUsers[i]){
            destroy_user(clientUsers[i]);
            clientUsers[i] = NULL;
        }
    }
    destroy_user(user);
    bindUser = NULL;
    
    return 0;
}



