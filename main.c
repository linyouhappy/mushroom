
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

#define kMUserNum 60
struct User* client_users[kMUserNum] = {0};
struct User* server_users[kMUserNum*2] = {0};
struct User* bind_user = NULL;

#define kMSERVER_TYPE 0
#define kMCLIENT_TYPE 1


#define TEST_SERVER_IP "127.0.0.1"
#define TEST_SERVER_PORT 8765

struct User* create_user(){
    struct User* user = (struct User*)mr_mem_malloc(sizeof(struct User));
    user->buffer = mr_buffer_create(4);
    return user;
}

void destroy_user(struct User* user){
    mr_buffer_free(user->buffer);
    mr_mem_free(user);
}

static void handle_kcp_connect(uintptr_t uid, int fd, char* data, int cnt_fd){
    struct User* user = (struct User*)uid;
    assert(user->bind_fd == fd);
    if (user->type == kMSERVER_TYPE){
        printf("[server] handle_kcp_connect data=%s \n", data);
        assert(0);
    }else if (user->type == kMCLIENT_TYPE){
        printf("[client] handle_kcp_connect data=%s \n", data);
        user->fd = cnt_fd;

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
       int ret = mr_socket_kcp_send(cnt_fd, buffer->write_data, buffer->write_len);
        if (ret < 0){
           printf("handle_kcp_baccept mr_socket_kcp_send faild ret = %d\n", ret);
        }
    }else{
        assert(0);
    }
}

static void handle_kcp_accept(uintptr_t uid, int fd, char* data, int apt_fd){
    struct User* user = (struct User*)uid;
    assert(user->bind_fd == fd);
    if (user->type == kMSERVER_TYPE){
        printf("[server] handle_kcp_accept data=%s \n", data);
        struct User* suser = NULL;
        int i = 0;
        for (; i < kMUserNum*2; ++i){
            if (server_users[i]){
                if (server_users[i]->fd == apt_fd){
                    suser = server_users[i];
                    break;
                }
            }
        }
        if (!suser){
            suser = create_user();
            suser->type = 0;
            suser->bind_fd = fd;
			suser->fd = apt_fd;
            int i = 0;
            for (; i < kMUserNum*2; ++i){
                if (!server_users[i]){
                    server_users[i] = suser;
                    suser->id = i;
					break;
                }
            }
        }
        mr_socket_kcp_start((uintptr_t)suser, apt_fd);

    }else if (user->type == kMCLIENT_TYPE){
        printf("[client] handle_kcp_accept data=%s \n", data);

    }else{
        assert(0);
    }
}

static void handle_kcp_data(uintptr_t uid, int fd, char* data, int size)
{
    struct User* user = (struct User*)uid;
    if (user->type == kMSERVER_TYPE){
        struct mr_buffer* buffer = user->buffer;
        mr_buffer_read_push(buffer, data, size);
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
    }else if (user->type == kMCLIENT_TYPE){
        struct mr_buffer* buffer = user->buffer;
        mr_buffer_read_push(buffer, data, size);
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
             printf("[client]fd = %d, id = %d, rcv_id=%d,  costtime = %d \n",fd, id, rcv_id, cur_time-time);
            assert(id%2 == 1);

            char* enptr = buffer->read_data;
            enptr = mr_encode32u(enptr, ++id);
            enptr = mr_encode32u(enptr, cur_time);
            enptr = mr_encode32u(enptr, (uint32_t)user->snd_id);
            user->snd_id++;

            mr_buffer_write_pack(buffer, buffer->read_data, buffer->read_len);
            int ret = mr_socket_kcp_send(fd, buffer->write_data, buffer->write_len);
            if (ret < 0){
               printf("[client]mr_socket_kcp_send faild ret = %d\n", ret);
            }
        }
    }else{
        assert(0);
    }
}

static void handle_kcp_close(uintptr_t uid, int fd, char* data, int ud){
    struct User* user = (struct User*)uid;
    if (user->type == kMSERVER_TYPE){
        printf("[server] handle_kcp_close fd=%d \n", fd);
        int i = 0;
        for (; i < kMUserNum*2; ++i){
            if (server_users[i] == user)
            {
                server_users[i] = NULL;
                destroy_user(user);
                break;
            }
        }

    }else if (user->type == kMCLIENT_TYPE){
        printf("[client] handle_kcp_close fd=%d \n", fd);
    }else{

    }
}

int main(int argc, char* argv[])
{
    mr_mem_detect(0xFFFF);
    //mr_mem_check(31);
    //mr_mem_check(32);

    mr_socket_kcp_init(0x11223344);
    mr_socket_kcp_run();

    mr_kcp_set_handle_connect(handle_kcp_connect);
    mr_kcp_set_handle_accept(handle_kcp_accept);
    mr_kcp_set_handle_data(handle_kcp_data);
    mr_kcp_set_handle_close(handle_kcp_close);

    int port = 8765;
    struct User* suser = create_user();
    suser->type = kMSERVER_TYPE;
    int server_fd = mr_socket_kcp((uintptr_t)suser, "0.0.0.0", TEST_SERVER_PORT);
    if (server_fd < 0){
        printf("mr_socket_kcp faild server_fd = %d\n", server_fd);
        assert(0);
    }
	suser->bind_fd = server_fd;
    bind_user = suser;

   int i = 0;
   for (; i < kMUserNum; ++i){
        struct User* cuser = create_user();
        cuser->id = i;
        cuser->type = kMCLIENT_TYPE;
        int cbind_fd = mr_socket_kcp((uintptr_t)cuser, NULL, 0);
        if (cbind_fd < 0){
            printf("mr_socket_kcp faild cbind_fd = %d\n", cbind_fd);
        }
        mr_socket_kcp_connect(cbind_fd, TEST_SERVER_IP, TEST_SERVER_PORT);
        cuser->bind_fd = cbind_fd;
        client_users[i] = cuser;
        break;
    }

    int n = 1000;
    while(n-->0){
        mr_socket_kcp_update();
        mr_sleep(1);
    }

	{
		int i = 0;
		for (; i < kMUserNum; ++i) {
			if (client_users[i]) {
				mr_socket_kcp_close(client_users[i]->fd);
			}
		}
	}

	{
		int n = 1000;
		while (n-- > 0) {
			mr_socket_kcp_update();
			mr_sleep(1);
		}
	}
    
    mr_socket_kcp_free();

    {
        int i = 0;
        for (; i < kMUserNum; ++i){
            if (client_users[i]){
                destroy_user(client_users[i]);
                client_users[i] = NULL;
            }
        }
    }
    {
        int i = 0;
        for (; i < kMUserNum*2; ++i){
            if (server_users[i]){
                destroy_user(server_users[i]);
                server_users[i] = NULL;
            }
        }
    }
	destroy_user(bind_user);

    mr_mem_info();
    return 0;
}



