
set(LIB_HEADER
	atomic.h
	socket_info.h
	socket_poll.h
	spinlock.h
	socket_epoll.h   
	socket_kqueue.h  
	socket_select.h  
	socket_server.h
	ikcp.h
	mr_socket_kcp.h
	mr_time.h
	mr_log.h
	mr_queue.h
	mr_pqueue.h
	mr_slist.h
	mr_socket.h
	mr_buffer.h
	mr_code.h
	mr_rbtree.h
)

set(LIB_SRC
	socket_server.c
	ikcp.c
	mr_socket_kcp.c
	mr_pqueue.c
	mr_socket.c
	mr_buffer.c
	mr_rbtree.c
)

if(WIN32)

list(APPEND LIB_HEADER win/inet.h)
list(APPEND LIB_HEADER win/spinlock.h)
list(APPEND LIB_HEADER win/winsocket.h)
list(APPEND LIB_HEADER win/winsocketdef.h)
list(APPEND LIB_HEADER win/atomic.h)
list(APPEND LIB_HEADER win/winport.h)

list(APPEND LIB_SRC win/inet.c)
list(APPEND LIB_SRC win/winport.c)
list(APPEND LIB_SRC win/winsocket.c)

link_libraries(ws2_32)

else()

link_libraries(pthread)

endif()

list(APPEND LIB_SRC ${LIB_HEADER})

add_library(skynet-socket STATIC ${LIB_SRC})

