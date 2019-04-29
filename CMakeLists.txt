#CMake最低版本号要求
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

set(APP_NAME tutorial)

PROJECT(${APP_NAME})

MESSAGE(STATUS "PROJECT_SOURCE_DIR: ${PROJECT_SOURCE_DIR}")
MESSAGE(STATUS "PROJECT_BINARY_DIR: ${PROJECT_BINARY_DIR}")

if(WIN32)
else()
#SET(CMAKE_BUILE_TYPE DEBUG) #指定编译类型
#SET(CMAKE_C_FLAGS_DEBUG "-g -Wall") #指定编译器
SET(CMAKE_C_FLAGS "-g -Wall") #指定编译器
endif()

SET(LIBMRSOCKET mrsocket)

file(COPY "${PROJECT_SOURCE_DIR}/mrsocket/mr_buffer.h" DESTINATION  "${PROJECT_SOURCE_DIR}/include")
file(COPY "${PROJECT_SOURCE_DIR}/mrsocket/mr_code.h" DESTINATION  "${PROJECT_SOURCE_DIR}/include")
file(COPY "${PROJECT_SOURCE_DIR}/mrsocket/mr_mem.h" DESTINATION  "${PROJECT_SOURCE_DIR}/include")
file(COPY "${PROJECT_SOURCE_DIR}/mrsocket/mr_socket.h" DESTINATION  "${PROJECT_SOURCE_DIR}/include")
file(COPY "${PROJECT_SOURCE_DIR}/mrsocket/mr_socket_kcp.h" DESTINATION  "${PROJECT_SOURCE_DIR}/include")
file(COPY "${PROJECT_SOURCE_DIR}/mrsocket/socket_info.h" DESTINATION  "${PROJECT_SOURCE_DIR}/include")
file(COPY "${PROJECT_SOURCE_DIR}/mrsocket/mrsocket.h" DESTINATION  "${PROJECT_SOURCE_DIR}/include")

SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib CACHE PATH "Single directory for all static libraries.")
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib CACHE PATH "Single directory for all dynamic libraries.")
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin CACHE PATH "Single directory for all executable.")

include_directories(${PROJECT_SOURCE_DIR}/${LIBMRSOCKET})
add_subdirectory(${PROJECT_SOURCE_DIR}/${LIBMRSOCKET})

#include_directories(${PROJECT_SOURCE_DIR}/include)
#link_directories(${PROJECT_BINARY_DIR}/${LIBMRSOCKET})

if(WIN32)
link_libraries(ws2_32)
else()
link_libraries(pthread)
endif()

add_executable(${APP_NAME} main.c)
target_link_libraries(${APP_NAME} ${LIBMRSOCKET})

#examples
#tcp===========================
add_executable(tcp_client examples/tcp/tcp_client.c)
target_link_libraries(tcp_client ${LIBMRSOCKET})
add_executable(tcp_server examples/tcp/tcp_server.c)
target_link_libraries(tcp_server ${LIBMRSOCKET})

#codebuffer===========================
add_executable(codebuffer examples/codebuffer.c)
target_link_libraries(codebuffer ${LIBMRSOCKET})

#udp===========================
add_executable(udp_client examples/udp/udp_client.c)
target_link_libraries(udp_client ${LIBMRSOCKET})
add_executable(udp_server examples/udp/udp_server.c)
target_link_libraries(udp_server ${LIBMRSOCKET})

#kcp===========================
add_executable(kcp_client examples/kcp/kcp_client.c)
target_link_libraries(kcp_client ${LIBMRSOCKET})
add_executable(kcp_server examples/kcp/kcp_server.c)
target_link_libraries(kcp_server ${LIBMRSOCKET})


















#file(GLOB APP_SOURCES app/*.cxx)
#foreach( testsourcefile ${APP_SOURCES} )
#    string( REPLACE ".cpp" "" testname ${testsourcefile} )
#    add_executable( ${testname} ${testsourcefile} )
#    target_link_libraries( ${testname} YourLib )
#endforeach( testsourcefile ${APP_SOURCES} )

