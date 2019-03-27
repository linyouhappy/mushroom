#CMake最低版本号要求
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

set(APP_NAME tutorial)
PROJECT(${APP_NAME})

MESSAGE(STATUS "PROJECT_SOURCE_DIR: ${PROJECT_SOURCE_DIR}")

#SET(CMAKE_BUILE_TYPE DEBUG) #指定编译类型
#SET(CMAKE_C_FLAGS_DEBUG "-g -Wall") #指定编译器

include_directories("${PROJECT_SOURCE_DIR}/skynet-socket")
add_subdirectory(skynet-socket) 

set(DIR_SRCS main.c)
add_executable(${APP_NAME} ${DIR_SRCS})

target_link_libraries(${APP_NAME} skynet-socket)


