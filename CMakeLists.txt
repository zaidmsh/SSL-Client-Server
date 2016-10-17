cmake_minimum_required(VERSION 2.8.11)

project(testSSL)
# SET(CMAKE_CXX_FLAGS "-Wall -O3 -std=c++11")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

find_package(PkgConfig REQUIRED)
pkg_check_modules(SSL REQUIRED openssl)

include_directories(${SSL_INCLUDE_DIRS})
link_directories(${SSL_LIBRARY_DIRS})

add_executable(server server.c)
target_link_libraries(server ${SSL_LIBRARIES})

add_executable(client client.c)
target_link_libraries(client ${SSL_LIBRARIES})
