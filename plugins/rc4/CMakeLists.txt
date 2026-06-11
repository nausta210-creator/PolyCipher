cmake_minimum_required(VERSION 3.10)
project(rc4)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Wpedantic)

add_library(rc4 MODULE rc4_cipher.cpp)

target_include_directories(rc4 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../..)
