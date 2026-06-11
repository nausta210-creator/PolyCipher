cmake_minimum_required(VERSION 3.10)
project(elgamal)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -Wpedantic)

add_library(elgamal MODULE elgamal_cipher.cpp)

target_include_directories(elgamal PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../..)
