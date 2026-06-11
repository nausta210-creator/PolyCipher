cmake_minimum_required(VERSION 3.12)
project(PolyCipher VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

add_executable(PolyCipher src/main.cpp)

target_link_libraries(PolyCipher ${CMAKE_DL_LIBS})

add_library(vigenere MODULE plugins/vigenere/vigenere_cipher.cpp)

add_library(rsa MODULE plugins/rsa/rsa_cipher.cpp)