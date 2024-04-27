# cmake_minimum_required(VERSION <specify CMake version here>)
project(perflib C)

set(CMAKE_C_STANDARD 11)

add_executable(perflib
        ms.c)
