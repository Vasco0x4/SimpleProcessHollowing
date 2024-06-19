cmake_minimum_required(VERSION 3.10)  

project(ProcessHollowing)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(ProcessHollowing main.cpp)

if(WIN32)
    target_link_libraries(ProcessHollowing PRIVATE kernel32 user32)
endif()
