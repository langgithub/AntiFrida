cmake_minimum_required(VERSION 3.18.1)

project("antifrida")

set(can_use_assembler TRUE)
enable_language(ASM)

find_library(log-lib log)
add_library(raw_syscall STATIC syscall64.s)
target_link_libraries(raw_syscall ${log-lib})

add_library(antifrida SHARED antifrida.cpp)
add_library(native-lib SHARED native-lib.cpp)
target_link_libraries(antifrida ${log-lib} raw_syscall)
target_link_libraries(native-lib ${log-lib} raw_syscall)




