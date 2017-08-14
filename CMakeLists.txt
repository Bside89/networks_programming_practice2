cmake_minimum_required(VERSION 3.7)
project(TP2)

set(CMAKE_C_STANDARD 99)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(GCC_OPT_FLAG "-lpthread -lpcap")
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_OPT_FLAG}")
SET(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_OPT_FLAG}")

set(SOURCE_FILES main.c lib/tp2opt.c lib/tp2opt.h lib/packet.c lib/packet.h lib/common.h lib/modules.c lib/modules.h lib/debug.h lib/modules/pipes.h)
add_executable(TP2 ${SOURCE_FILES})