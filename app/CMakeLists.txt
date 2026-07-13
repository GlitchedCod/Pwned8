cmake_minimum_required(VERSION 3.4.1)

# Android 15+ requires 16 KB aligned ELF PT_LOAD segments for native shared libraries.
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,max-page-size=16384")

add_library( native-lib SHARED src/main/cpp/native-lib.cpp )
include_directories(src/main/cpp/)