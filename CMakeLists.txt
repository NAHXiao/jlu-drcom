cmake_minimum_required(VERSION 3.5.0)

set(VCPKG_TARGET_TRIPLET "x64-windows-static")
set(CMAKE_TOOLCHAIN_FILE $ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(drcom VERSION 0.1.0 LANGUAGES C)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(NOT WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "-static")
endif()
set(BUILD_SHARED_LIBS OFF)

add_executable(drcom main.c curl.c curl.h md5.c md5.h)

find_package(CURL REQUIRED)

target_link_libraries(drcom PRIVATE CURL::libcurl)


