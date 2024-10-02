cmake_minimum_required(VERSION 3.5.0)
set(CMAKE_TOOLCHAIN_FILE $ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(drcom VERSION 0.1.0 LANGUAGES C)

add_executable(drcom main.c curl.c curl.h md5.c md5.h)

find_package(CURL REQUIRED)
target_link_libraries(drcom PRIVATE CURL::libcurl)


