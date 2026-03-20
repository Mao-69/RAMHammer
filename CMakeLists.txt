cmake_minimum_required(VERSION 3.14)
project(ramhammer LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(ZLIB REQUIRED)

pkg_check_modules(RTLSDR REQUIRED IMPORTED_TARGET librtlsdr)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

add_executable(ramhammer
    src/main.c
    src/tx_engine.c
    src/rx_callback.c
    src/utils.c
)

target_include_directories(ramhammer PRIVATE src)

target_link_libraries(ramhammer PRIVATE
    PkgConfig::RTLSDR
    ZLIB::ZLIB
    PkgConfig::SODIUM
    Threads::Threads
    m
)

target_compile_options(ramhammer PRIVATE -Wall -Wextra -pedantic)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(ramhammer PRIVATE -Wshadow -Wformat=2 -Wundef -Wstrict-overflow=4)
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
    target_compile_options(ramhammer PRIVATE -Wshadow -Wformat -Wundef)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    target_compile_options(ramhammer PRIVATE -O3 -march=native -flto -DNDEBUG)
endif()