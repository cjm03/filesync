cmake_minimum_required(VERSION 3.16)
project(filesync C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(sync
    src/main.c
    src/common/log.c
    src/common/sha256.c
    src/fs/scan.c
    src/fs/manifest.c
    src/sync/diff.c
    src/proto/frame.c
    src/net/server.c
    src/net/client.c
)

target_include_directories(sync PRIVATE src)
target_compile_options(sync PRIVATE -Wall -Wextra -Werror)
