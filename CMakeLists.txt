cmake_minimum_required(VERSION 3.16)
project(flow_monitor CXX)

# Cycle counts are only meaningful from an optimised build.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(PkgConfig REQUIRED)
# The plain form, not IMPORTED_TARGET: only this form provides DPDK_STATIC_LDFLAGS.
pkg_check_modules(DPDK REQUIRED libdpdk)

add_executable(flow-monitor
    src/main.cpp
    src/parse.cpp
    src/flow_table.cpp
    src/rules.cpp
)

target_include_directories(flow-monitor PRIVATE ${DPDK_INCLUDE_DIRS})
target_compile_options(flow-monitor PRIVATE ${DPDK_STATIC_CFLAGS_OTHER} -Wall -Wextra)

# Link DPDK statically. --no-as-needed keeps the driver libraries: nothing
# calls them by name (each registers itself at startup), so without it the
# linker drops them and no ports are found.
target_link_libraries(flow-monitor PRIVATE -Wl,--no-as-needed ${DPDK_STATIC_LDFLAGS})
