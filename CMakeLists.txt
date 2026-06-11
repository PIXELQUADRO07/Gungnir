cmake_minimum_required(VERSION 3.15)
project(Gungnir VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

include_directories(
    src
    modules
    modules/network
    modules/recon
    utils
)

set(SOURCES
    src/main.cpp
    src/engine.cpp
    src/shell.cpp
    modules/scraper.cpp
    modules/network/network.cpp
    modules/recon/recon.cpp
    utils/logger.cpp
)

add_executable(Gungnir ${SOURCES})

# resolv
find_library(RESOLV_LIBRARY resolv)
target_link_libraries(Gungnir PRIVATE Threads::Threads)
if(RESOLV_LIBRARY)
    target_link_libraries(Gungnir PRIVATE ${RESOLV_LIBRARY})
endif()

# readline (optional)
find_library(READLINE_LIB readline)
if(READLINE_LIB)
    target_link_libraries(Gungnir PRIVATE ${READLINE_LIB})
    target_compile_definitions(Gungnir PRIVATE USE_READLINE)
    message(STATUS "readline found: history and line editing enabled")
else()
    message(STATUS "readline not found: shell will use std::getline")
endif()
