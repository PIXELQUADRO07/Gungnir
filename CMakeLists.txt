cmake_minimum_required(VERSION 3.15)
project(Gungnir VERSION 1.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads  REQUIRED)
find_package(CURL     REQUIRED)
find_package(SQLite3  REQUIRED)

set(SOURCES
    src/main.cpp
    src/engine.cpp
    src/shell.cpp
    src/updater.cpp
    src/database.cpp
    src/config.cpp
    modules/scraper.cpp
    modules/network/network.cpp
    modules/network/http_client.cpp
    modules/recon
    modules/nmap
    modules/searchsploit/recon.cpp
    modules/recon
    modules/nmap
    modules/searchsploit/threat_intel.cpp
    modules/nmap/nmap.cpp
    modules/searchsploit/searchsploit.cpp
    utils/logger.cpp
)

add_executable(Gungnir ${SOURCES})

target_include_directories(Gungnir PRIVATE
    src
    modules
    modules/network
    modules/recon
    modules/nmap
    modules/searchsploit
    utils
    vendor
)

target_link_libraries(Gungnir PRIVATE
    Threads::Threads
    CURL::libcurl
    SQLite::SQLite3
)

# resolv — needed by recon.cpp for res_query / res_init
find_library(RESOLV_LIB resolv)
if(RESOLV_LIB)
    target_link_libraries(Gungnir PRIVATE ${RESOLV_LIB})
endif()

# readline — optional; enables history and line-editing in the interactive shell
find_library(READLINE_LIB readline)
if(READLINE_LIB)
    target_link_libraries(Gungnir PRIVATE ${READLINE_LIB})
    target_compile_definitions(Gungnir PRIVATE USE_READLINE)
    message(STATUS "readline found — shell history enabled")
else()
    message(STATUS "readline not found — shell will use std::getline")
endif()
