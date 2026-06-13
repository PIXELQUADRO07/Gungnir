cmake_minimum_required(VERSION 3.15)
project(Gungnir VERSION 1.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads  REQUIRED)
find_package(CURL     REQUIRED)
find_package(SQLite3  REQUIRED)
find_package(OpenSSL  REQUIRED)

set(SOURCES
    src/main.cpp
    src/engine.cpp
    src/shell.cpp
    src/updater.cpp
    src/database.cpp
    src/config.cpp
    src/workspace.cpp
    src/report_gen.cpp
    modules/scraper.cpp
    modules/network/network.cpp
    modules/network/http_client.cpp
    modules/network/waf.cpp
    modules/network/ssl_geoip.cpp
    modules/network/screenshot.cpp
    modules/recon/recon.cpp
    modules/recon/socmint.cpp
    modules/recon/secrets.cpp
    modules/recon/threat_intel.cpp
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
    OpenSSL::SSL
    OpenSSL::Crypto
)

find_library(RESOLV_LIB resolv)
if(RESOLV_LIB)
    target_link_libraries(Gungnir PRIVATE ${RESOLV_LIB})
endif()

find_library(READLINE_LIB readline)
if(READLINE_LIB)
    target_link_libraries(Gungnir PRIVATE ${READLINE_LIB})
    target_compile_definitions(Gungnir PRIVATE USE_READLINE)
    message(STATUS "readline found — shell history enabled")
else()
    message(STATUS "readline not found — shell will use std::getline")
endif()

# ─── Installation ─────────────────────────────────────────────────────────────

install(TARGETS Gungnir RUNTIME DESTINATION bin)

# ─── Testing ──────────────────────────────────────────────────────────────────

option(BUILD_TESTS "Build unit tests" ON)

if(BUILD_TESTS)
    enable_testing()
    include(FetchContent)
    FetchContent_Declare(
      googletest
      URL https://github.com/google/googletest/archive/refs/heads/main.zip
    )
    # For Windows: prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    add_executable(gungnir_tests
        tests/test_main.cpp
        tests/test_logger.cpp
        tests/test_config.cpp
        # Add core logic sources for testing
        utils/logger.cpp
        src/config.cpp
    )
    target_link_libraries(gungnir_tests PRIVATE gtest_main)
    target_include_directories(gungnir_tests PRIVATE src utils modules vendor)
    
    include(GoogleTest)
    gtest_discover_tests(gungnir_tests)
endif()