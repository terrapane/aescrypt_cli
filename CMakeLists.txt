cmake_minimum_required(VERSION 3.21)

# Define the AES Crypt CLI project
project(aescrypt_cli
        VERSION 4.0.1.0
        DESCRIPTION "AES Crypt Command-Line (CLI) Program"
        LANGUAGES CXX
        HOMEPAGE_URL "https://www.aescrypt.com")

set(COPYRIGHT_TEXT "Copyright (C) 2024")
set(AUTHOR_TEXT    "Terrapane Corporation")

# Tests are built by default when this is a top-level project
if(PROJECT_IS_TOP_LEVEL)
    option(aescrypt_cli_BUILD_TESTS "Build Tests for the AES Crypt CLI" ON)
    if(MSVC)
        option(aescrypt_cli_MSVC_STATIC "Build AES Crypt CLI Statically" ON)
    endif()
else()
    option(aescrypt_cli_BUILD_TESTS "Build Tests for the AES Crypt CLI" OFF)
    if(MSVC)
        option(aescrypt_cli_MSVC_STATIC "Build AES Crypt CLI Statically" OFF)
    endif()
endif()

# Option to control ability to install the program
option(aescrypt_cli_INSTALL "Install the AES Crypt CLI Program" ON)

# If building statically, this setting must trickle down to all dependencies
if(aescrypt_cli_MSVC_STATIC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Determine whether clang-tidy will be performed
option(aescrypt_cli_CLANG_TIDY "Use clang-tidy to perform linting during build" OFF)

add_subdirectory(dependencies)
add_subdirectory(src)

# Include packaging only if this is the top-level project
if(PROJECT_IS_TOP_LEVEL)
    add_subdirectory(packaging)
endif()

include(CTest)

if(BUILD_TESTING AND aescrypt_cli_BUILD_TESTS)
    add_subdirectory(test)
endif()
