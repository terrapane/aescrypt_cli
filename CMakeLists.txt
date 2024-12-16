cmake_minimum_required(VERSION 3.21)

# Define the AES Crypt CLI project
project(aescrypt_cli
        VERSION 4.1.2.0
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

# Option to control ability to install dependencies
option(aescrypt_cli_DEPENDENCIES_INSTALL "Install dependencies" OFF)

# Determine whether clang-tidy will be performed
option(aescrypt_cli_CLANG_TIDY "Use clang-tidy to perform linting during build" OFF)

# Option to control use of the license module (intended for enterprise use)
option(aescrypt_ENABLE_LICENSE_MODULE "Enable license module (disable for private enterprise builds)" ON)

# Ensure static or dynamic build selection trickles down to all dependencies
if(MSVC)
    if(aescrypt_cli_MSVC_STATIC)
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    endif()
endif()

# Set the target deployment version to macOS 10.15; this minimum version will
# be updated in the future when newer system dependencies become desired
if(APPLE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15")
endif()

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
