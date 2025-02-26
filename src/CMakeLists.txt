# Build a version number into the binary library
configure_file(version.h.in version.h @ONLY)

# Threading support is required
find_package(Threads REQUIRED)

# Create the executable
add_executable(aescrypt
    aescrypt.cpp
    key_file.cpp
    error_string.cpp
    password_prompt.cpp
    encrypt_files.cpp
    decrypt_files.cpp
    password_convert.cpp  ${CMAKE_CURRENT_BINARY_DIR}/version.rc)

# Include version.rc (version data) and aescrypt.rc (application icon)
if(WIN32)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/version.rc @ONLY)
    target_sources(aescrypt
        PRIVATE
            aescrypt.rc
            ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
endif()

# Declare the include directories
target_include_directories(aescrypt
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)

# Specify the C++ standard to observe
set_target_properties(aescrypt
    PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF)

# Use the following compile options
target_compile_options(aescrypt
    PRIVATE
        $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>: -Wpedantic -Wextra -Wall>
        $<$<CXX_COMPILER_ID:MSVC>: >)

# Link against library dependencies
target_link_libraries(aescrypt
    PRIVATE
        Terra::aescrypt_engine
        Terra::program_options
        Terra::conio
        Terra::logger
        Terra::secutil
        Terra::random
        Terra::charutil
        Threads::Threads)

# Check to see if the licensing module is disabled; this is to allow
# enterprise customers to build AES Crypt without license checks
if(aescrypt_ENABLE_LICENSE_MODULE)
    # Include the AES Crypt licensing module
    target_link_libraries(aescrypt PRIVATE Terra::aescrypt_lm)

    # Set the compiler definition to perform licensing checks
    target_compile_definitions(aescrypt PRIVATE AESCRYPT_ENABLE_LICENSE_MODULE)
endif()

# For MSVC, this is required to support file globbing (wildcards) and ensure
# that code is built to use Unicode
if(MSVC)
    target_link_options(aescrypt PRIVATE setargv.obj)
    target_compile_definitions(aescrypt PRIVATE UNICODE _UNICODE)
endif()

# If requesting clang-tidy, try to look for it
if(aescrypt_cli_CLANG_TIDY)
    find_program(CLANG_TIDY_COMMAND NAMES "clang-tidy")
    if(CLANG_TIDY_COMMAND)
        set_target_properties(aescrypt PROPERTIES CXX_CLANG_TIDY "${CLANG_TIDY_COMMAND}")
    else()
        message(WARNING "Could not find clang-tidy")
    endif()
endif()

# Install the executable and man page, as appropriate
if(aescrypt_cli_INSTALL)
    include(GNUInstallDirs)
    install(TARGETS aescrypt RUNTIME)
    if(NOT WIN32)
        install(FILES ${PROJECT_SOURCE_DIR}/man/aescrypt.1.gz DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
    endif()
endif()
