# Ensure CTest can find the test
if(WIN32)
    # MSVC 2022 defaults to using MS Build, and 2026 defaults to Ninja
    if(CMAKE_CONFIGURATION_TYPES)
        add_test(NAME test_file_set
                COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_file_set.cmd ${aescrypt_cli_BINARY_DIR}/src/CONFIG_TYPE/aescrypt.exe)
    else()
        add_test(NAME test_file_set
                COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_file_set.cmd ${aescrypt_cli_BINARY_DIR}/src/aescrypt.exe)
    endif()
else()
    add_test(NAME test_file_set
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_file_set ${aescrypt_cli_BINARY_DIR}/src/aescrypt)
endif()
