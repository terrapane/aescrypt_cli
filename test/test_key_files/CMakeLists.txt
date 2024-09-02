# Ensure CTest can find the test
if(WIN32)
    add_test(NAME test_key_files
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_key_files.cmd ${aescrypt_cli_BINARY_DIR}/src/CONFIG_TYPE/aescrypt.exe)
else()
    add_test(NAME test_key_files
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_key_files ${aescrypt_cli_BINARY_DIR}/src/aescrypt)
endif()
