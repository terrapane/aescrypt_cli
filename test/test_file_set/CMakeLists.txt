# Ensure CTest can find the test
if(WIN32)
    add_test(NAME test_file_set
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_file_set.cmd ${aescrypt_cli_BINARY_DIR}/src/CONFIG_TYPE/aescrypt.exe)
else()
    add_test(NAME test_file_set
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_file_set ${aescrypt_cli_BINARY_DIR}/src/aescrypt)
endif()
