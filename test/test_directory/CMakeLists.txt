# Include tests based on platform (Windows vs. non-Windows)
if(WIN32)
    add_test(NAME test_directory
             COMMAND powershell -ExecutionPolicy Bypass
                                -File ${CMAKE_CURRENT_SOURCE_DIR}/test_directory.ps1
                                -AESCRYPT "${aescrypt_cli_BINARY_DIR}/src/$<CONFIG>/aescrypt.exe")
else()
    add_test(NAME test_directory
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test_directory ${aescrypt_cli_BINARY_DIR}/src/aescrypt)
endif()
