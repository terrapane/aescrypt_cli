@echo off

@rem This program assumes the environment variable CMAKE_CONFIG_TYPE will be
@rem set to Debug or Release (or other value if appropriate).  It uses that
@rem value as a replacement for CONFIG_TYPE, which is a substring in the
@rem passed-in argument.  This is a part of the pathname, so it looks for
@rem the substring /CONFIG_TYPE/ as it makes the substitution.

setlocal enabledelayedexpansion

@rem Set the result code to 0 (success)
set RESULT=0

@rem Get the AES Crypt binary path
set "AESCRYPT=%1"

@rem Ensure AESCRYPT is not an empty string
if "%AESCRYPT%" == "" (
    echo First argument should be the AES Crypt binary
    set RESULT=1
    goto :EXIT_RESULT
)

@rem Ensure CMAKE_CONFIG_TYPE is not an empty string
if "%CMAKE_CONFIG_TYPE%" == "" (
    echo The CMAKE_CONFIG_TYPE variable must contain the build type
    set RESULT=1
    goto :EXIT_RESULT
)

@rem Use the CMAKE_CONFIG_TYPE env variable to determine the correct executable
set "AESCRYPT=!AESCRYPT:/CONFIG_TYPE/=/%CMAKE_CONFIG_TYPE%/!"

@rem Convert pathnames to use \ rather than / (CMake uses /) to pacify Windows
set "AESCRYPT=%AESCRYPT:/=\%"

@rem Ensure the executable binary exists
if not exist "%AESCRYPT%" (
    echo AES Crypt executable not found: %AESCRYPT%
    set RESULT=1
    goto :EXIT_RESULT
)

@rem Switch directories to where the test process resides
cd /D "%~dp0"

@rem Decrypting files using a key containing only ASCII digits
"%AESCRYPT%" -q -d -k keys/digits_utf8.key \
             -o NUL encrypted/sample_digits_v2.txt.aes 2>NUL
if %ERRORLEVEL% neq 0 (
    echo Error with UTF-8 digits key decrypting v2 file
    set RESULT=1
    goto :EXIT_RESULT
)
"%AESCRYPT%" -q -d -k keys/digits_utf16le.key \
             -o NUL encrypted/sample_digits_v2.txt.aes 2>NUL
if %ERRORLEVEL% neq 0 (
    echo Error with UTF-16LE digits key decrypting v2 file
    set RESULT=1
    goto :EXIT_RESULT
)

"%AESCRYPT%" -q -d -k keys/digits_utf8.key \
             -o NUL encrypted/sample_digits_v3.txt.aes 2>NUL
if %ERRORLEVEL% neq 0 (
    echo Error with UTF-8 digits key decrypting v3 file
    set RESULT=1
    goto :EXIT_RESULT
)
"%AESCRYPT%" -q -d -k keys/digits_utf16le.key \
             -o NUL encrypted/sample_digits_v3.txt.aes 2>NUL
if %ERRORLEVEL% neq 0 (
    echo Error with UTF-16LE digits key decrypting v3 file
    set RESULT=1
    goto :EXIT_RESULT
)

# Decrypt files using a key containing Unicode characters
"%AESCRYPT%" -q -d -k keys/unicode_utf8.key \
             -o NUL encrypted/sample_unicode_v2.txt.aes 2>NUL
if %ERRORLEVEL% neq 0 (
    echo Error with UTF-8 Unicode key decrypting v2 file
    set RESULT=1
    goto :EXIT_RESULT
)
"%AESCRYPT%" -q -d -k keys/unicode_utf16le.key \
             -o NUL encrypted/sample_unicode_v2.txt.aes 2>NUL
if %ERRORLEVEL% neq 0 (
    echo Error with UTF-16LE Unicode key decrypting v2 file
    set RESULT=1
    goto :EXIT_RESULT
)

"%AESCRYPT%" -q -d -k keys/unicode_utf8.key \
             -o NUL encrypted/sample_unicode_v3.txt.aes 2>NUL
if %ERRORLEVEL% neq 0 (
    echo Error with UTF-8 Unicode key decrypting v3 file
    set RESULT=1
    goto :EXIT_RESULT
)
"%AESCRYPT%" -q -d -k keys/unicode_utf16le.key \
             -o NUL encrypted/sample_unicode_v3.txt.aes 2>NUL
if %ERRORLEVEL% neq 0 (
    echo Error with UTF-16LE Unicode key decrypting v3 file
    set RESULT=1
    goto :EXIT_RESULT
)

:EXIT_RESULT
exit /B %RESULT%
endlocal
