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

@rem Perform encryption and decryption across test vectors
for %%s in (vectors\*.dat) do (
    echo Encrypting: %%s
    "%AESCRYPT%" -q -e -i 8192 -p password -o - "%%s" ^
        | "%AESCRYPT%" -q -d -p password -o "%TEMP%\aescrypt_test" -
    if not exist "%TEMP%\aescrypt_test" (
        echo Error with test vector: %%s
        set RESULT=1
        goto :EXIT_RESULT
    )
    fc "%%s" "%TEMP%\aescrypt_test" > nul
    if errorlevel 1 (
        echo Error with test vector: %%s
        del "%TEMP%\aescrypt_test"
        set RESULT=1
        goto :EXIT_RESULT
    )
    del "%TEMP%\aescrypt_test"
)

:EXIT_RESULT
exit /B %RESULT%
endlocal
