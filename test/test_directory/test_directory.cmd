@echo off

@rem This test will attempt to encrypt a filename that is a directory, which
@rem should fail since AES Crypt requires real filenames.

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

@rem Set the result code to 0 (success)
set RESULT=0

@rem
@rem Attempt to encrypt a directory (this should fail)
@rem

@rem Run your command using PowerShell and capture stderr and the exit code
for /f "tokens=* delims=" %%i in ('powershell -command "try { & {Invoke-Expression (''"%AESCRYPT%" -q -e -p secret -o - %WINDIR%'')} 2>&1; exit $LASTEXITCODE } catch { $_; exit 1 }"') do set "result_text=%%i"
set exit_code=%errorlevel%

if %exit_code% equ 0 (
    echo "Attempt to encrypt a directory should have failed"
    set RESULT=1
    goto :EXIT_RESULT
)

if "%result_text%" neq "Input name is not a file: %WINDIR%" (
    echo Unexpected output: %result_text%
    set RESULT=1
    goto :EXIT_RESULT
)

@rem
@rem Attempt to encrypt a file writing into a directory (this should fail)
@rem

@rem Run your command using PowerShell and capture stderr and the exit code
for /f "tokens=* delims=" %%i in ('powershell -command "try { & {Invoke-Expression (''"%AESCRYPT%" -q -e -p secret -o %WINDIR% %WINDIR%\win.ini'')} 2>&1; exit $LASTEXITCODE } catch { $_; exit 1 }"') do set "result_text=%%i"
set exit_code=%errorlevel%

if %exit_code% equ 0 (
    echo "Attempt to encrypt output to a directory should have failed"
    set RESULT=1
    goto :EXIT_RESULT
)

if "%result_text%" neq "Target output cannot be a directory: %WINDIR%" (
    echo Unexpected output: %result_text%
    set RESULT=1
    goto :EXIT_RESULT
)

@rem
@rem Attempt to decrypt a directory (this should fail)
@rem

@rem Run your command using PowerShell and capture stderr and the exit code
for /f "tokens=* delims=" %%i in ('powershell -command "try { & {Invoke-Expression (''"%AESCRYPT%" -q -d -p secret -o - %WINDIR%'')} 2>&1; exit $LASTEXITCODE } catch { $_; exit 1 }"') do set "result_text=%%i"
set exit_code=%errorlevel%

if %exit_code% equ 0 (
    echo "Attempt to decrypt a directory should have failed"
    set RESULT=1
    goto :EXIT_RESULT
)

if "%result_text%" neq "Input name is not a file: %WINDIR%" (
    echo Unexpected output: %result_text%
    set RESULT=1
    goto :EXIT_RESULT
)

@rem
@rem # Attempt to decrypt a file writing into a directory (this should fail)
@rem

@rem Run your command using PowerShell and capture stderr and the exit code
for /f "tokens=* delims=" %%i in ('powershell -command "try { & {Invoke-Expression (''"%AESCRYPT%" -q -d -p secret -o %WINDIR% %WINDIR%\win.ini'')} 2>&1; exit $LASTEXITCODE } catch { $_; exit 1 }"') do set "result_text=%%i"
set exit_code=%errorlevel%

if %exit_code% equ 0 (
    echo "Attempt to decrypt output to a directory should have failed"
    set RESULT=1
    goto :EXIT_RESULT
)

if "%result_text%" neq "Target output cannot be a directory: %WINDIR%" (
    echo Unexpected output: %result_text%
    set RESULT=1
    goto :EXIT_RESULT
)

:EXIT_RESULT
exit /B %RESULT%
endlocal
