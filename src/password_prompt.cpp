/*
 *  password_prompt.cpp
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines the functions to prompt the user for a password
 *      and return it to the calling function.  Input / output is directly
 *      with the TTY / console since stdin/stdout may be used for data.
 *
 *  Portability Issues:
 *      None.
 */

#include <cstdint>
#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>
#include <stdlib.h>
#include "password_convert.h"
#include <span>
#else
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#endif
#include "password_prompt.h"
#include "error_string.h"

namespace
{

#ifdef _WIN32

/*
 *  IsWindowsTerminal()
 *
 *  Description:
 *      This function will check to see if the program is executing inside
 *      Windows Terminal.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      True if executing inside Windows Terminal, false if not.
 *
 *  Comments:
 *      None.
 */
bool IsWindowsTerminal()
{
    char *buffer{};

    // Attempt to get the WT_SESSION environment variable
    if (_dupenv_s(&buffer, nullptr, "WT_SESSION")) return false;

    // If the environment variable is not set, return false
    if (buffer == nullptr) return false;

    free(buffer);

    return true;
}

/*
 *  IsWindows11OrNewer()
 *
 *  Description:
 *      This function will check to see if the system is Windows 11 or newer.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      True if the system is running Windows 11 or newer. In the event of an
 *      error, false is returned.
 *
 *  Comments:
 *      None.
 */
bool IsWindows11OrNewer()
{
    constexpr DWORD Windows11Major = 10;
    constexpr DWORD Windows11Build = 22000;

    typedef NTSTATUS (WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

    // Dynamically load RtlGetVersion from ntdll.dll
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    // Assume < 11 if there is a failure
    if (!ntdll) return false;

    RtlGetVersionPtr RtlGetVersion = reinterpret_cast<RtlGetVersionPtr>(
        GetProcAddress(ntdll, "RtlGetVersion"));

    // Assume < 11 if there is a failure
    if (!RtlGetVersion) return false;

    RTL_OSVERSIONINFOW versionInfo = { sizeof(versionInfo) };
    NTSTATUS status = RtlGetVersion(&versionInfo);
    if (status != 0) return false;

    // Check for Windows 11 (major 10, build >= 22000) or newer (major > 10)
    return (versionInfo.dwMajorVersion > Windows11Major ||
            (versionInfo.dwMajorVersion == Windows11Major &&
             versionInfo.dwBuildNumber >= Windows11Build));
}

/*
 *  ReadTerminalText()
 *
 *  Description:
 *      This function will read text from the terminal.  It will present
 *      the given prompt to the user and then collect input.
 *
 *  Parameters:
 *      logger [in]
 *          Logger to which error messages will be directed.
 *
 *      prompt [in]
 *          The prompt to present to the user before reading input.
 *
 *  Returns:
 *      A pair of values, the first of which indicates success or an error.
 *      If there is a successful result, the string read from the user will
 *      be stored in the second value in the pair.
 *
 *  Comments:
 *      Of the input source is STDIN on Windows, it is not possible to prompt
 *      the user for a password and this function will fail.  For example,
 *      "aescrypt -d -o a_file <a_file.aes" will result in an error that the
 *      password could not be read since stdin is not available to the console.
 *      To use stdin/stdout on Windows, one should provide the password by
 *      using either "-p" or "-k".
 */
std::pair<PasswordResult, SecureU8String> ReadTerminalText(
                                    const Terra::Logger::LoggerPointer &logger,
                                    const std::string &prompt)
{
    PasswordResult password_result = PasswordResult::Success;
    SecureU8String password;
    SecureU8String c(2,' ');
    DWORD read_count;
    DWORD mode;
    DWORD mode_changed{};

    // Make a pointer to simplify referencing the characters read
    wchar_t *c_w = reinterpret_cast<wchar_t *>(c.data());

    // Get the handle for reading input
    HANDLE console_in_handle = GetStdHandle(STD_INPUT_HANDLE);

    // Attempt to disable echo (if it is enabled); this will fail when
    // a console is not available or when AES Crypt is reading from
    // standard input
    if (!GetConsoleMode(console_in_handle, &mode))
    {
        logger->error << "Cannot access the console to read password"
                      << std::flush;
        return {PasswordResult::UnspecifiedError, {}};
    }

    // Turn off console echo if it is on
    if (mode & ENABLE_ECHO_INPUT)
    {
        if (!SetConsoleMode(console_in_handle, mode & (~ENABLE_ECHO_INPUT)))
        {
            logger->error << "Cannot disable echo on console" << std::flush;
            return {PasswordResult::UnspecifiedError, {}};
        }
        mode_changed = true;
    }

    // Get a handle to the console
    HANDLE console_out_handle = GetStdHandle(STD_OUTPUT_HANDLE);

    // Write a message to the console
    WriteConsoleA(console_out_handle,
                  prompt.c_str(),
                  static_cast<DWORD>(prompt.size()),
                  NULL,
                  NULL);

    // Read input from the console
    while (true)
    {
        // Read one Unicode character from the console
        if (!ReadConsoleW(console_in_handle, c_w, 1, &read_count, NULL))
        {
            logger->error << "Error reading from the console: "
                          << GetLastError() << std::flush;
            password_result = PasswordResult::UnspecifiedError;
            break;
        }

        // If nothing was read, continue (should never happen)
        if (read_count == 0) continue;

        // Stop reading once the user hits ENTER (Windows emits CR/LF, but CR
        // would have been discarded by the next line having read it previously)
        if (*c_w == L'\n')
        {
            // For legacy Windows console, we need to emit a CRLF
            if (!IsWindowsTerminal() && !IsWindows11OrNewer())
            {
                WriteConsoleW(console_out_handle, L"\r\n", 2, NULL, NULL);
            }
            break;
        }

        // Discard control characters
        if (*c_w < 0x20) continue;

        // Append the character to the password to form a UTF-16LE string
        password += (*c_w & 0xff);
        password += ((*c_w >> 8) & 0xff);
    }

    // Restore the console mode
    if (mode_changed) SetConsoleMode(console_in_handle, mode);

    // If there was an error, return
    if (password_result != PasswordResult::Success)
    {
        return {password_result, {}};
    }

    // Was a password entered?
    if (password.empty())
    {
        logger->error << "No password was entered" << std::flush;
        return {PasswordResult::NoInput, {}};
    }

    // Convert the UTF-16LE to UTF-8
    password = PasswordConvertUTF8(password, true);

    // If the string is empty, that's an error
    if (password.empty())
    {
        logger->error << "Error converting password to UTF-8" << std::flush;
        return {PasswordResult::UnspecifiedError, {}};
    }

    return {PasswordResult::Success, password};
}

#else

/*
 *  TurnOffEcho()
 *
 *  Description:
 *      Turn off echo on the specified TTY, if it is on.
 *
 *  Parameters:
 *      logger [in]
 *          Logger to which error messages will be directed.
 *
 *      fd [in]
 *          The file descriptor related to the TTY.
 *
 *  Returns:
 *      A pair of boolean values.  The first indicates success or failure of
 *      this function.  The second indicates whether echo was turned off.
 *      The function will return false if echo was already off, but is only
 *      valid if the first boolean it true.
 *
 *  Comments:
 *      None.
 */
std::pair<bool, bool> TurnOffEcho(const Terra::Logger::LoggerPointer &logger,
                                  int fd)
{
    termios tty_attributes{};

    // Get the TTY attributes
    if (tcgetattr(fd, &tty_attributes) == -1)
    {
        LogSystemError(logger, "Unable to get terminal attributes");
        return {false, false};
    }

    // Disable echo if it is on
    if ((tty_attributes.c_lflag & ECHO) != 0)
    {
        tty_attributes.c_lflag &= ~ECHO;
        if (tcsetattr(fd, TCSANOW, &tty_attributes) == -1)
        {
            LogSystemError(logger, "Unable to set terminal attributes");
            return {false, false};
        }

        return {true, true};
    }

    return {true, false};
}

/*
 *  TurnOnEcho()
 *
 *  Description:
 *      Turn echo on for the specified TTY, if it is off.
 *
 *  Parameters:
 *      logger [in]
 *          Logger to which error messages will be directed.
 *
 *      fd [in]
 *          The file descriptor related to the TTY.
 *
 *  Returns:
 *      A pair of boolean values.  The first indicates success or failure of
 *      this function.  The second indicates whether echo was turned on.
 *      The function will return false if echo was already on, but is only
 *      valid if the first boolean it true.
 *
 *  Comments:
 *      None.
 */
std::pair<bool, bool> TurnOnEcho(const Terra::Logger::LoggerPointer &logger,
                                 int fd)
{
    termios tty_attributes{};

    // Get the TTY attributes
    if (tcgetattr(fd, &tty_attributes) == -1)
    {
        LogSystemError(logger, "Unable to get terminal attributes");
        return {false, false};
    }

    // Enable echo if it is off
    if ((tty_attributes.c_lflag & ECHO) == 0)
    {
        tty_attributes.c_lflag |= ECHO;
        if (tcsetattr(fd, TCSANOW, &tty_attributes) == -1)
        {
            LogSystemError(logger, "Unable to set terminal attributes");
            return {false, false};
        }

        return {true, true};
    }

    return {true, false};
}

/*
 *  ReadTerminalText()
 *
 *  Description:
 *      This function will read text from the terminal.  It will present
 *      the given prompt to the user and then collect input.
 *
 *  Parameters:
 *      logger [in]
 *          Logger to which error messages will be directed.
 *
 *      prompt [in]
 *          The prompt to present to the user before reading input.
 *
 *  Returns:
 *      A pair of values, the first of which indicates success or an error.
 *      If there is a successful result, the string read from the user will
 *      be stored in the second value in the pair.
 *
 *  Comments:
 *      None.
 */
std::pair<PasswordResult, SecureU8String> ReadTerminalText(
                                    const Terra::Logger::LoggerPointer &logger,
                                    const std::string &prompt)
{
    PasswordResult password_result = PasswordResult::Success;
    SecureU8String password;
    SecureU8String c(1,' ');

    // Open the TTY for reading / writing
    int fd = open("/dev/tty", O_RDWR | O_CLOEXEC);

    // If there was an error, report and return
    if (fd == -1)
    {
        LogSystemError(logger, "Unable to open terminal device");
        return {PasswordResult::UnspecifiedError, {}};
    }

    // Turn off echo
    auto [echo_off_result, echo_disabled] = TurnOffEcho(logger, fd);
    if (!echo_off_result) return {PasswordResult::UnspecifiedError, {}};

    // Emit the prompt
    if (write(fd, prompt.data(), prompt.size()) == -1)
    {
        LogSystemError(logger, "Unable to emit password prompt");
        close(fd);
        return {PasswordResult::UnspecifiedError, {}};
    }

    // Read the terminal for password text
    while (true)
    {
        // Read a single character
        ssize_t result = read(fd, c.data(), 1);

        // If there was an error, then fail
        if (result == -1)
        {
            LogSystemError(logger, "Error reading password input");
            password_result = PasswordResult::UnspecifiedError;
            break;
        }

        // If nothing was read, continue (should never happen)
        if (result == 0) continue;

        // Stop reading once the user hits ENTER
        if (c[0] == '\n')
        {
            // Emit the NL character
            if (write(fd, c.data(), c.size()) == -1)
            {
                LogSystemError(logger, "Unable to emit newline to terminal");
                password_result = PasswordResult::UnspecifiedError;
                break;
            }

            break;
        }

        // Discard control characters
        if (static_cast<std::uint8_t>(c[0]) < 0x20) continue;

        // Append the character to the password
        password += c;
    }

    // If echo was disabled, re-enable it
    if (echo_disabled) TurnOnEcho(logger, fd);

    // Close the TTY
    close(fd);

    // Was a password entered?
    if ((password_result == PasswordResult::Success) && (password.empty()))
    {
        logger->error << "No password was entered" << std::flush;
        return {PasswordResult::NoInput, {}};
    }

    return {password_result, password};
}

#endif // _WIN32

} // namespace

/*
 *  GetUserPassword()
 *
 *  Description:
 *      This function will ask the user to provide a password and return
 *      that password to the calling function.  If the string is empty,
 *      it indicates an error.
 *
 *  Parameters:
 *      parent_logger [in]
 *          The logging object used to emit logging messages.
 *
 *      verify_input [in]
 *          This is set to true if the password prompt should be presented
 *          twice and the passwords compared for consistency.  This is to
 *          ensure the user did not mistype the password when encrypting.
 *
 *  Returns:
 *      Returns a status code of type PasswordResult.  Only if Success is
 *      returned does the string contain the password.
 *
 *  Comments:
 *      None.
 */
std::pair<PasswordResult, SecureU8String> GetUserPassword(
                            const Terra::Logger::LoggerPointer &parent_logger,
                            bool verify_input)
{
    // Create a child logger
    Terra::Logger::LoggerPointer logger =
        std::make_shared<Terra::Logger::Logger>(parent_logger, "PMPT");

    logger->info << "Preparing to prompt for the password" << std::flush;

    // Prompt user for the password
    auto [result_password, user_input] =
        ReadTerminalText(logger, "Enter password: ");

    // Return early on error
    if (result_password != PasswordResult::Success)
    {
        logger->error << "Unable to get password" << std::flush;
        return {result_password, {}};
    }

    // Verify the input?
    if (verify_input)
    {
        // Prompt user for the password again
        auto [result_verify, again] =
            ReadTerminalText(logger, "Re-enter password: ");

        // Return early on error
        if (result_verify != PasswordResult::Success)
        {
            logger->error << "Unable to get password: " << std::flush;
            return {result_verify, {}};
        }

        // Verify the passwords match
        if (user_input != again)
        {
            logger->error << "Passwords entered do not match" << std::flush;
            return {PasswordResult::Mismatch, {}};
        }
    }

    logger->info << "Finishing prompting for the password" << std::flush;

    return {PasswordResult::Success, user_input};
}
