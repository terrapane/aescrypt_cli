/*
 *  error_string.h
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This module implements a function that will return an error string for
 *      the given operating system's error number.
 *
 *  Portability Issues:
 *      None.
 */

#if defined(HAVE_STRERROR_R) || defined(HAVE_STRERROR_S)
#include <array>
#endif
#include <string>
#include <cstring>
#include <terra/logger/logger.h>

/*
 *  GetErrorString()
 *
 *  Description:
 *      Return a string from the operating system corresponding to the
 *      specifed error number.
 *
 *  Parameters:
 *      error [in]
 *          The error code for which an error string is sought.
 *
 *  Returns:
 *      The error message string.
 *
 *  Comments:
 *      This function may not be thread safe due to the call to strerror().
 *      Check operating system documentation if in doubt.
 */
std::string GetErrorString(int error)
{
#if defined(HAVE_POSIX_STRERROR_R) || defined(HAVE_STRERROR_S)
    std::array<char, 256> buffer{};

    // Retrieve the error string
#ifdef HAVE_POSIX_STRERROR_R
    int result = ::strerror_r(error, buffer.data(), buffer.size());
#else
    int result = ::strerror_s(buffer.data(), buffer.size(), error);
#endif

    // Ensure the error message was retrieved
    if (result != 0) return "Error: <message is unavailable>";

    return std::string(buffer.data());
#else
    return ::strerror(error);
#endif
}

/*
 *  LogSystemError()
 *
 *  Description:
 *      Log the last system error to the specified logger with the specified
 *      reason text.
 *
 *  Parameters:
 *      logger [in]
 *          Logger to utilize to log the system error message.
 *
 *      message [in]
 *          Message to report along with the system error information.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
void LogSystemError(const Terra::Logger::LoggerPointer &logger,
                    const std::string &message)
{
    std::string os_error = GetErrorString(errno);

    logger->error << message
                  << " (" << "errno=" << errno << ", msg=" << os_error << ")"
                  << std::flush;
}
