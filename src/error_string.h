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
 *      This module defines a function that will return an error string for
 *      the given operating system's error number.
 *
 *  Portability Issues:
 *      None.
 */

#include <string>

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
 *      None.
 */
std::string GetErrorString(int error);

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
void LogSystemError(const Terra::Logger::LoggerPointer logger,
                    const std::string &message);
