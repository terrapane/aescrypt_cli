/*
 *  password_prompt.h
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
 *      and return it to the calling function.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <utility>
#include <terra/logger/logger.h>
#include "secure_containers.h"

// Define the possible password-related errors
enum class PasswordResult
{
    UnspecifiedError,
    Success,
    Mismatch,
    NoInput
};

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
 *      Returns a status code of type PasswordResult and the password entered
 *      by the user.  Only if Success is returned does the string have any
 *      valid meaning.
 *
 *  Comments:
 *      None.
 */
std::pair<PasswordResult, SecureU8String> GetUserPassword(
                                Terra::Logger::LoggerPointer parent_logger,
                                bool verify_input);
