/*
 *  password_convert.h
 *
 *  Copyright (C) 2024, 2025
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines functions to convert a UTF-16 password to a
 *      UTF-8 password.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <span>
#include "secure_containers.h"

/*
 *  PasswordConvertUTF8()
 *
 *  Description:
 *      This function will convert a password in UTF-16 encoding to UTF-8.
 *
 *  Parameters:
 *      password [in]
 *          The string containing characters in UTF-16 format.
 *
 *      little_endian [in]
 *          True if the string's octets are in little endian order or not.
 *          This defaults to true, sime most modern computers utilize
 *          little endian (including all Windows machines).
 *
 *  Returns:
 *      The UTF-8-encoded string.  If there is an error, an empty string will
 *      be returned.
 *
 *  Comments:
 *      None.
 */
SecureU8String PasswordConvertUTF8(std::span<const char8_t> password,
                                   bool little_endian = true);
