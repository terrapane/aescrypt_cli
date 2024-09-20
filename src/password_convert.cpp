/*
 *  password_convert.cpp
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file implements a function to convert a UTF-16 password to a
 *      UTF-8 password.
 *
 *  Portability Issues:
 *      None.
 */

#include <cstdint>
#include <terra/charutil/character_utilities.h>
#include "password_convert.h"

/*
 *  PasswordConvertUTF8()
 *
 *  Description:
 *      This function will convert a password in UTF-16 encoding to UTF-8.
 *
 *  Parameters:
 *      password [in]
 *          The string containing characters in UTF-16 format.  This must be
 *          an even number of octets.
 *
 *      little_endian [in]
 *          True if the string's octets are in little endian order or not.
 *
 *  Returns:
 *      The UTF-8-encoded string.  If there is an error, an empty string will
 *      be returned.
 *
 *  Comments:
 *      None.
 */
SecureU8String PasswordConvertUTF8(std::span<const char8_t> password,
                                   bool little_endian)
{
    // Ensure there are an even number of octets in the input string
    if ((password.size() & 0x01) != 0) return {};

    // Prepare a buffer large enough (final length will be determined later)
    // Note: This UTF-8 string needs to be 50% larger than the input string
    //       in octets.  Since password.size() is a count of 2-octet characters
    //       as an octet count, then we just add half to the original size.
    SecureU8String u8password(password.size() + (password.size() >> 1), '\0');

    // Convert the character string to UTF-8
    auto [conversion_result, length] = Terra::CharUtil::ConvertUTF16ToUTF8(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(password.data()),
            password.size()),
        std::span<std::uint8_t>(
            reinterpret_cast<std::uint8_t *>(u8password.data()),
            u8password.size()),
        little_endian);

    // Verify the result
    if (!conversion_result || (length == 0)) return {};

    // Adjust the password length
    u8password.resize(length);

    return u8password;
}
