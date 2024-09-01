/*
 *  key_file.cpp
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file implements function related to reading and writing key files.
 *
 *  Portability Issues:
 *      None.
 */

#include <iostream>
#include <fstream>
#include <filesystem>
#include <memory>
#include <cstdint>
#include <climits>
#include <cstring>
#include <algorithm>
#include <span>
#include <string>
#include <terra/random/random_generator.h>
#include <terra/charutil/character_utilities.h>
#include "key_file.h"
#include "error_string.h"
#include "password_convert.h"

// It is assumed a character is 8 bits
static_assert(CHAR_BIT == 8);

// Character set to use for key files
static const char Key_Characters[64] =
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '_', '+'
};

/*
 *  GenerateKeyFile()
 *
 *  Description:
 *      This function will generate a key file.
 *
 *  Parameters:
 *      parent_logger [in]
 *          Parent logging object.
 *
 *      key_file [in]
 *          The name of the key file to create.
 *
 *      key_size [in]
 *          The size (in octets) of the random key data to emit.  Since each
 *          each octet has 6 bits of entropy, it is recommended to use a key
 *          file size of at least 43 octets to arrive at a 256-bit key.  The
 *          length can be any value, so long as the system has enough RAM.
 *
 *  Returns:
 *      True if successful, false if unsuccessful.  Errors will be emitted
 *      to stderr.
 *
 *  Comments:
 *      Key files are actually just text files containing a random string
 *      of characters.  Key files with a key length >= 256 bits of entropy
 *      are strongly recommended.  As an aside, older versions of AES Crypt
 *      used UTF-16LE for password files.
 */
bool GenerateKeyFile(const Terra::Logger::LoggerPointer &parent_logger,
                     const SecureString &key_file,
                     std::size_t key_size)
{
    std::ofstream file_stream;
    Terra::Random::RandomGenerator rng;
    bool using_stdout = true;

    // Create a child logger
    Terra::Logger::LoggerPointer logger =
        std::make_shared<Terra::Logger::Logger>(parent_logger, "KGEN");

    logger->info << "Preparing to generate key file" << std::flush;

    // Ensure the key length is not 0
    if (key_size == 0)
    {
        logger->error << "Key length is zero, which is not allowed"
                      << std::flush;
    }

    // If the file is not stdout, open the file
    if (key_file != "-")
    {
        // Filenames should be in UTF-8 format, so form a UTF-8 string type
        // for use with open()
        SecureU8String u8name(key_file.cbegin(), key_file.cend());

        try
        {
            // Ensure we do not overwrite an existing regular file
            if (std::filesystem::is_regular_file(std::filesystem::path(u8name)))
            {
                logger->error << "Specified key file name already exists: "
                              << key_file << std::flush;
                return false;
            }
        }
        catch (const std::filesystem::filesystem_error &e)
        {
            logger->error << "Exception checking key file existence: "
                          << key_file << "(file system err=" << e.what()
                          << ")" << std::flush;
            return false;
        }
        catch (const std::exception &e)
        {
            logger->error << "Exception checking key file existence: "
                          << key_file << "(err=" << e.what() << ")"
                          << std::flush;
            return false;
        }
        catch (...)
        {
            logger->error << "Exception checking key file existence: "
                          << key_file << std::flush;
            return false;
        }

        try
        {
            // Open the file for writing
            file_stream.open(std::filesystem::path(u8name), std::ios::out);
        }
        catch (const std::filesystem::filesystem_error &e)
        {
            logger->error << "Exception opening key file: "
                          << key_file << "(file system err=" << e.what()
                          << ")" << std::flush;
        }
        catch (const std::exception &e)
        {
            logger->error << "Exception opening key file: " << key_file
                          << "(err=" << e.what() << ")" << std::flush;
        }
        catch (...)
        {
            logger->error << "Exception opening key file: " << key_file
                          << std::flush;
        }

        // Ensure the file opened properly
        if (!file_stream.good() || !file_stream.is_open())
        {
            LogSystemError(logger,
                           std::string("Failed to open key file: \"") +
                               static_cast<std::string>(key_file) + "\"");
            return false;
        }

        // Not directing to stdout
        using_stdout = false;
    }

    // Assign the effective output stream to the "stream" variable
    std::ostream &stream = (using_stdout ? std::cout : file_stream);

    // Generate the random octets
    SecureVector<std::uint8_t> key(key_size);
    rng.GetRandomOctets(key);

    // Convert each to printable character (retains 6 bits of entropy)
    for (auto &value : key) value = Key_Characters[(value & 0x3f)];

    // Output a stream of octets
    stream.write(reinterpret_cast<char *>(key.data()),
                 static_cast<std::streamsize>(key.size()));

    // Check for write errors
    if (!stream.good())
    {
        LogSystemError(logger, "Error writing data to the output file");

        // Close and remove the key file
        if (!using_stdout)
        {
            // Filenames should be in UTF-8 format, so form a UTF-8 string type
            // for use with open()
            SecureU8String u8name(key_file.cbegin(), key_file.cend());

            try
            {
                if (file_stream.is_open()) file_stream.close();
                std::filesystem::remove(std::filesystem::path(u8name));
            }
            catch (const std::filesystem::filesystem_error &e)
            {
                logger->error << "Unable to remove key file: " << key_file
                              << " (file system err=" << e.what() << ")"
                              << std::flush;
                return false;
            }
            catch (const std::exception &e)
            {
                logger->error << "Unable to remove key file: "
                              << key_file << " (err=" << e.what() << ")"
                              << std::flush;
                return false;
            }
            catch (...)
            {
                logger->error << "Exception removing key file: " << key_file
                              << std::flush;
                return false;
            }
        }

        return false;
    }

    // Flush and close the output stream
    file_stream.flush();
    file_stream.close();

    logger->info << "Key file generated" << std::flush;

    return true;
}

/*
 *  ReadKeyFile()
 *
 *  Description:
 *      This function will read a key file and return the key value.  Key
 *      files may be in either UTF-8 or UTF-16LE format.
 *
 *  Parameters:
 *      parent_logger [in]
 *          Parent logging object.
 *
 *      key_file [in]
 *          The name of the key file to read.
 *
 *  Returns:
 *      A string containing the key or an empty string if there was an error.
 *      The returned string will be encoded as UTF-8.
 *
 *  Comments:
 *      None.
 */
SecureU8String ReadKeyFile(const Terra::Logger::LoggerPointer &parent_logger,
                           const SecureString &key_file)
{
    SecureU8String key;
    std::ifstream file_stream;
    bool using_stdin = true;
    bool little_endian = true;

    // Create a child logger
    Terra::Logger::LoggerPointer logger =
        std::make_shared<Terra::Logger::Logger>(parent_logger, "KFLE");

    logger->info << "Preparing to read key file" << std::flush;

    // Is the key file coming from stdin?
    if (key_file != "-")
    {
        // Filenames should be in UTF-8 format, so form a UTF-8 string type
        // for use with open()
        SecureU8String u8name(key_file.cbegin(), key_file.cend());

        try
        {
            // Open the file for writing
            file_stream.open(std::filesystem::path(u8name), std::ios::in);
        }
        catch (const std::filesystem::filesystem_error &e)
        {
            logger->error << "Exception opening key file: "
                          << key_file << "(file system err=" << e.what()
                          << ")" << std::flush;
        }
        catch (const std::exception &e)
        {
            logger->error << "Exception opening key file: " << key_file
                          << "(err=" << e.what() << ")" << std::flush;
        }
        catch (...)
        {
            logger->error << "Exception opening key file: " << key_file
                          << std::flush;
        }

        // Ensure the file opened properly
        if (!file_stream.good() || !file_stream.is_open())
        {
            LogSystemError(logger,
                           std::string("Failed to open input file \"") +
                               static_cast<std::string>(key_file) + "\"");
            return {};
        }

        // Not reading from stdin
        using_stdin = false;
    }

    // Assign the effective input stream to the "stream" variable
    std::istream &stream = (using_stdin ? std::cin : file_stream);

    // Read the entire file
    while (!stream.eof())
    {
        char octet{};

        // Read a single character
        stream.get(octet);

        // Check for errors
        if (!stream.good() && !stream.eof())
        {
            LogSystemError(logger,
                           std::string("Failed reading input file \"") +
                               static_cast<std::string>(key_file) + "\"");
            return {};
        }

        // Store octet is not EOF
        if (!stream.eof()) key.push_back(octet);
    }

    // Close the key file if still open
    if (file_stream.is_open()) file_stream.close();

    // If there is no key, return early
    if (key.empty())
    {
        logger->error << "No valid data read from the key file" << std::flush;
        return {};
    }

    // If the key does not start with byte-order-mark (BOM) value 0xFF or 0xFE,
    // it is assumed to be UTF-8
    if ((static_cast<std::uint8_t>(key[0]) != 0xFE) &&
        (static_cast<std::uint8_t>(key[0]) != 0xFF))
    {
        // Iterate over the key, truncating the key at the first observation
        // if \0, \r, or \n
        for (std::size_t i = 0; i < key.size(); i++)
        {
            if ((key[i] == '\0') || (key[i] == '\r') || (key[i] == '\n'))
            {
                key.resize(i);
                break;
            }
        }

        // Verify that the key if proper UTF-8
        if (!Terra::CharUtil::IsUTF8Valid(
                {reinterpret_cast<const std::uint8_t *>(key.data()),
                 key.size()}))
        {
            logger->error << "Key data does not appear to be valid UTF-8"
                          << std::flush;
            return {};
        }

        return key;
    }

    // UTF-16 data should have an even number of octets
    if ((key.length() & 0x01) != 0)
    {
        logger->error << "Key has an odd number of octets; UTF-16 data has "
                         "an even number of octets"
                      << std::flush;
        return {};
    }

    // The key length must be >= 4 since the BOM occupies the first 2 octets
    if (key.length() < 4)
    {
        logger->error << "Key file data appears to be too short" << std::flush;
        return {};
    }

    // Inspect the first octet to determine endianness
    little_endian = (static_cast<std::uint8_t>(key[0]) == 0xFF);

    // Strip off the BOM
    key.erase(0, 2);

    // Convert the UTF-16 key (password) to UTF-8
    key = PasswordConvertUTF8(key, little_endian);

    // Ensure the key is not empty
    if (key.empty())
    {
        logger->error << "Failed to convert key text to UTF-8" << std::flush;
        return {};
    }

    logger->info << "Finished reading the key file" << std::flush;

    return key;
}
