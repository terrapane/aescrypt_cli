/*
 *  key_file.h
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines function related to reading and writing key files.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <cstddef>
#include <terra/logger/logger.h>
#include "secure_containers.h"

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
 *      None.
 */
bool GenerateKeyFile(const Terra::Logger::LoggerPointer parent_logger,
                     const SecureString &key_file,
                     std::size_t key_length);

/*
 *  ReadKeyFile()
 *
 *  Description:
 *      This function will read a key file and ensure the returned data is
 *      in UTF-8 format.  Key files may be in either UTF-8 or UTF-16LE format.
 *      UTF-16 data will be converted to UTF-8 before returned.
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
 *
 *  Comments:
 *      None.
 */
SecureU8String ReadKeyFile(const Terra::Logger::LoggerPointer parent_logger,
                           const SecureString &key_file);
