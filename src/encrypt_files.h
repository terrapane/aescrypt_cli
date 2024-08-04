/*
 *  encrypt_files.h
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines a function to encrypt a set of files.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <utility>
#include <terra/conio/progress_meter.h>
#include <terra/logger/logger.h>
#include "secure_containers.h"
#include "process_control.h"

/*
 *  EncryptFiles()
 *
 *  Description:
 *      This function will take a list of filenames and encrypt them serially.
 *      All files are encrypted using the same password and the output will
 *      either be to a new file with a .aes extension or to stdout.
 *
 *  Parameters:
 *      parent_logger [in]
 *          A parent logger to which the child logger would direct logging
 *          messages.
 *
 *      process_control [in]
 *          A structure used by the main thread and worker thread to control
 *          execution.  For example, if the user pressed CTRL-C while
 *          encryption is in progress, it will gracefully terminate
 *          encryption and allow the program to exit.
 *
 *      quiet [in]
 *          If true, the program will not emit messages to the terminal, except
 *          for error messages (which are directed to stderr).
 *
 *      password [in]
 *          The password (in UTF-8 encoding) to use to encrypt files.
 *
 *      iterations [in]
 *          The number of iterations to use with the KDF function.
 *
 *      filenames [in]
 *          A vector of filenames to encrypt.
 *
 *      output_file [in]
 *          The name of the output file if output is going to a single file.
 *          This should not be specified if there is more than one file in
 *          the list of filenames. That requirement is not checked here.
 *
 *      extensions [in]
 *          A list of name/value string pairs that are inserted into the
 *          head of the AES Crypt output stream.  These are neither encrypted
 *          nor authenticated.
 *
 *  Returns:
 *      True if encryption is successful, false if not.
 *
 *  Comments:
 *      None.
 */
bool EncryptFiles(
    const Terra::Logger::LoggerPointer &parent_logger,
    ProcessControl &process_control,
    const bool quiet,
    const SecureU8String &password,
    const std::uint32_t iterations,
    const std::vector<SecureString> &filenames,
    const SecureString &output_file,
    const std::vector<std::pair<std::string, std::string>> &extensions);
