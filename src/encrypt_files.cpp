/*
 *  encrypt_files.cpp
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file implements functions to encrypt a set of files.
 *
 *  Portability Issues:
 *      None.
 */

#include <iostream>
#include <filesystem>
#include <fstream>
#include <thread>
#include <mutex>
#include <cstdint>
#include <terra/aescrypt/engine/encryptor.h>
#include "encrypt_files.h"
#include "error_string.h"
#include "aescrypt.h"

namespace
{

/*
 *  EncryptStream()
 *
 *  Description:
 *      This function will encrypt the given input stream to the given output
 *      stream using the specified password.
 *
 *  Parameters:
 *      logger [in]
 *          The logger to which logging output will be sent.
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
 *      extensions [in]
 *          A list of name/value string pairs that are inserted into the
 *          head of the AES Crypt output stream.  These are neither encrypted
 *          nor authenticated.
 *
 *      input_size [in]
 *          The number of octets in the input stream (if known).
 *
 *      istream [in]
 *          Input stream from which plaintext is read.
 *
 *      ostream [out]
 *          Output stream to which ciphertext is written.
 *
 *  Returns:
 *      True if encryption is successful, false if not.
 *
 *  Comments:
 *      None.
 */
bool EncryptStream(
    const Terra::Logger::LoggerPointer &logger,
    ProcessControl &process_control,
    bool quiet,
    const SecureU8String &password,
    const std::uint32_t iterations,
    const std::vector<std::pair<std::string, std::string>> &extensions,
    const std::size_t input_size,
    std::istream &istream,
    std::ostream &ostream)
{
    Terra::AESCrypt::Engine::EncryptResult encrypt_result{};
    bool encryption_complete{};
    bool cancel_encryption{};

    using namespace Terra::AESCrypt::Engine;

    // Create a ProgressMeter object matching the size of the input
    Terra::ConIO::ProgressMeter progress_meter((quiet ? 0 : input_size));

    // Set some reasonably low limit for the update interval
    std::size_t update_interval =
        input_size / Terra::ConIO::ProgressMeter::Default_Maximum_Width;

    // Arbitrarily select a minimum file size to drive the meter, which is
    // large enough to move the meter one position for the distance
    if (update_interval <
        Terra::ConIO::ProgressMeter::Default_Maximum_Width * 16)
    {
        update_interval = 0;
    }

    // Start the progress meter (if enabled with non-zero size)
    if (update_interval > 0) progress_meter.Start();

    // Progress meter update function
    auto meter_updater = [&]([[maybe_unused]]const std::string &,
                             std::size_t position)
    {
        progress_meter.Update(position);
    };

    // Create an AES Crypt Engine Encryptor object
    Encryptor encryptor(logger);

    // Encrypt the stream via a separate thread
    std::thread encrypt_thread(
        [&]()
        {
            // Encrypt the current input stream
            encrypt_result = encryptor.Encrypt(
                static_cast<std::u8string>(password),
                iterations,
                istream,
                ostream,
                extensions,
                meter_updater,
                input_size /
                    Terra::ConIO::ProgressMeter::Default_Maximum_Width);

            // Lock the mutex to assign result
            std::lock_guard<std::mutex> lock(process_control.mutex);
            encryption_complete = true;
            process_control.cv.notify_all();
        });

    // Lock the mutex
    std::unique_lock<std::mutex> lock(process_control.mutex);

    // Wait for encryption to complete or to be told to terminate
    process_control.cv.wait(lock,
                            [&]() -> bool
                            {
                                return encryption_complete ||
                                       process_control.terminate;
                            });

    // If the process should terminate, cancel encrytion if still going
    cancel_encryption = process_control.terminate && (!encryption_complete);

    // Unlock the mutex
    lock.unlock();

    // Clear the progress meter
    progress_meter.Stop();

    // If the process should terminate, can encryption if still working
    if (cancel_encryption)
    {
        std::cerr << "Request cancelled; cleaning up..." << std::endl;
        encryptor.Cancel();
    }

    // Wait for the encryption thread to exit
    encrypt_thread.join();

    // If encryption failed for reasons other than cancellation, report why
    if ((encrypt_result != EncryptResult::Success) &&
        (encrypt_result != EncryptResult::EncryptionCancelled))
    {
        std::cerr << "Error encrypting file: " << encrypt_result
                  << std::endl;
        return false;
    }

    return encrypt_result == EncryptResult::Success;
}

} // namespace

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
    const std::vector<std::pair<std::string, std::string>> &extensions)
{
    SecureString out_file;
    bool stdout_used = (output_file == "-");

    // Secure buffer for file I/O
    SecureVector<char> read_buffer(Buffered_IO_Size, 0);
    SecureVector<char> write_buffer(Buffered_IO_Size, 0);

    // Create a child logger
    Terra::Logger::LoggerPointer logger =
        std::make_shared<Terra::Logger::Logger>(parent_logger, "FILE");

    logger->info << "Encryption process starting" << std::flush;

    // Iterate over each file and encrypt it
    for (const auto &in_file : filenames)
    {
        std::size_t file_size{};
        std::ifstream ifs;
        std::ofstream ofs;
        bool remove_on_fail{};

        logger->info << "Encrypting: " << in_file << std::flush;

        // If this file is NOT stdin, get the file size
        if (in_file != "-")
        {
            // Filenames should be in UTF-8 format, so form a UTF-8 string type
            // for use with open() and file_size()
            SecureU8String u8name(in_file.cbegin(), in_file.cend());

            try
            {
                // Get the input file status
                std::filesystem::file_status file_status =
                    std::filesystem::status(std::filesystem::path(u8name));

                // If the input file does not exist, report an error
                if (!std::filesystem::exists(file_status))
                {
                    Terra::SecUtil::SecureString error_text;
                    error_text = "Input file does not exist: " + in_file;
                    logger->error << error_text << std::flush;
                    std::cerr << error_text << std::endl;
                    return false;
                }

                // The specified input file must be a regular file
                if (!std::filesystem::is_regular_file(file_status))
                {
                    Terra::SecUtil::SecureString error_text;
                    error_text = "Input name is not a file: " + in_file;
                    logger->error << error_text << std::flush;
                    std::cerr << error_text << std::endl;
                    return false;
                }
            }
            catch (const std::filesystem::filesystem_error &e)
            {
                Terra::SecUtil::SecureString error_text;
                error_text = "Error checking input file: " + in_file +
                             " (file system err=" + e.what() + ")";
                logger->error << error_text << std::flush;
                std::cerr << error_text << std::endl;
                return false;
            }
            catch (const std::exception &e)
            {
                Terra::SecUtil::SecureString error_text;
                error_text = "Error checking input file: " + in_file +
                             " (err=" + e.what() + ")";
                logger->error << error_text << std::flush;
                std::cerr << error_text << std::endl;
                return false;
            }
            catch (...)
            {
                Terra::SecUtil::SecureString error_text;
                error_text = "Error checking input file: " + in_file;
                logger->error << error_text << std::flush;
                std::cerr << error_text << std::endl;
                return false;
            }

            try
            {
                // Attempt to get the file size
                file_size =
                    std::filesystem::file_size(std::filesystem::path(u8name));
            }
            catch (const std::filesystem::filesystem_error &e)
            {
                logger->warning << "Unable to determine input file size "
                                   "(file system err="
                                << e.what() << ")" << std::flush;
            }
            catch (const std::exception &e)
            {
                logger->warning << "Unable to determine input file size (err="
                                << e.what() << ")" << std::flush;
            }
            catch (...)
            {
                logger->warning << "Unable to determine input file size"
                                << std::flush;
            }

            try
            {
                // Open the input file for reading
                ifs.open(std::filesystem::path(u8name),
                         std::ios::in | std::ios::binary);
            }
            catch (const std::filesystem::filesystem_error &e)
            {
                logger->error << "Exception opening input file "
                                 "(file system err="
                              << e.what() << ")" << std::flush;
            }
            catch (const std::exception &e)
            {
                logger->error << "Exception opening input file (err="
                              << e.what() << ")" << std::flush;
            }
            catch (...)
            {
                logger->error << "Exception opening input file" << std::flush;
            }
            if (!ifs.good() || !ifs.is_open())
            {
                LogSystemError(logger,
                               std::string("Unable to open input file: ") +
                                   static_cast<std::string>(in_file));
                std::cerr << "Unable to open input file: " << in_file
                          << std::endl;
                return false;
            }

            // Current output filename will be the input filename + .aes
            if (output_file.empty())
            {
                out_file = in_file + ".aes";
            }
            else
            {
                out_file = output_file;
            }
        }
        else
        {
            out_file = output_file;
        }

        // Assign the input file stream
        std::istream &istream = ((in_file == "-") ? std::cin : ifs);

        // Set the buffer to use for reading
        istream.rdbuf()->pubsetbuf(
            read_buffer.data(),
            static_cast<std::streamsize>(read_buffer.size()));

        // Open the output stream
        if (out_file != "-")
        {
            // Filenames should be in UTF-8 format, so form a UTF-8 string type
            // for use with open()
            SecureU8String u8name(out_file.cbegin(), out_file.cend());

            try
            {
                // Get the file status
                std::filesystem::file_status file_status =
                    std::filesystem::status(std::filesystem::path(u8name));

                // Is the output name a directory?
                if (std::filesystem::is_directory(file_status))
                {
                    std::cerr << "Target output cannot be a directory: "
                              << out_file << std::endl;
                    return false;
                }

                // If the output file does not exist, attempt to remove later
                // (Do not remove by default so as to not attempt to remove
                // things like character special devices.)
                if (!std::filesystem::exists(file_status))
                {
                    remove_on_fail = true;
                }

                // Does a regular file having this output file name exist?
                if (std::filesystem::is_regular_file(file_status))
                {
                    std::cerr << "Target output file already exists: "
                              << out_file << std::endl;
                    return false;
                }
            }
            catch (const std::filesystem::filesystem_error &e)
            {
                logger->error << "Exception checking output file existence: "
                              << out_file << "(file system err=" << e.what()
                              << ")" << std::flush;
                std::cerr << "Unable to open output file: " << out_file
                          << std::endl;
                return false;
            }
            catch (const std::exception &e)
            {
                logger->error << "Exception checking output file existence: "
                              << out_file << "(err=" << e.what() << ")"
                              << std::flush;
                std::cerr << "Unable to open output file: " << out_file
                          << std::endl;
                return false;
            }
            catch (...)
            {
                logger->error << "Exception checking output file existence: "
                              << out_file << std::flush;
                std::cerr << "Unable to open output file: " << out_file
                          << std::endl;
                return false;
            }

            try
            {
                // Open the output file for writing
                ofs.open(std::filesystem::path(u8name),
                         std::ios::out | std::ios::binary);
            }
            catch (const std::filesystem::filesystem_error &e)
            {
                logger->error << "Exception opening output file: " << out_file
                              << " (file system err=" << e.what() << ")"
                              << std::flush;
            }
            catch (const std::exception &e)
            {
                logger->error << "Exception opening output file: " << out_file
                              << " (err=" << e.what() << ")" << std::flush;
            }
            catch (...)
            {
                logger->error << "Exception opening output file: " << out_file
                              << std::flush;
            }
            if (!ofs.good() || !ofs.is_open())
            {
                LogSystemError(logger,
                               std::string("Unable to open output file: ") +
                                   static_cast<std::string>(out_file));
                std::cerr << "Unable to open output file: " << out_file
                          << std::endl;
                return false;
            }

            if (!quiet) std::cout << "Encrypting: " << in_file << std::endl;
        }

        // Assign the output file stream
        std::ostream &ostream = ((out_file == "-") ? std::cout : ofs);

        // Set the buffer to use for writing
        ofs.rdbuf()->pubsetbuf(
            write_buffer.data(),
            static_cast<std::streamsize>(write_buffer.size()));

        // Encrypt the input stream to the output stream
        bool result = EncryptStream(logger,
                                    process_control,
                                    (quiet || stdout_used),
                                    password,
                                    iterations,
                                    extensions,
                                    file_size,
                                    istream,
                                    ostream);

        // Close any open files; there may be delay in closing the output
        // file if it is large and transmission is over a network
        if (ifs.is_open()) ifs.close();
        if (ofs.is_open())
        {
            ofs.flush();
            ofs.close();
        }

        // Did encryption fail?
        if (!result)
        {
            // Remove the partial output file if possible
            if (remove_on_fail)
            {
                // Filenames should be in UTF-8 format, so form a UTF-8 string
                // type use with remove()
                SecureU8String u8name(out_file.cbegin(), out_file.cend());

                try
                {
                    std::filesystem::remove(std::filesystem::path(u8name));
                }
                catch (const std::filesystem::filesystem_error &e)
                {
                    logger->error << "Unable to remove output file: "
                                  << out_file << " (file system err="
                                  << e.what() << ")" << std::flush;
                    std::cerr << "Unable to remove output file" << std::endl;
                }
                catch (const std::exception &e)
                {
                    logger->error << "Unable to remove output file: "
                                  << out_file << " (err=" << e.what() << ")"
                                  << std::flush;
                    std::cerr << "Unable to remove output file" << std::endl;
                }
                catch (...)
                {
                    logger->error << "Unable to remove output file: "
                                  << out_file << std::flush;
                    std::cerr << "Unable to remove output file" << std::endl;
                }
            }

            return false;
        }

        // If termination requested, return
        if (process_control.terminate) return false;
    }

    logger->info << "Encryption process complete" << std::flush;

    return true;
}
