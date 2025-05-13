/*
 *  aescrypt.cpp
 *
 *  Copyright (C) 2025
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This is the main implementation file for the AES Crypt command-line
 *      program.
 *
 *  Portability Issues:
 *      None.
 */

#include <iostream>
#include <csignal>
#include <utility>
#include <cstddef>
#include <memory>
#include <iterator>
#include <algorithm>
#include <climits>
#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>
#include <wchar.h>
#include <io.h>
#include <fcntl.h>
#include <stdio.h>
#else
#include <clocale>
#include <langinfo.h>
#endif
#include <terra/conio/ansi.h>
#include <terra/logger/logger.h>
#include <terra/logger/null_ostream.h>
#include <terra/secutil/secure_erase.h>
#include <terra/charutil/character_utilities.h>
#include <terra/conio/ansi_capable.h>
#ifdef AESCRYPT_ENABLE_LICENSE_MODULE
#include <terra/aescrypt_lm/aescrypt_lm.h>
#endif
#include "aescrypt.h"
#include "version.h"
#include "mode.h"
#include "secure_containers.h"
#include "secure_program_options.h"
#include "process_control.h"
#include "key_file.h"
#include "password_prompt.h"
#include "encrypt_files.h"
#include "decrypt_files.h"

// It is assumed a character is 8 bits
static_assert(CHAR_BIT == 8);

namespace
{

ProcessControl process_control;

/*
 *  SignalHandler()
 *
 *  Description:
 *      This function is called when the program receives a signal that would
 *      normally result in program termination.  This function set a global
 *      variable that is observed in a couple of points in the process to
 *      facilitate a clean termination.
 *
 *  Parameters:
 *      signal_number [in]
 *          The signal that was caught.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
void SignalHandler(int signal_number)
{
    bool terminate = false;

    // Set the termination reason string
    switch (signal_number)
    {
        case SIGABRT:
            terminate = true;
            break;

        case SIGINT:
            terminate = true;
            break;

        case SIGTERM:
            terminate = true;
            break;

#ifndef _WIN32
        case SIGHUP:
            terminate = true;
            break;

        case SIGQUIT:
            terminate = true;
            break;
#endif
        default:
            break;
    }

    // If terminating, set the flag and notify all waiting threads
    if (terminate)
    {
        std::lock_guard<std::mutex> lock(process_control.mutex);
        process_control.terminate = true;
        process_control.cv.notify_all();
    }
}

/*
 *  InstallSignalHandlers
 *
 *  Description:
 *      This function defines the action to take when certain signals are
 *      received (e.g., SIGINT, SIGQUIT, etc.) so that the process can
 *      terminate in a sane way.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
void InstallSignalHandlers()
{
#ifdef _WIN32
    if (signal(SIGABRT, SignalHandler) == SIG_ERR)
    {
        std::cerr << "Failed to install SIGINT handler" << std::endl;
    }

    if (signal(SIGINT, SignalHandler) == SIG_ERR)
    {
        std::cerr << "Failed to install SIGINT handler" << std::endl;
    }

    if (signal(SIGTERM, SignalHandler) == SIG_ERR)
    {
        std::cerr << "Failed to install SIGTERM handler" << std::endl;
    }
#else
    struct sigaction sa = {};
    sa.sa_handler = SignalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGABRT, &sa, nullptr) == -1)
    {
        std::cerr << "Failed to install SIGABRT handler" << std::endl;
    }

    if (sigaction(SIGHUP, &sa, nullptr) == -1)
    {
        std::cerr << "Failed to install SIGHUP handler" << std::endl;
    }

    if (sigaction(SIGINT, &sa, nullptr) == -1)
    {
        std::cerr << "Failed to install SIGINT handler" << std::endl;
    }

    if (sigaction(SIGQUIT, &sa, nullptr) == -1)
    {
        std::cerr << "Failed to install SIGQUIT handler" << std::endl;
    }

    if (sigaction(SIGTERM, &sa, nullptr) == -1)
    {
        std::cerr << "Failed to install SIGTERM handler" << std::endl;
    }
#endif
}

/*
 *  Version()
 *
 *  Description:
 *      Display program version information.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
void Version()
{
#ifdef AESCRYPT_ENABLE_LICENSE_MODULE
    const std::u8string licensee = Terra::ACLM::GetLicensee();
#else
    const std::u8string licensee = u8"Enterprise Build";
#endif
    std::cout << Terra::Project_Name << " " << Terra::Project_Version
              << std::endl
              << Terra::Copyright_Text
              << std::endl
              << Terra::Author_Text
              << std::endl;
    std::cout << "Licensee: ";
    if (licensee.empty())
    {
        std::cout << "Unlicensed";
    }
    else
    {
        std::cout << std::string(licensee.begin(), licensee.end());
    }
    std::cout << std::endl;
}

#ifdef _WIN32
/*
 *  ConvertArguments()
 *
 *  Description:
 *      This function will convert program arguments using wchar_t (Unicode)
 *      to UTF-8, so that they may be processed by the Program Options Parser.
 *
 *  Parameters:
 *      argc [in]
 *          The argument count passed to main().
 *
 *      argv [in]
 *          The argument list passed to main().
 *
 *  Returns:
 *      A vector of strings representing the converted arguments.
 *
 *  Comments:
 *      None.
 */
SecureVector<SecureString> ConvertArguments(const int argc,
                                            const wchar_t *const argv[])
{
    SecureVector<SecureString> arguments;

    for (std::size_t i = 0; i < argc; i++)
    {
        // How many characters are in the string?
        auto length = wcslen(argv[i]);

        // If the length is zero, just push an empty string onto the vector
        if (length == 0)
        {
            arguments.emplace_back(Terra::SecUtil::SecureString());
            continue;
        }

        // Compute space required to convert UTF-16LE to UTF-8
        std::size_t octets = WideCharToMultiByte(CP_UTF8,
                                                 0,
                                                 argv[i],
                                                 static_cast<int>(length),
                                                 nullptr,
                                                 0,
                                                 nullptr,
                                                 nullptr);

        // A zero indicates an error
        if (octets == 0)
        {
            throw std::runtime_error("Failed to convert command arguments");
        }

        // Allocate string with space for converted argument
        SecureString argument(octets, '\0');

        // Convert the argument to UTF-8, ensuring length is as expected
        if (WideCharToMultiByte(CP_UTF8,
                                0,
                                argv[i],
                                static_cast<int>(length),
                                argument.data(),
                                static_cast<int>(argument.size()),
                                nullptr,
                                nullptr) != octets)
        {
            throw std::runtime_error("Error converting command arguments");
        };

        // Put the string on the arguments vector
        arguments.emplace_back(argument);
    }

    return arguments;
}
#endif

/*
 *  Usage()
 *
 *  Description:
 *      Display program usage.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:
 *      None.
 */
void Usage()
{
    const std::string usage =
R"(usage: aescrypt [MODE] [OPTIONS] [FILE]...

EXAMPLES:
    aescrypt -e filename.txt
    aescrypt -d -p secret filename.txt.aes
    aescrypt -e -p secret -o filename.txt.aes -
    aescrypt -g -s 128 -k /path/to/filename.key
    aescrypt -g -k /path/to/filename.key

    OPTIONS           NAME        DESCRIPTION

MODE:
    -d, --decrypt    [decrypt   ] Decrypt the specified file(s)
    -e, --encrypt    [encrypt   ] Encrypt the specified file(s)
    -g, --generate   [generate  ] Generate a key file with random data

FUNCTIONAL:
    -i, --iterations [iterations] Number of KDF iterations (default is 300000)
    -k, --keyfile    [keyfile   ] The key file to use
    -o, --outfile    [outfile   ] Output file when operating on a single file
    -p, --password   [password  ] Password for encryption or decryption
    -q, --quiet      [quiet     ] Do not produce progress output to stdout
    -s, --keysize    [keysize   ] The key size in octets to use with --generate
                                  (default is 64 octets; 384 bits of entropy)

DEBUGGING:
    -l, --logging    [logging   ] Enable logging output to stderr

HELP/VERSION:
    -h, --help       [help      ] Displays this help information
    -?               [question  ] Displays this help information
    -v, --version    [version   ] Display program version information

COMMENTS:
    * Exactly one MODE must be selected (encrypt, decrypt, or generate)
    * If a password or key file is not specified, user will be prompted
    * One may read/write from/to stdin/stdout using "-" as the filename
    * By default, .aes will be added when encrypting, removed when decrypting
    * One may use -o to specify the output file if operating on a single file)";

    std::cerr << usage << std::endl;
}

/*
 *  ParseOptions()
 *
 *  Description:
 *      This function will parse the command-line options and output an
 *      error if one is observed.  For options like "help", this function
 *      will emit program usage and instruct the caller to stop execution.
 *
 *  Parameters:
 *      parser [in/out]
 *          The program options Parser to use to parse options.
 *
 *      argc [in]
 *          The argument count passed to main().
 *
 *      argv [in]
 *          The argument list passed to main() or wmain() (for Windows).
 *
 *  Returns:
 *      This function will return a pair of boolean values.  If the first
 *      boolean is false, it indicates an error should be returned to the OS
 *      upon return from this function.  If the first boolean is true, then it
 *      means there were no critical errors.  In that case, the second boolean
 *      should be observed.  If the second boolean is false, it means the
 *      program should not continue and a success code should be returned to
 *      the OS.  An example of this is when the user uses an option flag
 *      that is handled by this function (e.g., program usage).  If both
 *      are true, it means the program should continue upon return with normal
 *      operation.
 *
 *  a success code
 *      should be returned to the OS.  If both the first and second boolean
 *      values are true, it means the caller should continue with normal
 *      operation.
 *
 *  Comments:
 *      None.
 */
template<typename T>
std::pair<bool, bool> ParseOptions(Terra::ProgramOptions::Parser &parser,
                                   const int argc,
                                   const T *const argv[])
{
    // clang-format off
    const Terra::ProgramOptions::Options options =
    {
    //    Name        Short  Long          Multi   Argument
        { "decrypt",    "d", "decrypt",    false,  false },
        { "encrypt",    "e", "encrypt",    false,  false },
        { "generate",   "g", "generate",   false,  false },
        { "help",       "h", "help",       false,  false },
        { "keyfile",    "k", "keyfile",    false,  true  },
        { "keysize",    "s", "keysize",    false,  true  },
        { "iterations", "i", "iterations", false,  true  },
        { "logging",    "l", "logging",    false,  false },
        { "outfile",    "o", "outfile",    false,  true  },
        { "password",   "p", "password",   false,  true  },
        { "question",   "?", "",           false,  false },
        { "quiet",      "q", "quiet",      false,  false },
        { "version",    "v", "version",    false,  false }
    };
    // clang-format on

    // Configure the programs option object with the above options specification
    try
    {
        parser.SetOptions(options);
    }
    catch (const Terra::ProgramOptions::SpecificationException &e)
    {
        std::cerr << "Program options exception error: "
                  << e.what()
                  << std::endl;
        return {false, false};
    }
    catch (const std::exception &e)
    {
        std::cerr << "Unknown error parsing program options: "
                  << e.what()
                  << std::endl;
        return {false, false};
    }
    catch (...)
    {
        std::cerr << "Unknown error parsing program options"
                  << std::endl;
        return {false, false};
    }

    // Now parse the program options

    try
    {
#ifdef _WIN32
        SecureVector<SecureString> arguments = ConvertArguments(argc, argv);
        parser.ParseArguments(
            std::vector<std::string_view>(arguments.begin(), arguments.end()));
#else
        parser.ParseArguments(argc, argv);
#endif

        // Was the version requested?
        if (parser.GetOptionCount("version") > 0)
        {
            // Print the program version information
            Version();

            return {true, false};
        }

        // Was help requested?
        if (parser.OptionGiven("help") || parser.OptionGiven("question"))
        {
            // Print the program usage information
            Usage();

            return {true, false};
        }
    }
    catch (const Terra::ProgramOptions::OptionsException &e)
    {
        std::cerr << e.what() << std::endl;
        return {false, false};
    }
    catch (const std::exception &e)
    {
        std::cerr << "Unexpected error parsing program options: "
                  << e.what()
                  << std::endl;
        return {false, false};
    }
    catch (...)
    {
        std::cerr << "Unexpected error parsing program options"
                  << std::endl;
        return {false, false};
    }

    return {true, true};
}

} // namespace

/*
 *  main()
 *
 *  Description:
 *      The main entry point for the AES Crypt CLI program.
 *
 *  Parameters:
 *      argc [in]
 *          A count of the number of command-line arguments.
 *
 *      argv [in]
 *          The actual command-line arguments given.
 *
 *  Returns:
 *      Result indicating success or failure.  Zero means success.
 *
 *  Comments:
 *      None.
 */
#ifdef _WIN32
int wmain(int argc, wchar_t *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    SecureOptionsParser options_parser;         // Program options parser
    bool using_stdout{};                        // Any output go to stdout?
    AESCryptMode mode{};                        // Operational mode
    SecureU8String password;                    // User-provided password
    SecureString key_file;                      // User-provided key file name
    SecureString output_file;                   // User-provided output file
    std::size_t file_count{};                   // File count
    std::uint32_t iterations{KDF_Iterations};   // KDF iterations
    Terra::Logger::LoggerPointer logger;        // Logger for debugging
    std::vector<SecureString> filenames;        // Filenames to encrypt/decrypt
    std::size_t stdin_filenames_seen{};         // Count of input files "-"
    std::size_t key_size{Default_Key_File_Size};// Default generated key length
    bool quiet = false;                         // Suppress progress output
    Terra::Logger::NullOStream null_stream;     // For no logging output

#ifdef _WIN32
    // On Windows, use UTF-8 for input/output to console
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Enable ANSI output if possible (for logging and progress meter)
    Terra::ConIO::EnableStdOutANSIOutput();
    Terra::ConIO::EnableStdErrANSIOutput();

    // Ensure stdin/stdout operate in binary mode
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#else
    // Set the locale based on the current environment
    if (std::setlocale(LC_CTYPE, "") == nullptr)
    {
        std::cerr << "Failed to set the local based on the current environment"
                  << std::endl;
        return EXIT_FAILURE;
    }

    {
        // Warn if the locale's character encoding is not UTF-8
        const std::string encoding = nl_langinfo(CODESET);
        if ((encoding != "UTF-8"))
        {
            std::cerr << "Warning: Your locale is set to '"
                      << encoding
                      << "', but 'UTF-8' required for Unicode.  Thus, do not"
                      << std::endl
                      << "         "
                      << "use passwords with non-ASCII characters."
                      << std::endl;
        }
    }
#endif

    // Parse the program options using the program_options object
    auto [parse_success, parse_continue] =
                                    ParseOptions(options_parser, argc, argv);
    if (!parse_success) return EXIT_FAILURE;
    if (!parse_continue) return EXIT_SUCCESS;

    try
    {
        // Ensure at least one file was specified
        file_count = options_parser.GetOptionCount("");

        // Get the list of filenames and store in a secure container
        if (file_count > 0)
        {
            // Get the list of filenames
            auto temp_names = options_parser.GetOptionStrings("");

            // Move file into secure container
            for (auto &file : temp_names)
            {
                // Check if this filename is "-"
                if (file == std::string("-")) stdin_filenames_seen++;

                // Store name in a secure container
                filenames.push_back(static_cast<SecureString>(file));

                // Erase the file name in normal container
                Terra::SecUtil::SecureErase(file);
            }

            // Ensure "-" was not given more than once
            if (stdin_filenames_seen > 1)
            {
                std::cerr << "stdin (\"-\") cannot be specified more than once"
                          << std::endl;
                return EXIT_FAILURE;
            }
        }

        // Paranoia check: container size should match file_count
        if (file_count != filenames.size())
        {
            std::cerr << "Internal error: inconsistent file name counts"
                      << std::endl;
            return EXIT_FAILURE;
        }

        // Determine the operational mode (encrypt, decrypt, or key generation)
        if (options_parser.OptionGiven("decrypt"))
        {
            mode = AESCryptMode::Decrypt;
        }

        if (options_parser.OptionGiven("encrypt"))
        {
            if (mode != AESCryptMode::Undefined)
            {
                std::cerr << "More than one mode was specified" << std::endl;
                return EXIT_FAILURE;
            }

            mode = AESCryptMode::Encrypt;
        }

        if (options_parser.OptionGiven("generate"))
        {
            if (mode != AESCryptMode::Undefined)
            {
                std::cerr << "More than one mode was specified" << std::endl;
                return EXIT_FAILURE;
            }

            // Input files cannot be specified when generating a key file
            if (file_count > 0)
            {
                std::cerr << "Cannot specify input files when generating a key"
                          << std::endl;
                return EXIT_FAILURE;
            }

            mode = AESCryptMode::KeyGenerate;
        }

        if (mode == AESCryptMode::Undefined)
        {
            std::cerr << "Specify either encrypt (-e), decrypt (-d), or "
                         "generate (-g) mode"
                      << std::endl;
            return EXIT_FAILURE;
        }

        // If not generating a key, ensure input files were given
        if ((mode != AESCryptMode::KeyGenerate) && (file_count == 0))
        {
            std::cerr << "No input files were given" << std::endl;
            return EXIT_FAILURE;
        }

        // Was a password specified?
        if (options_parser.OptionGiven("password"))
        {
            // Password cannot be provided when generating keys
            if (mode == AESCryptMode::KeyGenerate)
            {
                std::cerr << "Cannot specify a password when generating a key"
                          << std::endl;
                return EXIT_FAILURE;
            }

            // Get the user-provided password
            SecureString user_password = static_cast<SecureString>(
                options_parser.GetOptionString("password"));

            // If the length is zero, that is invalid
            if (user_password.empty())
            {
                std::cerr << "Password argument cannot be empty" << std::endl;
                return EXIT_FAILURE;
            }

            // Verify the string is valid UTF-8
            bool valid_encoding = Terra::CharUtil::IsUTF8Valid(
                {reinterpret_cast<const std::uint8_t *>(user_password.data()),
                 user_password.size()});

            // If the encoding is invalid, do not proceed
            if (!valid_encoding)
            {
                std::cerr << "Password is not in UTF-8 format" << std::endl;
                return EXIT_FAILURE;
            }

            // Copy the user-provided password into a UTF-8 string type
            std::copy(user_password.begin(),
                      user_password.end(),
                      std::back_inserter(password));
        }

        // The key file to use with encryption / decryption / key generation
        if (options_parser.OptionGiven("keyfile"))
        {
            // Ensure a password is not also specified
            if (!password.empty())
            {
                std::cerr << "Password and key file cannot both be specified"
                          << std::endl;
                return EXIT_FAILURE;
            }

            // Get the user-provided key file
            key_file = options_parser.GetOptionString("keyfile");

            // If the length is zero, that is invalid
            if (key_file.empty())
            {
                std::cerr << "Key file argument cannot be empty" << std::endl;
                return EXIT_FAILURE;
            }

            // If the length is zero, that is invalid
            if ((key_file == "-") && (mode != AESCryptMode::KeyGenerate))
            {
                std::cerr << "When encrypting or decrypting, the key file "
                             "cannot be stdin"
                          << std::endl;
                return EXIT_FAILURE;
            }
        }

        // The key file size parameter is valid only when generating
        if (options_parser.OptionGiven("keysize"))
        {
            // Only valid with generate mode
            if (mode != AESCryptMode::KeyGenerate)
            {
                std::cerr << "Key length only valid when generating a key file"
                          << std::endl;
                return EXIT_FAILURE;
            }

            options_parser.GetOptionValue("keysize",
                                          key_size,
                                          Min_Key_File_Size,
                                          Max_Key_File_Size);
        }

        // Use a user-specified number of KDF iterations?
        if (options_parser.OptionGiven("iterations"))
        {
            // Only valid when encrypting
            if (mode != AESCryptMode::Encrypt)
            {
                std::cerr << "Iteration value valid only when encrypting"
                          << std::endl;
            }

            options_parser.GetOptionValue("iterations",
                                          iterations,
                                          KDF_Min_Iterations,
                                          KDF_Max_Iterations);
        }

        // Was an output file specified?
        if (options_parser.OptionGiven("outfile"))
        {
            // There cannot be more than one input file with an output file
            if (file_count > 1)
            {
                std::cerr << "Output file cannot be specified when providing "
                             "multiple input files"
                          << std::endl;
                return EXIT_FAILURE;
            }

            // If generating a key, an output file cannot be specified
            if (mode == AESCryptMode::KeyGenerate)
            {
                std::cerr << "Output file cannot be specified when generating "
                             "a key file"
                          << std::endl;
                return EXIT_FAILURE;
            }

            // Get the output file name
            output_file = options_parser.GetOptionString("outfile");

            // Ensure the output file is not empty
            if (output_file.empty())
            {
                std::cerr << "Empty output file name not allowed" << std::endl;
                return EXIT_FAILURE;
            }

            // If the output file is stdout, take note
            if (output_file == SecureString("-")) using_stdout = true;
        }
        else
        {
            // If stdin was specified in the file list, complain that no
            // output file was specified
            if (stdin_filenames_seen > 0)
            {
                std::cerr << "Since stdin is used for input, an output "
                             "filename must be specified (may be \"-\")"
                          << std::endl;
                return EXIT_FAILURE;
            }
        }

        // Was logging requested?
        if (options_parser.OptionGiven("logging"))
        {
            // Create logger to emit logs to stderr
            logger = std::make_shared<Terra::Logger::Logger>(std::cerr);
            logger->notice << "Logging enabled" << std::flush;

            // We cannot allow logging and a progress bar since they conflict
            quiet = true;
        }
        else
        {
            // Create a logger that does not emit output
            logger = std::make_shared<Terra::Logger::Logger>(null_stream);
        }

        // Was quiet operation requested?
        if (options_parser.OptionGiven("quiet")) quiet = true;
    }
    catch (const Terra::ProgramOptions::OptionsException &e)
    {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    catch (...)
    {
        std::cerr << "Unknown error processing arguments" << std::endl;
        return EXIT_FAILURE;
    }

    // If generating a key file, do that now
    if (mode == AESCryptMode::KeyGenerate)
    {
        // Ensure a key file was given
        if (key_file.empty())
        {
            std::cerr << "To generate a key, specify the name of the key file"
                      << std::endl;
            return EXIT_FAILURE;
        }

        if (!GenerateKeyFile(logger, key_file, key_size))
        {
            std::cerr << "Unable to generate the key file" << std::endl;
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    // If a key file was provided, read the key file
    if (!key_file.empty())
    {
        // Read the key file (converting it to a password)
        password = ReadKeyFile(logger, key_file);

        // If the password is empty, that is a problem
        if (password.empty())
        {
            std::cerr << "Unable to get a key from the key file" << std::endl;
            return EXIT_FAILURE;
        }
    }

    // Prompt for a password if one was not provided
    if (password.empty())
    {
#ifdef _WIN32
        if (using_stdout)
        {
            std::cerr << "On Windows, output to stdout requires a password "
                         "given via -p or -k"
                      << std::endl;
            return EXIT_FAILURE;
        }
#endif

        auto [result, user_password] =
            GetUserPassword(logger, (mode == AESCryptMode::Encrypt));

        switch (result)
        {
            case PasswordResult::UnspecifiedError:
                std::cerr << "Failed to get a password" << std::endl;
                break;

            case PasswordResult::Success:
                break;

            case PasswordResult::Mismatch:
                std::cerr << "Passwords do not match" << std::endl;
                break;

            case PasswordResult::NoInput:
                std::cerr << "No input received" << std::endl;
                break;

            default:
                std::cerr << "Failed to get a password" << std::endl;
                break;
        }

        // Return if reading the password was not successful
        if (result != PasswordResult::Success) return EXIT_FAILURE;

        // If the password is empty, there was a problem
        if (user_password.empty())
        {
            std::cerr << "Password is empty" << std::endl;
            return EXIT_FAILURE;
        }

        // Copy the user-provided password into a UTF-8 string type
        password = std::move(user_password);
    }

#ifdef AESCRYPT_ENABLE_LICENSE_MODULE
    // Verify user license rights
    if (!Terra::ACLM::ValidateACLM())
    {
        std::cerr << "A valid license is required to use AES Crypt. You may "
                     "obtain a license by"
                  << std::endl
                  << "visiting https://www.aescrypt.com/." << std::endl;
        return EXIT_FAILURE;
    }
#endif

    // Install signal handlers to ensure proper cleanup if user aborts
    InstallSignalHandlers();

    try
    {
        // If encrypting, do that now
        if (mode == AESCryptMode::Encrypt)
        {
            // Create extensions vector to be inserted into stream header
            const std::vector<std::pair<std::string, std::string>> extensions =
            {
                {
                    "CREATED_BY",
                    Terra::Project_Name + " " + Terra::Project_Version
                }
            };

            // Encrypt files, disabling progress updates as appropriate
            bool encrypt_result = EncryptFiles(logger,
                                               process_control,
                                               (quiet || using_stdout),
                                               password,
                                               iterations,
                                               filenames,
                                               output_file,
                                               extensions);

            return (encrypt_result ? EXIT_SUCCESS : EXIT_FAILURE);
        }

        // Decrypt files, disabling progress updates as appropriate
        auto decrypt_result = DecryptFiles(logger,
                                           process_control,
                                           (quiet || using_stdout),
                                           password,
                                           filenames,
                                           output_file);

        return (decrypt_result ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    catch (const std::exception &e)
    {
        logger->critical << "Exception caught in main: " << e.what();
        std::cerr << "Failed due to unhandled exception caught in main: "
                  << e.what();
        return EXIT_FAILURE;
    }
    catch (...)
    {
        logger->critical << "Unknown exception caught in main";
        std::cerr << "Unknown exception caught in main; exiting";
        return EXIT_FAILURE;
    }
}
