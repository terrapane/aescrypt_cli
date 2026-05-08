/*
 *  command_arguments.cpp
 *
 *  Copyright (C) 2026
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines functions used to parse command-line options
 *      given by the user. Since this module is part of the command-line
 *      interface, any errors will be output directly to stderr.
 *
 *  Portability Issues:
 *      None.
 */

#include <iostream>
#include <utility>
#include <stdexcept>
#include <cstddef>
#include "command_arguments.h"

namespace Terra
{

namespace
{

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
    // Ensure Windows is using two octet wchar_t values
    static_assert(sizeof(wchar_t) == 2,
                  "wchar_t should be two octets in size on Windows");

    SecureVector<SecureString> arguments;

    for (std::size_t i = 0; i < argc; i++)
    {
        // How many octets are in the string?
        auto arg_length = wcslen(argv[i]) * sizeof(wchar_t);

        // If the length is zero, just push an empty string onto the vector
        if (arg_length == 0)
        {
            arguments.emplace_back(Terra::SecUtil::SecureString());
            continue;
        }

        // Create a string to hold the UTF-8 octets
        SecureString argument(arg_length + (arg_length >> 1), '\0');

        // Perform the UTF-16LE to UTF-8 conversion
        auto [result, length] = Terra::CharUtil::ConvertUTF16ToUTF8(
            std::span<const std::uint8_t>{
                reinterpret_cast<const std::uint8_t *>(argv[i]),
                arg_length},
            argument);

        // A zero indicates an error
        if (result == false)
        {
            throw std::runtime_error("Failed to convert command arguments");
        }

        // Reduce the string size to match the length
        argument.resize(length);

        // Put the string on the arguments vector
        arguments.emplace_back(argument);
    }

    return arguments;
}

#endif

/*
 *  SetOptions()
 *
 *  Description:
 *      Set the options for the ProgramOptions parser to consider.
 *
 *  Parameters:
 *      parser [in/out]
 *          The program options Parser to use to parse options.
 *
 *  Returns:
 *      True if successful, false if not.
 *
 *  Comments:
 *      None.
 */
bool SetOptions(Terra::ProgramOptions::Parser &parser) noexcept
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
        { "force",      "f", "force",      false,  false },
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
        return false;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Unknown error parsing program options: "
                  << e.what()
                  << std::endl;
        return false;
    }
    catch (...)
    {
        std::cerr << "Unknown error parsing program options"
                  << std::endl;
        return false;
    }

    return true;
}

}

/*
 *  ParseOptions()
 *
 *  Description:
 *      This function will parse the command-line options and output an
 *      error to stderr if one is observed.
 *
 *  Parameters:
 *      parser [in/out]
 *          The program options Parser to use to parse options.
 *
 *      argc [in]
 *          The argument count passed to main().
 *
 *      argv [in]
 *          The argument list passed to main() (or wmain() for Windows).
 *
 *  Returns:
 *      True if successful, false if not.
 *
 *  Comments:
 *      None.
 */
#ifdef _WIN32
bool ParseOptions(Terra::ProgramOptions::Parser &parser,
                  const int argc,
                  const wchar_t *const argv[])
#else
bool ParseOptions(Terra::ProgramOptions::Parser &parser,
                  const int argc,
                  const char *const argv[])
#endif
{
    // Set the program options
    if (!SetOptions(parser)) return false;

    // Parse the given program options
    try
    {
#ifdef _WIN32
        // Convert the given arguments to UTF-8 strings
        SecureVector<SecureString> arguments = ConvertArguments(argc, argv);
        parser.ParseArguments(
            std::vector<std::string_view>(arguments.begin(), arguments.end()));
#else
        parser.ParseArguments(argc, argv);
#endif
    }
    catch (const Terra::ProgramOptions::OptionsException &e)
    {
        std::cerr << e.what() << std::endl;
        return false;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Unexpected error parsing program options: "
                  << e.what()
                  << std::endl;
        return false;
    }
    catch (...)
    {
        std::cerr << "Unexpected error parsing program options"
                  << std::endl;
        return false;
    }

    return true;
}

} // namespace Terra
