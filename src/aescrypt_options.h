/*
 *  aescrypt_options.h
 *
 *  Copyright (C) 2026
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file declares the function used to parse command-line options
 *      given by the user. Since this module is part of the command-line
 *      interface, any errors will be output directly to stderr.
 *
 *  Portability Issues:
 *      None.
 */

#include <terra/program_options/program_options.h>

namespace Terra
{

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
                  const wchar_t * const argv[]);
#else
bool ParseOptions(Terra::ProgramOptions::Parser &parser,
                  const int argc,
                  const char * const argv[]);
#endif

} // namespace Terra
