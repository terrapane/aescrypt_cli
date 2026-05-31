/*
 *  usage.cpp
 *
 *  Copyright (C) 2026
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      Display usage information for AES Crypt.
 *
 *  Portability Issues:
 *      None.
 */

#include <string>
#include <iostream>
#include "usage.h"

namespace Terra
{

/*
 *  Usage()
 *
 *  Description:
 *      Display AES Crypt usage information.
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
    -f, --force      [force     ] Force overwriting output file if it exists
    -i, --iterations [iterations] Number of KDF iterations (default is 600000)
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

    std::cout << usage << "\n";
}

}
