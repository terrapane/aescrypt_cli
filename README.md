# AES Crypt Command-Line Program

This project contains the AES Crypt Command Line (CLI) program.  This software
allows one to encrypt and decrypt files from the Linux, Windows, or Mac
terminal command line, cron jobs, etc.

## Building the AES Crypt CLI Program

AES Crypt is intended to be built using CMake, which is a popular tool for
specifying how to compile C and C++ software.  It can (and does) automatically
import a number of dependencies (including the AES Crypt Engine library, console
I/O library, security utilities, random number library, etc.), which are
necessary to fully build.

One can build either a debug or release version of the software, but it is
important to understand that a debug build is far too slow for production use.

### Linux / Mac

To build a release build on Linux or Mac, change directories to the root of the
source directory and issue these commands:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

If you want to install the `aescrypt` binary and the man page, do this:

```bash
cmake --install build
```

Some code editors (e.g., Microsoft Visual Studio Code) have integrated
CMake support and can make building even easier than executing the above
commands.

### Windows

While you can build from the command-line with similar instructions as
shown above, Microsoft Visual Studio and Visual Studio Code make it much
easier to build.  You can just open the project folder and the integrated
CMake tools make is very easy.  Just select the compiler to use
(e.g., MSVC 64-bit)  and the `Release` build.

## Usage

To get complete usage information, type `aescrypt -h` at the command-line.
This provides a complete set of options.  Nearly all options may be
specified via short- or long-option format.

Each option has a "name" as indicated in the NAME column of the output.
This is mostly used internally, but will be displayed if there is an error
related to that option.

## Operational Modes

The AES Crypt command-line program operates in one of three modes when
one executes the `aescrypt` command.  Those modes are:

* Encryption
* Decryption
* Key Generation

For example, to encrypt a file named foo.txt, one may enter the encryption
mode by using the `-e` option like this:

```bash
aescrypt -e foo.txt
```

This will encrypt the file named foo as foo.txt.aes.  The file extension .aes
is added to all encrypted files.  While a .aes file extension is not strictly
necessary, it is generally easier for people to follow that convention.

When decrypting, one uses the `-d` option like this:

```bash
aescrypt -d foo.txt.aes
```

This will created a decrypted file written to the file named foo.txt.
AES Crypt will automatically remove the .aes extension.

The last operational mode is "key generation" via the `-g` option.  This
will create a key file containing a specified number of octets (or 64 octets
if no key size is specified).

### Encryption

AES Crypt uses that AES algorithm to encrypt files using a 256-bit key and
a password.  Passwords should be as strong as possible.  To make them
more difficult to guess, AES Crypt used a Key Derivation Function (KDF)
approved by FIPS SP 800-132 (namely PBKDF2 with HMAC-SHA512 using 300,000
iterations by default).  Deriving the key from a password takes a little time,
and that is intentional so as to make it more difficult to brute-force attack
an encrypted file.

The general form of the encryption command is as follows:

```bash
aescrypt -e -p password -o output.aes input.aes
```

or

```bash
aescrypt -e -k key_file -o output.aes input.aes
```

The `-p` option allows one to specify a password.  Alternatively, one may
specify a key file using the `-k` option.  If neither are given, AES Crypt
will prompt the user for a password.

The `-o` flag allows one to specify a specific output file.  By default,
AES Crypt will create an encrypted file with the same name as the input file,
but with a `.aes` extension appended.

One may also encrypt multiple files with the same password or key file by
specifying several files at once.  For example:

```bash
aescrypt -e -p password file1.txt file2.txt file3.txt
```

Note that the `-o` option cannot be specified when providing multiple
input files, as AES Crypt would not know which of the multiple files should
be stored in the output file.  So in this example above, AES Crypt will
create three files in the same directory named `file1.txt. aes`,
`file1.txt.aes`, and `file3.txt.aes`.

It is also possible to use stdin and stdout like this:

```bash
tar -czvf - files/ | aescrypt -e -p password -o - - | uuencode -m files.tgz.aes > file.tgz.aes.uu
```

Here, the `-o` flag specifies the filename `-`, which is treated as stdout.
Likewise, the input file given is named `-`, which is treated as stdin.

This makes AES Crypt quite useful in scripts for such things as backups where
the output of tar is piped into `aescrypt` and then directed to the next
process in the pipeline.

### Decryption

Decryption syntax is similar to encryption, though the number of iterations
cannot be specified.  The iteration count is stored in the produced `.aes` file
and will be read and used automatically.  By default, the output file for a
file (e.g., `file1.txt.aes`) will be the same name, but without `.aes`
(e.g., `file1.txt`).

For example, the following command will produce three decrypted output files
`file1.txt`, `file2.txt`, and ``file3.txt`.

```bash
aescrypt -d -p password file1.txt.aes file2.txt.aes file3.txt.aes
```

If one wants to direct output to a specific file, one may use this syntax:

```bash
aescrypt -d -p password -o plaintext_file.txt encrypted_file
```

As with encryption, one may use `-` as the filename to indicate reading from
stdin or writing to stdout.

### Key Generation

AES Crypt always uses a password, but the password may come from a "key file"
that contains the password.  This may be created manually or may be created
using the `-g` option when running AES Crypt.

Here's an example:

```bash
aescrypt -g -k foo.key
```

This will produce a random string of characters in a file named `foo.key`.
By default, the key file will contain 64 octets that are randomly selected
from an alphabet of 64 characters.  Thus, the total entropy is
log2(64) * 64 = 384 bits.  You may increase or decrease the number of octets
by using the `-s` option and specifying the number of octets.

For example:

```bash
aescrypt -g -k foo.key -s 128
```

This will produce a key file with 128 octets, which has a total entropy of
log2(64) * 128 = 768 bits.  Since the AES algorithm uses a 256-bit key, the
larger keys do not really add more strength.  Even so, the option exists if one
wishes to use a larger or smaller key size.  It is NOT recommended to use a key
with less than 256 bits of entropy (i.e., `-s` value less than 43).

For more examples with links to show the computation, visit Packetizer's
[Secure Password Generator](https://www.packetizer.com/security/pwgen/) page.

## KDF Iterations

For those who do not care about the technical details of converting a password
into a key suitable for encryption, you can ignore this section.  For those
who are curious, this section will make an effort to explain this in
relatively simple terms.

When a user provides a password (e.g., "apple") to AES Crypt, that password
needs to be converted into a key suitable for use with AES.  There are
industry standard algorithms for doing that, one of which is called PBKDF2
and is recommended by NIST.  NIST recommends using HMAC with an approved
hashing function with PBKDF2.  To satisfy this requirement, AES Crypt uses
HMAC-SHA512 as the hash function.

PBKDF2 is a type of "password based key derivation function."  Internally, it
takes the user's password and passes it to the specified hashing function
(HMAC-SHA512 in AES Crypt) repeatedly to produce a key suitable for use with
AES.  This repeated application of the hashing function is the "iterations"
value `-i` one may provide when encrypting.

The more iterations provided, the more work an attacker has to do in order
to attempt to break the password used to encrypt a file.  While this might
suggest it's better to increase the number of iterations as high as possible,
doing so is frustrating to the user since key derivation takes time.  More
importantly, though, is this does not make the password stronger.

The best way to ensure the strongest security is to use a strong password that
is kept safe.  For automated backups, one should consider using key files,
but take extra care to ensure those key files are not accessible to attackers.
Further, if one uses a key file containing truly random text of sufficient
length (at least 256 bits of entropy), the number of KDF iterations can
be reduced to 1 since adding iterations does not add strength in that case.

One may specify a KDF iterations value in the range of 1 (weak, but
acceptable if the password / key has at least 256 bits of entropy) to
5,000,000.  Using such a high value will make it harder for an attacker to
guess a password since it adds so much computational time, but this can cause
AES Crypt to hang several seconds as it works to produce a key.  For general use
cases, the default value is recommended and, thus, one does not usually need
to provide the `-i` option.

## Key Files

The CLI version of AES Crypt can generate a key file using random characters.
The files generated by the current version of AES Crypt contain UTF-8 strings.
Previous versions of AES Crypt used UTF-16LE.  One may manually create a key
file using any valid set of characters, but the file must be stored in UTF-8
or UTF-16 (LE or BE) format.  If using UTF-16, be sure to verify that the
"byte order mark" (BOM) is present in the file.  Notepad on Windows, for
example, will add a BOM to the start of the file.  The BOM is used by
AES Crypt to decide whether the file is UTF-8 or UTF-16.

## Passwords (and Key File Contents)

Passwords need to be secure.  While that is probably obvious, it is worth
understanding that the strength of a password can come from a larger
alphabet or longer length.  A common misconception is that "special characters"
make a password stronger.  They can add to the complexity, but those are
very ineffective if the password is only 8 characters long, for example.

If one uses characters from the entire set of ASCII characters (96 characters),
the entropy of a random string of 8 characters would be log2(96) * 8 = ~52 bits.
Conversely, just using upper/lower case letters and numbers would (62
characters) and having a 16-character password yields ~95 bits of entropy.
That is substantial.

It is best to ensure one's password has as much entropy as possible.  Using
key files with random values is best, but they need to be secured.
Alternatively, using a series of words can be effective.  If one uses a
dictionary of 5000 common words, then 8 truly random words from a set of 5000
words yields an entropy of log2(5000) * 8 = ~98 bits.  Thus, 8 random words
is far better than 8 characters using special characters.

When providing a password, one may use any character from the Unicode character
set, thus every human language is supported.  One may also use emoji characters,
though that may be a poor choice. The reason is that some emoji characters
are not a single character, but actually a combination of characters.  Some
systems may produce different byte sequences for them than another system.
While they might render in the same way on two systems, AES Crypt is going
to operate on passwords as a byte sequence.  Thus, the order of these
independent character sequences matter.  Admittedly, this can be confusing,
but to understand, you can enter characters on this page and see if they
result in a single character sequence or multiple character sequences:
[character converter](https://www.packetizer.com/labs/cs/characters.html).

Each character should appear as a single row in the output table showing
only that character (and the corresponding Unicode and UTF-8 sequence).
Emoticons like 🏄‍♀️ will produce a series of 4 code points.  One is for
a surfer (0x1f3c4), one is a "zero-width joiner" (0x200d), one is a a symbol
representing female (0x2640), and finally there is a character representing a
"variation selector" (0xfe0f).  While the same system is likely to produce
the same sequence, a concern is that the ordered sequence might change from
system to system or as Unicode is revised.  Unicode revisions over the years
have introduced concepts like skin color and gender that affected the byte
sequence produced for an emoji character, thus ensuring a correct byte sequence
might be problematic.  It's best to just avoid them.

It would be acceptable to use emojis in a key file, though, since the sequence
of octets would not be subject to change.  The concern is only when trying
to manually enter such symbols via a keyboard as a password that system
variations might cause issues.

## Other Configuration Options

There are a few additional options one may provide to AES Crypt for various
purposes.  Here is a brief summary of those options:

* -q = Quiet mode.  Suppress any output to stdout; errors will still be emitted
to stderr.
* -l = Logging.  Enabling logging output so that the user can see progress of
various calls and more detailed error messages.
* -v = Version.  Display AES Crypt version information.
* -h = Help.  Displays the program usage information.
