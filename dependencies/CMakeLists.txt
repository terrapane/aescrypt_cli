# Enable fetching content
include(FetchContent)

# Set the root of the Terrapane source repositories
if(DEFINED ENV{TERRAPANE_SOURCE_URI})
    set(TERRAPANE_SOURCE_URI "$ENV{TERRAPANE_SOURCE_URI}")
else()
    set(TERRAPANE_SOURCE_URI "https://github.com/terrapane")
endif()

# Fetch the AES Crypt Engine
FetchContent_Declare(aescrypt_engine
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/aescrypt_engine.git
    GIT_TAG        v4.0.2
    GIT_SHALLOW    true)

# Fetch the Program Options library
FetchContent_Declare(program_options
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/program_options.git
    GIT_TAG        v1.0.0
    GIT_SHALLOW    true)

# Fetch the Console I/O library
FetchContent_Declare(conio
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/conio.git
    GIT_TAG        v1.0.0
    GIT_SHALLOW    true)

# Fetch the Logger library
FetchContent_Declare(logger
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/logger.git
    GIT_TAG        v1.0.0
    GIT_SHALLOW    true)

# Fetch the Security Utilities library
FetchContent_Declare(secutil
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/secutil.git
    GIT_TAG        v1.0.1
    GIT_SHALLOW    true)

# Fetch the Random Number Generator library
FetchContent_Declare(random
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/random.git
    GIT_TAG        v1.0.0
    GIT_SHALLOW    true)

# Fetch the character utilities library
FetchContent_Declare(charutil
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/charutil.git
    GIT_TAG        v1.0.0
    GIT_SHALLOW    true)

# None of the libraries need to be installed, so turn off installation
set(aescrypt_engine_INSTALL OFF)
set(program_options_INSTALL OFF)
set(conio_INSTALL OFF)
set(logger_INSTALL OFF)
set(secutil_INSTALL OFF)
set(random_INSTALL OFF)
set(charutil_INSTALL OFF)

# Make dependencies available
FetchContent_MakeAvailable(
    aescrypt_engine
    program_options
    conio
    logger
    secutil
    random
    charutil)
