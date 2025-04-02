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
    GIT_TAG        v4.0.10
    GIT_SHALLOW    true)

# Fetch the AES Crypt Licensing Module for consumer builds
if(aescrypt_ENABLE_LICENSE_MODULE)
    FetchContent_Declare(aescrypt_lm
        GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/aescrypt_lm.git
        GIT_TAG        v1.0.8
        GIT_SHALLOW    true)
endif()

# Fetch the Program Options library
FetchContent_Declare(program_options
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/program_options.git
    GIT_TAG        v1.0.1
    GIT_SHALLOW    true)

# Fetch the Console I/O library
FetchContent_Declare(conio
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/conio.git
    GIT_TAG        v1.0.2
    GIT_SHALLOW    true)

# Fetch the Logger library
FetchContent_Declare(logger
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/logger.git
    GIT_TAG        v1.0.4
    GIT_SHALLOW    true)

# Fetch the Security Utilities library
FetchContent_Declare(secutil
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/secutil.git
    GIT_TAG        v1.0.5
    GIT_SHALLOW    true)

# Fetch the Random Number Generator library
FetchContent_Declare(random
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/random.git
    GIT_TAG        v1.0.1
    GIT_SHALLOW    true)

# Fetch the character utilities library
FetchContent_Declare(charutil
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/charutil.git
    GIT_TAG        v1.0.2
    GIT_SHALLOW    true)

# None of the libraries need to be installed, so do so only if requested
set(aescrypt_engine_INSTALL ${aescrypt_cli_DEPENDENCIES_INSTALL})
set(aescrypt_lm_INSTALL ${aescrypt_cli_DEPENDENCIES_INSTALL})
set(program_options_INSTALL ${aescrypt_cli_DEPENDENCIES_INSTALL})
set(conio_INSTALL ${aescrypt_cli_DEPENDENCIES_INSTALL})
set(logger_INSTALL ${aescrypt_cli_DEPENDENCIES_INSTALL})
set(secutil_INSTALL ${aescrypt_cli_DEPENDENCIES_INSTALL})
set(random_INSTALL ${aescrypt_cli_DEPENDENCIES_INSTALL})
set(charutil_INSTALL ${aescrypt_cli_DEPENDENCIES_INSTALL})

# Make dependencies available
FetchContent_MakeAvailable(
    aescrypt_engine
    program_options
    conio
    logger
    secutil
    random
    charutil)

# Fetch the licensing module for consumer builds
if(aescrypt_ENABLE_LICENSE_MODULE)
    FetchContent_MakeAvailable(aescrypt_lm)
endif()
