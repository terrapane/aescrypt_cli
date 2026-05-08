#
# Handle checks for the string error functions
#
# This will set these definitions based on what is found on the system:
#   HAVE_STRERROR_S
#   HAVE_STRERROR_R
#   HAVE_POSIX_STRERROR_R
#
# HAVE_STRERROR_R does not differentiate between the GNU version of the POSIX
# version, so one must look for HAVE_POSIX_STRERROR_R to see which version
# the system actually offers.
#

include(CheckFunctionExists)
include(CheckCXXSourceCompiles)

# Check to see if the system has strerror_s()
check_function_exists(strerror_s HAVE_STRERROR_S)

# Check to see if the system has strerror_r()
check_function_exists(strerror_r HAVE_STRERROR_R)

# Function to check for string error functions (reduces scope of set())
function(PerformStrerrorCheck)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)

    # Check to see if strerror_r() is the POSIX version (not GNU)
    if(HAVE_STRERROR_R)
        check_cxx_source_compiles("
            #include <cstring>
            #include <array>
            int main()
            {
                std::array<char, 256> buffer{};

                // The POSIX version returns int; the GNU version returns char*
                // This line will fail to compile if it's the GNU version.
                int result = ::strerror_r(0, buffer.data(), buffer.size());
                return result;
            }
        " _LOCAL_HAVE_POSIX_STRERROR_R)
    endif()

    # Export to the parent scope
    if(_LOCAL_HAVE_POSIX_STRERROR_R)
        set(HAVE_POSIX_STRERROR_R TRUE PARENT_SCOPE)
    else()
        set(HAVE_POSIX_STRERROR_R FALSE PARENT_SCOPE)
    endif()
endfunction()

PerformStrerrorCheck()
