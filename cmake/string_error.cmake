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

# Check to see if strerror_r() is the POSIX version (not GNU)
if(HAVE_STRERROR_R)
    check_cxx_source_compiles("
        #include <cstring>
        #include <array>
        int main()
        {
            std::array<char, 256> buffer{};
            int result = ::strerror_r(0, buffer.data(), buffer.size());
            return result;
        }
    " HAVE_POSIX_STRERROR_R)
endif()
