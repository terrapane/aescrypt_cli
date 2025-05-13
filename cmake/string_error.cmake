# Handle checks for the string error functions

# Check that Windows has strerror_s()
include(CheckFunctionExists)
check_function_exists(strerror_s HAVE_STRERROR_S)

# Check to see if the system has strerror_r()
include(CheckSymbolExists)
check_symbol_exists(strerror_r "string.h" HAVE_STRERROR_R)

#Check to see if it's the POSIX version, as opposed to the GNU version
if(HAVE_STRERROR_R)
    include(CheckCXXSourceCompiles)
    check_cxx_source_compiles("
        #include <cstring>
        int main()
        {
            char buffer[256];
            int result = ::strerror_r(0, buffer, sizeof(buffer));
            return result;
        }
    " HAVE_POSIX_STRERROR_R)
endif()
