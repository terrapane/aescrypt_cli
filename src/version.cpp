/*
 *  version.cpp
 *
 *  Copyright (C) 2026
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines the function to show program version information.
 *
 *  Portability Issues:
 *      None.
 */

#include <iostream>
#include <cstdint>
#ifdef AESCRYPT_ENABLE_LICENSE_MODULE
#include <terra/aescrypt_lm/aescrypt_lm.h>
#endif
#include "version.h"

namespace Terra
{

/*
 *  Version()
 *
 *  Description:
 *      Display AES Crypt version information.
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
    const std::u8string trial = u8"Unlicensed (License Required)";
    std::u8string licensee;

#ifdef AESCRYPT_ENABLE_LICENSE_MODULE
    licensee = Terra::ACLM::GetLicensee();
#endif

    // If no licensee was determined, it must be unlicensed
    if (licensee.empty()) licensee = trial;

    std::cout << Terra::Project_Name << " " << Terra::Project_Version
              << std::endl
              << Terra::Copyright_Text
              << std::endl
              << Terra::Author_Text
              << std::endl;

    std::cout << "Licensee: ";
    std::cout << std::string(licensee.begin(), licensee.end());
    std::cout << std::endl;
}

} // namespace Terra
