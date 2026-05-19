/*
 *  mode.h
 *
 *  Copyright (C) 2024, 2026
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      Defines the AESCryptMode type that dictates the mode of operation.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <cstdint>

// Define the operational modes
enum class AESCryptMode : std::uint8_t
{
    Undefined,
    Encrypt,
    Decrypt,
    KeyGenerate
};
