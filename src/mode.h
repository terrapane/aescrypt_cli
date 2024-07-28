/*
 *  mode.h
 *
 *  Copyright (C) 2024
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

// Define the operational modes
enum class AESCryptMode
{
    Undefined,
    Encrypt,
    Decrypt,
    KeyGenerate
};
