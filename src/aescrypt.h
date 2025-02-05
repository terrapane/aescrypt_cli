/*
 *  aescrypt.h
 *
 *  Copyright (C) 2025
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This header file defines some common types and values used by various
 *      functions that make up the AES Crypt command-line program.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <cstddef>
#include <cstdint>

// Define the default number of KDF iterations; these MUST align with the
// values in AES Crypt Engine's "engine_common.h" declarations
constexpr std::uint32_t KDF_Min_Iterations = 1;
constexpr std::uint32_t KDF_Iterations = 300'000;
constexpr std::uint32_t KDF_Max_Iterations = 5'000'000;

// Define the default key file size in octets; AES uses a max key length
// of 256 bits, so any size beyond 43 is actually superfluous; entropy in key
// generation is determined by log2(64) * length
constexpr std::size_t Default_Key_File_Size = 64;   // 384 bits of entropy
constexpr std::size_t Min_Key_File_Size = 43;       // 258 bits of entropy
constexpr std::size_t Max_Key_File_Size = 4096;     // 24576 bits of entropy

// Size in octets of buffer for file I/O
constexpr std::size_t Buffered_IO_Size = 131'072;
