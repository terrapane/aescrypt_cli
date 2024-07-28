/*
 *  secure_containers.h
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This header file defines aliases for container types that provide
 *      additional security features.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <terra/secutil/secure_vector.h>
#include <terra/secutil/secure_string.h>

// Definitions for readability
template<typename T>
using SecureVector = Terra::SecUtil::SecureVector<T>;
using SecureString = Terra::SecUtil::SecureString;
using SecureU8String = Terra::SecUtil::SecureU8String;
