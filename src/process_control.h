/*
 *  process_control.h
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This header defines a simple ProcessControl structure used to gracefully
 *      control the termination of the process when the user requests it
 *      (e.g., CTRL-C).
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <condition_variable>
#include <mutex>

// Simple structure to facilitate process control
struct ProcessControl
{
    bool terminate = false;
    std::condition_variable cv;
    std::mutex mutex;
};
