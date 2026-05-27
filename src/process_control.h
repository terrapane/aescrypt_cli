/*
 *  process_control.h
 *
 *  Copyright (C) 2024, 2026
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
#include <atomic>
#include <concepts>

// Simple class to facilitate process control
class ProcessControl
{
    public:
        // Set the flag to indicate that the signal-related thread should exit
        void SetSignalTerminate()
        {
            signal_terminate.store(true, std::memory_order_release);
        }

        // Check to see if the signal-related flag is set
        bool IsSignalTerminateSet()
        {
            return signal_terminate.load(std::memory_order_acquire);
        }

        // Set the main thread termination flag (and notify threads)
        void SetMainTerminate() { terminate = true; }

        // Check to see if the terminate flag is set
        bool IsMainTerminateSet() const { return terminate; }

        // Used for thread synchronization
        std::condition_variable cv;
        std::mutex mutex;

    private:
        std::atomic<bool> signal_terminate{false};
        bool terminate{false};
};
