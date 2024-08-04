/*
 *  secure_program_options.h
 *
 *  Copyright (C) 2024
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines a SecureOptionsParser object that extends the
 *      Program Options Parser object to ensure parsed strings are securely
 *      erased upon destruction.
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <terra/program_options/program_options.h>
#include <terra/secutil/secure_erase.h>

// Define the SecureProgramOptions object
class SecureOptionsParser : public Terra::ProgramOptions::Parser
{
    public:
        using Terra::ProgramOptions::Parser::Parser;
        virtual ~SecureOptionsParser()
        {
            SecureOptionsParser::ClearOptions();
        }
        virtual void ClearOptions()
        {
            for (auto &[option_name, option_values] : option_map)
            {
                for (auto &option : option_values)
                {
                    Terra::SecUtil::SecureErase(option);
                }
            }
            option_map.clear();
        }
};
