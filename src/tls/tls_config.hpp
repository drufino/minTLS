/* TLS Session Config
 * 
 * Copyright (c) 2015, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef mintls_config_hpp
#define mintls_config_hpp
#include <string>
#include "core/safe_enum.hpp"
 
struct TrustTypes
{
    enum type
    {
        FULL=0,         // Full verification
        CHAIN=1,        // Everything except root certificate
        NONE=2          // No verification 
    };
};

typedef safe_enum<TrustTypes> TrustType;

struct TLSConfig
{
    // Default constructor
    TLSConfig();

    TrustType           trust_type;
    std::string         ca_root_file;
};

#endif 