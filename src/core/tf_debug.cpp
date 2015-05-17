/* Debugging functionality
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "tls_api.h"
#include "tf_debug.hpp"
#include <vector>
#include <cstdlib>
#include <iostream>
#include <cstdint>
#include <stdarg.h>

bool& tf_debug_enabled()
{
    static bool s_debug_enabled(false);
    return s_debug_enabled;
}

void tf_debug_enable()
{
    tf_debug_enabled() = true;
}

int
tf_debug_impl(const char *fmt, ...)
{
    if (!tf_debug_enabled())
    {
        return 0;
    }

    va_list args;
    va_start(args, fmt);
    int ret = vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr,"\n");
    return ret;
}

int tf_debug_impl(std::string const& msg)
{
    if (!tf_debug_enabled())
    {
        return 0;
    }

    std::cerr << msg << std::endl;
    return 0;
}

std::string to_hex(std::vector<uint8_t> const& array)
{
    static char hex[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    std::string s;
    for (unsigned i = 0; i < array.size(); ++i)
    {
        s += hex[array[i] >> 4];
        s += hex[array[i] & 0x0f];
    }
    return s;
}
