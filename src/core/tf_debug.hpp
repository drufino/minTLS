/* Debugging functionality
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef tf_debug_hpp
#define tf_debug_hpp
#include <stdlib.h>
#include <string>
#include <sstream>
#include <vector>
#include <tls_api.h>
#include <cstdint>
 
int tf_debug_impl(const char *fmt, ...);
int tf_debug_impl(std::string const& msg);

bool& tf_debug_enabled();
void tf_debug_enable();

#define tf_debug(fmt, ...) { if (tf_debug_enabled()) { tf_debug_impl(fmt, ##__VA_ARGS__); } }
#define tf_dbg(x) { if (tf_debug_enabled()) {std::ostringstream os; os << x; tf_debug_impl(os.str()); }}

std::string to_hex(std::vector<uint8_t> const& array);

#endif
