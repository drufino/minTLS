/* Container for UTF-8 Strings
 * 
 * Copyright (c) 2015, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef utf8string_hpp
#define utf8string_hpp
#include <vector>
#include <string>

class UTF8String
{
public:
    // Default constructor
    UTF8String() {}

    // Construct from a vector of bytes
    UTF8String(std::vector<uint8_t> const& bytes);

    // Pre-allocate some space
    void reserve(size_t const sz);

    // Append a byte
    UTF8String& operator+=(uint8_t const b);

    // Comparison operator
    bool operator==(UTF8String const& rhs) const;

    // Pretty print, converts non-ascii characters to naive hex format
    std::string pretty_print() const;

    // Get the raw bytes
    std::vector<uint8_t> const& bytes() const { return m_bytes; }

private:
    std::vector<uint8_t>    m_bytes;
};

// Comparison for names used in X509 path validation. See
//
//    RFC-5280 section 7
//    RFC-4518
//
// Currently only peform the match correctly for ascii characters, other
// cases may be too strict.
bool caseIgnoreMatch(UTF8String const& lhs, UTF8String const& rhs);

#endif