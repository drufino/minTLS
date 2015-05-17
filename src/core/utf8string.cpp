/* Container for UTF-8 Strings
 * 
 * Copyright (c) 2015, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "core/utf8string.hpp"
#include "core/archive.hpp"

UTF8String::UTF8String(std::vector<uint8_t> const& bytes)
  : m_bytes(bytes)
{
}

UTF8String&
UTF8String::operator+=(uint8_t const x)
{
    m_bytes.push_back(x);
    return *this;
}

bool
UTF8String::operator==(UTF8String const& rhs) const
{
    return m_bytes == rhs.m_bytes;
}

std::string
UTF8String::pretty_print() const
{
    std::string res;
    iarchive ar(&m_bytes[0], m_bytes.size());

    while (ar.left() > 0)
    {
        uint8_t x; ar & x;
        // 1-byte encoding
        if ((x & 0x80) == 0)
        {
            res += char(x);
        }
        else
        {
            size_t nContinuationBytes(0x0);
            uint32_t code_point(0);
            if ((x & 0xE0) == 0xC0) { nContinuationBytes = 1; code_point = x & 0x1f; }
            else if ((x & 0xF0) == 0xE0) { nContinuationBytes = 2; code_point = x & 0x0f; }
            else if ((x & 0xF8) == 0xF0) { nContinuationBytes = 3; code_point = x & 0x07; }
            else
            {
                // Invalid encoding
                throw std::runtime_error("Invalid UTF-8 encoding");
            }

            if (ar.left() < nContinuationBytes)
            {
                throw std::runtime_error("Invalid UTF-8 encoding");
            }

            char tmp[20];
            snprintf(tmp,sizeof(tmp)-1,"\\x%.2X",x);
            res += tmp;

            for (unsigned i = 0; i < nContinuationBytes; ++i)
            {
                ar & x;
                if ((x & 0xC0) != 0x80)
                {
                    throw std::runtime_error("Invalid UTF8-encoding");
                }
                code_point <<= 6;
                code_point |= (x & 0x3f);

                snprintf(tmp,sizeof(tmp)-1,"\\x%.2X",x);
                res += tmp;
            }

        }
    }

    return res;
}

bool caseIgnoreMatch(UTF8String const& lhs, UTF8String const& rhs)
{
    std::vector<uint8_t> const& lhs_bytes = lhs.bytes();
    std::vector<uint8_t> const& rhs_bytes = rhs.bytes();

    // Simple case
    if (lhs_bytes == rhs_bytes)
    {
        return true;
    }
    else
    {
        unsigned ilhs(0);
        unsigned irhs(0);
        for (; ilhs < lhs_bytes.size() && irhs < rhs_bytes.size(); )
        {
            uint8_t const x = lhs_bytes[ilhs];
            uint8_t const y = rhs_bytes[irhs];

            if (!(x&0x80) && !(y&0x80))
            {
                // Ignore whitespace
                if (isspace(x))
                {
                    ++ilhs; continue;
                }
                else if (isspace(y))
                {
                    ++irhs; continue;
                }
                // Ignore case
                else if (tolower(x) != tolower(y))
                {
                    return false;
                }
                else
                {
                    ++ilhs; ++irhs;
                }
            }
            else if (x != y)
            {
                return false;
            }
            else
            {
                ++ilhs; ++irhs;
            }
        }

        // Strip trailing whitespace
        while (ilhs < lhs_bytes.size() && isspace(lhs_bytes[ilhs])) ++ilhs;
        while (irhs < rhs_bytes.size() && isspace(rhs_bytes[irhs])) ++irhs;

        // If there are extra letters then don't match
        if (ilhs < lhs_bytes.size() || irhs < rhs_bytes.size())
        {
            return false;
        }
        return true;
    }
}