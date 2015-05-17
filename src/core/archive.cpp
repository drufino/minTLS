/* Utility classes for serializing and deserializing TLS structures
 * with unified syntax.
 *
 * A very simplified version of the boost serialization framework.
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef _MSC_VER
#define archive_inline
#endif
#include <core/portability.h>
#include "archive.hpp"
#include <stdexcept>
#include <cstring>
#include <iomanip>
#include "tf_debug.hpp"

archive::archive(state_t state) :
    m_state(state)
{}

bool
archive::is_reading() const
{
    return m_state == reading;
}

bool 
archive::is_writing() const
{
    return m_state == writing;
}

archive &
archive::operator&(uint8_t& x)
{
    uint8_t buf[1];

    switch (m_state)
    {
    case reading:
        read_impl(buf,1);
        x = buf[0];
        break;
    case writing:
        buf[0] = x;
        write_impl(buf,1);
        break;
    }

    return *this;
}

archive &
archive::operator&(uint16_t& x)
{
    uint8_t buf[2];

    switch (m_state)
    {
    case reading:
        read_impl(buf,2);
		x = byteswap16(*(uint16_t *)buf);
        break;
    case writing:
		*(uint16_t *)buf = byteswap16(x);
        write_impl(buf,2);
        break;
    }

    return *this;
}

archive &
archive::operator&(uint32_t& x)
{
    uint8_t buf[4];

    switch (m_state)
    {
    case reading:
        read_impl(buf, 4);
        x = byteswap32(*(uint32_t *)buf);
        break;
    case writing:
		*(uint32_t *)buf = byteswap32(x);
        write_impl(buf,4);
        break;
    }

    return *this;
}

archive &
archive::operator&(uint64_t& x)
{
    uint8_t buf[8];

    switch (m_state)
    {
    case reading:
        read_impl(buf, 4);
		x = byteswap32(*(uint32_t *)buf);
        x <<= 32;
        read_impl(buf, 4);
		x |= byteswap32(*(uint32_t *)buf);
        break;
    case writing:
		*(uint32_t *)(buf + 0) = byteswap32(x >> 32);
		*(uint32_t *)(buf + 4) = byteswap32(x & 0xffffffff);
        write_impl(buf,8);
        break;
    }

    return *this;
}


void
archive::read_impl(uint8_t *out, size_t const sz) const
{
    throw error_mismatch();
}

void
archive::write_impl(uint8_t const*in, size_t const sz)
{
    throw error_eof();
}


////////////////
// Deserializer

iarchive::iarchive(uint8_t const*buf, size_t sz) :
    archive(reading),
    m_buf(buf),
    m_consumed(0),
    m_sz(sz)
{
}

iarchive::iarchive(iarchive const& rhs) :
    archive(reading),
    m_buf(rhs.m_buf),
    m_consumed(rhs.m_consumed),
    m_sz(rhs.m_sz)
{
}

void
iarchive::read_impl(uint8_t *out, size_t const sz) const
{
    // Check for integer overflow and buffer overflow
    if (m_consumed + sz < m_consumed || m_consumed+sz > m_sz)
    {
        throw error_eof();
    }

    memcpy(out, m_buf + m_consumed, sz);
    m_consumed += sz;
}

iarchive&
iarchive::raw(std::vector<uint8_t>& buf)
{
    buf.resize(left());
    iarchive::read_impl(&buf[0],left());
    return *this;
}

size_t
iarchive::size() const
{
    return m_consumed;
}

// Amount left
size_t
iarchive::left() const
{
    return m_sz - m_consumed;
}

// Extract opaque
iarchive
iarchive::opaque(size_t const sz) const
{
    if (sz + m_consumed < sz || sz + m_consumed > m_sz)
    {
        throw error_eof();
    }

    iarchive sub_ar(m_buf+m_consumed, sz);
    m_consumed += sz;
    return sub_ar;
}

//////////////////
// Serializer
oarchive::oarchive() :
    archive(writing),
    m_buf(NULL),
    m_written(0)
{
}

oarchive::oarchive(std::vector<uint8_t>& buf) :
    archive(writing),
    m_buf(&buf),
    m_written(0)
{
}

void
oarchive::write_impl(uint8_t const* data, size_t const sz)
{
    if (m_buf != 0)
    {
        size_t old_sz = m_buf->size();

        // Check for integer overflow
        if (old_sz + sz < old_sz)
        {
            throw error_eof();
        }

        m_buf->resize(old_sz + sz);
        memcpy(&(*m_buf)[old_sz], data, sz);
    }

    m_written += sz;
}


oarchive&
oarchive::raw(std::vector<uint8_t>& buf)
{
    oarchive::write_impl(&buf[0],buf.size());
    return *this;
}

size_t
oarchive::left() const
{
    throw std::runtime_error("oarchive::left not implemented");
}
size_t
oarchive::size() const
{
    return m_written;
}
