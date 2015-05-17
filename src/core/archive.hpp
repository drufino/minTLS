/* Utility classes for serializing and deserializing TLS structures
 * with unified syntax.
 *
 * A very simplified version of the boost serialization framework.
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef tf_archive_h
#define tf_archive_h
#include <stdlib.h>
#include <vector>
#include <stdint.h>

#ifndef archive_inline
#define archive_inline __inline
#endif

namespace asn1
{
    class ber_archive;
}
//
// Utility classes for serializing and deserializing TLS structures
// 
class archive;

struct uint24_t
{
    uint24_t() : val(0) {}
    uint24_t(uint32_t val_) : val(val_) {}

    operator size_t () const { return size_t(val); }

    uint24_t& operator *=(size_t const& rhs) { val *= rhs; return *this; }
    uint24_t& operator /=(size_t const& rhs) { val /= rhs; return *this; }

    uint32_t    val;
};

// Base class for simultaneously reading and writing
class archive
{
public:
    enum state_t
    {
        reading=0,
        writing=1
    };

    struct error : public std::exception {};

    // read from an oarchive and vice-versa
    struct error_mismatch           : public error {};

    // ran out of space for read
    struct error_eof                : public error {};

    // Serialization primitives
    virtual archive & operator&(uint8_t  & x);
    virtual archive & operator&(uint16_t & x);
    virtual archive & operator&(uint32_t & x);
    virtual archive & operator&(uint64_t & x);

    // Size of archive currently serialized
    virtual size_t size() const =0;
    virtual size_t left() const =0;

    bool is_reading() const;
    bool is_writing() const;

    // Raw read and write functions
    virtual void read_impl (uint8_t *out,       size_t const sz) const; 
    virtual void write_impl(uint8_t const*in,   size_t const sz);

    // Raw read/write
    virtual archive& raw(std::vector<uint8_t>& buf) =0;

protected:
    archive(state_t state);

private:
    archive();
    state_t     m_state;
};

// Class for just deserializing
class iarchive : public archive
{
public:
    // Constructor
    iarchive(uint8_t const *buf, size_t sz);

    // Copy constructor
    iarchive(iarchive const& rhs);

    // Amount read so far
    virtual size_t size() const;

    // Amount left
    virtual size_t left() const;

    // Underlying archive implementation
    virtual void read_impl (uint8_t *out, size_t const sz) const;
    virtual iarchive& raw(std::vector<uint8_t>& buf);

    // Extract opaque
    virtual iarchive opaque(size_t const sz) const;

    friend class asn1::ber_archive;
private:
    uint8_t const*      m_buf;          // Raw buffer
    mutable size_t      m_consumed;     // Amount already consumed
    size_t              m_sz;           // Total size
};

// Class for serializing
class oarchive : public archive
{
public:
    oarchive();

    oarchive(std::vector<uint8_t>& buf);

    virtual size_t size() const;
    virtual size_t left() const;

    virtual void write_impl(uint8_t const* data, size_t const sz);
    virtual oarchive& raw(std::vector<uint8_t>& buf);

private:
    std::vector<uint8_t>*   m_buf;      // Buffer to append to

    size_t                  m_written;  // Amount already written
};

#define ARCHIVE_ENUM(enum_type) \
template<> __inline             \
archive& operator&(archive& ar, enum_type& x)   \
{                                               \
    if (ar.is_reading())                        \
    {                                           \
        uint8_t x_;                             \
        ar & x_;                                \
        x = (enum_type)x_;                      \
    }                                           \
    else                                        \
    {                                           \
        uint8_t x_ = (uint8_t)x;                \
        ar & x_;                                \
    }                                           \
    return ar;                                  \
}

#define ARCHIVE_SAFE_ENUM(enum_type) \
template<> __inline                             \
archive& operator&(archive& ar, enum_type& x)   \
{                                               \
    if (ar.is_reading())                        \
    {                                           \
        uint8_t x_;                             \
        ar & x_;                                \
        x = (enum_type::type)x_;                \
    }                                           \
    else                                        \
    {                                           \
        uint8_t x_ = (uint8_t)x.underlying();   \
        ar & x_;                                \
    }                                           \
    return ar;                                  \
}

#define ARCHIVE_ENUM_16(enum_type) \
template<> __inline                             \
archive& operator&(archive& ar, enum_type& x)   \
{                                               \
    if (ar.is_reading())                        \
    {                                           \
        uint16_t x_;                            \
        ar & x_;                                \
        x = (enum_type)x_;                      \
    }                                           \
    else                                        \
    {                                           \
        uint16_t x_ = (uint16_t)x;              \
        ar & x_;                                \
    }                                           \
    return ar;                                  \
}

#define ARCHIVE_SAFE_ENUM_16(enum_type)         \
template<> __inline                             \
archive& operator&(archive& ar, enum_type& x)   \
{                                               \
    if (ar.is_reading())                        \
    {                                           \
        uint16_t x_;                            \
        ar & x_;                                \
        x = (enum_type::type)x_;                \
    }                                           \
    else                                        \
    {                                           \
        uint16_t x_ = (uint16_t)(x.underlying()); \
        ar & x_;                                \
    }                                           \
    return ar;                                  \
}

template<typename T>
archive& operator&(archive& ar, T& obj)
{
    obj.serialize(ar);
    return ar;
}

template<typename T>
oarchive& operator<<(oarchive& ar, T const& obj)
{
    ar & const_cast<T&>(obj);
    return ar;
}

template<> archive_inline
archive& operator&(archive& ar, bool & obj)
{
    if (ar.is_writing())
    {
        uint8_t x = obj;
        ar.operator&(x);
    }
    else
    {
        uint8_t x(0);
        ar.operator&(x);
        obj = (x == 0) ? false : true;
    }
    return ar;
}

template<> archive_inline
archive& operator&(archive& ar, uint8_t & obj)
{
    return ar.operator&(obj);
}

template<> archive_inline
archive& operator&(archive& ar, uint16_t & obj)
{
    return ar.operator&(obj);
}

template<> archive_inline
archive& operator&(archive& ar, uint32_t & obj)
{
    return ar.operator&(obj);
}

template<typename T, uint16_t size>
archive& operator&(archive& ar, T(&x)[size])
{
    for (unsigned i = 0; i < size; ++i)
    {
        ar & x[i];
    }

    return ar;
}

template<> archive_inline
archive& operator&(archive& ar, uint24_t & obj)
{
    uint8_t buf[3];
    uint32_t& val = obj.val;

    if (ar.is_reading())
    {
        ar & buf;
        val = uint32_t(buf[0])<<16;
        val |= uint32_t(buf[1])<<8;
        val |= uint32_t(buf[2])<<0;
    }
    else
    {
        buf[0] = (val>>16)&0xff;
        buf[1] = (val>>8) &0xff;
        buf[2] = (val>>0) &0xff;
        ar & buf;
    }
    return ar;
}

// Quick template magic to determine if data type is POD at compile time
template<typename T> struct is_pod { static const bool value = false; };
template<> struct is_pod<uint8_t>  { static const bool value = true; };
template<> struct is_pod<uint16_t> { static const bool value = true; };
template<> struct is_pod<uint24_t> { static const bool value = true; };
template<> struct is_pod<uint32_t> { static const bool value = true; };
template<> struct is_pod<uint64_t> { static const bool value = true; };

template<typename T, typename length_type>
void serialize_vector_pod(archive& ar, std::vector<T>& vec)
{
    if (ar.is_writing())
    {
        // XXX check overflow
        length_type len = vec.size(); len *= sizeof(T);
        ar & len;
        for (unsigned i = 0; i < vec.size(); ++i)
        {
            ar & vec[i];
        }
    }
    else
    {
        // XXX check overflow
        length_type len; ar & len; len /= sizeof(T);

        vec.resize(len);
        for (unsigned i = 0; i < vec.size(); ++i)
        {
            ar & vec[i];
        }
    }
}


template<typename T, typename length_type>
void serialize_vector(archive& ar, std::vector<T>& vec, bool omit_empty)
{
    // Capture the case where empty vector has empty serialization and vice-versa
    if (omit_empty)
    {
        if (ar.is_reading())
        {
            if (ar.left() == 0)
            {
                return;
            }
        }
        else
        {
            if (vec.size() == 0)
            {
                return;
            }
        }
    }
    if (is_pod<T>::value)
    {
        // POD case is simpler
        serialize_vector_pod<T,length_type>(ar, vec);
    }
    else
    {
        // Non-POD case, somewhat inefficient
        if (ar.is_writing())
        {
            std::vector<uint8_t> bytes;
            oarchive new_ar(bytes);

            for (size_t i = 0; i < vec.size(); ++i)
            {
                new_ar & vec[i];
            }

            // XXX- check overflow
            length_type len = bytes.size();
            ar & len;
            if (bytes.size() > 0) ar.write_impl(&bytes[0], bytes.size());
        }
        else
        {
            length_type len; ar & len;

            if (len > 0)
            {
                // Read the whole thing
                std::vector<uint8_t> bytes(len,0);
                ar.read_impl(&bytes[0], len);

                // Read each element in turn
                iarchive new_ar(&bytes[0], len);
                vec.clear();
                while (new_ar.size() < len)
                {
                    vec.push_back(T());
                    new_ar & vec.back();
                }
            }
        }
    }
}

template<typename T> archive_inline
archive& operator&(archive& ar, std::vector<T>& vec)
{
    serialize_vector<T,uint16_t>(ar,vec,false);
    return ar;
}

template<typename T>
size_t serialize_length(T const & obj)
{
    oarchive ar;
    ar << obj;
    return ar.size();
}

template<typename T, typename length_type, bool omit_empty>
class vararray_impl
{
public:
    typedef std::vector<T>              vec;

    // Default constructor
    vararray_impl() :
        m_vec()
    {}

    // Constructor
    vararray_impl(length_type cnt, T const& val) :
        m_vec(cnt, val)
    {}

    // Constructor
    vararray_impl(vec const & vec) :
        m_vec(vec)
    {}

    void serialize(archive & ar)
    {
        serialize_vector<T,length_type>(ar,m_vec,omit_empty);
    }

    // Implicit Conversion Operators
    operator vec const&() const { return m_vec; }
    operator vec &()       { return m_vec; }

    // Get the first element
    T const& front() const { return m_vec.front(); }
    T&       front()       { return m_vec.front(); }

    // Get the last element
    T const& back() const { return m_vec.back(); }
    T&       back()       { return m_vec.back(); }

    // Append an element
    void push_back(T const& x) { m_vec.push_back(x); }

    // Check for equality
    bool operator==(vararray_impl<T,length_type,omit_empty> const& rhs) const
    {
        return m_vec == rhs.m_vec;
    }

    // Clear the vector
    void clear()
    {
        m_vec.clear();
    }

    // Size
    size_t const size() const
    {
        return m_vec.size();
    }

    // Array index
    const T& operator[](typename vec::size_type i) const
    {
        return m_vec[i];
    }

    // Array index
    T& operator[](typename vec::size_type i)
    {
        return m_vec[i];
    }

    vec& get() { return m_vec; }
    vec const& get() const { return m_vec; }

private:
    vec  m_vec;
};

// Alias specific cases
template<typename T, bool omit_empty=false>
struct vararray
{
    typedef vararray_impl<T, uint8_t, omit_empty>  _8;
    typedef vararray_impl<T, uint16_t, omit_empty> _16;
    typedef vararray_impl<T, uint24_t, omit_empty> _24;
    typedef vararray_impl<T, uint32_t, omit_empty> _32;
};

#undef archive_inline
#endif /* tf_archive_h */
