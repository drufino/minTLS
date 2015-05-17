/* Functionality for TLS Extensions
 *
 * Main rfcs are
 *
 *  - RFC-4366  Transport Layer Security (TLS) Extensions 
 *  - RFC-4492  Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)
 * 
 * Copyright (c) 2015, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found in the
 * LICENSE file.
 */
#ifndef tf_tls_extensions_hpp
#define tf_tls_extensions_hpp
#include <core/safe_enum.hpp>
#include <core/archive.hpp>
#include <cassert>

struct TLSExtensionTypes
{
    enum type
    {
        unknown=0,
        // Elliptic Curve TLS Extensions - RFC 4492 Sec 5.1.1
        elliptic_curves=10,
        ec_point_formats=11
    };
};


typedef safe_enum<TLSExtensionTypes>        TLSExtensionType;

ARCHIVE_SAFE_ENUM_16(TLSExtensionType);

// Base class for all concrete implementations of TLS Extensions
class TLSExtensionBase
{
public:
    // Virtual destructor
    virtual ~TLSExtensionBase();

    // Factory method, returns null pointer if the type is not recognised
    static TLSExtensionBase *create_from_type(TLSExtensionType const& type);

    // Clone method
    virtual TLSExtensionBase *clone() const= 0;

    // Get the enumerated type
    virtual TLSExtensionType type() const= 0;

    // Comparison operator
    virtual bool equals(TLSExtensionBase const& rhs) const= 0;

    // Serialize method
    virtual void serialize(archive& ar)= 0;
};

// Polymorphic container class for TLS Extensions
class TLSExtension
{
public:
    // Default 
    TLSExtension();

    // Constructor
    TLSExtension(std::shared_ptr<TLSExtensionBase> impl);

    // Copy constructor
    TLSExtension(TLSExtension const& rhs);

    // Serialize
    void serialize(archive& ar);

    // Get implementation
    template<typename T>
    T const * get() const
    {
        if (m_impl.get() == 0)
        {
            return 0;
        }
        else
        {
            T const *pImpl = dynamic_cast<T const *>(m_impl.get());
            return pImpl;
        }
    }

    template<typename T>
    T * get()
    {
        if (m_impl.get() == 0)
        {
            return 0;
        }
        else
        {
            make_unique();
            T *pImpl = dynamic_cast<T *>(m_impl.get());
            return pImpl;
        }
    }

    // Comparison operator
    bool operator==(TLSExtension const& rhs) const;

    TLSExtensionType type() const { return m_type; }

private:
    void make_unique();

    TLSExtensionType                    m_type;    // Type
    std::shared_ptr<TLSExtensionBase>   m_impl;    // Concrete instantia
};


#endif /* tf_tls_extensions_hpp */