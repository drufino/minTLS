/* Functionality for TLS Extensions
 *
 * Copyright (c) 2015, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found in the
 * LICENSE file.
 */
#include <tls/tls_extensions.hpp>
#include <tls/tls_ecc.hpp>
 
TLSExtensionBase::~TLSExtensionBase()
{
}

// Factory method
TLSExtensionBase *
TLSExtensionBase::create_from_type(TLSExtensionType const& type)
{
    if (type.underlying() == TLSExtensionTypes::elliptic_curves)
    {
        return new TLSSupportedEllipticCurves();
    }
    else
    {
        return 0;
    }
}

TLSExtension::TLSExtension(std::shared_ptr<TLSExtensionBase> impl)
  : 
  m_type(TLSExtensionTypes::unknown),
  m_impl(impl)
{
    make_unique();

    if (m_impl.get() != 0)
    {
        m_type = m_impl->type();
    }
}
// Default constructor
TLSExtension::TLSExtension()
 : m_type(TLSExtensionTypes::unknown)
{
}

// Comparison operator
bool
TLSExtension::operator==(TLSExtension const& rhs) const
{
    if (m_impl && rhs.m_impl)
    {
        return m_impl->equals(*rhs.m_impl);
    }
    else
    {
        return m_impl.get() == rhs.m_impl.get();
    }
}

// Copy Constructor
TLSExtension::TLSExtension(TLSExtension const& rhs)
{
    m_type = rhs.m_type;
    m_impl = rhs.m_impl;
}

// Serialize
void
TLSExtension::serialize(archive& ar)
{
    if (ar.is_reading())
    {
        std::vector<uint8_t> extension_data;
        ar & m_type & extension_data;

        // Create an instance of this type
        m_impl.reset(TLSExtensionBase::create_from_type(m_type));

        // If successful serialize
        if (m_impl)
        {
            iarchive ar2(&extension_data[0], extension_data.size());
            ar2 & *m_impl;
        }
        // Otherwise ignore the bytes
    }
    else
    {
        assert(m_impl.get() != 0);

        // Serialize the extension first
        std::vector<uint8_t> extension_data;
        {
            oarchive ar_extension_data(extension_data);
            ar_extension_data & *m_impl;
        }

        // Then serialize whole object
        ar & m_type & extension_data;
    }
}

void
TLSExtension::make_unique()
{
    // Make sure it's unique
    if (m_impl && m_impl.use_count() > 1)
    {
        m_impl.reset(m_impl->clone());
    }
}

