/* Functionality related to ECC in TLS
 *
 * Main rfcs are
 *
 *  - RFC-4492  Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)
 * 
 * Copyright (c) 2015, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found in the
 * LICENSE file.
 */
#ifndef tf_tls_ecc_hpp
#define tf_tls_ecc_hpp
#include <core/safe_enum.hpp>
#include <core/archive.hpp>
#include <tls/tls_extensions.hpp>
#include <ecdh.h>

// RFC 4492 Sec 5.1.1 
struct TLSNamedCurves
{
    typedef MinTLS_NamedCurve type;
};

// RFC 4492 Sec 5.4
struct ECCurveTypes
{
    enum type
    {
        explicit_prime = 1,
        explicit_char2 = 2,
        named_curve    = 3
    };
};

struct ECPointFormats
{
    enum type
    {
        uncompressed   = 0,
        ansiX962_compressed_prime = 1,
        ansiX962_compressed_char2 = 2
    };
};

typedef safe_enum<TLSNamedCurves>           TLSNamedCurve;
typedef safe_enum<ECCurveTypes>             ECCurveType;
typedef safe_enum<ECPointFormats>           ECPointFormat;
ARCHIVE_SAFE_ENUM_16(TLSNamedCurve);
ARCHIVE_SAFE_ENUM(ECCurveType);
ARCHIVE_SAFE_ENUM(ECPointFormat);

typedef vararray<ECPointFormat>::_8         ECPointFormatList;

// RFC 4492 Sec 5.4
// Only supports the NamedCurve type
struct ECParameters
{
public:
    // Default constructor
    ECParameters();

    // (De)Serialize
    void serialize(archive& ar);

    ECCurveType         type;
    TLSNamedCurve       named_curve;
};

struct ECPoint
{
public:
    void serialize(archive& ar);    

    vararray<uint8_t>::_8       point; // Opaque point encoding
};

// RFC-4492 Section 5.1.1
class TLSSupportedEllipticCurves : public TLSExtensionBase
{
public:
    // Default constructor
    TLSSupportedEllipticCurves();

    // Constructor
    TLSSupportedEllipticCurves(std::vector<TLSNamedCurve> const& curves);

    // Serialize method
    virtual void serialize(archive& ar);

    // Clone method
    virtual TLSSupportedEllipticCurves *clone() const;

    // Get the enumerated type
    virtual TLSExtensionType type() const;

    // Comparison operator
    virtual bool equals(TLSExtensionBase const& rhs) const;

    // Comparison operator
    bool operator==(TLSSupportedEllipticCurves const& rhs) const;

    // Destructor
    virtual ~TLSSupportedEllipticCurves();

    std::vector<TLSNamedCurve>      m_curves;
};
#endif