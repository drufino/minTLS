/* Functionality related to TLS (x509) certificates
 * 
 * Primary reference
 *   [3] http://tools.ietf.org/html/rfc5280
 *   [4] http://tools.ietf.org/html/rfc3279
 *
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef tf_tls_certificate
#define tf_tls_certificate
#include "asn1/asn1_archive.hpp"
#include "asn1/asn1_objects.hpp"
#include "core/bigint.hpp"
#include "core/utf8string.hpp"
#include <map>

// All the x509 nonsense
namespace x509
{

// Forward declarations
class ExtensionBase;

// http://tools.ietf.org/html/rfc2818
// http://tools.ietf.org/html/rfc1779
// http://tools.ietf.org/html/rfc2253
// 
class Name : public asn1::ber_decodable_sequence
{
public:
    typedef std::vector<std::pair<asn1::OID, UTF8String> > container_type;

    // BER decoding
    void ber_decode(asn1::ber_archive& ar);

    // Get the contents
    container_type const& get_contents() const { return m_contents; }

    // Add an attribute
    void add_attribute(asn1::OID const& oid, UTF8String const& value);

    // Get string representation
    std::string to_string(bool const bSlashSeparator = false) const;

    // Comparison operator
    bool operator==(Name const& rhs) const;

private:
    container_type      m_contents;
};

// Case-Insensitive match
bool caseIgnoreMatch(Name const& lhs, Name const& rhs);

// [3] 4.2
class Extension : public asn1::ber_decodable
{
public:
    // Default constructor
    Extension();

    // Copy constructor
    Extension(Extension const& rhs);

    // Assignment operator
    Extension& operator=(Extension const& rhs);

    // Destructor
    ~Extension();

    void ber_decode(asn1::ber_archive& ar);

    // Comparison operator
    bool operator==(Extension const& rhs) const;

    asn1::OID                       extnID;
    bool                            critical;
    std::vector<uint8_t>            extnValue;

    ExtensionBase const *           get_impl() const;
    ExtensionBase *                 get_impl();

private:
    std::shared_ptr<ExtensionBase>  m_impl;
};

// http://tools.ietf.org/html/rfc5280#section-4.1.2
class Certificate : public asn1::ber_decodable_sequence
{
public:
    // [3] 4.1
    void ber_decode(asn1::ber_archive & ar);

    // Helper function for finding extension
    template<typename T>
    T const *get_extension() const
    {
        for (unsigned iExt = 0; iExt < extensions.size(); ++iExt)
        {
            T const *pExt = dynamic_cast<T const *>(extensions[iExt].get_impl());
            if (pExt) return pExt;
        }

        return 0;
    }

    template<typename T>
    T *get_extension()
    {
        for (unsigned iExt = 0; iExt < extensions.size(); ++iExt)
        {
            T *pExt = dynamic_cast<T *>(extensions[iExt].get_impl());
            if (pExt) return pExt;
        }

        return 0;
    }

    // Check an extension exists
    template<typename T>
    bool has_extension() const
    {
        return get_extension<T>() != 0;
    }

    // Raw bytes of TBS Certificate
    std::vector<uint8_t>        TBSCertificate; // TBS Certificate

    // TBSCertificate
    int                         version;        // Version (defaults to v1)
    BigInt                      serial_bn;      // Serial number
    Name                        dn_issuer;      // Issuer
    asn1::Time                  start, end;     // Validity
    Name                        dn_subject;     // Subject
    asn1::AlgorithmIdentifier   pk_algo;        // Public key algorithm
    std::vector<uint8_t>        public_key;     // Public key (ASN.1 Encoded)
    std::vector<uint8_t>        issuerUniqueID; // Unique Identifier
    std::vector<uint8_t>        subjectUniqueID;// Subject Unique ID
    std::vector<Extension>      extensions;     // Extensions

    // Outer signature
    asn1::AlgorithmIdentifier   sig_algo;       // Signature algorithm
    std::vector<uint8_t>        signature;      // Signature
};

// Load chain of x509 certificates from base64-encoded file
// 
// Returns true   if all base64 blocks were loaded correctly
//         false  otherwise
bool
load_certificates(
    std::vector<Certificate>&   certificates,   // (O) Certificates
    std::istream&               istream         // (I) Input stream
);

// Verify certificate chain (NB doesnt check root certificate is known)
//
// Returns true   if chain was successfully validated
//         false  otherwise, populating 'reason' with human readable message
bool
verify_certificate_chain(
    std::vector<Certificate> const& certificate,    // (I) Certificate
    asn1::Time const&               now,            // (I) The date at which it should be valid
    std::string&                    reason          // (O) Message if failed
);

} // namespace x509

#endif
