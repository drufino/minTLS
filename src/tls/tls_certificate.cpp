/*
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found in the
 * LICENSE file.
 */
#include "tls_certificate.hpp"
#include "tls_x509_v3.hpp"
#include "tls_primitives.hpp"
#include "core/base64.h"
#include "pubkey.h"
#include <istream>

namespace x509
{
    using namespace asn1;

    void
    Name::add_attribute(asn1::OID const& oid, UTF8String const& value)
    {
        m_contents.push_back(std::make_pair(oid,value));
    }

    std::string
    Name::to_string(bool const bSlashSeparator) const
    {
        std::ostringstream oss;

        if (bSlashSeparator)
        {
            oss << "/";
        }

        for (container_type::const_iterator it = m_contents.begin(); it != m_contents.end(); ++it)
        {
            std::string const& attribute_name = it->first.lookup_name();
            const char *abbrv = NULL;

            // Find the shortened version from RFC-1779
            //
            //    Key     Attribute(X.520 keys)
            //    ------------------------------
            //    CN      CommonName
            //    L       LocalityName
            //    ST      StateOrProvinceName
            //    O       OrganizationName
            //    OU      OrganizationalUnitName
            //    C       CountryName
            //    STREET  StreetAddress

            #define P(x,y) if (!strcasecmp(attribute_name.c_str(),x)) { bThisSlashSeparator = false; abbrv = y; } else
            #define Q(x,y) if (!strcasecmp(attribute_name.c_str(),x)) { bThisSlashSeparator = true; abbrv = y; } else

            bool bThisSlashSeparator = true;

            P("X520.CommonName","CN")
            P("X520.Country","C")
            P("X520.Locality","L")
            P("X520.State", "ST")
            P("X520.Organization", "O")
            P("X520.OrganizationalUnit", "OU") 
            P("X520.Surname","SN")
            P("X520.Name","name")
            Q("X520.PostalCode", "postalCode")
            Q("X520.SerialNumber", "serialNumber")
            Q("X520.BusinessCategory", "businessCategory")
            Q("X520.EmailAddress", "emailAddress")
            Q("X520.Street", "street")
            Q("X520.UnstructuredName", "unstructuredName")
            P("LDAP.DomainComponent", "DC")
            {}

            #undef P
            #undef Q
            if (it != m_contents.begin())
            {
                if (bThisSlashSeparator || bSlashSeparator)
                {
                    oss << "/";
                }
                else
                {
                    oss << ", ";
                }
            }

            if (abbrv != NULL)
            {
                oss << abbrv << "=" << it->second.pretty_print();
            }
            else
            {
                oss << attribute_name << "=" << it->second.pretty_print();
            }

        }

        return oss.str();
    }

    bool
    Name::operator==(Name const& rhs) const
    {
        return m_contents == rhs.m_contents;
    }

    void
    Name::ber_decode(asn1::ber_archive& ar)
    {
        while (!ar.empty())
        {
            ar & start_cons(Tags::SET);
            while (!ar.empty())
            {
                asn1::OID       oid;
                UTF8String      value;
                ar & start_cons() & oid & value & end_cons();
                add_attribute(oid,value);
            }
            ar & end_cons();
        }
    }


    bool caseIgnoreMatch(Name const& lhs_, Name const& rhs_)
    {
        Name::container_type const& lhs = lhs_.get_contents();
        Name::container_type const& rhs = rhs_.get_contents();

        if (lhs.size() != rhs.size())
            return false;

        // Ignore ordering, case insensitive
        for (unsigned i = 0; i < lhs.size(); ++i)
        {
            if (lhs[i].first != rhs[i].first)
                return false;

            if (!caseIgnoreMatch(lhs[i].second,rhs[i].second))
                return false;
        }

        return true;
    }

    Extension::Extension()
    {
        critical    = false;
        m_impl      = std::shared_ptr<ExtensionBase>();
    }

    // Copy Constructor
    Extension::Extension(Extension const& rhs)
    {
        extnID      = rhs.extnID;
        critical    = rhs.critical;
        extnValue   = rhs.extnValue;
        m_impl      = rhs.m_impl;
    }

    ExtensionBase const *
    Extension::get_impl() const
    {
        return m_impl.get();
    }

    ExtensionBase *
    Extension::get_impl()
    {
        if (!m_impl)
            return 0;

        // Make sure it's unique
        if (m_impl.use_count() > 1)
        {
            m_impl.reset(m_impl->clone());
        }

        return m_impl.get();
    }

    // Assignment operator
    Extension& Extension::operator=(Extension const& rhs)
    {
        if (this != &rhs)
        {
            extnID = rhs.extnID;
            critical = rhs.critical;
            extnValue = rhs.extnValue;
            m_impl = rhs.m_impl;
        }

        return *this;
    }

    // Destructor
    Extension::~Extension()
    {
    }

    void
    Extension::ber_decode(asn1::ber_archive& ar)
    {
        ar  & start_cons("x509.Extension")
                & extnID
                & default_(BOOLEAN,false) & critical
                & OCTET_STRING & extnValue
            & end_cons();

        m_impl.reset(ExtensionBase::create_from_oid(extnID.to_string().c_str()));
        if (critical && m_impl.get() == NULL)
        {
            BER_THROW_LONG(ar.get_ctx(), "Unrecognized critical x509v3 extension: " << extnID.lookup_name());
        }

        if (m_impl.get() != NULL)
        {
            // Decode the extension
            {
                iarchive ar2(&extnValue[0], extnValue.size());
                asn1::ber_archive ar3(ar2, extnID.lookup_name().c_str());
                ar3 & *m_impl;
                if (ar2.left() > 0)
                {
                    BER_THROW_LONG(ar.get_ctx(), "Error decoding x509v3 extension (" << extnID.lookup_name() << "): " << std::hex << ar2.left() << " bytes left over.");
                }
            }
        }
    }

    bool
    Extension::operator==(Extension const& rhs) const
    {
        return
            extnID == rhs.extnID &&
            critical == rhs.critical &&
            extnValue == rhs.extnValue;
    }

    void
    Certificate::ber_decode(asn1::ber_archive& ar)
    {
        using namespace asn1;

        asn1::AlgorithmIdentifier sig_algo_inner;

        ar & raw(TBSCertificate) & sig_algo & BIT_STRING & signature;

        if (!ar.empty())
        {
            BER_THROW("Certificate", "Data not exhausted");
        }

        iarchive tbs_ar(&TBSCertificate[0], TBSCertificate.size());
        ber_archive tbs_ar2(tbs_ar, "TBSCertificate", ar.bDER());

        // [3] 4.1
        tbs_ar2 & start_cons("TBSCertificate")
            & dbg("version") & optional_explicit(0,0) & version
            & dbg("serial_bn") & serial_bn
            & dbg("sig_algo_inner") & sig_algo_inner
            & dbg("dn_issuer") & dn_issuer
            & start_cons("range") & start & end & end_cons()
            & dbg("subject") & dn_subject
            & start_cons("subjectPublicKey") & pk_algo & BIT_STRING & public_key & end_cons()
            & dbg("issuerUniqueID") & optional_implicit(1, BIT_STRING) & issuerUniqueID
            & dbg("subjectUniqueID") & optional_implicit(2, BIT_STRING) & subjectUniqueID
            & dbg("extensions") & optional_explicit(3) & extensions
            & end_cons();

        if (!tbs_ar2.empty())
        {
            BER_THROW("TBSCertificate", "Not exhausted");
        }

        if (!(sig_algo == sig_algo_inner))
        {
            BER_THROW("Certificate", "SignatureAlgorithm field in Certificate and TBSCertificate don't match")
        }
    }

    bool
    load_certificates(
        std::vector<Certificate>&   certificates,   // (O) Certificates
        std::istream&               is              // (I) Input stream
    )
    {
        bool res = true;

        certificates.clear();
        while (!is.eof())
        {
            std::string line;
            std::getline(is, line);
            if (line.length() >= 27 && line.substr(0,27) == "-----BEGIN CERTIFICATE-----")
            {
                std::vector<uint8_t> bytes;

                try {
                    bytes = base64_decode(is);
                } catch (std::exception const& e) {
                    res = false;
                    continue;
                }

                certificates.push_back(Certificate());
                try {
                    asn1::ber_decode(bytes, certificates.back(), false);
                } catch (std::exception const& e) {
                    res = false;
                }
            }
            else
            {
                continue;
            }
        }

        return (res);
    }

    bool
    verify_certificate_chain(
        std::vector<Certificate> const&     certificates,   // (I) Certificate
        asn1::Time const&                   now,            // (I) The date at which it should be valid
        std::string&                        reason
    )
    {
        unsigned const nCerts = certificates.size();

        reason = "";

        if (nCerts == 0)
        {
            reason = "No certificates supplied";
            return false;
        }

        std::ostringstream oss;

        // Check root is a CA
        {
            Certificate const& top_cert = certificates[nCerts-1];

            // Check validity
            if (now < top_cert.start)
            {
                oss << "Root certificate only valid from " << top_cert.start.to_string() << " now=" << now.to_string();
                reason = oss.str();
                return false;
            }

            if (now > top_cert.end)
            {
                oss << "Root certificate only valid until " << top_cert.end.to_string();
                reason = oss.str();
                return false;
            }

            // Must have BasicConstraints
            BasicConstraints const *basic_constraints = top_cert.get_extension<x509::BasicConstraints>();
            if (!basic_constraints)
            {
                reason = "Top certificate must have BasicConstraints extension";
                return false;
            }
            // Check it's a certificate authority
            else if (basic_constraints->bCA == false)
            {
                reason = "Top certificate must be CA";
                return false;
            }
            // Path len is the number of intermediate certificates allowed
            else if (basic_constraints->pathLenConstraint != -1 && nCerts > (basic_constraints->pathLenConstraint+2))
            {
                reason = "Path length too small";
                return false;
            }
        }

        if (nCerts >= 2)
        {
            for (int iCert = 0; iCert < nCerts - 1; ++iCert)
            {
                Certificate const& cert      = certificates[iCert];
                Certificate const& next_cert = certificates[iCert+1];

                // Check validity
                if (now < cert.start)
                {
                    oss << "Certificate #" << (iCert+1) << " only valid from " << cert.start.to_string();
                    reason = oss.str();
                    return false;
                }

                if (now > cert.end)
                {
                    oss << "Certificate #" << (iCert+1) << " only valid until " << cert.end.to_string();
                    reason = oss.str();
                    return false;
                }

                // First check issuer matches subject
                if (!caseIgnoreMatch(cert.dn_issuer, next_cert.dn_subject))
                {
                    oss << "Issuer #" << (iCert+1) << "='" <<  cert.dn_issuer.to_string(true) << "' is not equal to Subject #" << (iCert+2) << "='" << next_cert.dn_subject.to_string(true) << "'";
                    reason = oss.str();
                    return false;
                }

                mintls_error res =
                pubkey_verify(
                    cert.signature,         // (I) TLS Signature
                    cert.TBSCertificate,    // (I) Data to be signed
                    cert.sig_algo,          // (I) Signature Algorithm
                    next_cert.pk_algo,      // (I) Public Key Algorithm
                    next_cert.public_key    // (I) Public Key
                );

                if (res != mintls_success)
                {
                    oss << "Signature of certificate " << (iCert+1) << " was found to be invalid";
                    reason = oss.str();
                    return false;
                }
            }
        }

        // TODO check the top root is a certificate authority

        return true;
    }

}
