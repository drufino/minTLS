/* Functionality related to TLS (x509) v3 Extensions certificates
 * 
 * Primary reference
 *   [3] http://tools.ietf.org/html/rfc5280
 *
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found in the
 * LICENSE file.
 */
#include "tls/tls_x509_v3.hpp"
#include "asn1/asn1_oid_registry.hpp"
#include "asn1/asn1.hpp"
#include <cstring>
#include "core/portability.h"

namespace x509
{
    using namespace asn1;

    ExtensionBase *
    ExtensionBase::create_from_oid(const char *oid)
    {
        #define factory_method(oid_name,class_name) \
            if (lookup_oid_from_name(oid_name) != NULL && !strcasecmp(oid,lookup_oid_from_name(oid_name))) \
            { return new class_name(); } else

        factory_method("X509v3.SubjectKeyIdentifier",    SubjectKeyIdentifier)
        factory_method("X509v3.AuthorityKeyIdentifier",  AuthorityKeyIdentifier)
        factory_method("X509v3.BasicConstraints",         BasicConstraints)
        factory_method("X509v3.KeyUsage",                KeyUsage)
        factory_method("X509v3.SubjectAltName",          SubjectAltName)
        factory_method("X509v3.IssuerAltName",           IssuerAltName)
        factory_method("X509v3.ExtendedKeyUsage",        ExtendedKeyUsage)
        factory_method("X509v3.AuthorityInfoAccess",     AuthorityInfoAccess)
        factory_method("X509v3.CertificatePolicies",     CertificatePolicies)
        factory_method("X509v3.CRLDistributionPoints",   CRLDistributionPoints)
        {
            return NULL;
        }

        #undef factory_method
    }

    ExtensionBase::~ExtensionBase()
    {
    }

    // [3] 4.2.1.1
    void
    AuthorityKeyIdentifier::ber_decode(asn1::ber_archive& ar)
    {
        ar  & start_cons("AuthorityKeyIdentifier")
                & dbg("keyIdentifier") & optional_implicit(0, OCTET_STRING) & keyIdentifier
                & dbg("authorityCertIssuer") & optional_implicit(1) & authorityCertIssuer
                & optional_implicit(2) & certificateSerialNumber
            & end_cons();
    }

    std::string
    GeneralName::type_to_string(GeneralName::NameType type)
    {
        switch (type)
        {
        case OtherName:
            return "OtherName";
        case rfc822Name:
            return "rfc822Name";
        case DNS:
            return "DNS";
        case x400Address:
            return "x400";
        case directoryName:
            return "DirName";
        case ediPartyName:
            return "ediPartyName";
        case URI:
            return "URI";
        case iPAddress:
            return "IP Address";
        default:
            return "unknown";
        }
    }

    std::string
    GeneralName::to_string() const
    {
        return type_to_string(type) + ":" + name;
    }

    void
    GeneralName::ber_decode(asn1::ber_archive& ar)
    {
        asn1::Tag tag = ar.peek_tag();

        name = "error";

        switch ((int)tag.number.underlying())
        {
        case rfc822Name:
        case DNS:
        case URI:
            ar & implicit(tag.number.underlying(), IA5_STRING) & name;
            break;
        case iPAddress:
            {
                // Encoded as OCTETS
                std::vector<uint8_t> octets;
                ar & implicit(tag.number.underlying(), OCTET_STRING) & octets;
                // Must be either 4 octets or 16 octets
                char buf[100]; buf[sizeof(buf)-1] = '\0';
                if (octets.size() == 4)       // IPv4
                {
                    snprintf(buf, sizeof(buf)-1,
                        "%d.%d.%d.%d",
                        octets[0], octets[1], octets[2], octets[3]);
                }
                else if (octets.size() == 16) // IPv6
                {
                    snprintf(buf, sizeof(buf)-1,
                        "%X:%X:%X:%X:%X:%X:%X:%X",
                        ntohs(*(uint16_t *)(&octets[0]+0)),
                        ntohs(*(uint16_t *)(&octets[0]+2)),
                        ntohs(*(uint16_t *)(&octets[0]+4)),
                        ntohs(*(uint16_t *)(&octets[0]+6)),
                        ntohs(*(uint16_t *)(&octets[0]+8)),
                        ntohs(*(uint16_t *)(&octets[0]+10)),
                        ntohs(*(uint16_t *)(&octets[0]+12)),
                        ntohs(*(uint16_t *)(&octets[0]+14))
                        );
                }
                else
                {
                    BER_THROW(ar.get_ctx(), "Invalid encoding for GeneralName.iPAddress");
                }
                name.assign(buf,buf+strlen(buf));
            }
            break;
        case directoryName:
            {
                x509::Name dname;
                ar & optional_explicit(tag.number.underlying()) & dname;
                name = dname.to_string(true);
            }
            break;
        default:
            BER_THROW_LONG(NULL, "Unsupported GeneralName type (0x" << std::hex << tag.hex() << ")");
        }

        type = (NameType)tag.number.underlying();
    }

    bool
    GeneralName::operator==(GeneralName const& rhs) const
    {
        return
            type == rhs.type &&
            name == rhs.name;
    }

    // [3] 4.2.1.6
    void
    SubjectAltName::ber_decode(asn1::ber_archive& ar)
    {
        ar & names;
    }

    // [3] 4.2.1.7
    void
    IssuerAltName::ber_decode(asn1::ber_archive& ar)
    {
        ar & names;
    }

    // [3] 4.2.1.2
    void
    SubjectKeyIdentifier::ber_decode(asn1::ber_archive& ar)
    {
        ar & dbg("SubjectKeyIdentifier") & OCTET_STRING & keyIdentifier;
    }

    BasicConstraints::BasicConstraints()
    {
        bCA = false;
        pathLenConstraint = -1;
    }

    void
    BasicConstraints::ber_decode(asn1::ber_archive& ar)
    {
        ar & start_cons("BasicConstraints")
            & dbg("bCA") & default_(BOOLEAN, false)  & bCA
            & dbg("pathLenConstraint") & default_(INTEGER, -1)      & pathLenConstraint
           & end_cons();
    }

    KeyUsage::KeyUsage()
    {
        keyUsage = 0x0;
    }

    std::string
    KeyUsage::keyUsageToString(KeyUsageFlags flag)
    {
        switch (flag)
        {
        case digitalSignature:
            return "Digital Signature";
        case nonRepudiation:
            return "Non Repudiation";
        case keyEncipherment:
            return "Key Encipherment";
        case dataEncipherment:
            return "Data Encipherment";
        case keyAgreement:
            return "Key Agreement";
        case keyCertSign:
            return "Certificate Sign";
        case cRLSign:
            return "CRL Sign";
        case encipherOnly:
            return "Encipher Only";
        case decipherOnly:
            return "Decipher Only";
        default:
            return "Unknown";
        }
    }

    void
    KeyUsage::ber_decode(asn1::ber_archive& ar)
    {
        ar & BIT_STRING & keyUsage;

        // TODO: check flags are valid
    }

    std::string
    KeyUsage::to_string() const
    {
        std::ostringstream oss;
        for (int i = 1; i <= decipherOnly; i <<= 1)
        {
            if (keyUsage & i)
            {
                if (!oss.str().empty())
                {
                    oss << ", ";
                }
                oss << keyUsageToString((KeyUsageFlags)i);
            }
        }
        return oss.str();
    }

    void
    ExtendedKeyUsage::ber_decode(asn1::ber_archive& ar)
    {
        ar & keyPurposeIds;
    }

    void
    AuthorityInfoAccess::ber_decode(asn1::ber_archive& ar)
    {
        ar & descs;
    }

    void
    CertificatePolicies::UserNotice::ber_decode(asn1::ber_archive& ar)
    {
        if (ar.peek_tag().number.underlying() == Tags::SEQUENCE)
        {
            ar & start_cons("NoticeReference") & organisation & noticeNumbers & end_cons();
        }
        if (!ar.empty())
        {
            ar & explicitText;
        }
    }

    void
    CertificatePolicies::PolicyInformation::ber_decode(asn1::ber_archive& ar)
    {
        ar & policyIdentifier;
        if (!ar.empty())
        {
            ar & start_cons("policyQualifiers");

            while (!ar.empty())
            {
                ar & start_cons("PolicyQualifierInfo");

                asn1::OID qualifier_id;
                ar & qualifier_id;
                if (qualifier_id.lookup_name() == "1.3.6.1.5.5.7.2.1")
                {
                    std::string cps_uri;
                    ar & cps_uri;
                    cps_uris.push_back(cps_uri);
                }
                else if (qualifier_id.lookup_name() == "1.3.6.1.5.5.7.2.2")
                {
                    UserNotice user_notice;
                    ar & user_notice;
                    user_notices.push_back(user_notice);
                }
                else
                {

                }

                ar & end_cons();
            }
            ar & end_cons();
        }
    }
    void
    CertificatePolicies::ber_decode(asn1::ber_archive& ar)
    {
        ar & certificatePolicies;
    }

    void
    CRLDistributionPoints::ber_decode(asn1::ber_archive& ar)
    {
        //ar.raw_bytes(bytes);
        ar & points;
    }

    void
    CRLDistributionPoints::Name::ber_decode(asn1::ber_archive& ar)
    {
        Tag tag = ar.peek_tag();
        if (tag.number.underlying() == 0)
        {
            ar & dbg("fullName") & implicit(0) & fullNames;
        }
        else if (tag.number.underlying() == 1)
        {
            ar & dbg("nameRelativeToCRLIssuer") & implicit(1) & nameRelativeToCRLIssuer;
        }
        else
        {
            BER_THROW_LONG(ar.get_ctx(), "Unexpected tag: " << std::hex << tag.hex());
        }
    }

    bool
    CRLDistributionPoints::Name::operator==(CRLDistributionPoints::Name const& rhs) const
    {
        return
            fullNames == rhs.fullNames &&
            nameRelativeToCRLIssuer == rhs.nameRelativeToCRLIssuer;
    }
    void
    CRLDistributionPoints::Point::ber_decode(asn1::ber_archive& ar)
    {
        ar & start_cons("CRLDistributionPoints")
            & dbg("distributionPoint") & optional_implicit(0) & distributionPoint
            & dbg("reasonFlags") & optional_implicit(1,BIT_STRING, 0) & reasonFlags
            & dbg("cRLIssuer") & optional_implicit(2) & cRLIssuer
          & end_cons();
    }
}
