/* Functionality related to TLS (x509) v3 Extensions certificates
 * 
 * Primary reference
 *   [3] http://tools.ietf.org/html/rfc5280
 *
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found in the
 * LICENSE file.
 */
#ifndef tls_x509_v3_hpp
#define tls_x509_v3_hpp
#include "asn1/asn1_archive.hpp"
#include "asn1/asn1_objects.hpp"
#include "tls/tls_certificate.hpp"

namespace x509
{
    // Base class for extension
    class ExtensionBase : public asn1::ber_decodable
    {
    public:
        // Factory method
        static ExtensionBase *create_from_oid(const char * oid);

        // Clone method
        virtual ExtensionBase *clone() const =0;

        // Virtual destructor
        virtual ~ExtensionBase();
    };

    // GeneralName
    class GeneralName : public asn1::ber_decodable
    {
    public:
        enum NameType
        {
            OtherName       =0,
            rfc822Name      =1,
            DNS             =2,
            x400Address     =3,
            directoryName   =4,
            ediPartyName    =5,
            URI             =6,
            iPAddress       =7
        };

        static std::string type_to_string(NameType type);

        // Convert to string e.g. URI:http://www.google.com
        std::string to_string() const;

        // Comparison operator
        bool operator==(GeneralName const& rhs) const;

        // BER decode
        virtual void ber_decode(asn1::ber_archive& ar);

        NameType            type;
        std::string         name;
    };
    typedef std::vector<GeneralName> GeneralNames;

    // AuthorityKeyIdentifier x509 extension - RFC-5280 4.2.1.1
    class AuthorityKeyIdentifier : public ExtensionBase
    {
    public:
        // BER decode
        virtual void ber_decode(asn1::ber_archive & ar);

        // Clone method
        virtual ExtensionBase *clone() const { return new AuthorityKeyIdentifier(*this); }

        std::vector<uint8_t>        keyIdentifier;
        GeneralNames                authorityCertIssuer;
        BigInt                      certificateSerialNumber;
    };

    // SubjectAltName x509 extension        - RFC-5280 4.2.1.6
    class SubjectAltName : public ExtensionBase
    {
    public:
        // BER decode
        virtual void ber_decode(asn1::ber_archive& ar);

        // Clone method
        virtual ExtensionBase *clone() const { return new SubjectAltName(*this); }

        GeneralNames                names;
    };

    class IssuerAltName : public ExtensionBase
    {
    public:
        // BER decode
        virtual void ber_decode(asn1::ber_archive& ar);

        // Clone method
        virtual ExtensionBase *clone() const { return new IssuerAltName(*this); }

        GeneralNames                names;
    };

    // SubjectKeyIdentifier x509 extension  - RFC-5280 4.2.1.2
    class SubjectKeyIdentifier : public ExtensionBase
    {
    public:
        // BER decode
        virtual void ber_decode(asn1::ber_archive & ar);

        // Clone method
        virtual ExtensionBase *clone() const { return new SubjectKeyIdentifier(*this); }

        std::vector<uint8_t>        keyIdentifier;
    };

    // BasicContraints x509 extension       - RFC-5280 4.2.1.9
    class BasicConstraints : public ExtensionBase
    {
    public:
        BasicConstraints();

        // BER decode
        virtual void ber_decode(asn1::ber_archive & ar);

        // Clone method
        virtual ExtensionBase *clone() const { return new BasicConstraints(*this); }

        bool                        bCA;
        int                         pathLenConstraint;
    };

    // KeyUsage x509 extension              - RFC-5280 4.2.1.3
    class KeyUsage : public ExtensionBase
    {
    public:
        // Default constructor
        KeyUsage();

        // BER decode
        virtual void ber_decode(asn1::ber_archive& ar);

        // Clone method
        virtual ExtensionBase *clone() const { return new KeyUsage(*this); }

        enum KeyUsageFlags {
            digitalSignature=0x01,
            nonRepudiation  =0x02,
            keyEncipherment =0x04,
            dataEncipherment=0x08,
            keyAgreement    =0x10,
            keyCertSign     =0x20,
            cRLSign         =0x40,
            encipherOnly    =0x80,
            decipherOnly    =0x100
        };

        static std::string keyUsageToString(KeyUsageFlags flag);

        std::string to_string() const;

        int keyUsage;
    };

    class ExtendedKeyUsage : public ExtensionBase
    {
    public:
        // BER decode
        virtual void ber_decode(asn1::ber_archive& ar);

        // Clone method
        virtual ExtensionBase *clone() const { return new ExtendedKeyUsage(*this); }

        std::vector<asn1::OID> keyPurposeIds;
    };

    // RFC 5280 - 4.2.2.1
    class AuthorityInfoAccess : public ExtensionBase
    {
    public:
        // BER decode
        virtual void ber_decode(asn1::ber_archive& ar);

        // Clone method
        virtual ExtensionBase *clone() const { return new AuthorityInfoAccess(*this); }

        std::vector<std::pair<asn1::OID, GeneralName> > descs;
    };

    // RFC 5280 - 4.2.1.5
    class CertificatePolicies : public ExtensionBase
    {
    public:
        enum policyType
        {
            CPS=1,
            userNotice=2
        };
        // BER decode
        virtual void ber_decode(asn1::ber_archive& ar);

        // Clone method
        virtual ExtensionBase *clone() const { return new CertificatePolicies(*this); }

        struct UserNotice : public asn1::ber_decodable_sequence
        {
            virtual void ber_decode(asn1::ber_archive& ar);

            std::string         organisation;
            std::vector<int>    noticeNumbers;
            std::string         explicitText;
        };

        struct PolicyInformation : public asn1::ber_decodable_sequence
        {
            virtual void ber_decode(asn1::ber_archive& ar);

            asn1::OID                   policyIdentifier;
            std::vector<std::string>    cps_uris;
            std::vector<UserNotice>     user_notices;
        };

        std::vector<PolicyInformation> certificatePolicies; 
    };

    class CRLDistributionPoints : public ExtensionBase
    {
    public:
        // BER decoding
        virtual void ber_decode(asn1::ber_archive& ar);

        // Clone method
        virtual ExtensionBase *clone() const { return new CRLDistributionPoints(*this); }

        class Name : public asn1::ber_decodable
        {
        public:
            // BER decoding
            virtual void ber_decode(asn1::ber_archive& ar);

            // Comparison operator
            bool operator==(Name const& rhs) const;

            GeneralNames                fullNames;
            x509::Name                  nameRelativeToCRLIssuer;
        };

        class Point : public asn1::ber_decodable
        {
        public:
            enum ReasonFlags
            {
                Unused              =0x00,
                keyCompromise       =0x01,
                CACompromise        =0x02,
                affiliationChanged  =0x04,
                superseded          =0x08,
                cessationOfOperation=0x10,
                certificateHold     =0x20,
                priviledgeWithdrawn =0x40,
                aACompromise        =0x80
            };

            // BER decode
            virtual void ber_decode(asn1::ber_archive& ar);

            Name                        distributionPoint;
            int                         reasonFlags;
            GeneralNames                cRLIssuer;
        };

        std::vector<Point> points;
    };
}
#endif // tls_x509_v3_hpp