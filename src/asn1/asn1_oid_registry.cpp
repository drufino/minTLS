/* IANA OID Registry
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "asn1/asn1_oid_registry.hpp"
#include <cstring>
#include <core/portability.h>

struct oid_registry_t oid_registry[] = {
    // http://tools.ietf.org/html/rfc5280#appendix-A    
    {"2.5.4.3","X520.CommonName"},
    {"2.5.4.4","X520.Surname"},
    {"2.5.4.5","X520.SerialNumber"},
    {"2.5.4.6","X520.Country"},
    {"2.5.4.7","X520.Locality"},
    {"2.5.4.8","X520.State"},
    {"2.5.4.9","X520.Street"},
    {"2.5.4.10","X520.Organization"},
    {"2.5.4.11","X520.OrganizationalUnit"},
    {"2.5.4.12","X520.Title"},
    {"2.5.4.15","X520.BusinessCategory"},
    {"2.5.4.17","X520.PostalCode"},
    {"2.5.4.41","X520.Name"},
    {"2.5.4.42","X520.GivenName"},
    {"2.5.4.43","X520.Initials"},
    {"2.5.4.44","X520.GenerationQualifier"},
    {"2.5.4.65","X520.Pseudonym"},
    {"1.2.840.113549.1.9.1", "X520.EmailAddress"},
    {"1.2.840.113549.1.9.2", "X520.UnstructuredName"},
    // RFC4519
    {"0.9.2342.19200300.100.1.25", "LDAP.DomainComponent"},
    // RFC-3447 Appendix B.1 Hash functions
    {"1.2.840.113549.2.5", "MD5"},
    {"1.3.14.3.2.26", "SHA1"},
    {"2.16.840.1.101.3.4.2.1", "SHA-256"},
    {"2.16.840.1.101.3.4.2.2", "SHA-384"},
    {"2.16.840.1.101.3.4.2.3", "SHA-512"},
    // RSA Signatures
    //   http://tools.ietf.org/html/rfc5698
    //   http://www.iana.org/assignments/dssc/dssc.xhtml
    {"1.2.840.113549.1.1.1",   "rsaEncryption" },
    {"1.2.840.113549.1.1.4",   "md5WithRSAEncryption"},
    {"1.2.840.113549.1.1.5",   "sha1WithRSAEncryption"},
    {"1.2.840.113549.1.1.11",  "sha256WithRSAEncryption"},
    {"1.2.840.113549.1.1.12",  "sha384WithRSAEncryption"},
    {"1.2.840.113549.1.1.13",  "sha512WithRSAEncryption"},
    // X509v3 Extensions RFC-5280 Section 4.2.1
    {"2.5.29.35", "X509v3.AuthorityKeyIdentifier"},
    {"2.5.29.14", "X509v3.SubjectKeyIdentifier"},
    {"2.5.29.15", "X509v3.KeyUsage"},
    {"2.5.29.32", "X509v3.CertificatePolicies"},
    {"2.5.29.33", "X509v3.PolicyMappings"},
    {"2.5.29.17", "X509v3.SubjectAltName"},
    {"2.5.29.18", "X509v3.IssuerAltName"},
    {"2.5.29.19", "X509v3.BasicConstraints"},
    {"2.5.29.30", "X509v3.NameConstraints"},
    {"2.5.29.36", "X509v3.PolicyConstraints"},
    {"2.5.29.37", "X509v3.ExtendedKeyUsage"},
    {"2.5.29.31", "X509v3.CRLDistributionPoints"},
    {"2.5.29.32.0", "X509v3 Any Policy"},
    {"1.3.6.1.5.5.7.1.1", "X509v3.AuthorityInfoAccess"},
    {"1.3.6.1.5.5.7.48.2", "CA Issuers"},
    {"1.3.6.1.5.5.7.48.1", "OCSP"},
    // Extended Key Usage RFC-5280 Section 4.2.1.13
    {"1.3.6.1.5.5.7.3.1", "TLS Web Server Authentication"},
    {"1.3.6.1.5.5.7.3.2", "TLS Web Client Authentication"},
    {"1.3.6.1.5.5.7.3.3", "TLS Code Signing"},
    {"1.3.6.1.5.5.7.3.4", "TLS Email Protection"},
    {"1.3.6.1.5.5.7.3.8", "TLS TimeStamping"},
    // Netscape Extensions
    {"2.16.840.1.113730.1.1", "Netscape Cert Type"},
    {"2.16.840.1.113730.1.13", "Netscape Comment"}
};

int oid_registry_sz = sizeof(oid_registry)/sizeof(struct oid_registry_t);

const char *lookup_oid_from_name(const char *name)
{
    for (unsigned i = 0; i < sizeof(oid_registry)/sizeof(struct oid_registry_t); ++i)
    {
        if (!strcasecmp(name, oid_registry[i].oid_name))
        {
            return oid_registry[i].oid_str;
        }
    }
    return NULL;
}