#include "tls_api.h"
#include "tls/tls_certificate.hpp"
#include "tls/tls_x509_v3.hpp"
#include "core/base64.h"
#include "rsa.h"
#include <fstream>
#include <cstdio>
#include <iostream>
#include <iomanip>

std::vector<uint8_t>
read_from_stream(std::istream & ifs)
{
    std::vector<uint8_t> buf;

    uint8_t tmp[1024];
    while (ifs.good())
    {
        ifs.read((char *)tmp,1024);
        std::streamsize n = ifs.gcount();
        if (n > 0)
        {
            std::copy(tmp,tmp+n,std::inserter(buf,buf.end()));
        }
    }
    return buf;
}

std::string
pretty_print(std::string const& indent, std::vector<uint8_t> const& bytes, int const wrap=15, bool const bUpperCase=false)
{
    std::ostringstream oss;

    oss << indent;
    if (bUpperCase)
    {
        oss << std::uppercase;
    }
    for (unsigned i = 0; i < bytes.size(); ++i)
    {
        oss << std::hex << std::setfill('0') << std::setw(2) << (unsigned short)bytes[i];
        if (i < bytes.size() - 1)
            oss << ':';

        if (wrap != 0 && ((i+1) % wrap) == 0)
        {
            oss << std::endl << indent;
        }
    }
    return oss.str();
}

void
dump_cert(x509::Certificate const& cert)
{
    std::string sig_algo = cert.sig_algo.oid.lookup_name();


    fprintf(stdout,
        "Certificate:\n"
        "    Data:\n"
        "        Version: %d (0x%x)\n",
        cert.version+1,cert.version
        );

    BigInt serial_number = cert.serial_bn;

    if (serial_number.size() <= (int)sizeof(long))
    {
        bool bNegative = serial_number < BigInt();
        if (bNegative) serial_number = -serial_number;
        fprintf(stdout,
            "        Serial Number: %s%s (%s%s)\n",
            bNegative ? "-" : "",
            serial_number.to_decimal().c_str(),
            bNegative ? "-" : "",
            serial_number.to_string().c_str()
        );
    }
    else
    {
        fprintf(stdout,
            "        Serial Number:\n"
            "            %s\n",
            pretty_print("", serial_number.get_binary(), 40,false).c_str()
        );
    }
    fprintf(stdout,
        "    Signature Algorithm: %s\n"
        "        Issuer: %s\n"
        "        Validity\n"
        "            Not Before: %s\n"
        "            Not After : %s\n"
        "        Subject: %s\n"
        "        Subject Public Key Info:\n"
        "            Public Key Algorithm: %s\n",
        sig_algo.c_str(),
        cert.dn_issuer.to_string().c_str(),
        cert.start.to_string().c_str(),
        cert.end.to_string().c_str(),
        cert.dn_subject.to_string().c_str(),
        cert.pk_algo.oid.lookup_name().c_str()
        );

    if (cert.pk_algo.oid.lookup_name() == "rsaEncryption")
    {
        std::vector<uint8_t> n, e;
        mintls_error err =
        mintls_rsa_decode_public_key(&cert.public_key[0], cert.public_key.size(), n, e);
        if (err == mintls_success)
        {
            fprintf(stdout,
            "                Public-Key: (%d bit)\n"
            "                Modulus:\n"
            "%s\n"
            "                Exponent: %s (%s)\n",
            BigInt(n).nbits(),
            pretty_print("                    ", n).c_str(),
            BigInt(e).to_decimal().c_str(),
            BigInt(e).to_string().c_str()
            );
        }
    }

    // extensions
    if (cert.extensions.size() > 0)
    {
        fprintf(stdout, "        X509v3 extensions:\n");

        for (unsigned iExtension = 0; iExtension < cert.extensions.size(); ++iExtension)
        {
            x509::Extension const&     ext = cert.extensions[iExtension];
            x509::ExtensionBase const *pExt= cert.extensions[iExtension].get_impl();

            const char *s_critical = ext.critical ? " critical" : " ";
            if (x509::BasicConstraints const *constraints = dynamic_cast<x509::BasicConstraints const *>(pExt))
            {
                fprintf(stdout, 
                    "            X509v3 Basic Constraints:%s\n"
                    "                CA:%s",
                    s_critical,
                    constraints->bCA ? "TRUE" : "FALSE"
                );
                if (constraints->pathLenConstraint != -1)
                {
                    fprintf(stdout,
                    ", pathlen:%d\n", constraints->pathLenConstraint);
                }
                else
                {
                    fprintf(stdout, "\n");
                }
            }
            else if (x509::KeyUsage const *key_usage = dynamic_cast<x509::KeyUsage const *>(pExt))
            {
                fprintf(stdout,
                    "            X509v3 Key Usage:%s\n"
                    "                %s\n",
                    s_critical,
                    key_usage->to_string().c_str()
                );
            }
            else if (x509::SubjectAltName const* alt_names = dynamic_cast<x509::SubjectAltName const *>(pExt))
            {
                std::vector<x509::GeneralName> const& names = alt_names->names;

                fprintf(stdout,
                    "            X509v3 Subject Alternative Name:%s\n"
                    "                ",
                    s_critical
                );
                for (unsigned i = 0; i <names.size(); ++i)
                {
                    x509::GeneralName const& name = names[i];

                    fprintf(stdout, "%s", name.to_string().c_str());
                    if (i + 1 < names.size())
                    {
                        fprintf(stdout, ", ");
                    }
                }
                if (names.size() == 0)
                {
                    fprintf(stdout,"<EMPTY>\n");
                }
                fprintf(stdout, "\n");
            }
            else if (x509::IssuerAltName const* alt_names = dynamic_cast<x509::IssuerAltName const *>(pExt))
            {
                std::vector<x509::GeneralName> const& names = alt_names->names;

                fprintf(stdout,
                    "            X509v3 Issuer Alternative Name:%s\n"
                    "                ",
                    s_critical
                );
                for (unsigned i = 0; i <names.size(); ++i)
                {
                    x509::GeneralName const& name = names[i];

                    fprintf(stdout, "%s", name.to_string().c_str());
                    if (i + 1 < names.size())
                    {
                        fprintf(stdout, ", ");
                    }
                }
                if (names.size() == 0)
                {
                    fprintf(stdout,"<EMPTY>\n");
                }
                fprintf(stdout, "\n");
            }
            else if (x509::AuthorityInfoAccess const *auth_info_access = dynamic_cast<x509::AuthorityInfoAccess const *>(pExt))
            {
                fprintf(stdout,
                    "            Authority Information Access:%s\n",
                    s_critical
                );
                for (unsigned i = 0; i < auth_info_access->descs.size(); ++i)
                {
                    asn1::OID oid           = auth_info_access->descs[i].first;
                    x509::GeneralName name  = auth_info_access->descs[i].second;

                    fprintf(stdout,
                    "                %s - %s\n",
                        oid.lookup_name().c_str(),
                        name.to_string().c_str()
                    );
                }
                fprintf(stdout, "\n");
            }
            else if (x509::SubjectKeyIdentifier const *subj_key_id = dynamic_cast<x509::SubjectKeyIdentifier const *>(pExt))
            {
                fprintf(stdout,
                    "            X509v3 Subject Key Identifier:%s\n"
                    "                %s\n",
                    s_critical,
                    pretty_print("", subj_key_id->keyIdentifier, 0, true).c_str()
                );
            }
            else if (x509::AuthorityKeyIdentifier const *auth_key_id = dynamic_cast<x509::AuthorityKeyIdentifier const *>(pExt))
            {
                fprintf(stdout,
                    "            X509v3 Authority Key Identifier:%s\n"
                    "                keyid:%s\n",
                    s_critical,
                    pretty_print("",auth_key_id->keyIdentifier, 0, true).c_str()
                    );
                if (auth_key_id->authorityCertIssuer.size() > 0)
                {
                    fprintf(stdout,
                    "                %s\n",
                    auth_key_id->authorityCertIssuer[0].to_string().c_str()
                    );
                }
                if (auth_key_id->certificateSerialNumber.size() > 0)
                {
                    fprintf(stdout,
                    "                serial:%s\n",
                    pretty_print("",auth_key_id->certificateSerialNumber.get_binary(),30,true).c_str()
                    );
                }
                fprintf(stdout, "\n");
            }
            else if (x509::ExtendedKeyUsage const *extended_key_usage = dynamic_cast<x509::ExtendedKeyUsage const *>(pExt))
            {
                fprintf(stdout,
                    "            X509v3 Extended Key Usage:%s\n"
                    "                ",
                    s_critical
                    );
                std::vector<asn1::OID> const& ids = extended_key_usage->keyPurposeIds;
                for (unsigned i = 0; i < ids.size(); ++i)
                {
                    fprintf(stdout, "%s", ids[i].lookup_name().c_str());
                    if (i + 1 != ids.size())
                    {
                        fprintf(stdout, ", ");
                    }
                }
                fprintf(stdout, "\n");
            }
            else if (x509::CertificatePolicies const *cert_policies = dynamic_cast<x509::CertificatePolicies const *>(pExt))
            {
                fprintf(stdout,
                    "            X509v3 Certificate Policies:%s\n",
                    s_critical
                );

                for (unsigned i = 0; i < cert_policies->certificatePolicies.size(); ++i)
                {
                    x509::CertificatePolicies::PolicyInformation const& policyInfo = cert_policies->certificatePolicies[i];

                    fprintf(stdout,
                    "                Policy: %s\n",
                    policyInfo.policyIdentifier.lookup_name().c_str()
                    );

                    for (unsigned iCPS = 0; iCPS < policyInfo.cps_uris.size(); ++iCPS)
                    {
                        fprintf(stdout,
                        "                  CPS: %s\n",
                        policyInfo.cps_uris[iCPS].c_str()
                        );
                    }

                    for (unsigned iUserNotice = 0; iUserNotice < policyInfo.user_notices.size(); ++iUserNotice)
                    {
                        x509::CertificatePolicies::UserNotice const& user_notice = policyInfo.user_notices[iUserNotice];

                        fprintf(stdout,"                  User Notice:\n");

                        if (!user_notice.organisation.empty())
                        {
                            fprintf(stdout,
                            "                    Organization: %s\n",
                            user_notice.organisation.c_str()
                            );
                        }

                        if (user_notice.noticeNumbers.size() > 0)
                        {
                            fprintf(stdout,
                            "                    Number: %d\n",
                            user_notice.noticeNumbers.at(0)
                            );
                        }

                        fprintf(stdout,
                        "                    Explicit Text: %s\n",
                        user_notice.explicitText.c_str()
                        );
                    }
                }

                fprintf(stdout,"\n");
            }
            else if (x509::CRLDistributionPoints const *crl_points = dynamic_cast<x509::CRLDistributionPoints const *>(pExt))
            {
                fprintf(stdout,
                    "            X509v3 CRL Distribution Points:%s\n\n",
                    s_critical
                );

                for (unsigned i = 0; i < crl_points->points.size(); ++i)
                {
                    x509::CRLDistributionPoints::Point const& point = crl_points->points[i];

                    fprintf(stdout, "                Full Name:\n");
                    x509::GeneralNames const& names = point.distributionPoint.fullNames;
                    for (unsigned i = 0; i < names.size(); ++i)
                    {
                        fprintf(stdout, "                  %s\n", names[i].to_string().c_str());
                    }
                    fprintf(stdout, "\n");
                }
            }
            else
            {
                std::string extn_name = cert.extensions[iExtension].extnID.lookup_name();
                std::vector<uint8_t> const& extn_body = cert.extensions[iExtension].extnValue;
                iarchive iar(&extn_body[0], extn_body.size());
                asn1::ber_archive ar(iar, NULL, true);
                if (extn_name == "Netscape Comment")
                {
                    std::string comment; ar & comment;
                    fprintf(stdout,
                    "            Netscape Comment: \n"
                    "                %s\n",
                    comment.c_str()
                    );
                }
                else if (extn_name == "Netscape Cert Type")
                {
                    int flags(0x0);
                    ar & asn1::BIT_STRING & flags;
                    std::ostringstream oss;
                    if (flags & 0x1) oss << "SSL Client";
                    if (flags & 0x2) oss << "SSL Server";
                    if (flags & 0x4) oss << "S/MIME";
                    if (flags & 0x8) oss << "Object-signing ";
                    if (flags & 0x20) oss << "SSL CA";
                    if (flags & 0x40) oss << "S/MIME CA";
                    if (flags & 0x80) oss << "Object-signing CA";
                    fprintf(stdout,
                    "            Netscape Cert Type: \n"
                    "                %s\n",
                    oss.str().c_str()
                    );
                }
                else
                {
                    fprintf(stdout, "            %s\n", cert.extensions[iExtension].extnID.lookup_name().c_str());
                }
            }
        }
    }
    fprintf(stdout,
        "    Signature Algorithm: %s\n"
        "%s\n"
        ,
        cert.sig_algo.oid.lookup_name().c_str(),
        pretty_print("         ", cert.signature, 18).c_str()
        );
    fflush(stdout);
}

int
parse_cert_file(std::istream & is)
{
    std::vector<x509::Certificate> certs;
    int res = x509::load_certificates(certs, is);
    for (unsigned i = 0; i < certs.size(); ++i)
    {
        dump_cert(certs[i]);
    }
    return (res);
}

void
dump(const char *fn)
{
    if (strcasecmp(fn, "-"))
    {
        std::ifstream ifs(fn, std::ios::binary);
        if (ifs.fail())
        {
            throw std::runtime_error("Failed to open file: " + std::string(fn));
        }
        parse_cert_file(ifs);
    }
    else
    {
        parse_cert_file(std::cin);
    }
}

int
verify(std::istream& is)
{
    std::vector<x509::Certificate> certs;
    int res = x509::load_certificates(certs, is);
    if (res == -1)
    {
        std::cerr << "Failed to load certificates" << std::endl;
        return -1;
    }

    std::string reason;
    bool bValidated = x509::verify_certificate_chain(certs,asn1::Time::now(),reason);
    if (bValidated)
    {
        std::cout << "Validation passed" << std::endl;
        return 0;
    }
    else
    {
        std::cout << "Validation failed: " << reason << std::endl;
        return -1;
    }
}

int
verify(char const *fn)
{
    if (strcasecmp(fn, "-"))
    {
        std::ifstream ifs(fn, std::ios::binary);
        if (ifs.fail())
        {
            throw std::runtime_error("Failed to open file: " + std::string(fn));
        }
        return verify(ifs);
    }
    else
    {
        return verify(std::cin);
    }
}
int
main(int argc, char const *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s [dump|verify] <filename>\n",argv[0]);
        return(-1);
    }

    try {
        if (argc == 2)
        {
            dump(argv[1]);
        }
        else if (!strcasecmp(argv[1], "dump"))
        {
            dump(argv[2]);
        }
        else if (!strcasecmp(argv[1], "verify"))
        {
            return verify(argv[2]);
        }
        else
        {
            std::cerr << "Unrecognised command '" << argv[1] << "'" << std::endl;
            return -1;
        }
    }
    catch (std::exception const& e)
    {
        std::cerr << "Error parsing certificate: " << e.what() << std::endl;
        return -1;
    }
    return 0;
}
