#include "test_helpers.hpp"
#include "test_helpers.cpp"
#include "test_main.hpp"
#include <tls/tls_certificate.hpp>
#include <tls/tls_x509_v3.hpp>
#include <fstream>

std::vector<x509::Certificate> const& google_certs()
{
    static std::vector<x509::Certificate> s_certs;
    if (s_certs.size() == 0)
    {
        std::ifstream ifs("example_certs/google.com.crt");
        EXPECT_EQ(true, x509::load_certificates(s_certs, ifs));
    }
    size_t nCerts = s_certs.size();
    if (nCerts != 3)
    {
        throw std::runtime_error("Failed to load certificates");
    }

    return s_certs;
}

asn1::Time const& verify_date()
{
    static asn1::Time s_verify_date(2015,1,14,13,06,15);
    return s_verify_date;
}

TEST(x509_test, simple_verify_test)
{
    std::vector<x509::Certificate> const& certs = google_certs();
    std::string reason;
    bool bRes = x509::verify_certificate_chain(certs,verify_date(),reason);
    EXPECT_EQ(true,bRes) << reason;
}

TEST(x509_test, bad_signature1)
{
    for (unsigned iCert = 0; iCert <= 1; ++iCert)
    {
        std::vector<x509::Certificate> certs = google_certs();

        certs[iCert].TBSCertificate[5] ^= 0x52;

        std::string reason;
        EXPECT_EQ(false,x509::verify_certificate_chain(certs,verify_date(),reason)) << " modifying cert #" << (iCert + 1) << " kept verification intact";
    }
}

TEST(x509_test, bad_signature2)
{
    for (unsigned iCert = 0; iCert <= 1; ++iCert)
    {
        std::vector<x509::Certificate> certs = google_certs();

        certs[iCert].signature[5] ^= 0x52;

        std::string reason;
        EXPECT_EQ(false,x509::verify_certificate_chain(certs, verify_date(),reason)) << " modifying cert #" << (iCert + 1) << " kept verification intact";
    }
}

TEST(x509_test, bad_key1)
{
    for (unsigned iCert = 1; iCert <= 2; ++iCert)
    {
        std::vector<x509::Certificate> certs = google_certs();

        certs[iCert].public_key[15] ^= 0x52;

        std::string reason;
        EXPECT_EQ(false,x509::verify_certificate_chain(certs,verify_date(), reason)) << " modifying cert key #" << (iCert + 1) << " kept verification intact";
    }
}

TEST(x509_test, bad_key2)
{
    for (unsigned iCert = 1; iCert <= 2; ++iCert)
    {
        std::vector<x509::Certificate> certs = google_certs();

        certs[iCert].pk_algo.oid = asn1::OID("1.2.3.4.5.6");

        std::string reason;
        EXPECT_EQ(false,x509::verify_certificate_chain(certs,verify_date(),reason)) << " modifying cert algo #" << (iCert + 1) << " kept verification intact";
    }
}

TEST(x509_test, bad_sig_algo)
{
    for (unsigned iCert = 0; iCert <= 1; ++iCert)
    {
        std::vector<x509::Certificate> certs = google_certs();

        certs[iCert].sig_algo.oid = asn1::OID("1.2.3.4.5.6");

        std::string reason;
        EXPECT_EQ(false,x509::verify_certificate_chain(certs,verify_date(),reason)) << " modifying cert algo #" << (iCert + 1) << " kept verification intact";
    }
}

TEST(x509_test, bad_sig_algo2)
{
    for (unsigned iCert = 0; iCert <= 1; ++iCert)
    {
        std::vector<x509::Certificate> certs = google_certs();

        certs[iCert].sig_algo.oid = certs[iCert+1].pk_algo.oid = asn1::OID("1.2.3.4.5.6");

        std::string reason;
        EXPECT_EQ(false,x509::verify_certificate_chain(certs,verify_date(),reason)) << " modifying cert algo #" << (iCert + 1) << " kept verification intact";
    }
}

TEST(x509_test, not_ca)
{
    using namespace x509;
    std::vector<x509::Certificate> certs = google_certs();
    ASSERT_EQ(true,certs.back().has_extension<BasicConstraints>());
    certs.back().get_extension<BasicConstraints>()->bCA = false;
    std::string reason;
    EXPECT_EQ(false,x509::verify_certificate_chain(certs,verify_date(),reason));
}

TEST(x509_test, path_length)
{
    using namespace x509;
    std::vector<x509::Certificate> certs = google_certs();
    ASSERT_EQ(true,certs.back().has_extension<BasicConstraints>());
    certs.back().get_extension<BasicConstraints>()->pathLenConstraint = 0;
    std::string reason;
    EXPECT_EQ(false,x509::verify_certificate_chain(certs,verify_date(),reason));
}