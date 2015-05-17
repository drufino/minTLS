#include "../include/rsa.h"
#include "../include/pubkey.h"
#include "test_helpers.hpp"
#include <fstream>
#include <core/bigint.hpp>
#include "../src/asn1/asn1.hpp"
#include "../src/asn1/asn1_archive.hpp"
struct rsa_test_case
{
    rsa_test_case() {}

    std::vector<uint8_t>    n,e,d,m,s;
    MinTLS_Hash              hash;
};

class RSASigVisitor
{
public:
    void visit(std::string const& lhs, std::string const& rhs)
    {
        if (lhs == "n")
        {
            n = convert_from_hex(rhs.c_str());
            e.clear(); m.clear(); s.clear(); d.clear();
        }
        else if (lhs == "e")
        {
            e = convert_from_hex(rhs.c_str());
        }
        else if (lhs == "d")
        {
            d = convert_from_hex(rhs.c_str());
        }
        else if (lhs == "Msg")
        {
            m = convert_from_hex(rhs.c_str());
        }
        else if (lhs == "S")
        {
            s = convert_from_hex(rhs.c_str());
        }
        else if (lhs == "SHAAlg")
        {
            if (rhs == "SHA1")
            {
                hash = MinTLS_SHA_160;
            }
            else if (rhs == "SHA256")
            {
                hash = MinTLS_SHA_256;
            }
            else if (rhs == "SHA224")
            {
                hash = MinTLS_SHA_224;
            }
            else if (rhs == "SHA384")
            {
                hash = MinTLS_SHA_384;
            }
            else if (rhs == "SHA512")
            {
                hash = MinTLS_SHA_512;
            }
            else
            {
                ASSERT_EQ(rhs, "rubbish");
            }
        }
        else
        {
            ASSERT_EQ(lhs, "rubbish");
        }

        if (n.size() > 0 && d.size() > 0 && e.size() > 0 && m.size() > 0 && s.size() > 0)
        {
            rsa_test_case case_;
            case_.n = n;
            case_.e = std::vector<uint8_t>(e.begin()+10,e.end());
            case_.d = d;
            case_.m = m;
            case_.s = s;
            case_.hash = hash;
            cases.push_back(case_);
            m.clear(); s.clear();
        }
    }

    void visit_mode(std::string const& mode)
    {

    }
    std::vector<rsa_test_case> get_cases() const { return cases; }

private:
    std::vector<uint8_t> n,e,d,m,s;
    MinTLS_Hash           hash;
    std::vector<rsa_test_case> cases;
};



class rsa_test : public testing::Test 
{
public:
    void SetUp()
    {
        test_cases = load_cases<RSASigVisitor,rsa_test_case>("test_vectors/KAT_RSA/SigGen15_186-3.txt",50);
    }

    std::vector<struct rsa_test_case> test_cases;
};

TEST_F(rsa_test, rsa_siggen_test)
{
    for (unsigned i = 0; i < test_cases.size(); ++i)
    {
        struct rsa_test_case const& test_case = test_cases[i];

        std::vector<uint8_t> sig(test_case.n.size(),0x0);

        EXPECT_EQ(
            0,
            mintls_rsa_sign(
                &sig[0],            // (O) Signature
                MinTLS_RSASSA_PKCS1_V1_5,  // (I) Method
                test_case.hash,     // (I) Hash scheme
                &test_case.m[0],    // (I) Message
                test_case.m.size(), // (I) Message length (bytes)
                &test_case.n[0],    // (I) Modulus
                test_case.n.size(), // (I) Modulus length
                &test_case.d[0],    // (I) Exponent
                test_case.d.size()  // (I) Exponent length
            )
        );

        EXPECT_EQ(sig, test_case.s);
    }
}

std::vector<uint8_t> encode_length(size_t const length)
{
    if (length < 0x80)
    {
        return std::vector<uint8_t>({(uint8_t)length});
    }
    else if (length <= 0xff)
    {
        return std::vector<uint8_t>({0x81,(uint8_t)length});
    }
    else if (length <= 0xffff)
    {
        return std::vector<uint8_t>({0x82,(uint8_t)((length>>8)&0xff),(uint8_t)(length&0xff)});
    }
    else
    {
        throw std::runtime_error("oops");
    }
}
TEST_F(rsa_test, rsa_pubkey_verify_test)
{
    for (unsigned i = 0; i < 5; ++i)
    {
        struct rsa_test_case const& test_case = test_cases[i];

        std::vector<uint8_t> sig(test_case.s);
        ASSERT_EQ(sig.size(), test_case.n.size());

        // Noddy ASN.1 Encoding
        std::vector<uint8_t> n = BigInt(test_case.n).get_binary();
        std::vector<uint8_t> e = BigInt(test_case.e).get_binary();
        if (e[0] & 0x80) e = std::vector<uint8_t>(1,0) + e;
        if (n[0] & 0x80) n = std::vector<uint8_t>(1,0) + n;

        std::vector<uint8_t> tmp = 
            std::vector<uint8_t>({(uint8_t)asn1::Tags::INTEGER}) + encode_length(n.size()) + n +
            std::vector<uint8_t>({(uint8_t)asn1::Tags::INTEGER}) + encode_length(e.size()) + e;

        std::vector<uint8_t> pubkey =
                 std::vector<uint8_t>({(uint8_t)asn1::Classes::CONSTRUCTED|(uint8_t)asn1::Tags::SEQUENCE}) +
                 encode_length(tmp.size()) +
                 tmp;

        mintls_error res =
        mintls_pubkey_verify(
            &sig[0],            // (I) Signature
            sig.size(),         // (I) Signature size
            MinTLS_RSA_PKCS15,  // (I) Method
            test_case.hash,     // (I) Hash scheme
            &test_case.m[0],    // (I) Message
            test_case.m.size(), // (I) Message length (bytes)
            &pubkey[0],         // (I) Public Key
            pubkey.size()       // (I) Public Key Size
        );
        ASSERT_EQ(mintls_success,res);
    }
}
TEST_F(rsa_test, rsa_sigverify_test)
{
    for (unsigned i = 0; i < test_cases.size(); ++i)
    {
        struct rsa_test_case const& test_case = test_cases[i];

        std::vector<uint8_t> sig(test_case.s);
        ASSERT_EQ(sig.size(), test_case.n.size());

        BigInt s(test_case.s);
        BigInt m(test_case.m);
        BigInt n(test_case.n);
        BigInt e(test_case.e);
        BigInt d(test_case.d);

        ASSERT_EQ(BigInt::exp_mod(BigInt::exp_mod(s,e,n),d,n),s);

        EXPECT_EQ(
            0,
            mintls_rsa_verify(
                &sig[0],            // (I) Signature
                MinTLS_RSASSA_PKCS1_V1_5,  // (I) Method
                test_case.hash,     // (I) Hash scheme
                &test_case.m[0],    // (I) Message
                test_case.m.size(), // (I) Message length (bytes)
                &test_case.n[0],    // (I) Modulus
                test_case.n.size(), // (I) Modulus length
                &test_case.e[0],    // (I) Exponent
                test_case.e.size()  // (I) Exponent length
            )
        );

        // Check bad signature causes verification to fail
        for (unsigned i = 0; i < sig.size(); i+= 5)
        {
            std::vector<uint8_t> bad_sig(sig);
            bad_sig[i] ^= 0x11;
            int res = 
            mintls_rsa_verify(
                &bad_sig[0],        // (I) Signature
                MinTLS_RSASSA_PKCS1_V1_5,  // (I) Method
                test_case.hash,     // (I) Hash scheme
                &test_case.m[0],    // (I) Message
                test_case.m.size(), // (I) Message length (bytes)
                &test_case.n[0],    // (I) Modulus
                test_case.n.size(), // (I) Modulus length
                &test_case.e[0],    // (I) Exponent
                test_case.e.size()  // (I) Exponent length
            );
            EXPECT_EQ(-1,res);
        }

        // Check changing the message causes verification to fail
        for (unsigned i = 0; i < test_case.m.size(); i+=5)
        {
            std::vector<uint8_t> bad_m(test_case.m);
            bad_m[i] ^= 0x11;
            int res = 
            mintls_rsa_verify(
                &sig[0],            // (I) Signature
                MinTLS_RSASSA_PKCS1_V1_5,  // (I) Method
                test_case.hash,     // (I) Hash scheme
                &bad_m[0],          // (I) Message
                test_case.m.size(), // (I) Message length (bytes)
                &test_case.n[0],    // (I) Modulus
                test_case.n.size(), // (I) Modulus length
                &test_case.e[0],    // (I) Exponent
                test_case.e.size()  // (I) Exponent length
            );
            EXPECT_EQ(-1,res);
        }
    }
}

TEST(rsa_adhoc_test, pkcs15)
{
    std::vector<uint8_t> sha1_prefix = convert_from_hex("0001ffffffffffffffffff003021300906052b0e03021a05000414");
    size_t const emlen = sha1_prefix.size() + 160/8;
    uint8_t emsg[1024];
    EXPECT_EQ(0,
        mintls_pkcs1_v15_encode(
            emsg,       // (O) Encoded Message
            emlen,      // (I) Target message length
            MinTLS_SHA_160,    // (I) Hash scheme
            (uint8_t const *)"test",     // (I) Message
            4           // (I) Size
        )
    );

    std::vector<uint8_t> emsg_(emsg,emsg+sha1_prefix.size());
    EXPECT_EQ(emsg_, sha1_prefix);
}
