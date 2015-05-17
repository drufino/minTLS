/*
 * These functions test the key expansion parts of TLS 1.2. This includes
 *
 * 1) Computation of master secret from pre-master secret (RFC-5246 8.1)
 * 2) Key expansion to generate client/server encryption/MAC/IVs (RFC-5246 6.3)
 *
 * The test vectors here were obtained by carefully parsing the debug output of gnutls-cli and openssl using versions
 *
 *     OpenSSL 1.0.2 and GnuTLS 3.2.17
 *
 * see
 * 
 *   tls_key_expansion_test_cases.py
 *
 */

#include "tls/tls_client.hpp"
#include "tls/tls_primitives.hpp"
#include "test_helpers.hpp"
#include <cstdlib>
#include <fstream>

struct test
{
    PRFMode         prf_mode;
    CipherSuite     cipher_suite;
    char const *    premaster_secret;
    char const *    client_random;
    char const *    server_random;
    char const *    master_secret;
    char const *    client_key;
    char const *    server_key;
    char const *    client_mac_key;
    char const *    server_mac_key;
};

void
master_secret_test_individual(struct test const& test_case)
{
    std::vector<uint8_t> premaster_secret   = convert_from_hex(test_case.premaster_secret);
    std::vector<uint8_t> client_random      = convert_from_hex(test_case.client_random);
    std::vector<uint8_t> server_random      = convert_from_hex(test_case.server_random);
    std::vector<uint8_t> master_secret      = convert_from_hex(test_case.master_secret);

    EXPECT_EQ(test_case.prf_mode, CipherSuites::prf_mode(test_case.cipher_suite));
    std::vector<uint8_t> master_secret_2;
    expand_premaster_secret(
        premaster_secret,           // (I) Premaster secret
        test_case.prf_mode,         // (I) Hash Algorithm
        client_random,              // (I) Client Random
        server_random,              // (I) Server Random
        master_secret_2             // (O) Master secret
    );
    EXPECT_EQ(master_secret_2.size(), master_secret.size());
    EXPECT_EQ(master_secret_2, master_secret);
}

void
keyblock_test_individual(struct test const& test_case)
{
    std::vector<uint8_t> master_secret      = convert_from_hex(test_case.master_secret);
    std::vector<uint8_t> client_random      = convert_from_hex(test_case.client_random);
    std::vector<uint8_t> server_random      = convert_from_hex(test_case.server_random);

    std::vector<uint8_t> client_mac_key, server_mac_key, client_key, server_key;
    expand_master_secret(
        master_secret,              // (I) Master secret
        client_random,              // (I) Client Random
        server_random,              // (I) Server Random
        test_case.cipher_suite,     // (I) Cipher Suite
        client_mac_key,             // (O) Client MAC key
        server_mac_key,             // (O) Server MAC key
        client_key,                 // (O) Client key
        server_key                  // (O) Server key
    );

    EXPECT_EQ(client_key, convert_from_hex(test_case.client_key));
    EXPECT_EQ(server_key, convert_from_hex(test_case.server_key));
    EXPECT_EQ(client_mac_key, convert_from_hex(test_case.client_mac_key));
    EXPECT_EQ(server_mac_key, convert_from_hex(test_case.server_mac_key));
}

// Generated from 'gnutls-cli --insecure -d 9 127.0.0.1 -p 4433'
namespace
{
struct test test_cases[] =
{
   {PRFModes::PRF_SHA256, CipherSuites::TLS_RSA_WITH_AES_128_CBC_SHA,
    // PREMASTER SECRET
    "9864199348b796d002cc62f56822fb4b00fe97931f3f8187064cf0c2793af2465484bd88689db75652f5560a99afe7b5cf4cffb2ccf9e1d25bc5a66da22a6912c15e7cb78fd173c47afe50b113ac934c41f7deaf714ddd09d6698a1d6a42fb7bd42025525522786c72b595d28705d6aed34b81919958be2bb32e8f3d3b0559c3",
    // CLIENT RANDOM
    "5455778235a489408abc8ca25dfd668ba1c1997eb328efe0f740834067bc5e50",
    // SERVER RANDOM
    "ac9ac9e87319bc54aa3172aec05ce9319b6b71e58b45e1b94a5d4775bdb65a2d",
    // MASTER SECRET
    "93616f98ee0c874154c33098517f4baa76000b780ecdc7134bcae2d59d68ae2cc4d99c6a22f41429b83d45dc993e1d98",
    // CLIENT KEY
    "be62f6aeebd8c283fabaa5301fe052cc",
    // SERVER KEY
    "5eb7a6213a60ca42dc9258381949aa59",
    // CLIENT MAC KEY
    "987653c3765b3f1a29805596eac339a6c3dd5201",
    // SERVER MAC KEY
    "d67c9ce69813b016fc0481d33d7587e061dce615"
   },
   {PRFModes::PRF_SHA256, CipherSuites::TLS_RSA_WITH_AES_128_CBC_SHA256,
    // PREMASTER SECRET
    "69ffa6d17e1ffa8714659c2523280e99273ddb859a541e3fe5c081f95506e5ccf506540c2d95e581efe2781a4a4dcafbb6eeb78e5aa3d0d9411796e5716f28b174c71cd7cfb51dbc5704b3f97c40d089bbfc77774b2c0a16ba33c2afd487ab1c77513e8bed42aca969ca0996ce2fa3111d959a061a209385c393ef1cc4b43058",
    // CLIENT RANDOM
    "545577025eef09a7a8386bbd7ad099c983d03702edb6f8b9e2d22113b316fb19",
    // SERVER RANDOM
    "88b68244a6282161f4ea7c3e0582bc2331401293ee7f2544e261107f8a650841",
    // MASTER SECRET
    "81dbd78aac80d0721cc17d94956d5771af6e9c6548200abf9bc2c98c8ccde00f3a6eb39dd73658824fc374102fdac1aa",
    // CLIENT KEY
    "7a59a00bd9c8c348c5d6cd4b5024be31",
    // SERVER KEY
    "9393bf2556c74405e43a55af3f7480e8",
    // CLIENT MAC KEY
    "f875b752410dae378841c043ab6a0880cfa8766aead7609704e362ec74fe7d2f",
    // SERVER MAC KEY
    "6c213df1970dc3a878eb9e637d532e55886f059b6f06ba13cef11a5abd48c48e"
   },
   {PRFModes::PRF_SHA256, CipherSuites::TLS_RSA_WITH_AES_256_CBC_SHA,
    // PREMASTER SECRET
    "90ec796df988469517c8a830f2fd8afc0226d53e71f9711a93a27ca3d30f9c3a6c33aff6932ac050e59208d2290af5f4229408e143fb6c819b14cbe905615f530fdf28adb681ca1a51fa57c9f3eb181c9e48b5b497316b786689592d4990b2c226d7131efb9f567e27aa4990833efcfe34d39c85443ec6e9ac3cf670b3604d25",
    // CLIENT RANDOM
    "5455773803f503474b11c73ce482b292f23ad1843fa4b6e491eb3f254ed7df0b",
    // SERVER RANDOM
    "28a84d4a9d10bf07d934b7babbf5cdde421af01971fa78174dc2b722c4555195",
    // MASTER SECRET
    "9c15567c206095838cde281021dd49e7b2d4b883b7965a12f9f9a38ab3c8f3df962b3a48120a13cd7d4f5e7fcf3fe71a",
    // CLIENT KEY
    "12a4b1d26f9dfd26c057399e40d2d20856483c9f4fdcf2ca80a286de5793b5ed",
    // SERVER KEY
    "da90fc7fd2c109e79e6401957cf8ee67ec48d0f751eeb969fe7281d15076b519",
    // CLIENT MAC KEY
    "875832300d52e9d2341bc6627590ea7986cd6a8d",
    // SERVER MAC KEY
    "87b79c4416f06471dd074957bc315c8e03b38c39"
   },
   {PRFModes::PRF_SHA256, CipherSuites::TLS_RSA_WITH_AES_256_CBC_SHA256,
    // PREMASTER SECRET
    "1eea9f84424baa1b80ed8913155c82c3c9ee81a6845f0b625c9a15603ff82509ba62a66f1109880102dd006216799c92db752befbefcc87d6cddd9932edf7eaf4f627e554aa26ec59d0065e44b12c10daac7ca8da1a6defd62a933fba1b9788afd8abfd7bdf0f14d9690bdcacfcb489b6ead8e9b9d8203eb1d87905c72d9e1f1",
    // CLIENT RANDOM
    "5455774a73730bf5d3ef84286eb7cffe3412670bb7d5f108b2af2c1680644a59",
    // SERVER RANDOM
    "e72132ef764a48de951af2f81b8e5b1086723012424b559ffb6de30e5599f33a",
    // MASTER SECRET
    "c864c443ce57500dea39521dc6fe91c64cfc60ea0e4dc97f2aa2692e6759c563cc13851067139e3af0338a81a0353727",
    // CLIENT KEY
    "8ba2647a0b6fb25538154f380585c99822bae8c5655de9ec12f4b4907fa84e85",
    // SERVER KEY
    "f4513dacdb7fd18c65335a7b4321c75894c96ffdb3cef401138ddf72f8520238",
    // CLIENT MAC KEY
    "9007b8669c3dc88b924aafb24c0f982914f23805c96e5f502f1f6ef2113c614d",
    // SERVER MAC KEY
    "6672b97ad77b4af8dba78009098f020e5c2927f0846e841fecb012d5f61a762e"
   },
   {PRFModes::PRF_SHA384, CipherSuites::TLS_RSA_WITH_AES_256_GCM_SHA384,
    // PREMASTER SECRET
    "8d29f0389dce78640e4396b219a1f743123a106972ede05b12e45adfc38181d396d795b08c3b6588116ef4d9ecaa6964d602eb1ea5629d74be82cf1efde2c762d1c407c5b8ad95cff63ac1b5c45338acd053e6bb41fbc08a842bda87b3a65639bd7b91039743e6a007cc4368af4ea6bed817530351f07a8ded73920baef3ef3a",
    // CLIENT RANDOM
    "545577b82818bc849e2ac782524ac1a9922dd01af3e1102be44431ad6c6987f7",
    // SERVER RANDOM
    "4daebccb63d4e4c67c631aaa69a0284e6b3c14a221cff80128ba84689997dc4d",
    // MASTER SECRET
    "0d61d858f9884fecfdee5ade734cf1d07c53da040e313a0ef326399b958618954069802cedbddaf44dceaa5c4d91828e",
    // CLIENT KEY
    "b6a4cbc905258ce097a393f19fa0fb2d651b57a678b99a76cf34d64ffe8ba1ab",
    // SERVER KEY
    "332d8eacd96f5b672cd8492c600f454402c2995da541d2e5d6734b669a0a3f06",
    // CLIENT MAC KEY
    "",
    // SERVER MAC KEY
    ""
   },
};
}

class tls_key_expansion : public ::testing::TestWithParam<struct test>
{

};

TEST_P(tls_key_expansion, master_secret)
{
    master_secret_test_individual(GetParam());
}

TEST_P(tls_key_expansion, keyblock)
{
    keyblock_test_individual(GetParam());
}

INSTANTIATE_TEST_CASE_P(tls_key_expansion_tests,tls_key_expansion,testing::ValuesIn(test_cases));
