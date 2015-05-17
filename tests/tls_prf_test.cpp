#include "tls/tls_client.hpp"
#include "tls/tls_primitives.hpp"
#include "test_helpers.hpp"
#include <cstdlib>
#include <fstream>

struct test
{
    PRFMode         prf_mode;
    char const *    secret;
    char const *    label;
    char const *    seed;
    char const *    output;
};

void
prf_test_individual(struct test const& test_case)
{
    std::vector<uint8_t> output_bytes = convert_from_hex(test_case.output);
    std::vector<uint8_t> secret       = convert_from_hex(test_case.secret);
    std::vector<uint8_t> seed         = convert_from_hex(test_case.seed);


    std::vector<uint8_t> output_bytes_2;
    TLSPRF(
        output_bytes_2,             // (O) PRF Output
        test_case.prf_mode,         // (I) PRF mode (i.e. hash variant used for HMAC)
        output_bytes.size(),        // (I) Number of bytes needed
        secret,                     // (I) Secret
        test_case.label,            // (I) Label (null-terminated string)
        seed                        // (I) Seed
    );
    EXPECT_EQ(output_bytes, output_bytes_2);
}

// http://www.ietf.org/mail-archive/web/tls/current/msg03416.html
namespace
{
struct test test_cases[] =
{
    {PRFModes::PRF_SHA224,
            "e18828740352b530d69b34c6597dea2e",
            "test label",
            "f5a3fe6d34e2e28560fdcaf6823f9091",
            "224d8af3c0453393"
            "a9779789d21cf7da"
            "5ee62ae6b617873d"
            "489428efc8dd58d1"
            "566e7029e2ca3a5e"
            "cd355dc64d4d927e"
            "2fbd78c4233e8604"
            "b14749a77a92a70f"
            "ddf614bc0df623d7"
            "98604e4ca5512794"
            "d802a258e82f86cf"
    },
    {PRFModes::PRF_SHA256,
            "9bbe436ba940f017b17652849a71db35",
            "test label",
            "a0ba9f936cda311827a6f796ffd5198c",
            "e3f229ba727be17b"
            "8d122620557cd453"
            "c2aab21d07c3d495"
            "329b52d4e61edb5a"
            "6b301791e90d35c9"
            "c9a46b4e14baf9af"
            "0fa022f7077def17"
            "abfd3797c0564bab"
            "4fbc91666e9def9b"
            "97fce34f796789ba"
            "a48082d122ee42c5"
            "a72e5a5110fff701"
            "87347b66"
    },
    {PRFModes::PRF_SHA384,
            "b80b733d6ceefcdc71566ea48e5567df",
            "test label",
            "cd665cf6a8447dd6ff8b27555edb7465",
            "7b0c18e9ced410ed"
            "1804f2cfa34a336a"
            "1c14dffb4900bb5f"
            "d7942107e81c83cd"
            "e9ca0faa60be9fe3"
            "4f82b1233c9146a0"
            "e534cb400fed2700"
            "884f9dc236f80edd"
            "8bfa961144c9e8d7"
            "92eca722a7b32fc3"
            "d416d473ebc2c5fd"
            "4abfdad05d918425"
            "9b5bf8cd4d90fa0d"
            "31e2dec479e4f1a2"
            "6066f2eea9a69236"
            "a3e52655c9e9aee6"
            "91c8f3a26854308d"
            "5eaa3be85e099070"
            "3d73e56f"
    },
    {PRFModes::PRF_SHA512,
            "b0323523c1853599584d88568bbb05eb",
            "test label",
            "d4640e12e4bcdbfb437f03e6ae418ee5",
            "1261f588c798c5c2"
            "01ff036e7a9cb5ed"
            "cd7fe3f94c669a12"
            "2a4638d7d508b283"
            "042df6789875c714"
            "7e906d868bc75c45"
            "e20eb40c1cf4a171"
            "3b27371f68432592"
            "f7dc8ea8ef223e12"
            "ea8507841311bf68"
            "653d0cfc4056d811"
            "f025c45ddfa6e6fe"
            "c702f054b409d6f2"
            "8dd0a3233e498da4"
            "1a3e75c5630eedbe"
            "22fe254e33a1b0e9"
            "f6b9826675bec7d0"
            "1a845658dc9c3975"
            "45401d40b9f46c7a"
            "400ee1b8f81ca0a6"
            "0d1a397a1028bff5"
            "d2ef5066126842fb"
            "8da4197632bdb54f"
            "f6633f86bbc836e6"
            "40d4d898"
    }
};
}

TEST(tls_prf_test, sha_224)
{
    prf_test_individual(test_cases[0]);
}
TEST(tls_prf_test, sha_256)
{
    prf_test_individual(test_cases[1]);
}
TEST(tls_prf_test, sha_384)
{
    prf_test_individual(test_cases[2]);
}
TEST(tls_prf_test, sha_512)
{
    prf_test_individual(test_cases[3]);
}
