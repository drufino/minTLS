#include "hash.h"
#include "test_helpers.hpp"
#include <cstdlib>
#include <fstream>

void kat_test_individual(std::vector<uint8_t> const& msg, std::vector<uint8_t> const& tag,MinTLS_Hash version, size_t const frag_size)
{
    mintls_hash_context ctx;
    ASSERT_EQ(mintls_hash_init(&ctx, version),0);
    if (msg.size() > 0)
    {
        uint8_t const *p = &msg[0];
        size_t done      = 0;

        while (done < msg.size())
        {
            size_t todo = std::min(frag_size,msg.size()-done);
            mintls_hash_update(&ctx,p,todo);
            done += todo;
            p += todo;
        }
    }
    std::vector<uint8_t> tag2(tag.size());
    ASSERT_EQ(mintls_hash_finish(&ctx,&tag2[0]),tag.size());
    ASSERT_EQ(tag2,tag);
    std::vector<uint8_t> tag3(tag.size());
	ASSERT_EQ(mintls_hash(version, msg.size() == 0 ? NULL : &msg[0], msg.size(), &tag3[0]),tag.size());
    ASSERT_EQ(tag3,tag);
}

void kat_test_individual(std::vector<uint8_t> const& msg, std::vector<uint8_t> const& tag,MinTLS_Hash version)
{
    kat_test_individual(msg,tag,version,msg.size());
    kat_test_individual(msg,tag,version,1);
    kat_test_individual(msg,tag,version,7);
}

void kat_test(const char *fn, MinTLS_Hash version)
{
    std::ifstream ifs(fn);
	ASSERT_FALSE(ifs.fail()) << " failed to open file: " << fn;
    std::string line;

    size_t msg_length(-1);
    std::vector<uint8_t> msg, tag;
    while (!ifs.eof())
    {
        getline(ifs, line, '\n');
        if (line.substr(0, 6) == "Len = ")
        {
            msg_length = atoi(line.substr(6).c_str())/8;
        }
        else if (line.substr(0,6) == "Msg = ")
        {
            ASSERT_NE(msg_length,(size_t)-1);
            if (msg_length > 0)
            {
                line = line.substr(6);
                msg = convert_from_hex(line.c_str());
            }
            else
            {
                msg.clear();
            }
        }
        else if (line.substr(0,5) == "MD = ")
        {
            line = line.substr(5);
            tag = convert_from_hex(line.c_str());
        }

        if (tag.size() > 0 && msg.size() == msg_length && msg_length != -1)
        {
            kat_test_individual(msg,tag,version);
            msg.clear();
            tag.clear();
            msg_length = -1;
        }
    }
}

TEST(sha160_test, kat_test_short_msg)
{
    kat_test("test_vectors/KAT_SHA/SHA1ShortMsg.rsp", MinTLS_SHA_160);
}
TEST(sha160_test, kat_test_long_msg)
{
    kat_test("test_vectors/KAT_SHA/SHA1LongMsg.rsp", MinTLS_SHA_160);
}
TEST(sha224_test, kat_test_short_msg)
{
    kat_test("test_vectors/KAT_SHA/SHA224ShortMsg.rsp", MinTLS_SHA_224);
}
TEST(sha224_test, kat_test_long_msg)
{
    kat_test("test_vectors/KAT_SHA/SHA224LongMsg.rsp", MinTLS_SHA_224);
}
TEST(sha256_test, kat_test_short_msg)
{
    kat_test("test_vectors/KAT_SHA/SHA256ShortMsg.rsp", MinTLS_SHA_256);
}
TEST(sha256_test, kat_test_long_msg)
{
    kat_test("test_vectors/KAT_SHA/SHA256LongMsg.rsp", MinTLS_SHA_256);
}
TEST(sha384_test, kat_test_short_msg)
{
    kat_test("test_vectors/KAT_SHA/SHA384ShortMsg.rsp", MinTLS_SHA_384);
}
TEST(sha384_test, kat_test_long_msg)
{
    kat_test("test_vectors/KAT_SHA/SHA384LongMsg.rsp", MinTLS_SHA_384);
}
TEST(sha512_test, kat_test_short_msg)
{
    kat_test("test_vectors/KAT_SHA/SHA512ShortMsg.rsp", MinTLS_SHA_512);
}
TEST(sha512_test, kat_test_long_msg)
{
    kat_test("test_vectors/KAT_SHA/SHA512LongMsg.rsp", MinTLS_SHA_512);
}
struct test
{
    const char *message;
    size_t      message_sz;
    const char *tag;
};

void sha_test_helper(struct test const *tests, size_t const nTests, MinTLS_Hash version)
{
    for (unsigned iTest = 0; iTest < nTests; ++iTest)
    {
        struct test const& test = tests[iTest];

        std::vector<uint8_t> const test_tag = convert_from_hex(test.tag);
        std::vector<uint8_t> const msg((uint8_t const *)(test.message),(uint8_t const *)(test.message+test.message_sz));
        kat_test_individual(msg,test_tag,version);
    }
}

TEST(sha_test, utility_test)
{
    EXPECT_EQ(mintls_hash_tag_length(MinTLS_SHA_160),160/8);
    EXPECT_EQ(mintls_hash_tag_length(MinTLS_SHA_224),224/8);
    EXPECT_EQ(mintls_hash_tag_length(MinTLS_SHA_256),256/8);
    EXPECT_EQ(mintls_hash_tag_length(MinTLS_SHA_384),384/8);
    EXPECT_EQ(mintls_hash_tag_length(MinTLS_SHA_512),512/8);
}

/*
 * FIPS-180-1 test vectors
 * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
 */
TEST(sha160_test, fips_test)
{
    struct test sha160_tests[] =
    {
        { "abc",3,
            "a9993e364706816aba3e25717850c26c9cd0d89d" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",56,
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1" }
    };

    sha_test_helper(sha160_tests,sizeof(sha160_tests)/sizeof(struct test),MinTLS_SHA_160);
}

TEST(sha224_test, fips_test)
{
    // [2] Change notice
    struct test sha224_tests[] = 
    {
        {"abc",3,
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",56,
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"}
    };

    sha_test_helper(sha224_tests,sizeof(sha224_tests)/sizeof(struct test),MinTLS_SHA_224);
}

TEST(sha256_test, fips_test)
{
    // [2] B.1
    struct test sha256_tests[] = 
    {
        {"abc",3,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",56,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"}
    };

    sha_test_helper(sha256_tests,sizeof(sha256_tests)/sizeof(struct test),MinTLS_SHA_256);
}
