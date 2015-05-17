#include "hmac.h"
#include "test_helpers.hpp"
#include "test_main.hpp"
#include <cstdlib>
#include <fstream>

void kat_test_individual(MinTLS_Hash type,std::vector<uint8_t> const& msg, std::vector<uint8_t> const& key, std::vector<uint8_t> const& tag,size_t const tag_len, size_t const frag_size)
{
    std::vector<uint8_t> tag2(tag.size());
    mintls_hmac_context ctx;
    mintls_hmac_init(&ctx,type,tag_len,&key[0],key.size());
    if (msg.size() > 0)
    {
        uint8_t const *p = &msg[0];
        size_t done      = 0;
        while (done < msg.size())
        {
            size_t todo = std::min(frag_size,msg.size()-done);
            mintls_hmac_update(&ctx,p,todo);
            p += todo;
            done += todo;
        }
    }
    EXPECT_EQ(mintls_hmac_finish(&ctx,&tag2[0]),tag.size());
    ASSERT_EQ(tag,tag2);
}

void kat_test_individual(std::vector<uint8_t> const& msg, std::vector<uint8_t> const& key, std::vector<uint8_t> const& tag,size_t L)
{
    MinTLS_Hash type;
    switch (L)
    {
    case 20: // 160
        type = MinTLS_SHA_160;
        break;
    case 28: // SHA-224
        type = MinTLS_SHA_224;
        break;
    case 32: // SHA-256
        type = MinTLS_SHA_256;
        break;
    case 48:
        type = MinTLS_SHA_384;
        break;
    case 64:
        type = MinTLS_SHA_512;
        break;
    default:
        return;
    }
    kat_test_individual(type,msg,key,tag,tag.size(),1);
    kat_test_individual(type,msg,key,tag,tag.size(),msg.size());
    kat_test_individual(type,msg,key,tag,tag.size(),7);

    std::vector<uint8_t> tag2 = mintls_hmac_do(type,key,msg,tag.size());
    ASSERT_EQ(tag,tag2);

    // Test the taglen=0 case
    if (tag.size() == L)
    {
        kat_test_individual(type,msg,key,tag,0,1);
        kat_test_individual(type,msg,key,tag,0,msg.size());
        kat_test_individual(type,msg,key,tag,0,7);
        tag2 = mintls_hmac_do(type,key,msg,0);
        ASSERT_EQ(tag,tag2);
        tag2 = mintls_hmac_do(type,key,msg);
        ASSERT_EQ(tag,tag2);
    }
}

void kat_test(const char *fn, size_t L_)
{
    std::ifstream ifs(fn);

    std::string line;

    size_t L(0);
    std::vector<uint8_t> key, msg, tag;
    while (!ifs.eof())
    {
        getline(ifs, line, '\n');
        if (line.substr(0,3) == "[L=")
        {
            L = atoi(line.substr(3).c_str());
        }
        if (line.substr(0, 6) == "Key = ")
        {
            line = line.substr(6);
            key = convert_from_hex(line.c_str());
        }
        else if (line.substr(0,6) == "Msg = ")
        {
            line = line.substr(6);
            msg = convert_from_hex(line.c_str());
        }
        else if (line.substr(0,6) == "Mac = ")
        {
            line = line.substr(6);
            tag = convert_from_hex(line.c_str());
        }

        if (tag.size() > 0 && msg.size() > 0 && L > 0 && key.size() > 0)
        {
            if (L == L_)
            {
                kat_test_individual(msg,key,tag,L);
            }
            msg.clear();
            tag.clear();
            key.clear();
        }
    }
}
TEST(hmac_test, sha160_test)
{
    kat_test("test_vectors/KAT_HMAC/HMAC.rsp",20);
}
TEST(hmac_test, sha224_test)
{
    kat_test("test_vectors/KAT_HMAC/HMAC.rsp",28);
}
TEST(hmac_test, sha256_test)
{
    kat_test("test_vectors/KAT_HMAC/HMAC.rsp",32);
}
TEST(hmac_test, sha384_test)
{
    kat_test("test_vectors/KAT_HMAC/HMAC.rsp",48);
}
TEST(hmac_test, sha512_test)
{
    kat_test("test_vectors/KAT_HMAC/HMAC.rsp",64);
}
TEST(hmac_test, sha256_simple_test)
{
    const char *p_msg = "The quick brown fox jumps over the lazy dog";
    std::vector<uint8_t> key = {'k','e','y'};
    std::vector<uint8_t> msg((uint8_t const *)p_msg,(uint8_t const *)(p_msg+strlen(p_msg)));;
    std::vector<uint8_t> tag = convert_from_hex("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
    kat_test_individual(msg,key,tag,32);
}
