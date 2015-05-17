/* Demonstration of the constant-time AES S-Box calculation described in
 *
 * Hamburg, Mike "Accelerating AES with vector permute instructions"
 * http://shiftleft.org/papers/vector_aes/vector_aes.pdf
 *
 * Copyright (c) 2013, David Rufino <david.rufino@gmail.com>
 * All rights reserved. See LICENSE for details.
 */

#include <cstdio>
#include <iostream>
#include <fstream>
#include <string.h>
#include <stdlib.h>
#include <vector>
#include "crypto/aes.h"
#include "cipher.h"
#include "test_helpers.hpp"
#include "test_helpers.cpp"

struct aes_test_case
{
    aes_test_case() {}

    std::vector<uint8_t>    key, pt, ct, iv;
    MinTLS_CipherMode       mode;
};

void run_test_case(aes_impl impl, struct aes_test_case const& case_)
{
    if (case_.mode == MinTLS_ECB)
    {
        aes_context     key_expansion;
        aes_context     key_expansion_dec;

        aes_key_expansion(
            impl,
            case_.key.size(),
            &key_expansion,
            &case_.key[0],
            MinTLS_Encrypt
        );

        aes_key_expansion(
            impl,
            case_.key.size(),
            &key_expansion_dec,
            &case_.key[0],
            MinTLS_Decrypt
        );

        std::vector<uint8_t> ct_test(16);
        aes_encrypt(
            &key_expansion,
            &case_.pt[0],
            &ct_test[0]
        );

        EXPECT_EQ(ct_test, case_.ct);

        std::vector<uint8_t> pt_test(16);
        aes_decrypt(
          &key_expansion_dec,
          &pt_test[0],
          &case_.ct[0]
        );

        EXPECT_EQ(pt_test, case_.pt);
    }
    else if (case_.mode == MinTLS_CBC)
    {
        size_t const key_sz = case_.key.size();
        MinTLS_Cipher cipher = (key_sz == 16) ? MinTLS_AES_128 : ((key_sz == 24) ? MinTLS_AES_192 : MinTLS_AES_256);
        mintls_cipher_ctx ctx_enc = mintls_cipher_new(cipher, MinTLS_CBC, MinTLS_Encrypt, &case_.key[0], &case_.iv[0]);
        mintls_cipher_ctx ctx_dec = mintls_cipher_new(cipher, MinTLS_CBC, MinTLS_Decrypt, &case_.key[0], &case_.iv[0]);

        std::vector<uint8_t> ct_test(case_.pt.size(),'a');
        mintls_cipher_do(ctx_enc, &case_.pt[0], case_.pt.size(), &ct_test[0]);
        EXPECT_EQ(case_.ct,ct_test);

        std::vector<uint8_t> pt_test(case_.ct.size(), 'a');
        mintls_cipher_do(ctx_dec, &case_.ct[0], case_.ct.size(), &pt_test[0]);
        EXPECT_EQ(case_.pt,pt_test);
    }
}

void run_test_case(struct aes_test_case const& case_)
{
    run_test_case(AES_DEFAULT, case_);
    if (case_.mode == MinTLS_ECB)
    {
        run_test_case(AES_SIMPLE, case_);
        run_test_case(AES_SSSE3, case_);
    }
}
static inline uint64_t get_cycles()
{
    uint64_t hi, lo;
#ifndef _MSC_VER
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
#else
    hi = lo = 0;
#endif
    return lo | (hi << 32);
}

void aes_speed_test()
{
    unsigned int key_sz=128;//256;
    unsigned char pt[16]; memcpy(pt,"0123456789ABCDEF",16);
    unsigned char ct[16];
    unsigned char *key=(unsigned char *)"0123456789ABCDEF01234566789ABCDEF";
    aes_context   key_expansion;

    aes_key_expansion(
      AES_DEFAULT,
      key_sz,
      &key_expansion,
      key,
      MinTLS_Encrypt
    );
    unsigned const nTimes=100;
    unsigned const nBlocks=100;
    uint64_t cycles_start, cycles_end;
    std::vector<uint64_t> runtimes(nTimes);
    for (unsigned j = 0; j < nTimes; ++j)
    {
        cycles_start = get_cycles();
        for (unsigned i = 0; i < nBlocks; ++i)
        {
            aes_encrypt(
                &key_expansion,
                pt,
                ct
            );
        }
        cycles_end = get_cycles();
        runtimes[j] = cycles_end - cycles_start;
    }
    std::sort(runtimes.begin(),runtimes.end());
    printf("AES-128 Encryption Cycles per byte: %.2f\n",double(runtimes[nTimes/2])/double(nBlocks*16));

    for (unsigned j = 0; j < nTimes; ++j)
    {
      cycles_start = get_cycles();
      for (unsigned i = 0; i < nBlocks; ++i)
      {
        aes_decrypt(
            &key_expansion,
            pt,
            ct
        );
      }
      cycles_end = get_cycles();
      runtimes[j] = cycles_end - cycles_start;
    }
    std::sort(runtimes.begin(), runtimes.end());
    printf("AES-128 Decryption Cycles per byte: %.2f\n",double(runtimes[nTimes/2])/double(nBlocks*16));
}

std::vector<struct aes_test_case> load_aes_test_cases(std::string const& fn, MinTLS_CipherMode mode)
{
    std::ifstream in_file(fn.c_str());
    char buf[500];
    buf[499] = '\0';

    std::vector<struct aes_test_case> test_cases;

    bool bEncrypt(true), bKey(false), bPt(false), bCt(false);
    std::vector<uint8_t> key, pt, ct, iv;
    unsigned idx;
    for (;;)
    {
        buf[0] = '\0';
		if (!in_file.getline(buf, sizeof(buf) - 1, '\n'))
			break;
        if (strlen(buf) == 0) continue;
        if (buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
            continue;

        if (!memcmp(buf,"[ENCRYPT]",9))
        {
            bEncrypt = true; 
        }
        else if (!memcmp(buf,"COUNT = ",8))
        {
            bPt = bCt = bKey = false;
            idx = strtoul(buf+8,NULL,10);
        }
        else if (!memcmp(buf, "IV = ", 5))
        {
            iv = convert_from_hex(buf+5);
        }
        else if (!memcmp(buf,"KEY = ",6))
        {
            key = convert_from_hex(buf+6);
            switch (key.size()*8)
            {
            case 256:
            case 192:
            case 128:
               bKey = true;
               break;
            default:
               fprintf(stderr, "Got key of length %u\n", (unsigned)key.size());    
            }
        }
        else if (!memcmp(buf,"PLAINTEXT = ",12))
        {
            pt = convert_from_hex(buf+12);
            bPt = true;
        }
        else if (!memcmp(buf,"CIPHERTEXT = ",13))
        {
            ct = convert_from_hex(buf+13);
            bCt = true;
        }

        if (bKey && bPt && bCt && (mode != MinTLS_CBC || iv.size() > 0))
        {
            test_cases.push_back(aes_test_case());
            struct aes_test_case& this_case = test_cases.back();
            this_case.mode = mode;
            this_case.pt = pt;
            this_case.ct = ct;
            this_case.key = key;
            if (mode == MinTLS_CBC)
            {
                this_case.iv = iv;
            }
        }
    }
    return test_cases;
}

typedef std::pair<int, aes_impl> aes_param;

class aes_test : public ::testing::TestWithParam<aes_param>
{

};

TEST_P(aes_test, ecb_kat_test)
{
    int bits = GetParam().first;
    aes_impl impl = GetParam().second;

    std::string s_bits; { std::ostringstream os; os << bits; s_bits = os.str(); }
    std::vector<struct aes_test_case> test_cases;
    test_cases += load_aes_test_cases(std::string("test_vectors/KAT_AES/ECBVarKey") + s_bits + ".rsp", MinTLS_ECB);
    test_cases += load_aes_test_cases(std::string("test_vectors/KAT_AES/ECBVarTxt") + s_bits + ".rsp", MinTLS_ECB);
    test_cases += load_aes_test_cases(std::string("test_vectors/KAT_AES/ECBKeySbox") + s_bits + ".rsp", MinTLS_ECB);
    test_cases += load_aes_test_cases(std::string("test_vectors/KAT_AES/ECBGFSbox") + s_bits + ".rsp", MinTLS_ECB);
    ASSERT_GT(test_cases.size(), 0);
    for (unsigned iCase = 0; iCase < test_cases.size(); ++iCase)
    {
        run_test_case(impl, test_cases[iCase]);
    }
}

TEST_P(aes_test, cbc_kat_test)
{
    int bits = GetParam().first;
    aes_impl impl = GetParam().second;

    std::string s_bits; { std::ostringstream os; os << bits; s_bits = os.str(); }
    std::vector<struct aes_test_case> test_cases;
    test_cases += load_aes_test_cases(std::string("test_vectors/KAT_AES/CBCVarKey") + s_bits + ".rsp", MinTLS_CBC);
    test_cases += load_aes_test_cases(std::string("test_vectors/KAT_AES/CBCMMT") + s_bits + ".rsp", MinTLS_CBC);
    ASSERT_GT(test_cases.size(), 0);
    for (unsigned iCase = 0; iCase < test_cases.size(); ++iCase)
    {
        run_test_case(impl, test_cases[iCase]);
    }
}

std::vector<aes_param> get_pairs(aes_impl impl)
{
    std::vector<aes_param> pairs;
    for (int i = 128; i <= 256; i += 64)
    {
        pairs.push_back(std::make_pair(i,impl));
    }
    return pairs;
}

INSTANTIATE_TEST_CASE_P(aes_default, aes_test, ::testing::ValuesIn(get_pairs(AES_DEFAULT)));
INSTANTIATE_TEST_CASE_P(aes_simple, aes_test, ::testing::ValuesIn(get_pairs(AES_SIMPLE)));
INSTANTIATE_TEST_CASE_P(aes_ssse3, aes_test, ::testing::ValuesIn(get_pairs(AES_SSSE3)));

