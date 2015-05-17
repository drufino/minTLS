/* Public interface to AES algorithms 
 *
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
  
#include "aes.h"
#include "crypto/aes_ssse3.h"
#include "crypto/aes_simple.h"
#include "core/tf_cpuid.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define Nb 4

#define AES256_Nr 14   // Number of rounds for AES-256
#define AES192_Nr 12   // Number of rounds for AES-192
#define AES128_Nr 10   // Number of rounds for AES-128

aes_impl get_default_aes_method()
{
    if (cpu_supports_ssse3())
    {
        return AES_SSSE3;
    }
    else
    {
        return AES_SIMPLE;
    }
}

// Follows (4.3.1 [1])
void aes_key_expansion(
    aes_impl            impl,
    size_t              key_sz,
    aes_context *       key_expansion,
    unsigned char const*key,
    MinTLS_CipherDirection direction
)
{
    if (key_sz <= 32) key_sz *= 8;

    key_expansion->key_sz = key_sz;

    if (impl == AES_DEFAULT)
        key_expansion->impl = get_default_aes_method();
    else
        key_expansion->impl = impl;

    switch (key_expansion->impl)
    {
    default:
    case AES_SIMPLE:
        if (direction == MinTLS_Encrypt)
        {
            rijndaelKeySetupEnc(key_expansion->buf, key, key_sz);
        }
        else
        {
            rijndaelKeySetupDec(key_expansion->buf, key, key_sz);
        }
        break;
    case AES_SSSE3:
        aes_key_expansion_ssse3(key_sz, key_expansion->buf, key,direction);
    }
}

size_t aes_ctx_len(size_t key_sz)
{
    unsigned Nr = aes_rounds(key_sz);
    if (Nr == -1)
    {
        return -1;
    }
    else
    {
        return 4*(Nr+1) + sizeof(aes_context);
    }
}

// Descrypt a single block
void aes_decrypt(
    aes_context const*          key_expansion,  // (I) Key Expansion
    unsigned char *             plaintext,      // (O) Plaintext (16-Bytes)
    unsigned char const *       ciphertext      // (I) Cipher Block (16-Bytes)
)
{
    switch (key_expansion->impl)
    {
    default:
    case AES_SIMPLE:
        {
            unsigned int const Nr = aes_rounds(key_expansion->key_sz);
            rijndaelDecrypt(key_expansion->buf, Nr, ciphertext, plaintext);
            break;
        }
    case AES_SSSE3:
        aes_decrypt_ssse3(key_expansion->key_sz, key_expansion->buf, plaintext, ciphertext);
    }
}


// Encryption single block
void aes_encrypt(
    aes_context const*          key_expansion,  // (I) Key Expansion
    unsigned char const*        plaintext,      // (I) Plaintext (16-Bytes)
    unsigned char *             ciphertext      // (O) Cipher Block (16-Bytes)
)
{
    switch (key_expansion->impl)
    {
    default:
    case AES_SIMPLE:
        {
            unsigned int const Nr = aes_rounds(key_expansion->key_sz);
            rijndaelEncrypt(key_expansion->buf, Nr, plaintext, ciphertext);
            break;
        }
    case AES_SSSE3:
        aes_encrypt_ssse3(key_expansion->key_sz, key_expansion->buf, plaintext, ciphertext);
    }
}
