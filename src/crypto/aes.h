/* Public interface to AES algorithms
 *
 * Reference is http://http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef tf_aes_h 
#define tf_aes_h 
#include <stdlib.h>
#include "tls_api.h"
#include "cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    AES_DEFAULT=0,
    AES_SIMPLE=1,
    AES_SSSE3
} aes_impl;

typedef struct
#ifdef _MSC_VER
__declspec(align(16))
#endif
{
    int             key_sz;     // Key Size
    aes_impl        impl;       // Implementation
    int             padding[2]; // Padding
    unsigned char   buf[240];   // Maximum size needed for key Expansion
} aes_context
#ifndef _MSC_VER
__attribute__((__aligned__(16)))
#endif
;

// Get the number of rounds for a given key size
unsigned aes_rounds(size_t key_sz);

// Calculate amount of space needed for context
size_t aes_ctx_len(size_t key_sz);

// Compute the key expansion required for encryption and decryption
void aes_key_expansion(
    aes_impl                impl,               // (I) Implementation
    size_t                  key_sz,             // (I) Key Size (128,192,256 or equiv 16,24,32)
    aes_context *           ctx,                // (O) Key Expansion
    unsigned char const *   key,                // (I) Key (of appropriate size)
    MinTLS_CipherDirection  direction           // (I) Direction (>=0 encrypt, <0 decrypt)
);

// Decryption of a single 16-byte block
void aes_decrypt(
    aes_context const*          key_expansion,  // (I) Key Expansion
    unsigned char *             plaintext,      // (O) Plaintext (16-Bytes)
    unsigned char const *       ciphertext      // (I) Cipher Block (16-Bytes)
);

// Encryption single 16-byte block
void aes_encrypt(
    aes_context const*          key_expansion,  // (I) Key Expansion
    unsigned char const*        plaintext,      // (I) Plaintext (16-Bytes)
    unsigned char *             ciphertext      // (O) Cipher Block (16-Bytes)
);

#ifdef __cplusplus
}
#endif

#endif
