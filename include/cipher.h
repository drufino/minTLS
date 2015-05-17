/* Public interface to symmetric ciphers 
 *
 * Copyright (c) 2013, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef mintls_ciphers_h 
#define mintls_ciphers_h
#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
 extern "C" {
#endif

typedef enum
{
    MinTLS_AES_128=1,
    MinTLS_AES_192=2,
    MinTLS_AES_256=3
} MinTLS_Cipher;

typedef enum
{
    MinTLS_Decrypt=-1,
    MinTLS_Encrypt=0
} MinTLS_CipherDirection;

typedef enum
{
    MinTLS_CBC=1,         // Cipher Block Chaining mode
    MinTLS_ECB=2
} MinTLS_CipherMode;

struct mintls_cipher_ctx_impl;
typedef struct mintls_cipher_ctx_impl *mintls_cipher_ctx;

// Length of the key for a particular cipher
size_t           mintls_cipher_key_length(MinTLS_Cipher cipher);

// Block length
size_t           mintls_cipher_block_length(MinTLS_Cipher cipher, MinTLS_CipherMode mode);

// Create a new block cipher context
mintls_cipher_ctx
mintls_cipher_new(
    MinTLS_Cipher       cipher,     // (I) Underlying Block Cipher
    MinTLS_CipherMode   mode,       // (I) Cipher Mode
    MinTLS_CipherDirection     direction,  // (I) Encryption (>=0) Decryption (<0)
    uint8_t const *     key,        // (I) Key
    uint8_t const *     IV          // (I) Initialization vector (if required for CBC)
);

// Encrypt some data using mode of operation, internally padding to multiple of block length
void
mintls_cipher_do(
    mintls_cipher_ctx   ctx,        // (I) Context
    uint8_t const *     input,      // (I) Input
    size_t const        input_sz,   // (I) Size (Assumed to be multiple of block size)
    uint8_t *           output      // (O) Output (padded to multiple of block size)
);

// Encrypt data in chunks, taking care to buffer up to block boundaries
void
mintls_cipher_do_partial(
    mintls_cipher_ctx   ctx,        // (I) Context
    uint8_t const *     input,      // (I) Input
    size_t              input_sz,   // (I) Size
    uint8_t **          output      // (O) Output
);

// Destroy a block cipher context
void mintls_cipher_destroy(mintls_cipher_ctx ctx);

#ifdef __cplusplus
}
#endif

#endif /* mintls_block_h */
