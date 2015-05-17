/* Public interface to SHA-(224,256,384,512)
 * 
 *   [1] http://csrc.nist.gov/publications/PubsFIPS.html#fips180-4
 *   [2] http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
 *
 * Copyright (c) 2015, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef mintls_sha_h
#define mintls_sha_h
#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    MinTLS_SHA_160=2,
    MinTLS_SHA_224=3,
    MinTLS_SHA_256=4,
    MinTLS_SHA_384=5,
    MinTLS_SHA_512=6
} MinTLS_Hash;

#define MINTLS_HASH_MAX_TAG_LENGTH 64
#define MINTLS_HASH_MAX_BLOCK_SIZE 128

typedef struct
{
    MinTLS_Hash         type;           // SHA Variant
    unsigned char       ctx[224];       // Opaque context
} mintls_hash_context;

// Initialize the context
int mintls_hash_init(
    mintls_hash_context *   ctx,            // (O) Context
    MinTLS_Hash             type            // (I) Type
);

// Process some data
void mintls_hash_update(
    mintls_hash_context *   ctx,            // (I/O) Context
    uint8_t const*          input,          // (I) Data
    size_t                  ilen            // (I) Length
);

// Return the tag length
size_t mintls_hash_tag_length(MinTLS_Hash variant);

// Return the block size
size_t mintls_hash_block_size(MinTLS_Hash variant);

// Retrieve the tag
size_t mintls_hash_finish(
    mintls_hash_context *   ctx,            // (I/O) Context
    uint8_t *               tag             // (O) Tag
);

// One-shot function
size_t mintls_hash(
    MinTLS_Hash         type,           // (I) SHA Variant
    uint8_t const *     input,          // (I) Input
    size_t const        ilen,           // (I) Size of input
    uint8_t *           sha             // (O) Tag
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
