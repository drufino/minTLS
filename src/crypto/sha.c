/*
 * Public interface to SHA-(224,256,384,512)
 *
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
/*
 *  The SHA-256 Secure Hash Standard was published by NIST in 2002.
 *
 *  http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
 */
#include "hash.h"
#include "sha1.h"
#include "sha2.h"
#include "sha4.h"
#include <string.h>
#include <stdio.h>

int mintls_hash_init(
    mintls_hash_context *   ctx,            // (O) Context
    MinTLS_Hash             type            // (I) Type
)
{
    switch (type)
    {
    case MinTLS_SHA_160:
        sha1_start((struct sha1_ctx *)ctx);
        return 0;
    case MinTLS_SHA_256:
    case MinTLS_SHA_224:
        return sha2_start((struct sha2_ctx *)ctx,type);
    case MinTLS_SHA_384:
    case MinTLS_SHA_512:
        return sha4_start((struct sha4_ctx *)ctx,type);
    default:
        return -1;
    }
}

// Process some data
void mintls_hash_update(
    mintls_hash_context *   ctx,            // (I/O) Context
    uint8_t const*          input,          // (I) Data
    size_t                  ilen            // (I) Length
)
{
    switch (ctx->type)
    {
    case MinTLS_SHA_160:
        sha1_update((struct sha1_ctx *)ctx,input,ilen);
        break;
    case MinTLS_SHA_256:
    case MinTLS_SHA_224:
        sha2_update((struct sha2_ctx *)ctx,input,ilen);
        break;
    case MinTLS_SHA_384:
    case MinTLS_SHA_512:
        sha4_update((struct sha4_ctx *)ctx,input,ilen);
        break;
    }
    return;
}

// Retrieve the tag
size_t mintls_hash_finish(
    mintls_hash_context *   ctx,            // (I/O) Context
    uint8_t *               tag             // (O) Tag
)
{
    switch (ctx->type)
    {
    case MinTLS_SHA_160:
        return sha1_finish((struct sha1_ctx *)ctx,tag);
    case MinTLS_SHA_256:
    case MinTLS_SHA_224:
        return sha2_finish((struct sha2_ctx *)ctx,tag);
    case MinTLS_SHA_384:
    case MinTLS_SHA_512:
        return sha4_finish((struct sha4_ctx *)ctx,tag);
    default:
        return 0;
    }
}

size_t mintls_hash_tag_length(MinTLS_Hash variant)
{
    switch (variant)
    {
    case MinTLS_SHA_160:
        return 160/8;
    case MinTLS_SHA_224:
        return 224/8;
    case MinTLS_SHA_256:
        return 256/8;
    case MinTLS_SHA_384:
        return 384/8;
    case MinTLS_SHA_512:
        return 512/8;
    default:
        return 0;
    }
}

size_t mintls_hash_block_size(MinTLS_Hash variant)
{
    switch (variant)
    {
    case MinTLS_SHA_160:
    case MinTLS_SHA_224:
    case MinTLS_SHA_256:
        return 64;
    case MinTLS_SHA_384:
    case MinTLS_SHA_512:
        return 128;
    default:
        return 0;
    }
}

// One-shot function
size_t mintls_hash(
    MinTLS_Hash         type,           // (I) SHA Variant
    uint8_t const *     input,          // (I) Input
    size_t const        ilen,           // (I) Size of input
    uint8_t *           sha             // (O) Tag
)
{
    mintls_hash_context ctx;
    mintls_hash_init(&ctx, type);
    mintls_hash_update(&ctx, input, ilen);
    return mintls_hash_finish(&ctx, sha);
}
