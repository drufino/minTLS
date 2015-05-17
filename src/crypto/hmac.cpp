/*
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#include "hmac.h"
#include <string.h>

extern "C" {

int
mintls_hmac_init(
    mintls_hmac_context *      ctx,        // (O) Context
    MinTLS_Hash         type,       // (I) Type
    size_t              tag_len,    // (I) Tag Length (set to 0 to default to mac length)
    uint8_t const *     key,        // (I) Key
    size_t              key_sz      // (I) Key Length
)
{
    size_t const B          = mintls_hash_block_size(type);

    // Default the required tag length
    if (tag_len == 0)
    {
        tag_len = mintls_hash_tag_length(type);
    }
    // Tag length can't be longer than the underlying hash
    else if (tag_len > mintls_hash_tag_length(type))
    {
        return -1;
    }

    // Rember the tag length
    ctx->tag_len = tag_len;

    // [1] 3, The key for HMAC can be of any length (keys longer than B bytes are first hashed using H)
    uint8_t hashed_key[MINTLS_HASH_MAX_BLOCK_SIZE];
    memset(hashed_key, 0, MINTLS_HASH_MAX_BLOCK_SIZE);
    if (key_sz > B)
    {
        key_sz  = mintls_hash(type, key, key_sz, hashed_key);
        key     = hashed_key;
    }
    else
    {
        memcpy(hashed_key, key, key_sz);
        key     = hashed_key;
    }

    #define ipad ctx->pad
    #define opad (ctx->pad+MINTLS_HASH_MAX_BLOCK_SIZE)

    // [1] 2
    memset(ipad, 0x36, B);
    memset(opad, 0x5C, B);

    for (unsigned i = 0; i < key_sz; ++i)
    {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    mintls_hash_init(&ctx->hash_ctx, type);
    mintls_hash_update(&ctx->hash_ctx, ipad, B);

    // Zero-out sensitive data
    memset(hashed_key,  0, B);

    #undef ipad

    return 0;
}

void mintls_hmac_update(
    mintls_hmac_context *   ctx,        // (I/O) Context
    uint8_t const *         input,      // (I) Input data
    size_t const            ilen        // (I) Input data length
)
{
    mintls_hash_update(&ctx->hash_ctx,input,ilen);
}

size_t mintls_hmac_finish(
    mintls_hmac_context *   ctx,        // (I) Context
    uint8_t *               output      // (O) Output
)
{
    uint8_t tmp[MINTLS_HASH_MAX_TAG_LENGTH];

    size_t const B          = mintls_hash_block_size(ctx->hash_ctx.type);
    size_t const tag_len    = mintls_hash_finish(&ctx->hash_ctx,tmp);

    mintls_hash_init(&ctx->hash_ctx,ctx->hash_ctx.type);
    mintls_hash_update(&ctx->hash_ctx,opad,B);
    mintls_hash_update(&ctx->hash_ctx,tmp,tag_len);
    mintls_hash_finish(&ctx->hash_ctx,tmp);
    memcpy(output,tmp,ctx->tag_len);

    // Zero-out sensitive data
    memset(tmp,0,sizeof(tmp));
    memset(ctx->pad,0,sizeof(ctx->pad));

    return ctx->tag_len;
}

size_t mintls_hmac_do(
    MinTLS_Hash         type,       // (I) Underlying hash
    uint8_t const *     key,        // (I) Key
    size_t const        klen,       // (I) Key length
    uint8_t const *     input,      // (I) Input data
    size_t const        ilen,       // (I) Input length
    uint8_t *           output,     // (O) Output
    size_t              olen        // (I) Required tag size (must be <= underlying hash tag length. Set to 0 to default to mac length)
)
{
    mintls_hmac_context ctx;

    // Create the context
    if (mintls_hmac_init(&ctx,type,olen,key,klen)) return -1;

    // Process the data
    mintls_hmac_update(&ctx,input,ilen);

    // Return the tag
    return mintls_hmac_finish(&ctx,output);
}

}

std::vector<uint8_t>
mintls_hmac_do(
    MinTLS_Hash                     type,
    std::vector<uint8_t> const&     key,
    std::vector<uint8_t> const&     data,
    size_t const                    taglen
)
{
    std::vector<uint8_t> tag((taglen == 0) ? mintls_hash_tag_length(type) : taglen,0);

    if (mintls_hmac_do(
            type,
            &key[0],
            key.size(),
            &data[0],
            data.size(),
            &tag[0],
            taglen
        ) == -1)
    return std::vector<uint8_t>();

    return tag;
}