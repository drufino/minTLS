/* Public interface to HMAC-SHA-(224,256,384,512)
 * 
 *   [1] http://tools.ietf.org/html/rfc2104
 *   [2] http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf
 *
 *   HMAC(K,m) = H((K + opad) | H((K + ipad)|M))
 * 
 * Copyright (c) 2014, David Rufino <david.rufino@gmail.com>. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#ifndef mintls_hmac_h
#define mintls_hmac_h
#include "hash.h"
#include <stdint.h>

#ifdef __cplusplus
#include <vector>

extern "C" {
#endif

// Context for HMAC construction
typedef struct
{
    mintls_hash_context hash_ctx;
    size_t              tag_len;
    uint8_t             pad[MINTLS_HASH_MAX_BLOCK_SIZE*2];
} mintls_hmac_context;

int mintls_hmac_init(
    mintls_hmac_context *   ctx,        // (I/O) Context
    MinTLS_Hash             type,       // (I) Type
    size_t                  tag_len,    // (I) Tag Length (must be less than the hash tag length. Set to 0 to default to mac length)
    uint8_t const *         key,        // (I) Key
    size_t                  key_sz      // (I) Key Length
);

void mintls_hmac_update(
    mintls_hmac_context *   ctx,        // (I/O) Context
    uint8_t const *         input,      // (I) Input data
    size_t const            ilen        // (I) Input data length
);

size_t mintls_hmac_finish(
    mintls_hmac_context *   ctx,        // (I/O) Context
    uint8_t *               output      // (O) Output (size equal to ctx->tag_len)
);

// One-shot function
size_t mintls_hmac_do(
    MinTLS_Hash         type,       // (I) Underlying hash
    uint8_t const *     key,        // (I) Key
    size_t const        klen,       // (I) Key length
    uint8_t const *     input,      // (I) Input data
    size_t const        ilen,       // (I) Input length
    uint8_t *           output,     // (O) Output
    size_t              olen        // (I) Required tag size (must be <= underlying hash tag length. Set to 0 to default to mac length)
);

#ifdef __cplusplus
} // extern "C"

std::vector<uint8_t>
mintls_hmac_do(
    MinTLS_Hash                     type,
    std::vector<uint8_t> const&     key,
    std::vector<uint8_t> const&     data,
    size_t const                    taglen=0
);
#endif

#endif /* TF_HMAC_H */
