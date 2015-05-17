#include "cipher.h"
#include "crypto/aes.h"
#include "string.h"
#include <stdio.h>
#include "core/portability.h"

#define MAX_IV_SIZE 32
#define MAX_CIPHER_CONTEXT sizeof(aes_context)

TF_ALIGN struct mintls_cipher_ctx_impl
{
    MinTLS_Cipher               cipher;                     // Underlying block cipher
    MinTLS_CipherMode           mode;                       // Mode of operation
    MinTLS_CipherDirection      direction;                  // Encryption (>=0) or Decryption (<0)
    int                         scratch_sz;                 // Size of partial blocks
    uint8_t                     iv[MAX_IV_SIZE];            // Initialization Vector (if applicable)
    uint8_t                     scratch[MAX_IV_SIZE];       // Space for partial blocks
    uint8_t                     ctx[MAX_CIPHER_CONTEXT];    // Underlying block cipher context
};

size_t
mintls_cipher_key_length(MinTLS_Cipher cipher)
{
    switch (cipher)
    {
    case MinTLS_AES_256:
        return 32;
        break;
    case MinTLS_AES_192:
        return 24;
        break;
    case MinTLS_AES_128:
        return 16;
        break;
    default:
        return 0;
    }
}

size_t
mintls_cipher_block_length(MinTLS_Cipher cipher, MinTLS_CipherMode mode)
{
    switch (mode)
    {
    case MinTLS_CBC:
        return 16;
    default:
        return 0;
    }
}

void
mintls_cipher_do_ecb(
    MinTLS_Cipher       cipher,     // (I) Cipher
    uint8_t  const *    cipher_ctx, // (I) Cipher context
    MinTLS_CipherDirection const  direction,  // (I) Encrypt (>=0) Decrypt (<0)
    uint8_t const *     input,      // (I) One block
    uint8_t *           output      // (I) One block
)
{
    aes_context const *aes_ctx = (aes_context const *)cipher_ctx;
    switch (cipher)
    {
    case MinTLS_AES_256:
    case MinTLS_AES_192:
    case MinTLS_AES_128:
        if (direction == MinTLS_Encrypt)
        {
            // Encryption single 16-byte block
            aes_encrypt(aes_ctx, input, output);
        }
        else
        {
            aes_decrypt(aes_ctx, output, input);
        }
        break;
    default:
        fprintf(stderr, "FATAL ERROR: Unexpected block cipher %d\n", cipher);
        exit(-1);
        return;
    }
}

void
mintls_cipher_do_cbc(
    mintls_cipher_ctx   ctx,        // (I) Context
    uint8_t const *     input,      // (I) Input
    size_t const        input_sz,   // (I) Size
    uint8_t *           output      // (O) Output
)
{
    // Block length
    size_t const block_sz = mintls_cipher_block_length(ctx->cipher, ctx->mode);

    unsigned const nBlocks = (input_sz + (block_sz-1)) / block_sz;

    // Encryption
    if (ctx->direction == MinTLS_Encrypt)
    {
        // Do all but the final block
        for (unsigned iBlock = 0; iBlock < nBlocks; ++iBlock, input += block_sz, output += block_sz)
        {
            for (unsigned j = 0; j < block_sz; ++j)
            {
                ctx->iv[j] ^= input[j];
            }

            // Apply underlying block encryption
            mintls_cipher_do_ecb(ctx->cipher, ctx->ctx, ctx->direction, ctx->iv, output);

            // Need it for the next round
            memcpy(ctx->iv, output, block_sz);
        }
    }
    else if (nBlocks > 0)
    {
        uint8_t const *this_iv = ctx->iv;

        for (unsigned iBlock = 0; iBlock < nBlocks; ++iBlock, input += block_sz, output += block_sz)
        {
            mintls_cipher_do_ecb(ctx->cipher, ctx->ctx, ctx->direction, input, output);

            for (unsigned j = 0; j < block_sz; ++j)
            {
                output[j] ^= this_iv[j];
            }

            this_iv = input;
        }

        // Remember the IV for next time
        memcpy (ctx->iv, this_iv, block_sz);
    }
}

void
mintls_cipher_do(
    mintls_cipher_ctx   ctx,        // (I) Context
    uint8_t const *     input,      // (I) Input
    size_t const        input_sz,   // (I) Size
    uint8_t *           output      // (O) Output
)
{
    switch (ctx->mode)
    {
    case MinTLS_CBC:
        mintls_cipher_do_cbc(ctx,input,input_sz,output);
        break;
    default:
        break;
    }
}

void
mintls_cipher_do_partial(
    mintls_cipher_ctx   ctx,        // (I) Context
    uint8_t const *     input,      // (I) Input
    size_t              input_sz,   // (I) Size
    uint8_t **          output      // (O) Output
)
{
    size_t const block_sz = mintls_cipher_block_length(ctx->cipher, ctx->mode);

    size_t const scratch_left = block_sz - ctx->scratch_sz;
    if (input_sz < scratch_left)
    {
        memcpy(ctx->scratch + ctx->scratch_sz, input, input_sz);
        ctx->scratch_sz += input_sz;
    }
    else
    {
        // Do the partial blocks first
        if (ctx->scratch_sz > 0)
        {
            memcpy(ctx->scratch + ctx->scratch_sz, input, scratch_left);
            input    += scratch_left;
            input_sz -= scratch_left;

            mintls_cipher_do(ctx, ctx->scratch, block_sz, *output);
            *output += block_sz;
            ctx->scratch_sz = 0;
        }

        // Process entire blocks
        unsigned const nBlocks = (input_sz / block_sz);
        if (nBlocks > 0)
        {
            size_t const todo = nBlocks * block_sz;
            mintls_cipher_do(ctx, input, todo, *output);
            input += todo;
            input_sz -= todo;
            *output += todo;
        }

        // Save any left over data
        if (input_sz > 0)
        {
            memcpy(ctx->scratch, input, input_sz);
            ctx->scratch_sz = input_sz;
        }
    }
}

mintls_cipher_ctx
mintls_cipher_new(
    MinTLS_Cipher       cipher,     // (I) Underlying Block Cipher
    MinTLS_CipherMode   mode,       // (I) Underlying Mode
    MinTLS_CipherDirection const  direction,  // (I) Encryption (>=0) Decryption (<0)
    uint8_t const *     key,        // (I) Secret Key
    uint8_t const *     IV          // (I) Initialization vector (if required for CBC)
)
{
    mintls_cipher_ctx ctx = _aligned_malloc(sizeof(struct mintls_cipher_ctx_impl), 16);

    ctx->cipher = cipher;
    ctx->mode   = mode;
    ctx->direction= direction;
    ctx->scratch_sz = 0;

    if (cipher == MinTLS_AES_256 || cipher == MinTLS_AES_192 || cipher == MinTLS_AES_128)
    {
        unsigned const key_sz = (cipher == MinTLS_AES_256) ? 32 : ((cipher == MinTLS_AES_192) ? 24 : 16);

        if (mode == MinTLS_CBC)
        {
            memcpy(ctx->iv, IV, key_sz);
        }

        aes_context *aes_ctx = (aes_context *)ctx->ctx;
        aes_key_expansion(AES_DEFAULT, key_sz, aes_ctx, key, direction);
    }
    else
    {
        mintls_cipher_destroy(ctx);
        return NULL;
    }

    return ctx;
}

void
mintls_cipher_destroy(mintls_cipher_ctx ctx)
{
    memset(ctx->iv,0,sizeof(ctx->iv));
    memset(ctx->ctx,0,sizeof(ctx->ctx));
    memset(ctx->scratch,0,sizeof(ctx->scratch));
    _aligned_free(ctx);
}
