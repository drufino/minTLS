/**
 * \file sha4.h
 */
#ifndef TF_SHA4_H
#define TF_SHA4_H
#include "hash.h"


#ifdef __cplusplus
extern "C" {
#endif

struct sha4_ctx;

int
sha4_start(
    struct sha4_ctx *   ctx,
    MinTLS_Hash         type
);

void
sha4_process(
    struct sha4_ctx *   ctx,
    uint8_t const *     data
);

void
sha4_update(
    struct sha4_ctx *   ctx,
    uint8_t const *     input,
    size_t              ilen
);

size_t
sha4_finish(
    struct sha4_ctx *   ctx,
    uint8_t *           tag
);

#ifdef __cplusplus
}
#endif

#endif /* sha4.h */
