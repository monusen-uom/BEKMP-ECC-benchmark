#ifndef _LOCAL_SHA2_H
#define _LOCAL_SHA2_H

#define SHA256_DIGEST_SIZE 32

#include <stdint.h>

#ifdef sha256_ctx
#error
#endif

struct sha256_ctx {
    uint8_t data[64];
    uint32_t datalen;
    uint32_t bitlen[2];
    uint32_t state[8];
};

void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, uint32_t len, const uint8_t data[]);
void sha256_final(struct sha256_ctx *ctx, uint8_t hash[]);

#endif //_LOCAL_SHA2_H
