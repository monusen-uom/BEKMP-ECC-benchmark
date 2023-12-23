#include "sha.h"

#include "local_sha2.h"

int uSHA256(uint8_t *out,
            const uint8_t *in,
            const uint8_t size) {

    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, size, in);
    sha256_final(&ctx, out);
    return 1;
}
