/*
 * SHA-512 — Brad Conte, public domain
 * https://github.com/B-Con/crypto-algorithms
 */
#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <stdint.h>

#define SHA512_BLOCK_SIZE 64

typedef struct {
    uint8_t  data[128];
    uint32_t datalen;
    uint64_t bitlen;
    uint64_t state[8];
} SHA512_CTX;

void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const uint8_t *data, size_t len);
void sha512_final(SHA512_CTX *ctx, uint8_t *hash);

#endif /* SHA512_H */
