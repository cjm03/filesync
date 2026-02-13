#ifndef __CRYPTO_SHA256_H
#define __CRYPTO_SHA256_H

#include <stdlib.h>
#include <stdint.h>

#define SHA256_DIGEST_SIZE 32

typedef struct sha256_t {
    uint32_t state[8];
    uint64_t count;
    unsigned char buffer[64];
} sha256_t;

#endif
