#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/common/sha256.h"

// "hello"
unsigned char hello_hashed[] = {
    0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a,
    0xc5, 0xb9, 0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
    0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24
};

int main(void) {
    unsigned char buf[32] = {0};

    // sha256_hash(buf, (unsigned char*)"hello", 5);

    sha256_t hash;
    sha256_init(&hash);
    sha256_update(&hash, (unsigned char*)"hello", 0);
    for (int i = 0; i < 32; i++) printf("%x", buf[i]);
    if (memcmp(buf, hello_hashed, 32) == 0) printf("\nmatch\n");
    else printf("\ndoes not match\n");

    sha256_update(&hash, (unsigned char*)"there", 0);
    for (int i = 0; i < 32; i++) printf("%x", buf[i]);
    if (memcmp(buf, hello_hashed, 32) == 0) printf("\nmatch\n");
    else printf("\ndoes not match\n");

    sha256_final(&hash, buf);
    for (int i = 0; i < 32; i++) printf("%x", buf[i]);
    if (memcmp(buf, hello_hashed, 32) == 0) printf("\nmatch\n");
    else printf("\ndoes not match\n");

}
