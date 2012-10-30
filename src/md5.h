#ifndef __MD5_H_INCLUDED__
#define __MD5_H_INCLUDED__

#include <stdint.h>

typedef struct {
    uint64_t        bytes;
    uint32_t        a, b, c, d;
    unsigned char   buffer[64];
} MD5_CTX;

void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const void *data, size_t size);
void md5_final(unsigned char digest[16], MD5_CTX *ctx);
void md5(unsigned char digest[16], const unsigned char *data, 
        uint64_t size);

#endif /* __MD5_H_INCLUDED__ */
