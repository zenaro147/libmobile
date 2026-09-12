// SPDX-License-Identifier: LGPL-3.0-or-later
#include "md5.h"

#include <string.h>

static const uint32_t k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const unsigned s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static uint32_t rotl(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

static void md5_transform(struct mobile_md5 *ctx, const unsigned char block[MOBILE_MD5_BLOCK_SIZE])
{
    uint32_t m[16];
    for (unsigned i = 0; i < 16; i++) {
        m[i] = (uint32_t)block[i * 4 + 0] |
            (uint32_t)block[i * 4 + 1] << 8 |
            (uint32_t)block[i * 4 + 2] << 16 |
            (uint32_t)block[i * 4 + 3] << 24;
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];

    for (unsigned i = 0; i < 64; i++) {
        uint32_t f;
        unsigned g;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }

        uint32_t temp = d;
        d = c;
        c = b;
        b = b + rotl(a + f + k[i] + m[g], s[i]);
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
}

void mobile_md5_init(struct mobile_md5 *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

void mobile_md5_update(struct mobile_md5 *ctx, const void *data, size_t size)
{
    const unsigned char *p = data;
    ctx->bitlen += (uint64_t)size * 8;

    while (size > 0) {
        unsigned n = MOBILE_MD5_BLOCK_SIZE - ctx->buffer_len;
        if (n > size) n = (unsigned)size;

        memcpy(ctx->buffer + ctx->buffer_len, p, n);
        ctx->buffer_len += n;
        p += n;
        size -= n;

        if (ctx->buffer_len == MOBILE_MD5_BLOCK_SIZE) {
            md5_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

void mobile_md5_final(struct mobile_md5 *ctx, unsigned char digest[MOBILE_MD5_SIZE])
{
    uint64_t bitlen = ctx->bitlen;

    // Append the mandatory '1' bit, which is always byte-aligned here since
    //   we only ever operate on whole bytes.
    ctx->buffer[ctx->buffer_len++] = 0x80;

    if (ctx->buffer_len > 56) {
        memset(ctx->buffer + ctx->buffer_len, 0,
            MOBILE_MD5_BLOCK_SIZE - ctx->buffer_len);
        md5_transform(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }
    memset(ctx->buffer + ctx->buffer_len, 0, 56 - ctx->buffer_len);

    // Unlike SHA-256, MD5 stores the length little-endian.
    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (unsigned char)bitlen;
        bitlen >>= 8;
    }
    md5_transform(ctx, ctx->buffer);

    for (unsigned i = 0; i < 4; i++) {
        digest[i * 4 + 0] = (unsigned char)(ctx->state[i]);
        digest[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 8);
        digest[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 16);
        digest[i * 4 + 3] = (unsigned char)(ctx->state[i] >> 24);
    }
}
