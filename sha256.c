// SPDX-License-Identifier: LGPL-3.0-or-later
#include "sha256.h"

#include <string.h>

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static void sha256_transform(struct mobile_sha256 *ctx, const unsigned char block[MOBILE_SHA256_BLOCK_SIZE])
{
    uint32_t w[64];
    for (unsigned i = 0; i < 16; i++) {
        w[i] = (uint32_t)block[i * 4 + 0] << 24 |
            (uint32_t)block[i * 4 + 1] << 16 |
            (uint32_t)block[i * 4 + 2] << 8 |
            (uint32_t)block[i * 4 + 3];
    }
    for (unsigned i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (unsigned i = 0; i < 64; i++) {
        uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void mobile_sha256_init(struct mobile_sha256 *ctx)
{
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

void mobile_sha256_update(struct mobile_sha256 *ctx, const void *data, size_t size)
{
    const unsigned char *p = data;
    ctx->bitlen += (uint64_t)size * 8;

    while (size > 0) {
        unsigned n = MOBILE_SHA256_BLOCK_SIZE - ctx->buffer_len;
        if (n > size) n = (unsigned)size;

        memcpy(ctx->buffer + ctx->buffer_len, p, n);
        ctx->buffer_len += n;
        p += n;
        size -= n;

        if (ctx->buffer_len == MOBILE_SHA256_BLOCK_SIZE) {
            sha256_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

void mobile_sha256_final(struct mobile_sha256 *ctx, unsigned char digest[MOBILE_SHA256_SIZE])
{
    uint64_t bitlen = ctx->bitlen;

    // Append the mandatory '1' bit, which is always byte-aligned here since
    //   we only ever operate on whole bytes.
    ctx->buffer[ctx->buffer_len++] = 0x80;

    if (ctx->buffer_len > 56) {
        memset(ctx->buffer + ctx->buffer_len, 0,
            MOBILE_SHA256_BLOCK_SIZE - ctx->buffer_len);
        sha256_transform(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }
    memset(ctx->buffer + ctx->buffer_len, 0, 56 - ctx->buffer_len);

    for (int i = 7; i >= 0; i--) {
        ctx->buffer[56 + i] = (unsigned char)bitlen;
        bitlen >>= 8;
    }
    sha256_transform(ctx, ctx->buffer);

    for (unsigned i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (unsigned char)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (unsigned char)(ctx->state[i]);
    }
}

static void sha256_oneshot(const void *data, size_t size, unsigned char digest[MOBILE_SHA256_SIZE])
{
    struct mobile_sha256 ctx;
    mobile_sha256_init(&ctx);
    mobile_sha256_update(&ctx, data, size);
    mobile_sha256_final(&ctx, digest);
}

void mobile_hmac_sha256(const unsigned char *key, size_t key_size, const void *data, size_t size, unsigned char digest[MOBILE_SHA256_SIZE])
{
    unsigned char key_hash[MOBILE_SHA256_SIZE];
    if (key_size > MOBILE_SHA256_BLOCK_SIZE) {
        sha256_oneshot(key, key_size, key_hash);
        key = key_hash;
        key_size = MOBILE_SHA256_SIZE;
    }

    unsigned char key_block[MOBILE_SHA256_BLOCK_SIZE] = {0};
    memcpy(key_block, key, key_size);

    unsigned char ipad[MOBILE_SHA256_BLOCK_SIZE];
    unsigned char opad[MOBILE_SHA256_BLOCK_SIZE];
    for (unsigned i = 0; i < MOBILE_SHA256_BLOCK_SIZE; i++) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    unsigned char inner[MOBILE_SHA256_SIZE];
    struct mobile_sha256 ctx;
    mobile_sha256_init(&ctx);
    mobile_sha256_update(&ctx, ipad, sizeof(ipad));
    mobile_sha256_update(&ctx, data, size);
    mobile_sha256_final(&ctx, inner);

    mobile_sha256_init(&ctx);
    mobile_sha256_update(&ctx, opad, sizeof(opad));
    mobile_sha256_update(&ctx, inner, sizeof(inner));
    mobile_sha256_final(&ctx, digest);
}
