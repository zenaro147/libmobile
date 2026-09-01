// SPDX-License-Identifier: LGPL-3.0-or-later
#pragma once

// Minimal, self-contained SHA-256/HMAC-SHA256 implementation (FIPS 180-4 /
//   RFC 2104), vendored so the library doesn't depend on an external crypto
//   library. Only used internally, to sign device-auth requests.

#include <stddef.h>
#include <stdint.h>

#define MOBILE_SHA256_SIZE 32
#define MOBILE_SHA256_BLOCK_SIZE 64

struct mobile_sha256 {
    uint32_t state[8];
    uint64_t bitlen;
    unsigned char buffer[MOBILE_SHA256_BLOCK_SIZE];
    unsigned buffer_len;
};

void mobile_sha256_init(struct mobile_sha256 *ctx);
void mobile_sha256_update(struct mobile_sha256 *ctx, const void *data, size_t size);
void mobile_sha256_final(struct mobile_sha256 *ctx, unsigned char digest[MOBILE_SHA256_SIZE]);

void mobile_hmac_sha256(const unsigned char *key, size_t key_size, const void *data, size_t size, unsigned char digest[MOBILE_SHA256_SIZE]);
