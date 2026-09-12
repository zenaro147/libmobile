// SPDX-License-Identifier: LGPL-3.0-or-later
#pragma once

// Minimal, self-contained MD5 implementation (RFC 1321), vendored so the
//   library doesn't depend on an external crypto library. Only used
//   internally, to compute the APOP digest for POP3 authentication -- MD5's
//   weaknesses as a general-purpose hash don't apply to that narrow use
//   (a single-use server-issued nonce concatenated with a 256-bit secret,
//   never used to hash attacker-controlled data on its own).

#include <stddef.h>
#include <stdint.h>

#define MOBILE_MD5_SIZE 16
#define MOBILE_MD5_BLOCK_SIZE 64

struct mobile_md5 {
    uint32_t state[4];
    uint64_t bitlen;
    unsigned char buffer[MOBILE_MD5_BLOCK_SIZE];
    unsigned buffer_len;
};

void mobile_md5_init(struct mobile_md5 *ctx);
void mobile_md5_update(struct mobile_md5 *ctx, const void *data, size_t size);
void mobile_md5_final(struct mobile_md5 *ctx, unsigned char digest[MOBILE_MD5_SIZE]);
