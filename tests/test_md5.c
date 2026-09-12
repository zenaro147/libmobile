#include <stdio.h>
#include <string.h>
#include "md5.h"

static void md5_hex(const char *s, char *out) {
    struct mobile_md5 ctx;
    unsigned char d[MOBILE_MD5_SIZE];
    mobile_md5_init(&ctx);
    mobile_md5_update(&ctx, s, strlen(s));
    mobile_md5_final(&ctx, d);
    for (int i = 0; i < 16; i++) sprintf(out + i*2, "%02x", d[i]);
}

static int checks, failures;
static void check(const char *label, const char *got, const char *want) {
    checks++;
    int ok = strcmp(got, want) == 0;
    if (!ok) failures++;
    printf("%s %s (got %s want %s)\n", ok ? "PASS" : "FAIL", label, got, want);
}

int main(void) {
    char out[33];
    md5_hex("", out);
    check("md5('')", out, "d41d8cd98f00b204e9800998ecf8427e");
    md5_hex("abc", out);
    check("md5('abc')", out, "900150983cd24fb0d6963f7d28e17f72");
    md5_hex("The quick brown fox jumps over the lazy dog", out);
    check("md5(quick fox)", out, "9e107d9d372bb6826bd81d3542a419d6");
    md5_hex("message digest", out);
    check("md5('message digest')", out, "f96b697d7cb7938d525a2f31aaf161d0");
    // 56-byte input, exercises the buffer_len > 56 padding branch
    md5_hex("12345678901234567890123456789012345678901234567890123456789012345678901234567890", out);
    check("md5(80 chars)", out, "57edf4a22be3c955ac49da2e2107b67a");
    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
