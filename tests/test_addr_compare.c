// Unit test for mobile_addr_compare() after the padding-safe rewrite.
// The actual short-enum/padding repro (enum=1 byte, 3 bytes of gap before
// `port`) only reproduces on ARM EABI toolchains, not available here -- but
// the field-by-field contract itself is fully testable on any platform:
// same fields must compare equal regardless of whatever garbage sits in
// the struct's memory outside those fields, and differing fields must
// always compare unequal.
#include <stdio.h>
#include <string.h>
#include "mobile.h"
#include "util.h"

static int checks, failures;
static void check(const char *label, bool cond) {
    checks++;
    if (!cond) failures++;
    printf("%s %s\n", cond ? "PASS" : "FAIL", label);
}

int main(void) {
    struct mobile_addr4 a, b;

    // Same fields, but the two structs' backing memory was left in
    // different states beforehand (0xAA vs 0x55) before writing the real
    // fields -- on an ABI with padding, that garbage would previously have
    // leaked into the memcmp(). Must still compare equal.
    memset(&a, 0xAA, sizeof(a));
    a.type = MOBILE_ADDRTYPE_IPV4;
    a.port = 5453;
    memcpy(a.host, (unsigned char[]){1, 2, 3, 4}, 4);

    memset(&b, 0x55, sizeof(b));
    b.type = MOBILE_ADDRTYPE_IPV4;
    b.port = 5453;
    memcpy(b.host, (unsigned char[]){1, 2, 3, 4}, 4);

    check("identical fields, differing surrounding memory -> equal",
        mobile_addr_compare((struct mobile_addr *)&a, (struct mobile_addr *)&b));

    struct mobile_addr4 c = a;
    c.port = 5454;
    check("different port -> not equal",
        !mobile_addr_compare((struct mobile_addr *)&a, (struct mobile_addr *)&c));

    struct mobile_addr4 d = a;
    d.host[3] = 9;
    check("different host -> not equal",
        !mobile_addr_compare((struct mobile_addr *)&a, (struct mobile_addr *)&d));

    struct mobile_addr none1 = { .type = MOBILE_ADDRTYPE_NONE };
    struct mobile_addr none2 = { .type = MOBILE_ADDRTYPE_NONE };
    check("both NONE -> not equal (no address to compare)",
        !mobile_addr_compare(&none1, &none2));

    struct mobile_addr6 e, f;
    memset(&e, 0x11, sizeof(e));
    e.type = MOBILE_ADDRTYPE_IPV6;
    e.port = 80;
    memset(e.host, 7, sizeof(e.host));
    memset(&f, 0x99, sizeof(f));
    f.type = MOBILE_ADDRTYPE_IPV6;
    f.port = 80;
    memset(f.host, 7, sizeof(f.host));
    check("IPv6 identical fields, differing surrounding memory -> equal",
        mobile_addr_compare((struct mobile_addr *)&e, (struct mobile_addr *)&f));

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
