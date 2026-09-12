// Verifies the device id derivation and both forms of the signed message,
// against vectors computed independently in Python:
//
//   device_id = sha256("mgba" \0 "reon-test-host")[:8] = a4a290f8b2bd1a42
//   with device: HMAC(key, "USER|a4a290f8b2bd1a42|authorize|1")
//   without    : HMAC(key, "USER|authorize|1")
//
// The "without" case is what a frontend that sets no identity callback must
// still produce, so the older wire format keeps working.
//
// The frontend name is in the hash because two frontends on one machine get
// the same answer when they ask the OS who it is; without it they would
// derive one id, and the server would read one's requests as replays of the
// other's. "libmobile-bgb" over the same identity bytes gives
// 612d1781e6d85e04, which is what the same-machine case below checks.
#include <stdio.h>
#include <string.h>
#include "mobile_data.h"
#include "commands.h"
#include "config.h"

static unsigned char store[MOBILE_CONFIG_SIZE];

static bool cb_config_read(void *user, void *dest, uintptr_t offset, size_t size) {
    (void)user; memcpy(dest, store + offset, size); return true;
}
static bool cb_config_write(void *user, const void *src, uintptr_t offset, size_t size) {
    (void)user; memcpy(store + offset, src, size); return true;
}
static bool cb_sock_open(void *user, unsigned conn, enum mobile_socktype type, enum mobile_addrtype addrtype, unsigned bindport) {
    (void)user;(void)conn;(void)type;(void)addrtype;(void)bindport; return true;
}
static void cb_sock_close(void *user, unsigned conn) { (void)user;(void)conn; }

static unsigned char dns_reply[512];
static unsigned dns_reply_len, dns_reply_pos;
static struct mobile_addr last_send_addr;

static int cb_sock_send(void *user, unsigned conn, const void *data, unsigned size, const struct mobile_addr *addr) {
    (void)user;(void)conn;
    if (addr) last_send_addr = *addr;
    unsigned char *q = (unsigned char *)data;
    unsigned char r[512];
    unsigned n = 0;
    r[n++] = q[0]; r[n++] = q[1];
    r[n++] = 0x81; r[n++] = 0x80;
    r[n++] = 0; r[n++] = 1;  r[n++] = 0; r[n++] = 1;
    r[n++] = 0; r[n++] = 0;  r[n++] = 0; r[n++] = 0;
    unsigned qlen = 0;
    unsigned char *qq = q + 12;
    while (qq[qlen] != 0) qlen += qq[qlen] + 1;
    qlen += 1 + 4;
    memcpy(r + n, q + 12, qlen);
    n += qlen;
    r[n++] = 0xC0; r[n++] = 12;
    r[n++] = 0; r[n++] = 1;  r[n++] = 0; r[n++] = 1;
    r[n++] = 0; r[n++] = 0; r[n++] = 0; r[n++] = 60;
    r[n++] = 0; r[n++] = 4;
    r[n++] = 1; r[n++] = 1; r[n++] = 1; r[n++] = 1;
    memcpy(dns_reply, r, n);
    dns_reply_len = n; dns_reply_pos = 0;
    return (int)size;
}
static int cb_sock_recv(void *user, unsigned conn, void *data, unsigned size, struct mobile_addr *addr) {
    (void)user;(void)conn;
    unsigned avail = dns_reply_len - dns_reply_pos;
    if (!avail) return 0;
    unsigned n = avail < size ? avail : size;
    memcpy(data, dns_reply + dns_reply_pos, n);
    dns_reply_pos += n;
    if (addr) {
        struct mobile_addr4 *a4 = (struct mobile_addr4 *)addr;
        a4->type = MOBILE_ADDRTYPE_IPV4;
        a4->port = ((struct mobile_addr4 *)&last_send_addr)->port;
        memcpy(a4->host, ((struct mobile_addr4 *)&last_send_addr)->host, 4);
    }
    return (int)n;
}

// Identity source under test. When identity_bytes is NULL the callback
// reports "nothing available", which must select the older message form.
static const char *identity_bytes = "reon-test-host";
static const char *impl_name = "mgba";
static unsigned cb_device_identity(void *user, void *data, unsigned size) {
    (void)user;
    if (!identity_bytes) return 0;
    unsigned len = (unsigned)strlen(identity_bytes);
    if (len > size) return 0;
    memcpy(data, identity_bytes, len);
    return len;
}

static char got_sig[65];
static char got_device[64];
static bool got_device_null;
static int auth_calls;
static void cb_update_device_auth(void *user, enum mobile_device_auth_action action, const unsigned char *ppp_id, unsigned ppp_id_size, uint64_t counter, const unsigned char *sig, const unsigned char *addr_ipv4, const char *device) {
    (void)user;(void)action;(void)ppp_id;(void)ppp_id_size;(void)counter;(void)addr_ipv4;
    auth_calls++;
    for (int i = 0; i < 32; i++) sprintf(got_sig + i * 2, "%02x", sig[i]);
    got_device_null = (device == NULL);
    if (device) snprintf(got_device, sizeof(got_device), "%s", device);
    else got_device[0] = '\0';
}
static void cb_debug_log(void *user, const char *line) { (void)user; fputs(line, stderr); }

static uint16_t checksum(unsigned char *buf, unsigned len) {
    uint16_t sum = 0; while (len--) sum += *buf++; return sum;
}

static int checks, failures;
static void check(const char *label, bool cond) {
    checks++;
    if (!cond) failures++;
    printf("%s %s\n", cond ? "PASS" : "FAIL", label);
}

static struct mobile_adapter *make(void) {
    memset(store, 0xFF, sizeof(store));
    unsigned char da[0x2D];
    da[0] = 'D'; da[1] = 'A'; da[2] = 0;
    for (int i = 0; i < 32; i++) da[5 + i] = (unsigned char)(0x40 + i);
    for (int i = 0; i < 8; i++) da[0x25 + i] = 0;
    uint16_t sum = checksum(da + 5, sizeof(da) - 5);
    da[3] = sum & 0xff; da[4] = sum >> 8;
    memcpy(store + 0x160, da, sizeof(da));

    struct mobile_adapter *a = mobile_new(NULL);
    mobile_def_config_read(a, cb_config_read);
    mobile_def_config_write(a, cb_config_write);
    mobile_def_sock_open(a, cb_sock_open);
    mobile_def_sock_close(a, cb_sock_close);
    mobile_def_sock_send(a, cb_sock_send);
    mobile_def_sock_recv(a, cb_sock_recv);
    mobile_def_update_device_auth(a, cb_update_device_auth);
    mobile_def_device_identity(a, cb_device_identity, impl_name);
    mobile_def_debug_log(a, cb_debug_log);
    mobile_config_load(a);
    mobile_start(a);

    struct mobile_addr4 dns1 = { .type = MOBILE_ADDRTYPE_IPV4, .port = 53 };
    memcpy(dns1.host, (unsigned char[]){9, 9, 9, 9}, 4);
    mobile_config_set_dns(a, (struct mobile_addr *)&dns1, MOBILE_DNS1);
    return a;
}

static void make_and_run(void);

static void run_one(struct mobile_adapter *a) {
    mobile_device_auth_notify(a, MOBILE_DEVICE_AUTH_AUTHORIZE,
        (const unsigned char *)"USER", 4);
    int guard = 0;
    while (auth_calls == 0 && guard++ < 20) {
        mobile_actions_process(a, mobile_actions_get(a));
    }
}

static void make_and_run(void) {
    struct mobile_adapter *a = make();
    run_one(a);
}

int main(void) {
    // --- With an identity callback: device id derived, new message form.
    {
        identity_bytes = "reon-test-host";
        auth_calls = 0;
        struct mobile_adapter *a = make();
        run_one(a);
        check("callback fired", auth_calls == 1);
        check("device id is sha256(impl_name || 0 || identity)[:8] hex",
            strcmp(got_device, "a4a290f8b2bd1a42") == 0);
        check("signature matches HMAC(key, \"USER|<device>|authorize|1\")",
            strcmp(got_sig, "c74879bda4b65b3fd8ca40b90115289836a9059a4fde368ca85e3d8531653d9d") == 0);
        if (failures) printf("   (device=%s sig=%s)\n", got_device, got_sig);
    }

    // --- Without one: no device id, older message form preserved.
    {
        identity_bytes = NULL;
        auth_calls = 0;
        struct mobile_adapter *a = make();
        run_one(a);
        check("callback fired (no identity)", auth_calls == 1);
        check("device reported as NULL to the frontend", got_device_null);
        check("signature matches HMAC(key, \"USER|authorize|1\")",
            strcmp(got_sig, "8248013754d2e003ca00b75d4692a1e7f2ae6f6d9e0e51a5c0c46bd69af05b7f") == 0);
        if (failures) printf("   (sig=%s)\n", got_sig);
    }

    // --- Same machine, two frontends: the identity bytes are identical, so
    // only the frontend name keeps them from being taken for one device.
    {
        char first[64];
        identity_bytes = "reon-test-host"; impl_name = "mgba";
        auth_calls = 0; make_and_run();
        snprintf(first, sizeof(first), "%s", got_device);

        impl_name = "libmobile-bgb";
        auth_calls = 0; make_and_run();
        check("same machine, other frontend -> different device id",
            strcmp(first, got_device) != 0);
        check("and it is the expected one",
            strcmp(got_device, "612d1781e6d85e04") == 0);
    }

    // --- Registering the callback without naming the frontend must behave
    // as no identity at all, rather than a colliding one.
    {
        identity_bytes = "reon-test-host"; impl_name = NULL;
        auth_calls = 0; make_and_run();
        check("no frontend name -> no device id, legacy form", got_device_null);
    }

    // --- The getters a frontend uses to show the user which device this is.
    {
        identity_bytes = "reon-test-host"; impl_name = "mgba";
        struct mobile_adapter *a = make();
        char id[MOBILE_DEVICE_ID_STR_SIZE];
        char code[MOBILE_PAIRING_CODE_STR_SIZE];
        check("get_id returns the same hex that goes on the wire",
            mobile_device_auth_get_id(a, id) && strcmp(id, "a4a290f8b2bd1a42") == 0);
        check("pairing code is the first half, upper case, grouped",
            mobile_device_auth_get_pairing_code(a, code) && strcmp(code, "A4A2-90F8") == 0);

        impl_name = NULL;
        struct mobile_adapter *b = make();
        char untouched[MOBILE_PAIRING_CODE_STR_SIZE];
        memset(untouched, '?', sizeof(untouched));
        check("no id -> both getters report false and leave the buffer alone",
            !mobile_device_auth_get_pairing_code(b, untouched) &&
            !mobile_device_auth_get_id(b, id) && untouched[0] == '?');
    }

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
