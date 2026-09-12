// Verifies the "no connection slot free" path: device-auth must wait
// (stay pending), not drop the event, when both MOBILE_MAX_CONNECTIONS
// slots are already taken by the game's own connections -- and must
// resolve as soon as one frees up.
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
    r[n++] = 0; r[n++] = 1;
    r[n++] = 0; r[n++] = 1;
    r[n++] = 0; r[n++] = 0;
    r[n++] = 0; r[n++] = 0;
    unsigned qlen = 0;
    unsigned char *qq = q + 12;
    while (qq[qlen] != 0) qlen += qq[qlen] + 1;
    qlen += 1 + 4;
    memcpy(r + n, q + 12, qlen);
    n += qlen;
    r[n++] = 0xC0; r[n++] = 12;
    r[n++] = 0; r[n++] = 1;
    r[n++] = 0; r[n++] = 1;
    r[n++] = 0; r[n++] = 0; r[n++] = 0; r[n++] = 60;
    r[n++] = 0; r[n++] = 4;
    r[n++] = 3; r[n++] = 3; r[n++] = 3; r[n++] = 3;
    memcpy(dns_reply, r, n);
    dns_reply_len = n;
    dns_reply_pos = 0;
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

static int auth_calls;
static void cb_update_device_auth(void *user, enum mobile_device_auth_action action, const unsigned char *ppp_id, unsigned ppp_id_size, uint64_t counter, const unsigned char *sig, const unsigned char *addr_ipv4, const char *device) {
    (void)user;(void)action;(void)ppp_id;(void)ppp_id_size;(void)counter;(void)sig;(void)addr_ipv4;(void)device;
    auth_calls++;
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

int main(void) {
    memset(store, 0xFF, sizeof(store));
    unsigned char da[0x2D];
    da[0] = 'D'; da[1] = 'A'; da[2] = 0;
    for (int i = 0; i < 32; i++) da[5 + i] = (unsigned char)(0x40 + i);
    for (int i = 0; i < 8; i++) da[0x25 + i] = 0;
    uint16_t sum = checksum(da + 5, sizeof(da) - 5);
    da[3] = sum & 0xff; da[4] = sum >> 8;
    memcpy(store + 0x160, da, sizeof(da));

    struct mobile_adapter *adapter = mobile_new(NULL);
    mobile_def_config_read(adapter, cb_config_read);
    mobile_def_config_write(adapter, cb_config_write);
    mobile_def_sock_open(adapter, cb_sock_open);
    mobile_def_sock_close(adapter, cb_sock_close);
    mobile_def_sock_send(adapter, cb_sock_send);
    mobile_def_sock_recv(adapter, cb_sock_recv);
    mobile_def_update_device_auth(adapter, cb_update_device_auth);
    mobile_def_debug_log(adapter, cb_debug_log);
    mobile_config_load(adapter);
    mobile_start(adapter);

    struct mobile_addr4 dns1 = { .type = MOBILE_ADDRTYPE_IPV4, .port = 53 };
    memcpy(dns1.host, (unsigned char[]){9, 9, 9, 9}, 4);
    mobile_config_set_dns(adapter, (struct mobile_addr *)&dns1, MOBILE_DNS1);

    // Both connection slots occupied by the game (MOBILE_MAX_CONNECTIONS==2).
    adapter->global.active = true;
    adapter->commands.connections[0] = true;
    adapter->commands.connections[1] = true;

    mobile_device_auth_notify(adapter, MOBILE_DEVICE_AUTH_AUTHORIZE,
        (const unsigned char *)"NOSLOT", 6);
    check("pending set after notify()", adapter->device_auth.pending);

    // Run several ticks with both slots still taken -- must NOT dispatch,
    // NOT drop, and NOT get stuck in a non-IDLE state waiting forever.
    for (int i = 0; i < 10; i++) {
        adapter->global.active = true;
        enum mobile_action actions = mobile_actions_get(adapter);
        mobile_actions_process(adapter, actions);
    }
    check("still pending while both slots taken", adapter->device_auth.pending);
    check("auth callback NOT fired yet", auth_calls == 0);
    check("state stayed IDLE while waiting for a slot",
        adapter->device_auth.state == MOBILE_DEVICE_AUTH_IDLE);

    // Slot 0 frees up (game's mail connection closed).
    adapter->commands.connections[0] = false;

    int guard = 0;
    while (auth_calls == 0 && guard++ < 20) {
        adapter->global.active = true;
        enum mobile_action actions = mobile_actions_get(adapter);
        mobile_actions_process(adapter, actions);
    }
    check("dispatched once a slot freed up", auth_calls == 1);
    check("pending cleared after dispatch", !adapter->device_auth.pending);

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
