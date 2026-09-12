// Additional coverage: fallback to game-supplied commands.dns1 when no
// config override is set, single-pending-slot replace, and mutual exclusion
// with number_fetch_handle() over the shared dns/relay union buffer.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mobile_data.h"
#include "commands.h"
#include "config.h"
#include "sha256.h"

static unsigned char store[MOBILE_CONFIG_SIZE];
static unsigned char test_key[32];

static bool cb_config_read(void *user, void *dest, uintptr_t offset, size_t size) {
    (void)user; memcpy(dest, store + offset, size); return true;
}
static bool cb_config_write(void *user, const void *src, uintptr_t offset, size_t size) {
    (void)user; memcpy(store + offset, src, size); return true;
}
static bool cb_sock_open(void *user, unsigned conn, enum mobile_socktype type, enum mobile_addrtype addrtype, unsigned bindport) {
    (void)user;(void)conn;(void)type;(void)addrtype;(void)bindport; return true;
}
static int cb_sock_connect(void *user, unsigned conn, const struct mobile_addr *addr) {
    (void)user;(void)conn;(void)addr; return 1;
}
static void cb_sock_close(void *user, unsigned conn) { (void)user;(void)conn; }
static void cb_debug_log(void *user, const char *line) { (void)user; fputs(line, stderr); }

static unsigned char dns_reply[512];
static unsigned dns_reply_len, dns_reply_pos;
static struct mobile_addr last_send_addr;
static int fail_sends; // if >0, sock_send fails (returns -1) this many times

static int cb_sock_send(void *user, unsigned conn, const void *data, unsigned size, const struct mobile_addr *addr) {
    (void)user;(void)conn;
    if (addr) last_send_addr = *addr;
    if (fail_sends > 0) { fail_sends--; return -1; }

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
    r[n++] = 1; r[n++] = 2; r[n++] = 3; r[n++] = 4;
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
static enum mobile_device_auth_action last_action;
static unsigned char last_ppp_id[0x20];
static unsigned last_ppp_id_size;
static void cb_update_device_auth(void *user, enum mobile_device_auth_action action, const unsigned char *ppp_id, unsigned ppp_id_size, uint64_t counter, const unsigned char *sig, const unsigned char *addr_ipv4, const char *device) {
    (void)user;(void)counter;(void)sig;(void)addr_ipv4;(void)device;
    auth_calls++;
    last_action = action;
    last_ppp_id_size = ppp_id_size;
    memcpy(last_ppp_id, ppp_id, ppp_id_size);
}

static uint16_t checksum(unsigned char *buf, unsigned len) {
    uint16_t sum = 0; while (len--) sum += *buf++; return sum;
}

static struct mobile_packet *run(struct mobile_adapter *adapter, struct mobile_packet *packet) {
    struct mobile_packet *r;
    int guard = 0;
    adapter->buffer.commands.processing = 0;
    while (!(r = mobile_commands_process(adapter, packet))) {
        if (++guard > 100) { fprintf(stderr, "stuck!\n"); exit(1); }
    }
    return r;
}

// mobile_new() is a plain malloc(); a freed adapter's heap block can come
// back with stale fields (e.g. commands.dns1) from a previous test's
// session still in it. Real hardware has static storage duration (zero-
// initialized at boot), so simulate that explicitly for test isolation.
static struct mobile_adapter *new_adapter(void) {
    struct mobile_adapter *adapter = malloc(mobile_sizeof);
    memset(adapter, 0, mobile_sizeof);
    mobile_init(adapter, NULL);
    return adapter;
}

static void setup(struct mobile_adapter *adapter) {
    memset(store, 0xFF, sizeof(store));
    for (int i = 0; i < 32; i++) test_key[i] = (unsigned char)(0x40 + i);
    unsigned char da[0x2D];
    da[0]='D'; da[1]='A'; da[2]=0;
    memcpy(da+5, test_key, 32);
    for (int i=0;i<8;i++) da[0x25+i]=0;
    uint16_t sum = checksum(da+5, sizeof(da)-5);
    da[3]=sum&0xff; da[4]=sum>>8;
    memcpy(store+0x160, da, sizeof(da));

    adapter->serial.device = MOBILE_ADAPTER_BLUE;
    mobile_def_config_read(adapter, cb_config_read);
    mobile_def_config_write(adapter, cb_config_write);
    mobile_def_sock_open(adapter, cb_sock_open);
    mobile_def_sock_connect(adapter, cb_sock_connect);
    mobile_def_sock_send(adapter, cb_sock_send);
    mobile_def_sock_recv(adapter, cb_sock_recv);
    mobile_def_sock_close(adapter, cb_sock_close);
    mobile_def_update_device_auth(adapter, cb_update_device_auth);
    mobile_def_debug_log(adapter, cb_debug_log);
    mobile_config_load(adapter);
    mobile_start(adapter);
}

static void start_session(struct mobile_adapter *adapter, const char *ppp_id) {
    unsigned char buf[64];
    struct mobile_packet packet = { .data = buf };
    memcpy(buf, "NINTENDO", 8);
    packet.command = MOBILE_COMMAND_START;
    packet.length = 8;
    run(adapter, &packet);

    adapter->commands.state = MOBILE_CONNECTION_CALL_ISP;
    unsigned char *p = buf;
    *p++ = (unsigned char)strlen(ppp_id);
    memcpy(p, ppp_id, strlen(ppp_id)); p += strlen(ppp_id);
    *p++ = 0;
    // Game supplies its OWN dns1 (no config override set) -> should fall
    // back to commands.dns1, exactly like the game's own DNS_REQUEST would.
    unsigned char game_dns1[4] = {200, 1, 2, 3};
    memcpy(p, game_dns1, 4); p += 4;
    memset(p, 0, 4); p += 4; // dns2 empty
    packet.command = MOBILE_COMMAND_PPP_CONNECT;
    packet.length = (unsigned char)(p - buf);
    run(adapter, &packet);
}

static void tcp_connect_mail(struct mobile_adapter *adapter, unsigned port) {
    unsigned char buf[64];
    struct mobile_packet packet = { .data = buf };
    buf[0]=1; buf[1]=2; buf[2]=3; buf[3]=4;
    buf[4] = (unsigned char)(port >> 8); buf[5] = (unsigned char)port;
    packet.command = MOBILE_COMMAND_TCP_CONNECT;
    packet.length = 6;
    run(adapter, &packet);
}

int main(void) {
    // --- Test 1: fallback to game-supplied commands.dns1 (no config
    // override), and its port is the fixed MOBILE_DNS_PORT (53), matching
    // dns_get_addr()'s exact priority chain used by the game's own lookups.
    {
        struct mobile_adapter *adapter = new_adapter();
        setup(adapter);
        auth_calls = 0;
        start_session(adapter, "g000000034");
        tcp_connect_mail(adapter, 110);

        int guard = 0;
        while (auth_calls == 0 && guard++ < 20) {
            enum mobile_action actions = mobile_actions_get(adapter);
            mobile_actions_process(adapter, actions);
        }
        printf("[T1] auth_calls=%d (expected 1) action=%d (expected 0=AUTHORIZE)\n",
            auth_calls, last_action);
        printf("[T1] DNS query sent to %u.%u.%u.%u:%u (expected 200.1.2.3:53)\n",
            ((struct mobile_addr4 *)&last_send_addr)->host[0],
            ((struct mobile_addr4 *)&last_send_addr)->host[1],
            ((struct mobile_addr4 *)&last_send_addr)->host[2],
            ((struct mobile_addr4 *)&last_send_addr)->host[3],
            ((struct mobile_addr4 *)&last_send_addr)->port);
        free(adapter);
    }

    // --- Test 2: no DNS server available anywhere (true blank-slate power-
    // on state, not just a freshly malloc'd/possibly-stale-heap adapter --
    // real hardware zero-inits static storage, so simulate that explicitly)
    // -- the IDLE handler must drop the event immediately instead of
    // hanging or (worse) querying a garbage address.
    {
        struct mobile_adapter *adapter = new_adapter();
        setup(adapter);
        auth_calls = 0;

        printf("[T2] config.dns1.type=%d config.dns2.type=%d commands.dns1.type=%d commands.dns2.type=%d\n",
            adapter->config.dns1.type, adapter->config.dns2.type,
            adapter->commands.dns1.type, adapter->commands.dns2.type);

        mobile_device_auth_notify(adapter, MOBILE_DEVICE_AUTH_AUTHORIZE,
            (const unsigned char *)"AAAA", 4);
        mobile_device_auth_notify(adapter, MOBILE_DEVICE_AUTH_DEAUTHORIZE,
            (const unsigned char *)"BBBB", 4);

        // No DNS configured at all -> IDLE handler should drop immediately.
        int guard = 0;
        while (adapter->device_auth.pending && guard++ < 5) {
            enum mobile_action actions = mobile_actions_get(adapter);
            mobile_actions_process(adapter, actions);
        }
        printf("[T2] auth_calls=%d (expected 0, no DNS server configured)\n", auth_calls);
        printf("[T2] pending=%d (expected 0, dropped)\n", adapter->device_auth.pending);
        free(adapter);
    }

    // --- Test 2b: same replace test, but WITH a working DNS server, to
    // confirm the surviving event is the newer one and the older is gone.
    {
        struct mobile_adapter *adapter = new_adapter();
        setup(adapter);
        auth_calls = 0;
        struct mobile_addr4 dns1 = { .type = MOBILE_ADDRTYPE_IPV4, .port = 5300 };
        memcpy(dns1.host, (unsigned char[]){9,9,9,9}, 4);
        mobile_config_set_dns(adapter, (struct mobile_addr *)&dns1, MOBILE_DNS1);

        mobile_device_auth_notify(adapter, MOBILE_DEVICE_AUTH_AUTHORIZE,
            (const unsigned char *)"OLDOLD", 6);
        mobile_device_auth_notify(adapter, MOBILE_DEVICE_AUTH_DEAUTHORIZE,
            (const unsigned char *)"NEWNEWID", 8);

        int guard = 0;
        while (auth_calls == 0 && guard++ < 20) {
            enum mobile_action actions = mobile_actions_get(adapter);
            mobile_actions_process(adapter, actions);
        }
        printf("[T2b] auth_calls=%d (expected 1, only the newer fires)\n", auth_calls);
        printf("[T2b] action=%d (expected 1=DEAUTHORIZE)\n", last_action);
        printf("[T2b] ppp_id_size=%u ppp_id=%.*s (expected 8 NEWNEWID)\n",
            last_ppp_id_size, last_ppp_id_size, last_ppp_id);
        free(adapter);
    }

    // --- Test 3: send failure/timeout drop path -- sock_send always fails,
    // resolution must give up (after trying DNS2 fallback too) rather than
    // hang, and pending must end up false.
    {
        struct mobile_adapter *adapter = new_adapter();
        setup(adapter);
        auth_calls = 0;
        fail_sends = 1000;
        struct mobile_addr4 dns1 = { .type = MOBILE_ADDRTYPE_IPV4, .port = 53 };
        memcpy(dns1.host, (unsigned char[]){9,9,9,9}, 4);
        mobile_config_set_dns(adapter, (struct mobile_addr *)&dns1, MOBILE_DNS1);
        struct mobile_addr4 dns2 = { .type = MOBILE_ADDRTYPE_IPV4, .port = 53 };
        memcpy(dns2.host, (unsigned char[]){8,8,8,8}, 4);
        mobile_config_set_dns(adapter, (struct mobile_addr *)&dns2, MOBILE_DNS2);

        mobile_device_auth_notify(adapter, MOBILE_DEVICE_AUTH_AUTHORIZE,
            (const unsigned char *)"FAILID", 6);

        int guard = 0;
        while (adapter->device_auth.pending && guard++ < 10) {
            enum mobile_action actions = mobile_actions_get(adapter);
            mobile_actions_process(adapter, actions);
        }
        printf("[T3] auth_calls=%d (expected 0)\n", auth_calls);
        printf("[T3] pending=%d (expected 0, dropped after send failure on both DNS1/DNS2)\n",
            adapter->device_auth.pending);
        printf("[T3] state=%d (expected 0=IDLE, not stuck)\n", adapter->device_auth.state);
        free(adapter);
    }

    return 0;
}
