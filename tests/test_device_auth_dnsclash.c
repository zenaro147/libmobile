// adapter->buffer.dns is a single buffer shared between the game's own
// DNS_REQUEST command and the device-auth side channel's lookups. If the
// game builds a query into it while device-auth is waiting for a reply,
// device-auth's query id/type are overwritten and it can no longer
// recognise its own answer.
//
// The game must win (it fails hard, device-auth retries), and device-auth
// must be left queued rather than resolving against a clobbered buffer.
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
static int cb_sock_send(void *user, unsigned conn, const void *data, unsigned size, const struct mobile_addr *addr) {
    (void)user;(void)conn;(void)data;(void)addr; return (int)size;
}
// Never answers, so device-auth stays parked in RESOLVE_RECV holding the
// shared buffer for the whole test.
static int cb_sock_recv(void *user, unsigned conn, void *data, unsigned size, struct mobile_addr *addr) {
    (void)user;(void)conn;(void)data;(void)size;(void)addr; return 0;
}
static bool cb_time_check_ms(void *user, unsigned timer, unsigned ms) {
    (void)user;(void)timer;(void)ms; return false;
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
    mobile_def_time_check_ms(adapter, cb_time_check_ms);
    mobile_def_debug_log(adapter, cb_debug_log);
    mobile_config_load(adapter);
    mobile_start(adapter);

    struct mobile_addr4 dns1 = { .type = MOBILE_ADDRTYPE_IPV4, .port = 53 };
    memcpy(dns1.host, (unsigned char[]){9, 9, 9, 9}, 4);
    mobile_config_set_dns(adapter, (struct mobile_addr *)&dns1, MOBILE_DNS1);

    // Online, no connections held by the game yet -- so a slot stays free
    // and the connection-exhaustion path does NOT fire. This is the case
    // where only the shared buffer is contended.
    adapter->commands.session_started = true;
    adapter->commands.state = MOBILE_CONNECTION_INTERNET;
    adapter->commands.ppp_id_size = 4;
    memcpy(adapter->commands.ppp_id, "USER", 4);
    adapter->global.active = true;

    mobile_device_auth_notify(adapter, MOBILE_DEVICE_AUTH_AUTHORIZE,
        (const unsigned char *)"USER", 4);

    for (int i = 0; i < 5; i++) {
        adapter->global.active = true;
        mobile_actions_process(adapter, mobile_actions_get(adapter));
    }
    check("device-auth is parked mid-resolution owning buffer.dns",
        adapter->device_auth.state != MOBILE_DEVICE_AUTH_IDLE);

    unsigned da_id = adapter->buffer.dns.id;
    check("a free connection slot exists (so this is buffer contention, not slot)",
        mobile_commands_connection_new(adapter) >= 0);

    // The game now issues its own DNS_REQUEST for a different hostname.
    unsigned char buf[64];
    struct mobile_packet packet = { .data = buf };
    const char *host = "pop.reon.dion.ne.jp";
    memcpy(buf, host, strlen(host));
    packet.command = MOBILE_COMMAND_DNS_REQUEST;
    packet.length = (unsigned char)strlen(host);
    adapter->buffer.commands.processing = 0;
    mobile_commands_process(adapter, &packet);

    check("the game's query took over buffer.dns (its id differs)",
        adapter->buffer.dns.id != da_id);
    check("device-auth was pushed back to IDLE, not left resolving a clobbered buffer",
        adapter->device_auth.state == MOBILE_DEVICE_AUTH_IDLE);
    check("device-auth's event survives, still queued for a retry",
        adapter->device_auth.pending);

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
