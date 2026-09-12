// Regression test: a session teardown while device-auth is mid-resolution
// must not close device-auth's socket behind its back.
//
// do_ppp_disconnect() closes every slot connections[] marks as used. Since
// 77b09e9 let device-auth run mid-session, that can include a slot it is
// holding -- which left libmobile using a closed socket on the next tick
// and then closing it a second time, both of which mobile.h promises the
// library never does.
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

// Track which conns are open, so a double close or a use-after-close is a
// hard failure rather than something only visible on real hardware.
static bool open_conns[MOBILE_MAX_CONNECTIONS];
static int double_closes, use_after_close;

static bool cb_sock_open(void *user, unsigned conn, enum mobile_socktype type, enum mobile_addrtype addrtype, unsigned bindport) {
    (void)user;(void)type;(void)addrtype;(void)bindport;
    open_conns[conn] = true;
    return true;
}
static void cb_sock_close(void *user, unsigned conn) {
    (void)user;
    if (!open_conns[conn]) double_closes++;
    open_conns[conn] = false;
}
static int cb_sock_send(void *user, unsigned conn, const void *data, unsigned size, const struct mobile_addr *addr) {
    (void)user;(void)data;(void)addr;
    if (!open_conns[conn]) { use_after_close++; return -1; }
    return (int)size;
}
static int cb_sock_recv(void *user, unsigned conn, void *data, unsigned size, struct mobile_addr *addr) {
    (void)user;(void)data;(void)size;(void)addr;
    if (!open_conns[conn]) { use_after_close++; return -1; }
    return 0;  // never answers, so resolution stays in flight
}
static bool cb_time_check_ms(void *user, unsigned timer, unsigned ms) {
    (void)user;(void)timer;(void)ms; return false;  // never times out
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

    // Mid-session, game online with its own mail connection on slot 0.
    adapter->commands.session_started = true;
    adapter->commands.state = MOBILE_CONNECTION_INTERNET;
    adapter->commands.ppp_id_size = 4;
    memcpy(adapter->commands.ppp_id, "USER", 4);
    adapter->commands.mail_authorized = true;
    adapter->commands.connections[0] = true;
    open_conns[0] = true;
    adapter->global.active = true;

    mobile_device_auth_notify(adapter, MOBILE_DEVICE_AUTH_AUTHORIZE,
        (const unsigned char *)"USER", 4);

    for (int i = 0; i < 5; i++) {
        adapter->global.active = true;
        mobile_actions_process(adapter, mobile_actions_get(adapter));
    }
    check("device-auth is mid-resolution holding slot 1",
        adapter->device_auth.state != MOBILE_DEVICE_AUTH_IDLE &&
        adapter->commands.connections[1] && open_conns[1]);

    // The game drops the PPP link while that resolution is still in flight.
    unsigned char buf[8];
    struct mobile_packet packet = { .data = buf, .length = 0 };
    packet.command = MOBILE_COMMAND_PPP_DISCONNECT;
    adapter->buffer.commands.processing = 0;
    mobile_commands_process(adapter, &packet);

    check("no socket was closed twice", double_closes == 0);
    check("device-auth released its slot during teardown",
        !adapter->commands.connections[1] && !open_conns[1]);
    check("device-auth is back to IDLE", adapter->device_auth.state == MOBILE_DEVICE_AUTH_IDLE);

    // Keep ticking: device-auth must not touch the closed socket afterwards.
    for (int i = 0; i < 10; i++) {
        mobile_actions_process(adapter, mobile_actions_get(adapter));
    }
    check("no use of a closed socket afterwards", use_after_close == 0);
    check("still no double close after further ticks", double_closes == 0);

    // The deauthorize queued by the hang-up must survive all of this.
    check("a device-auth event is still pending (the deauthorize)",
        adapter->device_auth.pending);

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
