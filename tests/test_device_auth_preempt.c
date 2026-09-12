// The game must never be denied a connection slot because the device-auth
// side channel is holding one. Device-auth waits gracefully when it can't
// get a slot; the game does not -- command_tcp_connect_begin() and
// command_dns_request_begin() return a hard error_packet() with no retry.
// So when the game needs a slot and none is free, device-auth yields.
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
static int closed_conns[8];
static int closed_count;
static void cb_sock_close(void *user, unsigned conn) {
    (void)user;
    if (closed_count < 8) closed_conns[closed_count++] = (int)conn;
}
static int cb_sock_connect(void *user, unsigned conn, const struct mobile_addr *addr) {
    (void)user;(void)conn;(void)addr; return 1;
}

// DNS server that never answers, so device-auth stays mid-resolution
// holding its slot for the whole test (the window Pico flagged).
static int cb_sock_send(void *user, unsigned conn, const void *data, unsigned size, const struct mobile_addr *addr) {
    (void)user;(void)conn;(void)data;(void)addr; return (int)size;
}
static int cb_sock_recv(void *user, unsigned conn, void *data, unsigned size, struct mobile_addr *addr) {
    (void)user;(void)conn;(void)data;(void)size;(void)addr; return 0;
}
static bool cb_time_check_ms(void *user, unsigned timer, unsigned ms) {
    (void)user;(void)timer;(void)ms; return false;  // never time out
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
    mobile_def_sock_connect(adapter, cb_sock_connect);
    mobile_def_sock_send(adapter, cb_sock_send);
    mobile_def_sock_recv(adapter, cb_sock_recv);
    mobile_def_time_check_ms(adapter, cb_time_check_ms);
    mobile_def_debug_log(adapter, cb_debug_log);
    mobile_config_load(adapter);
    mobile_start(adapter);

    struct mobile_addr4 dns1 = { .type = MOBILE_ADDRTYPE_IPV4, .port = 53 };
    memcpy(dns1.host, (unsigned char[]){9, 9, 9, 9}, 4);
    mobile_config_set_dns(adapter, (struct mobile_addr *)&dns1, MOBILE_DNS1);

    // Mid-session, game holding slot 0 with its mail connection.
    adapter->global.active = true;
    adapter->commands.connections[0] = true;

    mobile_device_auth_notify(adapter, MOBILE_DEVICE_AUTH_AUTHORIZE,
        (const unsigned char *)"PREEMPT", 7);

    // Tick until device-auth grabs the only free slot (1) and blocks there,
    // since the mock DNS server never answers and never times out. (A few
    // ticks, since higher-priority actions like WRITE_CONFIG take their
    // turn first -- mobile_actions_process() runs one action per call.)
    for (int i = 0; i < 5; i++) {
        adapter->global.active = true;
        mobile_actions_process(adapter, mobile_actions_get(adapter));
    }

    check("device-auth took slot 1 and is mid-resolution",
        adapter->device_auth.state != MOBILE_DEVICE_AUTH_IDLE &&
        adapter->commands.connections[1] == true);

    // Now the game asks for a second connection -- both slots are taken.
    // Before the fix this returned -1 and the game got a protocol error.
    closed_count = 0;
    int conn = mobile_commands_connection_new(adapter);

    check("game got a connection slot instead of an error", conn >= 0);
    check("the slot it got is the one device-auth was holding", conn == 1);
    check("device-auth closed its socket to yield", closed_count == 1 && closed_conns[0] == 1);
    check("device-auth went back to IDLE", adapter->device_auth.state == MOBILE_DEVICE_AUTH_IDLE);
    check("the yielded event is still pending, not lost", adapter->device_auth.pending);
    check("game's own slot 0 untouched", adapter->commands.connections[0] == true);

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
