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

// Mock DNS server: replies to any query on conn 0 with an A record for
// whatever name was queried, resolving to 9.8.7.6, using the query's own id.
static unsigned char dns_reply[512];
static unsigned dns_reply_len, dns_reply_pos;
static int dns_send_calls;
static unsigned char last_query[512];
static unsigned last_query_len;
static struct mobile_addr last_send_addr;

static int cb_sock_send(void *user, unsigned conn, const void *data, unsigned size, const struct mobile_addr *addr) {
    (void)user;(void)conn;
    dns_send_calls++;
    memcpy(last_query, data, size);
    last_query_len = size;
    if (addr) last_send_addr = *addr;

    // Build a matching response: header (id echoed, ANCOUNT=1) + question
    // echoed + answer (name via pointer to offset 12, A, IN, TTL, RDATA).
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
    r[n++] = 9; r[n++] = 8; r[n++] = 7; r[n++] = 6;
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
        a4->port = last_send_addr.type == MOBILE_ADDRTYPE_IPV4 ?
            ((struct mobile_addr4 *)&last_send_addr)->port : 53;
        memcpy(a4->host, ((struct mobile_addr4 *)&last_send_addr)->host, 4);
    }
    return (int)n;
}

static int auth_calls;
static unsigned char last_addr[4];
static void cb_update_device_auth(void *user, enum mobile_device_auth_action action, const unsigned char *ppp_id, unsigned ppp_id_size, uint64_t counter, const unsigned char *sig, const unsigned char *addr_ipv4, const char *device) {
    (void)user;(void)action;(void)ppp_id;(void)ppp_id_size;(void)counter;(void)sig;(void)device;
    auth_calls++;
    memcpy(last_addr, addr_ipv4, 4);
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

int main(void) {
    memset(store, 0xFF, sizeof(store));
    for (int i = 0; i < 32; i++) test_key[i] = (unsigned char)(0x40 + i);
    unsigned char da[0x2D];
    da[0]='D'; da[1]='A'; da[2]=0;
    memcpy(da+5, test_key, 32);
    for (int i=0;i<8;i++) da[0x25+i]=0;
    uint16_t sum = checksum(da+5, sizeof(da)-5);
    da[3]=sum&0xff; da[4]=sum>>8;
    memcpy(store+0x160, da, sizeof(da));

    struct mobile_adapter *adapter = mobile_new(NULL);
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

    // Configure a DNS server on a NON-standard port (5453), matching the
    // real REON deployment -- must be respected, not hardcoded to 53.
    struct mobile_addr4 dns1 = { .type = MOBILE_ADDRTYPE_IPV4, .port = 5453 };
    memcpy(dns1.host, (unsigned char[]){152,67,55,127}, 4);
    mobile_config_set_dns(adapter, (struct mobile_addr *)&dns1, MOBILE_DNS1);

    unsigned char buf[64];
    struct mobile_packet packet = { .data = buf };
    memcpy(buf, "NINTENDO", 8);
    packet.command = MOBILE_COMMAND_START;
    packet.length = 8;
    run(adapter, &packet);

    adapter->commands.state = MOBILE_CONNECTION_CALL_ISP;
    const char *ppp_id = "g000000034";
    unsigned char *p = buf;
    *p++ = (unsigned char)strlen(ppp_id);
    memcpy(p, ppp_id, strlen(ppp_id)); p += strlen(ppp_id);
    *p++ = 0;
    memset(p, 0, 8); p += 8; // game supplies empty dns1/dns2 -> config.dns1 used
    packet.command = MOBILE_COMMAND_PPP_CONNECT;
    packet.length = (unsigned char)(p - buf);
    run(adapter, &packet);

    printf("commands.dns1 after PPP connect: type=%d port=%u host=%u.%u.%u.%u (expected type=1 port=5453 152.67.55.127)\n",
        adapter->commands.dns1.type, adapter->commands.dns1.port,
        adapter->commands.dns1.host[0], adapter->commands.dns1.host[1],
        adapter->commands.dns1.host[2], adapter->commands.dns1.host[3]);

    buf[0]=1; buf[1]=2; buf[2]=3; buf[3]=4; buf[4]=0; buf[5]=110;
    packet.command = MOBILE_COMMAND_TCP_CONNECT;
    packet.length = 6;
    run(adapter, &packet);

    printf("auth_calls right after TCP connect = %d (expected 0, resolution not synchronous)\n", auth_calls);
    printf("device_auth.pending = %d (expected 1)\n", adapter->device_auth.pending);

    // Drive idle ticks (mobile_loop-equivalent) until the callback fires.
    int guard = 0;
    while (auth_calls == 0 && guard++ < 20) {
        enum mobile_action actions = mobile_actions_get(adapter);
        mobile_actions_process(adapter, actions);
    }

    printf("auth_calls after idle ticks = %d (expected 1)\n", auth_calls);
    printf("resolved addr = %u.%u.%u.%u (expected 9.8.7.6)\n",
        last_addr[0], last_addr[1], last_addr[2], last_addr[3]);
    printf("DNS query sent to port %u (expected 5453, NOT 53)\n",
        ((struct mobile_addr4 *)&last_send_addr)->port);
    printf("device_auth.state after dispatch = %d (expected 0=IDLE)\n", adapter->device_auth.state);
    printf("device_auth.pending after dispatch = %d (expected 0)\n", adapter->device_auth.pending);

    return 0;
}
