// SPDX-License-Identifier: LGPL-3.0-or-later
#include "device_auth.h"

#include <string.h>

#include "mobile_data.h"
#include "commands.h"
#include "dns.h"
#include "sha256.h"
#include "util.h"
#include "compat.h"

// The device-auth server's hostname. Lives here, and only here -- every
//   frontend gets the resolved address through the callback instead of
//   needing to know this string (or reimplement its own resolution/DNS
//   port handling) independently.
static const char device_auth_host[] = "device.auth.dion.ne.jp";
#define DEVICE_AUTH_HOST_LEN (sizeof(device_auth_host) - 1)

// Longest possible "ppp_id|action|counter" message:
//   0x20 (ppp_id) + 1 ('|') + 11 ("deauthorize") + 1 ('|') + 20 (2^64-1)
#define MESSAGE_MAX_SIZE (0x20 + 1 + 11 + 1 + 20)

static void debug_prefix(struct mobile_adapter *adapter)
{
    mobile_debug_print(adapter, PSTR("<DEVICE-AUTH> "));
}

// Mirrors dns_get_addr() in commands.c exactly: a configured override
//   (config.dns1/dns2, with whatever port it was set up with) is always
//   preferred over the game-chosen server (commands.dns1/dns2, which -- like
//   the real adapter -- only ever uses the fixed DNS_PORT), and DNS2 is a
//   fallback for either. This is the same address a DNS_REQUEST triggered
//   by the game itself would end up using.
static struct mobile_addr *device_auth_get_addr(struct mobile_adapter *adapter, unsigned char id)
{
    switch (id) {
        default:
        case 0: return &adapter->config.dns1;
        case 1: return (struct mobile_addr *)&adapter->commands.dns1;
        case 2: return &adapter->config.dns2;
        case 3: return (struct mobile_addr *)&adapter->commands.dns2;
    }
}

// Renders counter as decimal ASCII, without leading zeros, matching exactly
//   what the device-auth server expects to find in the signed message.
static unsigned counter_to_decimal(uint64_t counter, unsigned char *out)
{
    unsigned char tmp[20];
    unsigned len = 0;

    do {
        tmp[len++] = (unsigned char)('0' + counter % 10);
        counter /= 10;
    } while (counter != 0);

    for (unsigned i = 0; i < len; i++) {
        out[i] = tmp[len - 1 - i];
    }
    return len;
}

void mobile_device_auth_init(struct mobile_adapter *adapter)
{
    adapter->device_auth.state = MOBILE_DEVICE_AUTH_IDLE;
    adapter->device_auth.pending = false;
}

void mobile_device_auth_notify(struct mobile_adapter *adapter, enum mobile_device_auth_action action, const unsigned char *ppp_id, unsigned ppp_id_size)
{
    if (ppp_id_size == 0 || ppp_id_size > 0x20) return;
    if (!adapter->config.device_auth_key_init) return;

    struct mobile_adapter_device_auth *s = &adapter->device_auth;

    // Say exactly what was lost and how far it got. This is the log that
    //   disambiguates a relay server seeing "deauthorize with no authorize":
    //   that used to mean only one thing (the authorize could never
    //   dispatch at all), but since device-auth yields its connection slot
    //   to the game it can also just mean the authorize kept losing the
    //   slot to a busy game. Only the client-side log can tell those apart.
    if (s->pending) {
        debug_prefix(adapter);
        if (s->pending_action == MOBILE_DEVICE_AUTH_AUTHORIZE) {
            if (s->state == MOBILE_DEVICE_AUTH_IDLE) {
                mobile_debug_print(adapter,
                    PSTR("Replacing authorize that never got a turn to resolve"));
            } else {
                mobile_debug_print(adapter,
                    PSTR("Replacing authorize still resolving"));
            }
        } else {
            if (s->state == MOBILE_DEVICE_AUTH_IDLE) {
                mobile_debug_print(adapter,
                    PSTR("Replacing deauthorize that never got a turn to resolve"));
            } else {
                mobile_debug_print(adapter,
                    PSTR("Replacing deauthorize still resolving"));
            }
        }
        mobile_debug_endl(adapter);
    }

    s->pending = true;
    s->pending_action = action;
    memcpy(s->pending_ppp_id, ppp_id, ppp_id_size);
    s->pending_ppp_id_size = (unsigned char)ppp_id_size;
}

// Signs and dispatches the event that just finished resolving (or failed
//   to), then clears it either way.
static void device_auth_sign_and_dispatch(struct mobile_adapter *adapter, const unsigned char *addr_ipv4)
{
    struct mobile_adapter_device_auth *s = &adapter->device_auth;

    uint64_t counter;
    if (!mobile_config_device_auth_next(adapter, &counter)) return;

    unsigned char key[MOBILE_DEVICE_AUTH_KEY_SIZE];
    if (!mobile_config_get_device_auth_key(adapter, key)) return;

    const char *action_name = s->pending_action == MOBILE_DEVICE_AUTH_AUTHORIZE ?
        "authorize" : "deauthorize";
    unsigned action_len = (unsigned)strlen(action_name);

    unsigned char message[MESSAGE_MAX_SIZE];
    unsigned pos = 0;

    memcpy(message + pos, s->pending_ppp_id, s->pending_ppp_id_size);
    pos += s->pending_ppp_id_size;
    message[pos++] = '|';
    memcpy(message + pos, action_name, action_len);
    pos += action_len;
    message[pos++] = '|';
    pos += counter_to_decimal(counter, message + pos);

    unsigned char sig[MOBILE_SHA256_SIZE];
    mobile_hmac_sha256(key, sizeof(key), message, pos, sig);

    static_assert(MOBILE_SHA256_SIZE == MOBILE_DEVICE_AUTH_SIG_SIZE,
        "device-auth signature size mismatch");
    mobile_cb_update_device_auth(adapter, s->pending_action,
        s->pending_ppp_id, s->pending_ppp_id_size, counter, sig, addr_ipv4);
}

// Starts (or restarts, for the next fallback candidate) resolution at
//   addr_id, borrowing a connection slot via mobile_commands_connection_new()
//   -- the same accounting the game's own connections use, so this can
//   never collide with one it already has open.
// Returns 1 if resolution started (state moved to RESOLVE_SEND); 0 if every
//   candidate address is set, but no connection slot is free right now (the
//   caller must leave the event pending and retry later, NOT give up); -1
//   if there's no address left to try, or the socket/query couldn't be set
//   up (the caller must give up).
static int device_auth_resolve_start(struct mobile_adapter *adapter, unsigned char addr_id)
{
    struct mobile_adapter_device_auth *s = &adapter->device_auth;

    struct mobile_addr *addr_send;
    for (; addr_id < 4; addr_id++) {
        addr_send = device_auth_get_addr(adapter, addr_id);
        if (addr_send->type != MOBILE_ADDRTYPE_NONE) break;
    }
    if (addr_id >= 4) return -1;

    int conn = mobile_commands_connection_new(adapter);
    if (conn < 0) return 0;

    mobile_addr_copy(&s->addr, addr_send);
    s->addr_id = addr_id;

    if (!mobile_cb_sock_open(adapter, (unsigned)conn, MOBILE_SOCKTYPE_UDP,
            s->addr.type, 0)) {
        return -1;
    }
    if (!mobile_dns_request_build(adapter, device_auth_host, DEVICE_AUTH_HOST_LEN)) {
        mobile_cb_sock_close(adapter, (unsigned)conn);
        return -1;
    }

    adapter->commands.connections[conn] = true;
    s->conn = (unsigned char)conn;

    debug_prefix(adapter);
    mobile_debug_print(adapter, PSTR("Resolving "));
    mobile_debug_write(adapter, device_auth_host, DEVICE_AUTH_HOST_LEN);
    mobile_debug_endl(adapter);

    mobile_cb_time_latch(adapter, MOBILE_TIMER_COMMAND);
    s->state = MOBILE_DEVICE_AUTH_RESOLVE_SEND;
    return 1;
}

// Closes and releases the connection slot the current attempt was using.
static void device_auth_release_conn(struct mobile_adapter *adapter)
{
    struct mobile_adapter_device_auth *s = &adapter->device_auth;
    mobile_cb_sock_close(adapter, s->conn);
    adapter->commands.connections[s->conn] = false;
}

void mobile_device_auth_cancel(struct mobile_adapter *adapter)
{
    struct mobile_adapter_device_auth *s = &adapter->device_auth;

    // Nothing in flight means nothing to give back. This is also what makes
    //   it safe for device_auth_resolve_start() to go through
    //   mobile_commands_connection_new(), which calls this: it only ever
    //   does so with state == IDLE, so it can never cancel itself.
    if (s->state == MOBILE_DEVICE_AUTH_IDLE) return;

    debug_prefix(adapter);
    mobile_debug_print(adapter, PSTR("Yielding connection to the game"));
    mobile_debug_endl(adapter);

    device_auth_release_conn(adapter);
    s->state = MOBILE_DEVICE_AUTH_IDLE;
    // pending is deliberately left set: the event is retried once a slot
    //   frees up again, rather than being lost.
}

void mobile_device_auth_handle(struct mobile_adapter *adapter)
{
    struct mobile_adapter_device_auth *s = &adapter->device_auth;

    if (s->state == MOBILE_DEVICE_AUTH_IDLE) {
        if (!s->pending) return;

        int rc = device_auth_resolve_start(adapter, 0);
        if (rc == 0) return;  // No connection slot free right now, retry later
        if (rc < 0) {
            debug_prefix(adapter);
            mobile_debug_print(adapter, PSTR("No DNS server available, dropping"));
            mobile_debug_endl(adapter);
            s->pending = false;
            return;
        }
        // fallthrough
    }

    if (s->state == MOBILE_DEVICE_AUTH_RESOLVE_SEND) {
        int rc = mobile_dns_request_send(adapter, s->conn, &s->addr);
        if (rc == 0) {
            if (mobile_cb_time_check_ms(adapter, MOBILE_TIMER_COMMAND, 3000)) rc = -1;
            else return;
        }
        if (rc < 0) {
            debug_prefix(adapter);
            mobile_debug_print(adapter, PSTR("Failed to send query, dropping"));
            mobile_debug_endl(adapter);
            device_auth_release_conn(adapter);
            s->state = MOBILE_DEVICE_AUTH_IDLE;
            s->pending = false;
            return;
        }

        mobile_cb_time_latch(adapter, MOBILE_TIMER_COMMAND);
        s->state = MOBILE_DEVICE_AUTH_RESOLVE_RECV;
    }

    if (s->state == MOBILE_DEVICE_AUTH_RESOLVE_RECV) {
        unsigned char ip[MOBILE_HOSTLEN_IPV4] = {0};
        int rc = mobile_dns_request_recv(adapter, s->conn, &s->addr,
            device_auth_host, DEVICE_AUTH_HOST_LEN, ip);
        if (rc == 0 && !mobile_cb_time_check_ms(adapter, MOBILE_TIMER_COMMAND, 3000)) {
            return;
        }

        device_auth_release_conn(adapter);
        s->state = MOBILE_DEVICE_AUTH_IDLE;

        if (rc <= 0) {
            // Same fallback the game's own DNS_REQUEST uses: if DNS1 (ids
            //   0-1) just failed, try DNS2 (ids 2-3) before giving up. If no
            //   connection slot is free for that attempt right now (rc2==0),
            //   stay pending -- state is already IDLE, so the next tick
            //   retries cleanly from addr_id 0 (a harmless extra DNS1 round
            //   trip at worst).
            if (s->addr_id < 2) {
                int rc2 = device_auth_resolve_start(adapter, 2);
                if (rc2 != -1) return;
            }

            debug_prefix(adapter);
            mobile_debug_print(adapter, PSTR("Resolution failed, dropping"));
            mobile_debug_endl(adapter);
            s->pending = false;
            return;
        }

        s->pending = false;

        debug_prefix(adapter);
        mobile_debug_print(adapter, PSTR("Resolved to %u.%u.%u.%u"),
            ip[0], ip[1], ip[2], ip[3]);
        mobile_debug_endl(adapter);

        device_auth_sign_and_dispatch(adapter, ip);
    }
}
