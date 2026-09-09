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

// Longest signed message, "ppp_id|device|query-response|<value>|<echo>":
//   0x20 (ppp_id) + 1 + 16 (device id) + 1 + 14 ("query-response", the
//   longest action word) + 1 + 20 (a 2^64-1 counter, or "blocked", which
//   is shorter) + 1 + 20 (the echo). Every other message is a prefix of
//   this shape or shorter, so this bounds them all.
#define ACTION_MAX_LEN 14
#define MESSAGE_MAX_SIZE \
    (0x20 + 1 + (MOBILE_DEVICE_ID_SIZE * 2) + 1 + ACTION_MAX_LEN + 1 + 20 + 1 + 20)

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
    adapter->device_auth.device_id[0] = '\0';
    adapter->device_auth.device_id_init = false;
    adapter->device_auth.impl_name[0] = '\0';
    adapter->device_auth.addr_resolved = false;
    adapter->device_auth.addr_failed = false;
    adapter->device_auth.query_pending = false;
    adapter->device_auth.query_inflight = false;
    adapter->device_auth.block_state = MOBILE_DEVICE_AUTH_BLOCK_UNKNOWN;
}

void mobile_device_auth_session_start(struct mobile_adapter *adapter)
{
    struct mobile_adapter_device_auth *s = &adapter->device_auth;

    // The resolved address deliberately survives: it belongs to the device's
    //   run, not to one session. A failed attempt does not: a session brings
    //   a DNS server the game chose, which the earlier try never had.
    s->addr_failed = false;
    s->query_inflight = false;
    s->query_pending = adapter->config.device_auth_key_init;
    // Learned afresh each session, on purpose; see mobile_device_auth_block_state().
    s->block_state = MOBILE_DEVICE_AUTH_BLOCK_UNKNOWN;
}

enum mobile_device_auth_block_state mobile_device_auth_block_state(struct mobile_adapter *adapter)
{
    return adapter->device_auth.block_state;
}

void mobile_device_auth_set_impl_name(struct mobile_adapter *adapter, const char *impl_name)
{
    struct mobile_adapter_device_auth *s = &adapter->device_auth;

    unsigned len = 0;
    if (impl_name) {
        while (impl_name[len] && len < MOBILE_IMPL_NAME_MAX_SIZE) {
            s->impl_name[len] = impl_name[len];
            len++;
        }
    }
    s->impl_name[len] = '\0';

    // The id may already have been derived; the next caller must derive it
    //   again rather than keep one built without this name.
    s->device_id_init = false;
    s->device_id[0] = '\0';
}

// Builds "ppp_id|device|action" (or "ppp_id|action" without a device id),
//   the common prefix of every signed device-auth message. Returns its
//   length; the caller appends whatever else that message carries.
static unsigned device_auth_message_prefix(unsigned char *message, const unsigned char *ppp_id, unsigned ppp_id_size, const char *device, const char *action)
{
    unsigned pos = 0;
    memcpy(message + pos, ppp_id, ppp_id_size);
    pos += ppp_id_size;
    message[pos++] = '|';
    if (device) {
        memcpy(message + pos, device, MOBILE_DEVICE_ID_SIZE * 2);
        pos += MOBILE_DEVICE_ID_SIZE * 2;
        message[pos++] = '|';
    }
    unsigned action_len = (unsigned)strlen(action);
    memcpy(message + pos, action, action_len);
    pos += action_len;
    return pos;
}

// Derives this device's id from the frontend's identity bytes, hashing them
//   so nothing the frontend considers identifying (a MAC, a machine id, a
//   host name) is ever put on the wire as-is. Computed once and cached;
//   returns NULL when the frontend offers no identity, which selects the
//   older, device-less form of the message.
static const char *device_auth_device_id(struct mobile_adapter *adapter)
{
    struct mobile_adapter_device_auth *s = &adapter->device_auth;
    if (s->device_id_init) return s->device_id;

    // Without a name there is nothing to tell this frontend from another on
    //   the same machine, and two frontends claiming one id is worse than
    //   neither claiming any: the server would read one's requests as
    //   replays of the other's.
    if (s->impl_name[0] == '\0') return NULL;

    // Only success is remembered. A frontend may have nothing to offer yet
    //   and something later -- on the 3DS the Wi-Fi MAC is unreadable until
    //   the network is up, which can be after the first thing here that
    //   wants an id -- so "no identity" is asked again every time rather
    //   than settled once, and the frontend needn't retry on its own.
    unsigned char identity[MOBILE_DEVICE_IDENTITY_MAX_SIZE];
    unsigned size = mobile_cb_device_identity(adapter, identity,
        sizeof(identity));
    if (size == 0 || size > sizeof(identity)) return NULL;

    // sha256(impl_name || 0 || identity). Without the separator ("ab", "cd")
    //   and ("a", "bcd") would hash alike; with it, no two pairs can.
    // That holds because impl_name is a C string and so cannot contain a
    //   zero, which puts the first zero of the concatenation at the length
    //   of the name in every case -- so equal hashes mean equal names and
    //   equal identities. Note the guarantee rests on the NAME, not on the
    //   identity: identity is raw bytes and may well contain zeros (a board
    //   id often does), which is harmless. Worth knowing before anyone
    //   "fixes" this, since binary identity is the first thing that looks
    //   like it should break it.
    unsigned char digest[MOBILE_SHA256_SIZE];
    struct mobile_sha256 ctx;
    mobile_sha256_init(&ctx);
    mobile_sha256_update(&ctx, s->impl_name, strlen(s->impl_name));
    mobile_sha256_update(&ctx, "", 1);
    mobile_sha256_update(&ctx, identity, size);
    mobile_sha256_final(&ctx, digest);

    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < MOBILE_DEVICE_ID_SIZE; i++) {
        s->device_id_raw[i] = digest[i];
        s->device_id[i * 2] = hex[digest[i] >> 4];
        s->device_id[i * 2 + 1] = hex[digest[i] & 0xF];
    }
    s->device_id[MOBILE_DEVICE_ID_SIZE * 2] = '\0';
    s->device_id_init = true;

    debug_prefix(adapter);
    mobile_debug_print(adapter, PSTR("Device id "));
    mobile_debug_write(adapter, s->device_id, MOBILE_DEVICE_ID_SIZE * 2);
    mobile_debug_endl(adapter);

    return s->device_id;
}

const unsigned char *mobile_device_auth_device_id_raw(struct mobile_adapter *adapter)
{
    if (!device_auth_device_id(adapter)) return NULL;
    return adapter->device_auth.device_id_raw;
}

bool mobile_device_auth_get_id(struct mobile_adapter *adapter, char *buf)
{
    const char *id = device_auth_device_id(adapter);
    if (!id) return false;

    memcpy(buf, id, MOBILE_DEVICE_ID_STR_SIZE);
    return true;
}

bool mobile_device_auth_get_pairing_code(struct mobile_adapter *adapter, char *buf)
{
    const char *id = device_auth_device_id(adapter);
    if (!id) return false;

    // First half of the id as XXXX-XXXX, upper case.
    for (unsigned i = 0; i < 8; i++) {
        char c = id[i];
        buf[i < 4 ? i : i + 1] = (c >= 'a' && c <= 'f') ? (char)(c - 'a' + 'A') : c;
    }
    buf[4] = '-';
    buf[9] = '\0';
    static_assert(MOBILE_PAIRING_CODE_STR_SIZE == 10,
        "pairing code buffer size is out of sync with its format");
    return true;
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

    // "ppp_id|device|action|counter", or "ppp_id|action|counter" when this
    //   device has no id to give. The device field sits where it does so a
    //   server can tell the two forms apart without ambiguity.
    const char *device = device_auth_device_id(adapter);

    unsigned char message[MESSAGE_MAX_SIZE];
    unsigned pos = device_auth_message_prefix(message, s->pending_ppp_id,
        s->pending_ppp_id_size, device, action_name);
    message[pos++] = '|';
    pos += counter_to_decimal(counter, message + pos);

    unsigned char sig[MOBILE_SHA256_SIZE];
    mobile_hmac_sha256(key, sizeof(key), message, pos, sig);

    static_assert(MOBILE_SHA256_SIZE == MOBILE_DEVICE_AUTH_SIG_SIZE,
        "device-auth signature size mismatch");
    mobile_cb_update_device_auth(adapter, s->pending_action,
        s->pending_ppp_id, s->pending_ppp_id_size, counter, sig, addr_ipv4,
        device);
}

// Signs and hands the frontend a counter query. Returns whether it was
//   taken; if not, the session simply proceeds on the counter it has.
static bool device_auth_dispatch_query(struct mobile_adapter *adapter)
{
    struct mobile_adapter_device_auth *s = &adapter->device_auth;
    struct mobile_adapter_commands *c = &adapter->commands;

    if (c->ppp_id_size == 0 || c->ppp_id_size > 0x20) return false;

    unsigned char key[MOBILE_DEVICE_AUTH_KEY_SIZE];
    if (!mobile_config_get_device_auth_key(adapter, key)) return false;

    // Spend a counter value on the query, as an authorization would. The
    //   server echoes it inside its signed answer, which is what makes the
    //   answer provably a reply to THIS query and not a recording of an
    //   earlier one. It has to come from the never-reused sequence rather
    //   than from anything about the device's state, because the case that
    //   matters most -- a device the server has blocked -- is exactly the
    //   case where nothing else about the device changes between sessions.
    uint64_t counter;
    if (!mobile_config_device_auth_next(adapter, &counter)) return false;

    const char *device = device_auth_device_id(adapter);

    unsigned char message[MESSAGE_MAX_SIZE];
    unsigned pos = device_auth_message_prefix(message, c->ppp_id,
        c->ppp_id_size, device, "query");
    message[pos++] = '|';
    pos += counter_to_decimal(counter, message + pos);

    unsigned char sig[MOBILE_SHA256_SIZE];
    mobile_hmac_sha256(key, sizeof(key), message, pos, sig);

    if (!mobile_cb_device_auth_query(adapter, s->addr_ipv4, c->ppp_id,
            c->ppp_id_size, counter, sig, device)) {
        return false;
    }
    s->query_counter = counter;

    debug_prefix(adapter);
    mobile_debug_print(adapter, PSTR("Asking the server for our counter"));
    mobile_debug_endl(adapter);
    return true;
}

// Reads one decimal field: 1-20 digits, no leading zero, no overflow.
//   Returns how many characters it took, 0 if the text isn't one.
static unsigned device_auth_parse_decimal(const unsigned char *p, unsigned size, uint64_t *out)
{
    unsigned n = 0;
    uint64_t value = 0;
    while (n < size && p[n] >= '0' && p[n] <= '9') {
        if (value > (UINT64_MAX - (uint64_t)(p[n] - '0')) / 10) return 0;
        value = value * 10 + (uint64_t)(p[n] - '0');
        n++;
    }
    if (n == 0 || n > 20) return 0;
    if (n > 1 && p[0] == '0') return 0;
    *out = value;
    return n;
}

// Pulls the fields out of a query response body, or reports that the body
//   isn't one. Split out so every way of failing gets logged in one place:
//   silently discarding an answer leaves nothing to tell "the server said
//   something unexpected" apart from "the server never answered".
// Body is exactly "<counter> <echo> <sig>" or "blocked <echo> <sig>": each
//   number 1-20 digits without a leading zero, single spaces, 64 lowercase
//   hex, and nothing else. Anything else is discarded rather than salvaged
//   -- this sets a counter, and a bad one strands the device.
// Trailing CR/LF is the exception, and only because it is the one
//   difference a server can add without meaning to (an echo with a
//   newline, a proxy being helpful) and the one that costs nothing to
//   accept: the signature covers the fields, not the framing around them.
static bool device_auth_parse_answer(const void *data, unsigned size, bool *blocked, uint64_t *counter, uint64_t *echo, const unsigned char **sig_hex)
{
    const unsigned char *body = data;
    while (size > 0 && (body[size - 1] == '\n' || body[size - 1] == '\r')) {
        size--;
    }

    unsigned pos;
    static const char word[] = "blocked";
    if (size >= sizeof(word) - 1 && memcmp(body, word, sizeof(word) - 1) == 0) {
        *blocked = true;
        *counter = 0;
        pos = sizeof(word) - 1;
    } else {
        *blocked = false;
        pos = device_auth_parse_decimal(body, size, counter);
        if (pos == 0) return false;
    }

    if (pos >= size || body[pos] != ' ') return false;
    pos++;
    unsigned n = device_auth_parse_decimal(body + pos, size - pos, echo);
    if (n == 0) return false;
    pos += n;

    if (pos >= size || body[pos] != ' ') return false;
    pos++;
    if (size - pos != MOBILE_SHA256_SIZE * 2) return false;
    for (unsigned i = 0; i < MOBILE_SHA256_SIZE * 2; i++) {
        unsigned char ch = body[pos + i];
        bool ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        if (!ok) return false;  // uppercase and anything else is not this format
    }
    *sig_hex = body + pos;
    return true;
}

void mobile_device_auth_query_result(struct mobile_adapter *adapter, const void *data, unsigned size)
{
    struct mobile_adapter_device_auth *s = &adapter->device_auth;
    struct mobile_adapter_commands *c = &adapter->commands;

    if (!s->query_inflight) return;
    s->query_inflight = false;
    // Everything below that returns early leaves block_state UNKNOWN. That
    //   is the fail-open rule: only a verified, fresh answer may say YES,
    //   and nothing short of that may say NO either.
    if (!data || size == 0) return;

    bool blocked;
    uint64_t value, echo;
    const unsigned char *hex;
    if (!device_auth_parse_answer(data, size, &blocked, &value, &echo, &hex)) {
        debug_prefix(adapter);
        mobile_debug_print(adapter, PSTR("Counter answer isn't in the expected form, ignored"));
        mobile_debug_endl(adapter);
        return;
    }

    // Not the answer to the query that went out -- whatever it is, and
    //   however well it is signed. This is the whole defence against a
    //   recorded answer being played back later.
    if (echo != s->query_counter) {
        debug_prefix(adapter);
        mobile_debug_print(adapter, PSTR("Counter answer echoes a different query, ignored"));
        mobile_debug_endl(adapter);
        return;
    }

    unsigned char given[MOBILE_SHA256_SIZE];
    for (unsigned i = 0; i < MOBILE_SHA256_SIZE; i++) {
        unsigned char byte = 0;
        for (unsigned j = 0; j < 2; j++) {
            unsigned char ch = hex[i * 2 + j];
            byte = (unsigned char)(byte << 4 |
                (ch <= '9' ? ch - '0' : ch - 'a' + 10));
        }
        given[i] = byte;
    }

    unsigned char key[MOBILE_DEVICE_AUTH_KEY_SIZE];
    if (!mobile_config_get_device_auth_key(adapter, key)) return;
    if (c->ppp_id_size == 0 || c->ppp_id_size > 0x20) return;

    // "ppp_id|device|query-response|<counter or blocked>|<echo>"
    unsigned char message[MESSAGE_MAX_SIZE];
    unsigned pos = device_auth_message_prefix(message, c->ppp_id,
        c->ppp_id_size, device_auth_device_id(adapter), "query-response");
    message[pos++] = '|';
    if (blocked) {
        memcpy(message + pos, "blocked", 7);
        pos += 7;
    } else {
        pos += counter_to_decimal(value, message + pos);
    }
    message[pos++] = '|';
    pos += counter_to_decimal(echo, message + pos);

    unsigned char want[MOBILE_SHA256_SIZE];
    mobile_hmac_sha256(key, sizeof(key), message, pos, want);

    unsigned diff = 0;
    for (unsigned i = 0; i < MOBILE_SHA256_SIZE; i++) diff |= given[i] ^ want[i];
    if (diff != 0) {
        debug_prefix(adapter);
        mobile_debug_print(adapter, PSTR("Counter answer failed its signature, ignored"));
        mobile_debug_endl(adapter);
        return;
    }

    if (blocked) {
        s->block_state = MOBILE_DEVICE_AUTH_BLOCK_YES;
        // An authorization still waiting to go out would only be refused;
        //   dropping it spares the round trip and the frontend a rejection
        //   it would otherwise have to explain as something other than a
        //   network fault.
        s->pending = false;
        debug_prefix(adapter);
        mobile_debug_print(adapter, PSTR("Blocked by the server: no network this session"));
        mobile_debug_endl(adapter);
        return;
    }

    s->block_state = MOBILE_DEVICE_AUTH_BLOCK_NO;
    if (mobile_config_device_auth_catch_up(adapter, value)) {
        debug_prefix(adapter);
        mobile_debug_print(adapter, PSTR("Counter caught up to the server"));
        mobile_debug_endl(adapter);
    }
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

// Sends whatever is due now that the address is known. Both the query and a
//   queued event go out without any lookup in front of them.
static void device_auth_dispatch_due(struct mobile_adapter *adapter)
{
    struct mobile_adapter_device_auth *s = &adapter->device_auth;

    // The query first, so a counter corrected by the server is already in
    //   place when the authorize that follows it is signed.
    if (s->query_pending && !s->query_inflight) {
        s->query_pending = false;
        s->query_inflight = device_auth_dispatch_query(adapter);
        if (s->query_inflight) {
            mobile_cb_time_latch(adapter, MOBILE_TIMER_DEVICE_AUTH);
        }
    }

    if (!s->pending) return;

    // Signing an event while the answer to that query is still on its way
    //   would use the counter it is about to correct -- and in the case that
    //   makes the query worth doing at all, that means this event is
    //   rejected and the game sees the failure. So wait for it, but only
    //   briefly: an answer that never comes must not hold an authorize
    //   hostage, since a stale counter is a maybe and a missing authorize is
    //   a certainty.
    if (s->query_inflight &&
            !mobile_cb_time_check_ms(adapter, MOBILE_TIMER_DEVICE_AUTH, 3000)) {
        return;
    }

    s->pending = false;
    device_auth_sign_and_dispatch(adapter, s->addr_ipv4);
}

void mobile_device_auth_handle(struct mobile_adapter *adapter)
{
    struct mobile_adapter_device_auth *s = &adapter->device_auth;

    if (s->state == MOBILE_DEVICE_AUTH_IDLE) {
        bool work = s->pending || s->query_pending;

        // Already know where the server is: nothing to look up, send now.
        if (s->addr_resolved) {
            if (work) device_auth_dispatch_due(adapter);
            return;
        }

        // With nothing to send yet, still resolve -- as soon as there is a
        //   key and somewhere to ask. Getting the address out of the way
        //   while idle is the whole point of keeping it: by the time an
        //   authorize is due, there is no lookup left to wait for.
        if (!work) {
            if (s->addr_failed || !adapter->config.device_auth_key_init) return;
        }

        int rc = device_auth_resolve_start(adapter, 0);
        if (rc == 0) return;  // No connection slot free right now, retry later
        if (rc < 0) {
            if (work) {
                debug_prefix(adapter);
                mobile_debug_print(adapter, PSTR("No DNS server available, dropping"));
                mobile_debug_endl(adapter);
                s->pending = false;
                s->query_pending = false;
            }
            // Nothing to send, so nothing was lost -- just stop trying until
            //   a session gives a reason, and a DNS server, to try again.
            s->addr_failed = true;
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
            s->query_pending = false;
            s->addr_failed = true;
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
            mobile_debug_print(adapter, PSTR("Resolution failed"));
            mobile_debug_endl(adapter);
            s->pending = false;
            s->query_pending = false;
            s->addr_failed = true;
            return;
        }

        // Kept for the rest of this adapter's run, so this is the only
        //   lookup device-auth ever does.
        memcpy(s->addr_ipv4, ip, sizeof(s->addr_ipv4));
        s->addr_resolved = true;

        debug_prefix(adapter);
        mobile_debug_print(adapter, PSTR("Resolved to %u.%u.%u.%u"),
            ip[0], ip[1], ip[2], ip[3]);
        mobile_debug_endl(adapter);

        device_auth_dispatch_due(adapter);
    }
}
