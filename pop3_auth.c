// SPDX-License-Identifier: LGPL-3.0-or-later
#include "pop3_auth.h"

#include <string.h>

#include "mobile_data.h"
#include "sha256.h"
#include "compat.h"

static void debug_prefix(struct mobile_adapter *adapter)
{
    mobile_debug_print(adapter, PSTR("<POP3> "));
}

static const char hex_digits[] = "0123456789abcdef";

static void hex_encode(unsigned char *out, const unsigned char *data, unsigned size)
{
    for (unsigned i = 0; i < size; i++) {
        out[i * 2] = hex_digits[data[i] >> 4];
        out[i * 2 + 1] = hex_digits[data[i] & 0xf];
    }
}

static int hex_nibble(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hex_decode(unsigned char *out, const unsigned char *data, unsigned out_size)
{
    for (unsigned i = 0; i < out_size; i++) {
        int hi = hex_nibble(data[i * 2]);
        int lo = hex_nibble(data[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (unsigned char)(hi << 4 | lo);
    }
    return true;
}

// Appends [data, size) to buf (tracked by *len, capped at cap). Returns
//   false (appending nothing) if it wouldn't fit.
static bool append(unsigned char *buf, unsigned *len, unsigned cap, const unsigned char *data, unsigned size)
{
    if (*len + size > cap) return false;
    memcpy(buf + *len, data, size);
    *len += size;
    return true;
}

// Finds a "\r\n"-terminated line at the start of buf[0..len). Returns its
//   length, including the trailing "\r\n", or 0 if not present yet.
static unsigned find_line(const unsigned char *buf, unsigned len)
{
    for (unsigned i = 1; i < len; i++) {
        if (buf[i - 1] == '\r' && buf[i] == '\n') return i + 1;
    }
    return 0;
}

static void queue_for_game(struct mobile_pop3_auth *p, const unsigned char *data, unsigned len)
{
    memcpy(p->out, data, len);
    p->out_len = len;
    p->out_pos = 0;
}

// Queues a message to actually send to the real server. p->state is NOT
//   changed to next_state until the whole thing has been accepted by
//   mobile_cb_sock_send(), possibly over several calls -- see
//   flush_send_retry().
static void queue_send(struct mobile_pop3_auth *p, const unsigned char *data, unsigned len, enum mobile_pop3_auth_state next_state)
{
    memcpy(p->send_retry, data, len);
    p->send_retry_len = len;
    p->send_retry_pos = 0;
    p->send_retry_next = next_state;
}

// Retries mobile_cb_sock_send() for whatever's left of a queued message.
//   Returns 1 once fully sent (p->state has been advanced to
//   send_retry_next), 0 if still incomplete (caller should treat this
//   exactly like "no data yet" and try again next tick), or -1 on a hard
//   socket error (caller should propagate that to the game like any other
//   comms failure).
static int flush_send_retry(struct mobile_adapter *adapter, unsigned conn, struct mobile_pop3_auth *p)
{
    if (p->send_retry_pos >= p->send_retry_len) return 1;

    int rc = mobile_cb_sock_send(adapter, conn,
        p->send_retry + p->send_retry_pos,
        p->send_retry_len - p->send_retry_pos, NULL);
    if (rc < 0) return -1;

    p->send_retry_pos += (unsigned)rc;
    if (p->send_retry_pos < p->send_retry_len) return 0;

    p->send_retry_len = 0;
    p->send_retry_pos = 0;
    p->state = p->send_retry_next;
    return 1;
}

void mobile_pop3_auth_start(struct mobile_adapter *adapter, unsigned conn)
{
    struct mobile_pop3_auth *p = &adapter->commands.pop3;
    memset(p, 0, sizeof(*p));
    p->conn = conn;
    p->state = MOBILE_POP3_AUTH_GREETING;

    debug_prefix(adapter);
    mobile_debug_print(adapter, PSTR("Starting interception on conn %u"), conn);
    mobile_debug_endl(adapter);
}

bool mobile_pop3_auth_done(struct mobile_adapter *adapter, unsigned conn)
{
    struct mobile_pop3_auth *p = &adapter->commands.pop3;
    if (p->conn != conn) return true;
    return p->state == MOBILE_POP3_AUTH_INACTIVE ||
        p->state == MOBILE_POP3_AUTH_DONE;
}

// Derives the per-purpose subkey and signs "ppp_id|nonce" with it, writing
//   a full "XAPOP <ppp_id> <sig-hex>\r\n" line to out (which must be able
//   to hold at least 0x20 + 1 + 0x20 + 1 + 64 + 2 bytes).
static unsigned build_xapop(struct mobile_adapter *adapter, struct mobile_pop3_auth *p, unsigned char *out)
{
    struct mobile_adapter_commands *s = &adapter->commands;

    unsigned char key[MOBILE_DEVICE_AUTH_KEY_SIZE];
    mobile_config_get_device_auth_key(adapter, key);

    static const unsigned char subkey_label[] = "pop3-xapop";
    unsigned char subkey[MOBILE_SHA256_SIZE];
    mobile_hmac_sha256(key, sizeof(key), subkey_label, sizeof(subkey_label) - 1, subkey);

    unsigned char message[0x20 + 1 + sizeof(p->nonce_hex)];
    unsigned pos = 0;
    memcpy(message + pos, s->ppp_id, s->ppp_id_size);
    pos += s->ppp_id_size;
    message[pos++] = '|';
    memcpy(message + pos, p->nonce_hex, sizeof(p->nonce_hex));
    pos += sizeof(p->nonce_hex);

    unsigned char sig[MOBILE_SHA256_SIZE];
    mobile_hmac_sha256(subkey, sizeof(subkey), message, pos, sig);

    unsigned n = 0;
    memcpy(out + n, "XAPOP ", 6);
    n += 6;
    memcpy(out + n, s->ppp_id, s->ppp_id_size);
    n += s->ppp_id_size;
    out[n++] = ' ';
    hex_encode(out + n, sig, sizeof(sig));
    n += sizeof(sig) * 2;
    out[n++] = '\r';
    out[n++] = '\n';
    return n;
}

static bool line_is_ok(const unsigned char *buf)
{
    return buf[0] == '+';
}

// Called whenever find_line() has confirmed a complete line sits at the
//   start of p->buf. Consumes it (shifting any remainder to the front),
//   and drives the state machine forward -- which may mean sending
//   something to the real server, queuing something for the game, or both.
static void process_line(struct mobile_adapter *adapter, struct mobile_pop3_auth *p, unsigned line_len)
{
    unsigned char line[MOBILE_POP3_AUTH_LINE_MAX];
    memcpy(line, p->buf, line_len);

    unsigned remainder = p->buf_len - line_len;
    if (remainder) memmove(p->buf, p->buf + line_len, remainder);
    p->buf_len = remainder;

    switch (p->state) {
    case MOBILE_POP3_AUTH_GREETING: {
        static const unsigned char prefix[] = "+OK service ready ";
        unsigned prefix_len = sizeof(prefix) - 1;

        p->has_key = adapter->config.device_auth_key_init;
        if (line_len >= prefix_len + sizeof(p->nonce_hex) &&
                memcmp(line, prefix, prefix_len) == 0) {
            memcpy(p->nonce_hex, line + prefix_len, sizeof(p->nonce_hex));
        } else {
            // Not the greeting we expected -- can't do a signed exchange
            //   without a nonce, so only the classic path remains usable.
            p->has_key = false;
        }

        debug_prefix(adapter);
        mobile_debug_print(adapter, PSTR("Greeting seen, has_key=%u, nonce="), p->has_key);
        mobile_debug_write(adapter, p->nonce_hex, sizeof(p->nonce_hex));
        mobile_debug_endl(adapter);

        queue_for_game(p, line, line_len);
        p->state = MOBILE_POP3_AUTH_USER;
        break;
    }

    case MOBILE_POP3_AUTH_USER:
        if (p->has_key) {
            memcpy(p->saved_user, line, line_len);
            p->saved_user_len = line_len;
            // Must match the real server's genuine USER response
            //   byte-for-byte: some POP3 clients validate more than just
            //   the leading '+' and silently never proceed to PASS if it
            //   looks unfamiliar.
            static const unsigned char ok[] = "+OK user accepted\r\n";
            queue_for_game(p, ok, sizeof(ok) - 1);
            p->state = MOBILE_POP3_AUTH_PASS;

            debug_prefix(adapter);
            mobile_debug_print(adapter, PSTR("USER seen (%u bytes), faked local ack"), line_len);
            mobile_debug_endl(adapter);
        } else {
            queue_send(p, line, line_len, MOBILE_POP3_AUTH_USER_RESP);

            debug_prefix(adapter);
            mobile_debug_print(adapter, PSTR("USER seen (%u bytes), forwarded (no key)"), line_len);
            mobile_debug_endl(adapter);
        }
        break;

    case MOBILE_POP3_AUTH_USER_RESP:
        queue_for_game(p, line, line_len);
        p->state = MOBILE_POP3_AUTH_PASS;
        break;

    case MOBILE_POP3_AUTH_PASS:
        memcpy(p->saved_pass, line, line_len);
        p->saved_pass_len = line_len;
        if (p->has_key) {
            unsigned char xapop[MOBILE_POP3_AUTH_LINE_MAX];
            unsigned xapop_len = build_xapop(adapter, p, xapop);
            queue_send(p, xapop, xapop_len, MOBILE_POP3_AUTH_RESP);

            debug_prefix(adapter);
            mobile_debug_print(adapter, PSTR("PASS seen (%u bytes), sending: "), line_len);
            mobile_debug_write(adapter, (const char *)xapop, xapop_len - 2);
            mobile_debug_endl(adapter);
        } else {
            queue_send(p, line, line_len, MOBILE_POP3_AUTH_RESP);

            debug_prefix(adapter);
            mobile_debug_print(adapter, PSTR("PASS seen (%u bytes), forwarded (no key)"), line_len);
            mobile_debug_endl(adapter);
        }
        break;

    case MOBILE_POP3_AUTH_RESP:
        debug_prefix(adapter);
        mobile_debug_print(adapter, PSTR("Auth response: "));
        mobile_debug_write(adapter, (const char *)line, line_len >= 2 ? line_len - 2 : line_len);
        mobile_debug_endl(adapter);

        if (line_is_ok(line)) {
            if (p->has_key) {
                queue_for_game(p, line, line_len);
                p->state = MOBILE_POP3_AUTH_DONE;
            } else {
                memcpy(p->pending, line, line_len);
                p->pending_len = line_len;
                static const unsigned char provision[] = "XPROVISION\r\n";
                queue_send(p, provision, sizeof(provision) - 1, MOBILE_POP3_AUTH_PROVISION_RESP);
            }
        } else if (p->has_key) {
            // XAPOP was rejected (e.g. a revoked key) -- fall back to a
            //   real login with what the game actually sent, instead of
            //   breaking mail outright.
            debug_prefix(adapter);
            mobile_debug_print(adapter, PSTR("XAPOP rejected, falling back to real login"));
            mobile_debug_endl(adapter);
            queue_send(p, p->saved_user, p->saved_user_len, MOBILE_POP3_AUTH_FALLBACK_USER_RESP);
        } else {
            queue_for_game(p, line, line_len);
            p->state = MOBILE_POP3_AUTH_DONE;
        }
        break;

    case MOBILE_POP3_AUTH_FALLBACK_USER_RESP:
        // The game already got its (faked) "+OK" for USER earlier; this
        //   real response is never shown to it.
        queue_send(p, p->saved_pass, p->saved_pass_len, MOBILE_POP3_AUTH_FALLBACK_PASS_RESP);
        break;

    case MOBILE_POP3_AUTH_FALLBACK_PASS_RESP:
        debug_prefix(adapter);
        mobile_debug_print(adapter, PSTR("Fallback login response: "));
        mobile_debug_write(adapter, (const char *)line, line_len >= 2 ? line_len - 2 : line_len);
        mobile_debug_endl(adapter);

        if (line_is_ok(line)) {
            memcpy(p->pending, line, line_len);
            p->pending_len = line_len;
            static const unsigned char provision[] = "XPROVISION\r\n";
            queue_send(p, provision, sizeof(provision) - 1, MOBILE_POP3_AUTH_PROVISION_RESP);
        } else {
            // The real password was wrong too -- this is a genuine
            //   failure, not a stale-key problem.
            queue_for_game(p, line, line_len);
            p->state = MOBILE_POP3_AUTH_DONE;
        }
        break;

    case MOBILE_POP3_AUTH_PROVISION_RESP: {
        static const unsigned char prefix[] = "+OK ";
        unsigned prefix_len = sizeof(prefix) - 1;
        bool provisioned = false;
        if (line_is_ok(line) && line_len >= prefix_len + 64) {
            unsigned char key[MOBILE_DEVICE_AUTH_KEY_SIZE];
            if (hex_decode(key, line + prefix_len, sizeof(key))) {
                mobile_config_set_device_auth_key(adapter, key);
                provisioned = true;
            }
        }

        debug_prefix(adapter);
        mobile_debug_print(adapter, PSTR("XPROVISION response (%u bytes), provisioned=%u"), line_len, provisioned);
        mobile_debug_endl(adapter);
        // Whether or not provisioning worked, the real login already
        //   succeeded -- release that result to the game either way.
        queue_for_game(p, p->pending, p->pending_len);
        p->state = MOBILE_POP3_AUTH_DONE;
        break;
    }

    case MOBILE_POP3_AUTH_INACTIVE:
    case MOBILE_POP3_AUTH_DONE:
        break;
    }
}

int mobile_pop3_auth_send(struct mobile_adapter *adapter, unsigned conn, const void *data, unsigned size)
{
    struct mobile_pop3_auth *p = &adapter->commands.pop3;
    if (p->conn != conn) return mobile_cb_sock_send(adapter, conn, data, size, NULL);

    switch (p->state) {
    case MOBILE_POP3_AUTH_USER:
    case MOBILE_POP3_AUTH_PASS:
        if (!append(p->buf, &p->buf_len, sizeof(p->buf), data, size)) {
            // Not real POP3 traffic (an implausibly long USER/PASS line)
            //   -- give up on interception, flushing what was buffered
            //   and letting the rest of the connection through raw.
            debug_prefix(adapter);
            mobile_debug_print(adapter, PSTR("Line too long in state %u (%u+%u bytes), bailing to passthrough"),
                p->state, p->buf_len, size);
            mobile_debug_endl(adapter);

            mobile_cb_sock_send(adapter, conn, p->buf, p->buf_len, NULL);
            p->buf_len = 0;
            p->state = MOBILE_POP3_AUTH_DONE;
            return mobile_cb_sock_send(adapter, conn, data, size, NULL);
        }

        unsigned line_len = find_line(p->buf, p->buf_len);
        if (line_len) process_line(adapter, p, line_len);
        return (int)size;

    default:
        return mobile_cb_sock_send(adapter, conn, data, size, NULL);
    }
}

int mobile_pop3_auth_recv(struct mobile_adapter *adapter, unsigned conn, void *data, unsigned size)
{
    struct mobile_pop3_auth *p = &adapter->commands.pop3;
    if (p->conn != conn) return mobile_cb_sock_recv(adapter, conn, data, size, NULL);

    if (p->out_pos < p->out_len) {
        unsigned n = p->out_len - p->out_pos;
        if (n > size) n = size;
        memcpy(data, p->out + p->out_pos, n);
        p->out_pos += n;
        if (p->out_pos == p->out_len) {
            p->out_len = 0;
            p->out_pos = 0;
        }
        return (int)n;
    }

    if (p->state == MOBILE_POP3_AUTH_DONE) {
        return mobile_cb_sock_recv(adapter, conn, data, size, NULL);
    }

    // Finish sending whatever's queued (XAPOP, XPROVISION, a forwarded
    //   USER/PASS, ...) before doing anything else -- there's nothing
    //   meaningful to receive until the server has actually gotten it.
    int flush_rc = flush_send_retry(adapter, conn, p);
    if (flush_rc < 0) return -1;
    if (flush_rc == 0) return 0;

    // A line may already be fully buffered (e.g. left over from a previous
    //   recv() that returned more than one line's worth at once).
    unsigned line_len = find_line(p->buf, p->buf_len);
    if (!line_len) {
        unsigned char tmp[MOBILE_POP3_AUTH_LINE_MAX];
        unsigned space = sizeof(p->buf) - p->buf_len;
        int recv = mobile_cb_sock_recv(adapter, conn, tmp, space, NULL);
        if (recv <= 0) return recv;

        if (!append(p->buf, &p->buf_len, sizeof(p->buf), tmp, (unsigned)recv)) {
            // The server sent something unexpectedly huge -- bail to
            //   passthrough, handing whatever was buffered to the game.
            queue_for_game(p, p->buf, p->buf_len);
            p->buf_len = 0;
            p->state = MOBILE_POP3_AUTH_DONE;
            return mobile_pop3_auth_recv(adapter, conn, data, size);
        }

        line_len = find_line(p->buf, p->buf_len);
        if (!line_len) return 0;
    }

    process_line(adapter, p, line_len);

    if (p->out_len > p->out_pos) {
        return mobile_pop3_auth_recv(adapter, conn, data, size);
    }
    return 0;
}
