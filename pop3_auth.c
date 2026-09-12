// SPDX-License-Identifier: LGPL-3.0-or-later
#include "pop3_auth.h"

#include <string.h>

#include "mobile_data.h"
#include "md5.h"
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

// Finds the last "<...>" token in a line -- the RFC 1939 challenge is
//   whatever sits between (and including) the last '<' and the following
//   '>'. Taking the *last* one is deliberate: it's cheap insurance against
//   a greeting banner that happens to mention '<' earlier in free text.
//   Returns the token's length (copied into out), or 0 if none is found or
//   it wouldn't fit in out_cap -- callers treat both the same as "no
//   challenge available".
static unsigned find_challenge(const unsigned char *line, unsigned line_len, unsigned char *out, unsigned out_cap)
{
    int start = -1;
    for (unsigned i = 0; i < line_len; i++) {
        if (line[i] == '<') start = (int)i;
    }
    if (start < 0) return 0;

    unsigned end = 0;
    for (unsigned i = (unsigned)start + 1; i < line_len; i++) {
        if (line[i] == '>') {
            end = i;
            break;
        }
    }
    if (!end) return 0;

    unsigned len = end - (unsigned)start + 1;
    if (len > out_cap) return 0;
    memcpy(out, line + start, len);
    return len;
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

// Derives the APOP digest per RFC 1939: MD5(challenge || secret). challenge
//   is the token captured from the greeting, verbatim (angle brackets
//   included). secret is the device_auth_key as 64 lowercase hex ASCII
//   characters, not the raw 32 bytes -- that's the text form Dovecot's
//   passdb actually holds, so it's what has to be on both sides of the
//   comparison. Writes a full "APOP <ppp_id> <digest-hex>\r\n" line to out
//   (which must be able to hold at least 5 + 0x20 + 1 + 32 + 2 bytes) and
//   returns its length.
static unsigned build_apop(struct mobile_adapter *adapter, struct mobile_pop3_auth *p, unsigned char *out)
{
    struct mobile_adapter_commands *s = &adapter->commands;

    unsigned char key[MOBILE_DEVICE_AUTH_KEY_SIZE];
    mobile_config_get_device_auth_key(adapter, key);
    unsigned char key_hex[MOBILE_DEVICE_AUTH_KEY_SIZE * 2];
    hex_encode(key_hex, key, sizeof(key));

    struct mobile_md5 ctx;
    mobile_md5_init(&ctx);
    mobile_md5_update(&ctx, p->challenge, p->challenge_len);
    mobile_md5_update(&ctx, key_hex, sizeof(key_hex));
    unsigned char digest[MOBILE_MD5_SIZE];
    mobile_md5_final(&ctx, digest);

    unsigned n = 0;
    memcpy(out + n, "APOP ", 5);
    n += 5;
    memcpy(out + n, s->ppp_id, s->ppp_id_size);
    n += s->ppp_id_size;
    out[n++] = ' ';
    hex_encode(out + n, digest, sizeof(digest));
    n += sizeof(digest) * 2;
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
        p->has_key = adapter->config.device_auth_key_init && line_is_ok(line);
        if (p->has_key) {
            p->challenge_len = find_challenge(line, line_len, p->challenge, sizeof(p->challenge));
            if (!p->challenge_len) {
                // No RFC 1939 challenge in the greeting -- can't build a
                //   signed exchange, so only the classic path remains.
                p->has_key = false;
            }
        }

        debug_prefix(adapter);
        mobile_debug_print(adapter, PSTR("Greeting seen, has_key=%u"), p->has_key);
        if (p->has_key) {
            mobile_debug_print(adapter, PSTR(", challenge="));
            mobile_debug_write(adapter, (const char *)p->challenge, p->challenge_len);
        }
        mobile_debug_endl(adapter);

        queue_for_game(p, line, line_len);
        p->state = MOBILE_POP3_AUTH_USER;
        break;
    }

    case MOBILE_POP3_AUTH_USER:
        if (p->has_key) {
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
        if (p->has_key) {
            unsigned char apop[MOBILE_POP3_AUTH_LINE_MAX];
            unsigned apop_len = build_apop(adapter, p, apop);
            queue_send(p, apop, apop_len, MOBILE_POP3_AUTH_RESP);

            debug_prefix(adapter);
            mobile_debug_print(adapter, PSTR("PASS seen (%u bytes), sending: "), line_len);
            mobile_debug_write(adapter, (const char *)apop, apop_len - 2);
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

        if (p->has_key && !line_is_ok(line)) {
            // Deliberate: APOP is the only path once a key is provisioned,
            //   and there is no fallback to the real mailbox password --
            //   leaving an 8-character password enabled next to a 256-bit
            //   secret would just be the door an attacker picks instead.
            //   Make the failure loud rather than silently degrading.
            debug_prefix(adapter);
            mobile_debug_print(adapter, PSTR("APOP REJECTED, no fallback: mail login failed"));
            mobile_debug_endl(adapter);
        }

        queue_for_game(p, line, line_len);
        p->state = MOBILE_POP3_AUTH_DONE;
        break;

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

    // Finish sending whatever's queued (APOP, a forwarded USER/PASS, ...)
    //   before doing anything else -- there's nothing meaningful to
    //   receive until the server has actually gotten it.
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
