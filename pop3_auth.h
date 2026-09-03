// SPDX-License-Identifier: LGPL-3.0-or-later
#pragma once

#include <stdbool.h>

struct mobile_adapter;

// Line-oriented POP3 authentication interception. Used only on the
//   connection tracked by commands.c as the game's POP3 session (see
//   mail_conn[]), and only until authentication resolves one way or
//   another -- every byte before and after that is untouched passthrough,
//   same as any other connection. This is unrelated to (but runs
//   alongside) the HTTP device-auth side channel in device_auth.h, which
//   also keys off that same connection.
//
// While active, this owns command_data()'s sock_send/sock_recv calls for
//   that connection, buffering by line so it can:
//   - capture the per-connection nonce from the server's greeting;
//   - if a device_auth_key is already provisioned, substitute a signed
//     XAPOP challenge-response for the game's real USER/PASS, so the
//     mailbox password never crosses the wire on ordinary sessions;
//   - if XAPOP is rejected (e.g. a revoked key), transparently retry with
//     the game's real USER/PASS, so a revoked key degrades to today's
//     behavior instead of breaking mail outright;
//   - opportunistically provision a device_auth_key (via XPROVISION) any
//     time the real credentials do end up authenticating, without the game
//     ever noticing the extra round trip.
#define MOBILE_POP3_AUTH_LINE_MAX 128

enum mobile_pop3_auth_state {
    MOBILE_POP3_AUTH_INACTIVE,
    MOBILE_POP3_AUTH_GREETING,
    MOBILE_POP3_AUTH_USER,
    MOBILE_POP3_AUTH_USER_RESP,
    MOBILE_POP3_AUTH_PASS,
    MOBILE_POP3_AUTH_RESP,
    MOBILE_POP3_AUTH_FALLBACK_USER_RESP,
    MOBILE_POP3_AUTH_FALLBACK_PASS_RESP,
    MOBILE_POP3_AUTH_PROVISION_RESP,
    MOBILE_POP3_AUTH_DONE
};

struct mobile_pop3_auth {
    enum mobile_pop3_auth_state state;
    unsigned conn;
    bool has_key;

    char nonce_hex[32];

    // Bytes accumulated line-by-line (POP3 is "\r\n"-delimited text) from
    //   whichever side is currently being read -- only one side is ever
    //   being accumulated at a time, per state.
    unsigned char buf[MOBILE_POP3_AUTH_LINE_MAX];
    unsigned buf_len;

    // The game's real USER/PASS lines, kept only in the has_key path, in
    //   case the XAPOP fast path is rejected and a real login needs to be
    //   attempted instead.
    unsigned char saved_user[MOBILE_POP3_AUTH_LINE_MAX];
    unsigned saved_user_len;
    unsigned char saved_pass[MOBILE_POP3_AUTH_LINE_MAX];
    unsigned saved_pass_len;

    // A response that's ready for the game, but held back until an
    //   in-flight side exchange (XPROVISION) with the real server
    //   finishes, so the game never sees that extra round trip.
    unsigned char pending[MOBILE_POP3_AUTH_LINE_MAX];
    unsigned pending_len;

    // Bytes already decided for the game, drained out through
    //   mobile_pop3_auth_recv() (which may be called with a buffer smaller
    //   than what's ready).
    unsigned char out[MOBILE_POP3_AUTH_LINE_MAX];
    unsigned out_len;
    unsigned out_pos;

    // A message queued to send to the real server (XAPOP, XPROVISION, a
    //   forwarded USER/PASS, ...), retried across as many
    //   mobile_pop3_auth_recv() calls as it takes: mobile_cb_sock_send() is
    //   documented as non-blocking and may accept less than requested, and
    //   this is the only place in the library that sends its own protocol
    //   messages rather than relaying bytes the game already retries on its
    //   own. state only advances to send_retry_next once this fully drains.
    unsigned char send_retry[MOBILE_POP3_AUTH_LINE_MAX];
    unsigned send_retry_len;
    unsigned send_retry_pos;
    enum mobile_pop3_auth_state send_retry_next;
};

// Starts interception for a freshly recognized POP3 connection.
void mobile_pop3_auth_start(struct mobile_adapter *adapter, unsigned conn);

// Whether interception has finished for this connection (successfully or
//   not) -- once true, callers should go back to calling
//   mobile_cb_sock_send()/mobile_cb_sock_recv() directly for its remaining
//   lifetime. Also true for any connection interception was never started
//   for.
bool mobile_pop3_auth_done(struct mobile_adapter *adapter, unsigned conn);

// Drop-in replacements for mobile_cb_sock_send()/mobile_cb_sock_recv(),
//   with the same calling convention and return value meaning, for use
//   only while mobile_pop3_auth_done() is false.
int mobile_pop3_auth_send(struct mobile_adapter *adapter, unsigned conn, const void *data, unsigned size);
int mobile_pop3_auth_recv(struct mobile_adapter *adapter, unsigned conn, void *data, unsigned size);
