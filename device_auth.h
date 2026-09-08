// SPDX-License-Identifier: LGPL-3.0-or-later
#pragma once

#include <stdbool.h>

#include "mobile.h"

struct mobile_adapter;

// The device-auth server's hostname is resolved here, internally, through
//   the same DNS1/DNS2 mechanism (and port) the current session is already
//   using -- exactly like the game's own DNS lookups -- rather than being
//   hardcoded independently by every frontend. This means notify() can't
//   fire the callback synchronously: resolution takes real ticks, so it's
//   queued and driven from mobile_device_auth_handle(), called once per
//   idle tick (see mobile.c).
//
// Authorize is meant to land *during* the PPP session, right after the game
//   connects to a mail port and before it starts the actual SMTP/POP3
//   exchange -- that's the entire point of a "please authorize this device
//   before it's about to send/fetch mail" side channel. So, unlike the
//   relay number-fetch background task, resolution is NOT restricted to
//   idle time between sessions: it runs as soon as a connection slot is
//   actually free, via mobile_commands_connection_new() (see commands.h)
//   -- the same accounting the game's own connections use, so this can
//   never collide with (or steal) a connection the game already has open.
//   With only MOBILE_MAX_CONNECTIONS slots, that means device-auth may
//   have to wait a tick or two for one to free up; it stays pending, not
//   dropped, until it gets a turn.
// It IS still mutually exclusive with the number-fetch background task
//   (see mobile.c): both alias the same shared dns/relay socket buffer for
//   their own protocol state, which number-fetch is allowed to hold onto
//   for its whole (idle-only) run.
enum mobile_device_auth_state {
    MOBILE_DEVICE_AUTH_IDLE,
    MOBILE_DEVICE_AUTH_RESOLVE_SEND,
    MOBILE_DEVICE_AUTH_RESOLVE_RECV,
};

struct mobile_adapter_device_auth {
    enum mobile_device_auth_state state;

    // At most one event is ever in flight. If a new one arrives while
    //   another is still resolving, the older one is dropped (never
    //   silently corrupted/mixed up) -- the 30-minute server-side TTL is
    //   the backstop for anything lost this way, same as any other
    //   dropped authorize/deauthorize call.
    bool pending;
    enum mobile_device_auth_action pending_action;
    unsigned char pending_ppp_id[0x20];
    unsigned char pending_ppp_id_size;

    // Which candidate DNS address is currently being tried (0: config.dns1,
    //   1: commands.dns1, 2: config.dns2, 3: commands.dns2), and a stable
    //   copy of it for the duration of that attempt -- the exact same
    //   priority order and fallback-on-failure the game's own DNS_REQUEST
    //   command uses (see dns_get_addr() in commands.c), so a configured
    //   override (with its own port) is always preferred over the game's,
    //   and either can be a working path to the same result.
    unsigned char addr_id;
    struct mobile_addr addr;

    // The connection slot borrowed from mobile_commands_connection_new()
    //   for the current attempt (valid only while state != IDLE), held for
    //   the whole attempt including any DNS1->DNS2 fallback, and released
    //   (adapter->commands.connections[conn] = false) the moment it's no
    //   longer needed -- success, failure, or timeout.
    unsigned char conn;
};

void mobile_device_auth_init(struct mobile_adapter *adapter);

// Queues a device-auth event for signing and dispatch through
//   mobile_func_update_device_auth, once the server's address has been
//   resolved -- a no-op if no device_auth_key has been provisioned, so
//   calling this unconditionally is always safe.
void mobile_device_auth_notify(struct mobile_adapter *adapter, enum mobile_device_auth_action action, const unsigned char *ppp_id, unsigned ppp_id_size);

// Advances any in-flight resolution/dispatch. Must only be called while
//   idle (see mobile.c's MOBILE_ACTION_DEVICE_AUTH gating) -- resolution
//   shares the same socket buffer as the relay number-fetch background
//   task and the game's own DNS/relay commands.
void mobile_device_auth_handle(struct mobile_adapter *adapter);

// Aborts an in-flight resolution, freeing the connection slot it borrowed,
//   and leaves the event pending so it's retried later. A no-op if nothing
//   is in flight.
// Called when the game itself needs a connection slot and none is free
//   (see mobile_commands_connection_new()): the emulated protocol always
//   wins, since a game must never see a connection error caused by a side
//   channel it can't even observe. Same idea as
//   mobile_number_fetch_cancel().
void mobile_device_auth_cancel(struct mobile_adapter *adapter);
