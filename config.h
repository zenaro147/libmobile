// SPDX-License-Identifier: LGPL-3.0-or-later
#pragma once

#include "mobile.h"
#include "atomic.h"

// Signals Pokémon Crystal (jp) that the connection isn't metered,
//   removing the time limit in mobile battles.
// We have no idea of the effects of this in other games.
#define MOBILE_CONFIG_DEVICE_UNMETERED 0x80

struct mobile_adapter_config {
    // Whether the config has already been loaded
    bool loaded: 1;

    // Whether the config has been updated recently
    bool dirty: 1;

    // Whether relay_token has been set
    bool relay_token_init: 1;

    // What device to emulate
    _Atomic volatile unsigned char device;  // Read by serial thread

    // DNS servers to override the gameboy's chosen servers with.
    // Only overridden if their type isn't MOBILE_ADDRTYPE_NONE.
    struct mobile_addr dns1;
    struct mobile_addr dns2;

    // What port to use for direct TCP connections
    unsigned p2p_port;

    // If p2p_relay.type isn't MOBILE_ADDRTYPE_NONE, use this relay server
    //   for p2p communication, instead of direct TCP connections
    struct mobile_addr relay;

    // Makes the adapter use port 587 instead 25 for SMTP connections.
    bool mail_port: 1;

    // Authentication token used for relay connections
    unsigned char relay_token[MOBILE_RELAY_TOKEN_SIZE];

    // Whether device_auth_key was successfully loaded from config storage
    bool device_auth_key_init: 1;

    // Per-account secret used to sign device-auth requests (see
    //   mobile_func_update_device_auth), provisioned externally by writing
    //   it into config storage (unlike relay_token, this is never negotiated
    //   over the wire by the library itself).
    unsigned char device_auth_key[MOBILE_DEVICE_AUTH_KEY_SIZE];

    // Monotonically increasing counter, used to prevent replay of
    //   device-auth requests. Never reused, even across a crash: storage
    //   only ever records a reserved ceiling (see
    //   mobile_config_device_auth_next()), not each individual value, to
    //   bound how often it's rewritten on wear-limited flash.
    uint64_t device_auth_counter;

    // Highest counter value reserved (and persisted) so far. device_auth_counter
    //   is only handed out up to this ceiling before storage needs to be
    //   rewritten again to reserve a new batch.
    uint64_t device_auth_counter_ceiling;
};

void mobile_config_init(struct mobile_adapter *adapter);
void mobile_config_set_relay_token_internal(struct mobile_adapter *adapter, const unsigned char *token);
bool mobile_config_device_auth_next(struct mobile_adapter *adapter, uint64_t *counter);

// Catches the counter up to <last_accepted>, the highest value a server says
//   it has already taken from this device, so the next one handed out is
//   last_accepted + 1. Only ever moves forward: a value at or below what is
//   already reserved is ignored, so a stale or replayed answer cannot rewind
//   the counter and cause requests to be rejected as replays.
// Returns whether the counter actually moved.
bool mobile_config_device_auth_catch_up(struct mobile_adapter *adapter, uint64_t last_accepted);

#undef _Atomic  // "atomic.h"
