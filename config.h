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
    //   device-auth requests. Persisted immediately whenever incremented, so
    //   that no value is ever reused, even across a crash.
    uint64_t device_auth_counter;
};

void mobile_config_init(struct mobile_adapter *adapter);
void mobile_config_set_relay_token_internal(struct mobile_adapter *adapter, const unsigned char *token);
bool mobile_config_device_auth_next(struct mobile_adapter *adapter, uint64_t *counter);

#undef _Atomic  // "atomic.h"
