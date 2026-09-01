// SPDX-License-Identifier: LGPL-3.0-or-later
#include "device_auth.h"

#include <string.h>

#include "mobile_data.h"
#include "sha256.h"
#include "compat.h"

// Longest possible "ppp_id|action|counter" message:
//   0x20 (ppp_id) + 1 ('|') + 11 ("deauthorize") + 1 ('|') + 20 (2^64-1)
#define MESSAGE_MAX_SIZE (0x20 + 1 + 11 + 1 + 20)

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

void mobile_device_auth_notify(struct mobile_adapter *adapter, enum mobile_device_auth_action action, const unsigned char *ppp_id, unsigned ppp_id_size)
{
    if (ppp_id_size == 0 || ppp_id_size > 0x20) return;

    uint64_t counter;
    if (!mobile_config_device_auth_next(adapter, &counter)) return;

    unsigned char key[MOBILE_DEVICE_AUTH_KEY_SIZE];
    if (!mobile_config_get_device_auth_key(adapter, key)) return;

    const char *action_name = action == MOBILE_DEVICE_AUTH_AUTHORIZE ?
        "authorize" : "deauthorize";
    unsigned action_len = (unsigned)strlen(action_name);

    unsigned char message[MESSAGE_MAX_SIZE];
    unsigned pos = 0;

    memcpy(message + pos, ppp_id, ppp_id_size);
    pos += ppp_id_size;
    message[pos++] = '|';
    memcpy(message + pos, action_name, action_len);
    pos += action_len;
    message[pos++] = '|';
    pos += counter_to_decimal(counter, message + pos);

    unsigned char sig[MOBILE_SHA256_SIZE];
    mobile_hmac_sha256(key, sizeof(key), message, pos, sig);

    static_assert(MOBILE_SHA256_SIZE == MOBILE_DEVICE_AUTH_SIG_SIZE,
        "device-auth signature size mismatch");
    mobile_cb_update_device_auth(adapter, action, ppp_id, ppp_id_size, counter, sig);
}
