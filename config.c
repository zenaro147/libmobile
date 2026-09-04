// SPDX-License-Identifier: LGPL-3.0-or-later
#include "config.h"

#include <string.h>

#include "mobile_data.h"
#include "util.h"
#include "compat.h"

// The area of the config in which data is actually stored by the game boy
#define MOBILE_CONFIG_SIZE_INTERNAL 0xC0
// Extra data used by the library
#define MOBILE_CONFIG_OFFSET_LIBRARY 0x100
#define MOBILE_CONFIG_SIZE_LIBRARY 0x60
static_assert(MOBILE_CONFIG_SIZE >= MOBILE_CONFIG_OFFSET_LIBRARY +
    MOBILE_CONFIG_SIZE_LIBRARY, "MOBILE_CONFIG_SIZE isn't big enough!");

// Independent extension area, holding the device-auth key/counter. Kept
//   separate from the "library" area above (rather than using up its
//   remaining unused bytes) so it can be provisioned/versioned on its own,
//   without disturbing the existing area's checksum.
#define MOBILE_CONFIG_OFFSET_DEVICE_AUTH 0x160
#define MOBILE_CONFIG_SIZE_DEVICE_AUTH 0x2D
static_assert(MOBILE_CONFIG_SIZE >= MOBILE_CONFIG_OFFSET_DEVICE_AUTH +
    MOBILE_CONFIG_SIZE_DEVICE_AUTH, "MOBILE_CONFIG_SIZE isn't big enough!");

static uint16_t checksum(unsigned char *buf, unsigned len)
{
    uint16_t sum = 0;
    while (len--) sum += *buf++;
    return sum;
}

static void config_internal_clear(struct mobile_adapter *adapter)
{
    unsigned char buffer[MOBILE_CONFIG_SIZE_INTERNAL / 2] = {0};
    mobile_cb_config_write(adapter, buffer, sizeof(buffer) * 0,
        sizeof(buffer));
    mobile_cb_config_write(adapter, buffer, sizeof(buffer) * 1,
        sizeof(buffer));
}

static bool config_internal_verify(struct mobile_adapter *adapter)
{
    unsigned char buffer[MOBILE_CONFIG_SIZE_INTERNAL / 2];
    if (!mobile_cb_config_read(adapter, buffer, sizeof(buffer) * 0,
            sizeof(buffer))) {
        return false;
    }
    if (buffer[0] != 'M' || buffer[1] != 'A') {
        return false;
    }

    uint16_t sum = checksum(buffer, sizeof(buffer));
    if (!mobile_cb_config_read(adapter, buffer, sizeof(buffer) * 1,
            sizeof(buffer))) {
        return false;
    }
    sum += checksum(buffer, sizeof(buffer) - 2);

    uint16_t config_sum = buffer[sizeof(buffer) - 2] << 8 |
        buffer[sizeof(buffer) - 1];
    return sum == config_sum;
}

static bool config_check_addrtype(enum mobile_addrtype val)
{
    switch (val) {
    case MOBILE_ADDRTYPE_NONE:
    case MOBILE_ADDRTYPE_IPV4:
    case MOBILE_ADDRTYPE_IPV6:
        return true;
    // No default case so the compiler raises a warning with unhandled values
    }
    return false;
}

static void config_library_load_host(struct mobile_addr *addr, const void *host, const unsigned char *port)
{
    if (addr->type == MOBILE_ADDRTYPE_IPV4) {
        struct mobile_addr4 *addr4 = (struct mobile_addr4 *)addr;
        static_assert(sizeof(addr4->host) == 4, "addr size mismatch");
        addr4->port = port[0];
        addr4->port |= port[1] << 8;
        memcpy(addr4->host, host, sizeof(addr4->host));
    } else if (addr->type == MOBILE_ADDRTYPE_IPV6) {
        struct mobile_addr6 *addr6 = (struct mobile_addr6 *)addr;
        static_assert(sizeof(addr6->host) == 16, "addr size mismatch");
        addr6->port = port[0];
        addr6->port |= port[1] << 8;
        memcpy(addr6->host, host, sizeof(addr6->host));
    }
}

static bool config_library_load(struct mobile_adapter *adapter)
{
    struct mobile_adapter_config *config = &adapter->config;

    unsigned char buffer[MOBILE_CONFIG_SIZE_LIBRARY];
    if (!mobile_cb_config_read(adapter, buffer, MOBILE_CONFIG_OFFSET_LIBRARY,
            sizeof(buffer))) {
        return false;
    }

    if (buffer[0] != 'L') return false;
    if (buffer[1] != 'M') return false;
    if (buffer[2] != 0) return false;
    uint16_t sum = checksum(buffer + 5, sizeof(buffer) - 5);
    uint16_t config_sum = buffer[3] | buffer[4] << 8;
    if (sum != config_sum) return false;

    config->device = buffer[0x05];
    config->dns1.type = buffer[0x06];
    config->dns2.type = buffer[0x07];
    config->p2p_port = buffer[0x08];
    config->p2p_port |= buffer[0x09] << 8;
    config->relay.type = buffer[0x0a];
    config->relay_token_init = buffer[0x0b];
    config->mail_port = buffer[0x0c];

    if (!config_check_addrtype(config->dns1.type)) return false;
    if (!config_check_addrtype(config->dns2.type)) return false;
    if (!config_check_addrtype(config->relay.type)) return false;

    config_library_load_host(&config->dns1, buffer + 0x20, buffer + 0x1a);
    config_library_load_host(&config->dns2, buffer + 0x30, buffer + 0x1c);
    config_library_load_host(&config->relay, buffer + 0x40, buffer + 0x1e);

    if (config->relay_token_init) {
        static_assert(sizeof(config->relay_token) == 0x10,
            "token size mismatch");
        memcpy(config->relay_token, buffer + 0x50,
            sizeof(config->relay_token));
    }

    return true;
}

static void config_library_save_host(const struct mobile_addr *addr, void *host, unsigned char *port)
{
    if (addr->type == MOBILE_ADDRTYPE_IPV4) {
        const struct mobile_addr4 *addr4 = (struct mobile_addr4 *)addr;
        static_assert(sizeof(addr4->host) == 4, "addr size mismatch");
        port[0] = addr4->port;
        port[1] = addr4->port >> 8;
        memcpy(host, addr4->host, sizeof(addr4->host));
    } else if (addr->type == MOBILE_ADDRTYPE_IPV6) {
        const struct mobile_addr6 *addr6 = (struct mobile_addr6 *)addr;
        static_assert(sizeof(addr6->host) == 16, "addr size mismatch");
        port[0] = addr6->port;
        port[1] = addr6->port >> 8;
        memcpy(host, addr6->host, sizeof(addr6->host));
    }
}

static void config_library_save(struct mobile_adapter *adapter)
{
    struct mobile_adapter_config *config = &adapter->config;

    unsigned char buffer[MOBILE_CONFIG_SIZE_LIBRARY] = {0};
    buffer[0] = 'L';
    buffer[1] = 'M';
    buffer[2] = 0;

    buffer[0x05] = config->device;
    buffer[0x06] = config->dns1.type;
    buffer[0x07] = config->dns2.type;
    buffer[0x08] = config->p2p_port;
    buffer[0x09] = config->p2p_port >> 8;
    buffer[0x0a] = config->relay.type;
    buffer[0x0b] = config->relay_token_init;
    buffer[0x0c] = config->mail_port;

    // 0x0d - 0x19 unused

    config_library_save_host(&config->dns1, buffer + 0x20, buffer + 0x1a);
    config_library_save_host(&config->dns2, buffer + 0x30, buffer + 0x1c);
    config_library_save_host(&config->relay, buffer + 0x40, buffer + 0x1e);

    if (config->relay_token_init) {
        static_assert(sizeof(config->relay_token) == 0x10,
            "token size mismatch");
        memcpy(buffer + 0x50, config->relay_token,
            sizeof(config->relay_token));
    }

    uint16_t sum = checksum(buffer + 5, sizeof(buffer) - 5);
    buffer[0x03] = sum & 0xff;
    buffer[0x04] = sum >> 8;

    mobile_cb_config_write(adapter, buffer, MOBILE_CONFIG_OFFSET_LIBRARY,
        sizeof(buffer));
}

// How many counter values are reserved (and persisted as a single ceiling)
//   per storage write, to bound how often device-auth requests wear
//   flash-backed config storage. Deliberately generous relative to actual
//   mail usage (per real MAGB game survey data, expect ~1-3 mail
//   logins/session for the minority of games that use mail at all) --
//   "wasting" up to this many counter values on every crash/reboot is
//   inconsequential against a 64-bit space, so this is tuned purely for
//   write frequency, not counter exhaustion risk.
#define MOBILE_DEVICE_AUTH_COUNTER_BATCH 50

// Layout of the device-auth extension area (MOBILE_CONFIG_SIZE_DEVICE_AUTH
//   bytes, starting at MOBILE_CONFIG_OFFSET_DEVICE_AUTH):
//   0x00      'D'
//   0x01      'A'
//   0x02      0 (version)
//   0x03-0x04 checksum (little-endian, over everything from 0x05 onward)
//   0x05-0x24 device_auth_key (32 bytes)
//   0x25-0x2c device_auth_counter_ceiling (uint64, little-endian) -- the
//             highest counter value ever reserved, NOT the last one
//             actually used; see mobile_config_device_auth_next().
static bool config_device_auth_load(struct mobile_adapter *adapter)
{
    struct mobile_adapter_config *config = &adapter->config;

    // Once established in memory, this is always authoritative and must
    //   never be rewound by a later reload: mobile_config_load() has no
    //   guard against being called again by the frontend after the first
    //   time (its only check is against mobile_start()/mobile_stop(), not
    //   against having already loaded), and re-reading storage that
    //   happens to not yet reflect the last device-auth write (a write
    //   whose durability is entirely up to the frontend's config_write
    //   implementation) would silently roll the replay counter backwards.
    if (config->device_auth_key_init) return true;

    unsigned char buffer[MOBILE_CONFIG_SIZE_DEVICE_AUTH];
    if (!mobile_cb_config_read(adapter, buffer, MOBILE_CONFIG_OFFSET_DEVICE_AUTH,
            sizeof(buffer))) {
        return false;
    }

    if (buffer[0] != 'D') return false;
    if (buffer[1] != 'A') return false;
    if (buffer[2] != 0) return false;
    uint16_t sum = checksum(buffer + 5, sizeof(buffer) - 5);
    uint16_t config_sum = buffer[3] | buffer[4] << 8;
    if (sum != config_sum) return false;

    static_assert(sizeof(config->device_auth_key) == 0x20,
        "device_auth_key size mismatch");
    memcpy(config->device_auth_key, buffer + 0x05,
        sizeof(config->device_auth_key));

    uint64_t ceiling = 0;
    for (unsigned i = 0; i < 8; i++) {
        ceiling |= (uint64_t)buffer[0x25 + i] << (8 * i);
    }
    // Both start equal to the persisted ceiling: the next
    //   mobile_config_device_auth_next() call must see counter >= ceiling
    //   immediately, forcing a fresh reservation (and a fresh, larger
    //   persisted ceiling) before handing out any value, so nothing at or
    //   below what was already reserved before this boot is ever reused.
    config->device_auth_counter = ceiling;
    config->device_auth_counter_ceiling = ceiling;
    config->device_auth_key_init = true;
    return true;
}

static void config_device_auth_save(struct mobile_adapter *adapter)
{
    struct mobile_adapter_config *config = &adapter->config;
    if (!config->device_auth_key_init) return;

    unsigned char buffer[MOBILE_CONFIG_SIZE_DEVICE_AUTH];
    buffer[0] = 'D';
    buffer[1] = 'A';
    buffer[2] = 0;

    memcpy(buffer + 0x05, config->device_auth_key,
        sizeof(config->device_auth_key));
    for (unsigned i = 0; i < 8; i++) {
        buffer[0x25 + i] = (unsigned char)(config->device_auth_counter_ceiling >> (8 * i));
    }

    uint16_t sum = checksum(buffer + 5, sizeof(buffer) - 5);
    buffer[0x03] = sum & 0xff;
    buffer[0x04] = sum >> 8;

    mobile_cb_config_write(adapter, buffer, MOBILE_CONFIG_OFFSET_DEVICE_AUTH,
        sizeof(buffer));
}

bool mobile_config_get_device_auth_key(struct mobile_adapter *adapter, unsigned char *key)
{
    if (!adapter->config.device_auth_key_init) return false;
    memcpy(key, adapter->config.device_auth_key,
        sizeof(adapter->config.device_auth_key));
    return true;
}

// Provisions a new device_auth_key (e.g. one just received live from
//   XPROVISION), replacing any existing one. The counter is reset to 0,
//   since it's meaningless against a key the server has never seen a
//   counter value for yet.
void mobile_config_set_device_auth_key(struct mobile_adapter *adapter, const unsigned char *key)
{
    struct mobile_adapter_config *config = &adapter->config;

    memcpy(config->device_auth_key, key, sizeof(config->device_auth_key));
    config->device_auth_counter = 0;
    config->device_auth_counter_ceiling = 0;
    config->device_auth_key_init = true;

    config_device_auth_save(adapter);
}

// Returns the next, not-yet-used counter value to sign a device-auth
//   request with. Storage is only rewritten when the current reserved
//   batch is exhausted (see MOBILE_DEVICE_AUTH_COUNTER_BATCH), not on every
//   call: the persisted ceiling is always >= any value actually handed out,
//   so a crash can only skip ahead into the next batch, never repeat one.
bool mobile_config_device_auth_next(struct mobile_adapter *adapter, uint64_t *counter)
{
    struct mobile_adapter_config *config = &adapter->config;
    if (!config->device_auth_key_init) return false;

    if (config->device_auth_counter >= config->device_auth_counter_ceiling) {
        config->device_auth_counter_ceiling =
            config->device_auth_counter + MOBILE_DEVICE_AUTH_COUNTER_BATCH;
        config_device_auth_save(adapter);
    }

    config->device_auth_counter++;
    *counter = config->device_auth_counter;
    return true;
}

void mobile_config_init(struct mobile_adapter *adapter)
{
    adapter->config.loaded = false;
    adapter->config.dirty = true;
    adapter->config.device = MOBILE_ADAPTER_BLUE;
    adapter->config.dns1 = (struct mobile_addr){.type = MOBILE_ADDRTYPE_NONE};
    adapter->config.dns2 = (struct mobile_addr){.type = MOBILE_ADDRTYPE_NONE};
    adapter->config.p2p_port = MOBILE_DEFAULT_P2P_PORT;
    adapter->config.relay = (struct mobile_addr){.type = MOBILE_ADDRTYPE_NONE};
    adapter->config.relay_token_init = false;
    adapter->config.mail_port = true;
    memset(adapter->config.relay_token, 0, MOBILE_RELAY_TOKEN_SIZE);
    adapter->config.device_auth_key_init = false;
    adapter->config.device_auth_counter = 0;
    adapter->config.device_auth_counter_ceiling = 0;
    memset(adapter->config.device_auth_key, 0, MOBILE_DEVICE_AUTH_KEY_SIZE);
}

void mobile_config_load(struct mobile_adapter *adapter)
{
    if (adapter->global.start) return;
    if (!config_internal_verify(adapter)) config_internal_clear(adapter);
    if (config_library_load(adapter)) adapter->config.dirty = false;
    config_device_auth_load(adapter);
    adapter->config.loaded = true;
}

void mobile_config_save(struct mobile_adapter *adapter)
{
    if (!adapter->config.dirty) return;
    config_library_save(adapter);
    adapter->config.dirty = false;
}

static void mobile_config_apply(struct mobile_adapter *adapter)
{
    adapter->config.dirty = true;
    adapter->config.loaded = true;
}

void mobile_config_set_device(struct mobile_adapter *adapter, enum mobile_adapter_device device, bool unmetered)
{
    // Latched at the start of a command when session hasn't been started.
    // In serial.c:mobile_serial_transfer()
    adapter->config.device = device |
        (unmetered ? MOBILE_CONFIG_DEVICE_UNMETERED : 0);

    mobile_config_apply(adapter);
}

void mobile_config_get_device(struct mobile_adapter *adapter, enum mobile_adapter_device *device, bool *unmetered)
{
    *device = adapter->config.device & ~MOBILE_CONFIG_DEVICE_UNMETERED;
    *unmetered = adapter->config.device & MOBILE_CONFIG_DEVICE_UNMETERED;
}

static struct mobile_addr *get_dns(struct mobile_adapter *adapter, enum mobile_dns num)
{
    switch (num) {
    case MOBILE_DNS1: return &adapter->config.dns1;
    case MOBILE_DNS2: return &adapter->config.dns2;
    }
    return NULL;
}

void mobile_config_set_dns(struct mobile_adapter *adapter, const struct mobile_addr *dns, enum mobile_dns num)
{
    // Latched for each dns query
    struct mobile_addr *cfg = get_dns(adapter, num);
    if (!cfg) return;
    mobile_addr_copy(cfg, dns);

    mobile_config_apply(adapter);
}

void mobile_config_get_dns(struct mobile_adapter *adapter, struct mobile_addr *dns, enum mobile_dns num)
{
    struct mobile_addr *cfg = get_dns(adapter, num);
    if (!cfg) return;
    mobile_addr_copy(dns, cfg);
}

void mobile_config_set_p2p_port(struct mobile_adapter *adapter, unsigned p2p_port)
{
    // Latched whenever a number a dialed or the wait command is executed
    if (p2p_port == 0) return;
    adapter->config.p2p_port = p2p_port;

    mobile_config_apply(adapter);
}

void mobile_config_get_p2p_port(struct mobile_adapter *adapter, unsigned *p2p_port)
{
    *p2p_port = adapter->config.p2p_port;
}

void mobile_config_set_relay(struct mobile_adapter *adapter, const struct mobile_addr *relay)
{
    // Latched whenever a number a dialed or the wait command is executed
    mobile_addr_copy(&adapter->config.relay, relay);

    mobile_config_apply(adapter);
    mobile_number_fetch_reset(adapter);
}

void mobile_config_get_relay(struct mobile_adapter *adapter, struct mobile_addr *relay)
{
    mobile_addr_copy(relay, &adapter->config.relay);
}

void mobile_config_set_relay_token_internal(struct mobile_adapter *adapter, const unsigned char *token)
{
    adapter->config.relay_token_init = !!token;
    if (token) {
        memcpy(adapter->config.relay_token, token, MOBILE_RELAY_TOKEN_SIZE);
    }

    mobile_config_apply(adapter);
}

void mobile_config_set_relay_token(struct mobile_adapter *adapter, const unsigned char *token)
{
    mobile_config_set_relay_token_internal(adapter, token);
    mobile_number_fetch_reset(adapter);
}

bool mobile_config_get_relay_token(struct mobile_adapter *adapter, unsigned char *token)
{
    if (!adapter->config.relay_token_init) return false;
    memcpy(token, adapter->config.relay_token, MOBILE_RELAY_TOKEN_SIZE);
    return true;
}

void mobile_config_set_alt_mail(struct mobile_adapter *adapter, bool alt_mail) 
{
    adapter->config.mail_port = alt_mail;
    mobile_config_apply(adapter);
}

void mobile_config_get_alt_mail(struct mobile_adapter *adapter, bool *alt_mail) 
{
    *alt_mail = adapter->config.mail_port;
}