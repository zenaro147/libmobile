// Directly exercises mobile_actions_get()'s mutual-exclusion gating between
// MOBILE_ACTION_INIT_NUMBER (relay number-fetch) and MOBILE_ACTION_DEVICE_AUTH
// (device-auth resolution) -- both alias the same adapter->buffer.dns /
// adapter->buffer.relay union, so they must never both be requested at once.
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mobile_data.h"

static bool cb_config_read(void *user, void *dest, uintptr_t offset, size_t size) {
    (void)user;(void)offset; memset(dest, 0xFF, size); return true;
}
static bool cb_config_write(void *user, const void *src, uintptr_t offset, size_t size) {
    (void)user;(void)src;(void)offset;(void)size; return true;
}

static int checks;
static bool assert_true(const char *label, bool cond) {
    checks++;
    printf("%s %s\n", cond ? "PASS" : "FAIL", label);
    return cond;
}

int main(void) {
    struct mobile_adapter *adapter = mobile_new(NULL);
    mobile_def_config_read(adapter, cb_config_read);
    mobile_def_config_write(adapter, cb_config_write);
    mobile_config_load(adapter);
    mobile_start(adapter);

    struct mobile_addr4 relay = { .type = MOBILE_ADDRTYPE_IPV4, .port = 1000 };
    mobile_config_set_relay(adapter, (struct mobile_addr *)&relay);
    unsigned char token[16] = {1};
    mobile_config_set_relay_token_internal(adapter, token);

    int failures = 0;

    // Baseline: relay configured, device_auth idle+not pending -> only
    // INIT_NUMBER should be offered (device-auth has nothing to do).
    {
        enum mobile_action a = mobile_actions_get(adapter);
        failures += !assert_true("baseline: INIT_NUMBER offered",
            a & MOBILE_ACTION_INIT_NUMBER);
        failures += !assert_true("baseline: DEVICE_AUTH not offered",
            !(a & MOBILE_ACTION_DEVICE_AUTH));
    }

    // A device-auth event becomes pending (as if notify() had just been
    // called) while number_fetch is untouched (idle, never started) ->
    // device-auth must win the race and INIT_NUMBER must NOT be offered,
    // even though relay is configured and retries are available.
    adapter->device_auth.pending = true;
    {
        enum mobile_action a = mobile_actions_get(adapter);
        failures += !assert_true("pending device-auth: DEVICE_AUTH offered",
            a & MOBILE_ACTION_DEVICE_AUTH);
        failures += !assert_true("pending device-auth: INIT_NUMBER excluded",
            !(a & MOBILE_ACTION_INIT_NUMBER));
    }

    // Once device-auth resolution has actually started (state != IDLE),
    // INIT_NUMBER must stay excluded even if pending were somehow cleared
    // mid-flight, and DEVICE_AUTH must keep being offered to let it finish.
    adapter->device_auth.state = MOBILE_DEVICE_AUTH_RESOLVE_SEND;
    adapter->device_auth.pending = false;
    {
        enum mobile_action a = mobile_actions_get(adapter);
        failures += !assert_true("mid-resolution: DEVICE_AUTH still offered (to finish)",
            a & MOBILE_ACTION_DEVICE_AUTH);
        failures += !assert_true("mid-resolution: INIT_NUMBER excluded",
            !(a & MOBILE_ACTION_INIT_NUMBER));
    }
    adapter->device_auth.state = MOBILE_DEVICE_AUTH_IDLE;

    // Symmetric case: number_fetch already active (mid-flight) -> even a
    // freshly pending device-auth event must wait, not jump in and stomp
    // the shared buffer number_fetch is using.
    adapter->global.number_fetch_active = true;
    adapter->device_auth.pending = true;
    {
        enum mobile_action a = mobile_actions_get(adapter);
        failures += !assert_true("number_fetch active: INIT_NUMBER still offered (to finish)",
            a & MOBILE_ACTION_INIT_NUMBER);
        failures += !assert_true("number_fetch active: DEVICE_AUTH excluded despite pending",
            !(a & MOBILE_ACTION_DEVICE_AUTH));
    }
    adapter->global.number_fetch_active = false;
    adapter->device_auth.pending = false;

    printf("\n%d/%d checks passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
