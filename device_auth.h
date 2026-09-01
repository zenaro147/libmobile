// SPDX-License-Identifier: LGPL-3.0-or-later
#pragma once

#include "mobile.h"

struct mobile_adapter;

// Signs and dispatches a device-auth event through
//   mobile_func_update_device_auth, if (and only if) a device_auth_key has
//   been provisioned through config storage. A no-op otherwise, so calling
//   this unconditionally is always safe.
void mobile_device_auth_notify(struct mobile_adapter *adapter, enum mobile_device_auth_action action, const unsigned char *ppp_id, unsigned ppp_id_size);
