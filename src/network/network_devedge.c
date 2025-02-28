/*
 * Copyright 2020-2025 AVSystem <avsystem@avsystem.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdatomic.h>
#include <zephyr/logging/log.h>

#include <zephyr/net/socket.h>
#include <zephyr/net/socket_offload.h>

#include <anjay/anjay.h>

#ifdef CONFIG_MODEM_MURATA_1SC
#    include <zephyr/drivers/modem/murata-1sc.h>
int murata_socket_offload_init(void);
#endif // CONFIG_MODEM_MURATA_1SC

#ifdef CONFIG_WIFI_RS9116W
#    include <zephyr/net/wifi.h>
#    include <zephyr/net/wifi_mgmt.h>

// Suppress warnings stemming from redefinitions in rsi_wlan.h
#    undef AF_INET
#    undef AF_INET6
#    undef AF_UNSPEC
#    undef PF_INET
#    undef PF_INET6
#    undef TCP_NODELAY

#    include "rsi_wlan_apis.h"

#    include "rsi_wlan.h"

// Hack: including an internal header
#    include <zephyr/drivers/../../../drivers/wifi/rs9116w/rs9116w.h>

uint8_t rsi_wlan_get_state(void);
#endif // CONFIG_WIFI_RS9116W

#include "network_devedge.h"
#include "network_internal.h"

#include "../config.h"
#include "../utils.h"

LOG_MODULE_REGISTER(anjay_zephyr_network_devedge);

enum bearer_state_t {
    BEARER_STATE_DISABLED,
    BEARER_STATE_FAILED,
    BEARER_STATE_CONNECTING,
    BEARER_STATE_CONNECTED
};

static volatile atomic_bool connection_administratively_requested;

static K_MUTEX_DEFINE(bearers_mutex);
static struct anjay_zephyr_network_preferred_bearer_list_t preferred_bearers;

static volatile _Atomic enum bearer_state_t
        bearer_states[ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT];

#ifdef CONFIG_MODEM_MURATA_1SC
static struct net_if *murata_iface;
#endif // CONFIG_MODEM_MURATA_1SC

#ifdef CONFIG_WIFI_RS9116W
static struct net_if *rs9116w_iface;
#endif // CONFIG_WIFI_RS9116W

#ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS

static enum anjay_zephyr_network_bearer_t
get_current_bearer_with_state(enum bearer_state_t *out_state) {
    enum anjay_zephyr_network_bearer_t result =
            ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT;

    if (out_state) {
        *out_state = BEARER_STATE_DISABLED;
    }

    k_mutex_lock(&bearers_mutex, K_FOREVER);

    for (size_t i = 0;
         i < AVS_ARRAY_SIZE(preferred_bearers.bearers)
         && _anjay_zephyr_network_bearer_valid(preferred_bearers.bearers[i]);
         ++i) {
        enum bearer_state_t state =
                atomic_load(&bearer_states[preferred_bearers.bearers[i]]);

        if (state >= BEARER_STATE_CONNECTING) {
            if (out_state) {
                *out_state = state;
            }
            result = preferred_bearers.bearers[i];
            break;
        }
    }

    k_mutex_unlock(&bearers_mutex);

    return result;
}

#    ifdef CONFIG_MODEM_MURATA_1SC
static const struct socket_dns_offload *murata_dns_offload;
#    endif // CONFIG_MODEM_MURATA_1SC

#    ifdef CONFIG_WIFI_RS9116W
static const struct socket_dns_offload *rs9116w_dns_offload;
#    endif // CONFIG_WIFI_RS9116W

struct devedge_addrinfo {
    struct zsock_addrinfo base;
    struct zsock_addrinfo *orig;
    void (*orig_freeaddrinfo)(struct zsock_addrinfo *res);
};

static const struct socket_dns_offload *
get_backend_dns_offload(enum anjay_zephyr_network_bearer_t bearer) {
    switch (bearer) {
#    ifdef CONFIG_WIFI_RS9116W
    case ANJAY_ZEPHYR_NETWORK_BEARER_WIFI:
        return rs9116w_dns_offload;
#    endif // CONFIG_WIFI_RS9116W

#    ifdef CONFIG_MODEM_MURATA_1SC
    case ANJAY_ZEPHYR_NETWORK_BEARER_CELLULAR:
        return murata_dns_offload;
#    endif // CONFIG_MODEM_MURATA_1SC

    case ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT:
        break;
    }

    return NULL;
}

static int devedge_getaddrinfo(const char *node,
                               const char *service,
                               const struct zsock_addrinfo *hints,
                               struct zsock_addrinfo **res) {
    const struct socket_dns_offload *impl =
            get_backend_dns_offload(get_current_bearer_with_state(NULL));

    if (!impl) {
        return DNS_EAI_FAIL;
    }

    struct zsock_addrinfo *impl_res = NULL;

    int result = impl->getaddrinfo(node, service, hints, &impl_res);

    if (result) {
        return result;
    }

    struct devedge_addrinfo *wrapped_res =
            avs_malloc(sizeof(struct devedge_addrinfo));

    if (!wrapped_res) {
        impl->freeaddrinfo(impl_res);
        return DNS_EAI_MEMORY;
    }

    wrapped_res->orig = impl_res;
    wrapped_res->orig_freeaddrinfo = impl->freeaddrinfo;
    memcpy(&wrapped_res->base, wrapped_res->orig, sizeof(wrapped_res->base));

    *res = &wrapped_res->base;

    return 0;
}

static void devedge_freeaddrinfo(struct zsock_addrinfo *res) {
    if (!res) {
        return;
    }

    struct devedge_addrinfo *wrapped_res =
            CONTAINER_OF(res, struct devedge_addrinfo, base);

    wrapped_res->orig_freeaddrinfo(wrapped_res->orig);
    avs_free(wrapped_res);
}

const struct socket_dns_offload devedge_dns_offload = {
    .getaddrinfo = devedge_getaddrinfo,
    .freeaddrinfo = devedge_freeaddrinfo,
};

static bool devedge_is_supported(int family, int type, int proto) {
    return true;
}

static int devedge_socket(int family, int type, int proto) {
    struct net_if *iface = NULL;

    switch (get_current_bearer_with_state(NULL)) {
#    ifdef CONFIG_WIFI_RS9116W
    case ANJAY_ZEPHYR_NETWORK_BEARER_WIFI:
        iface = rs9116w_iface;
        break;
#    endif // CONFIG_WIFI_RS9116W

#    ifdef CONFIG_MODEM_MURATA_1SC
    case ANJAY_ZEPHYR_NETWORK_BEARER_CELLULAR:
        iface = murata_iface;
        break;
#    endif // CONFIG_MODEM_MURATA_1SC

    case ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT:
        break;
    }

    if (!iface) {
        errno = EINVAL;
        return -1;
    }

    assert(iface->if_dev);
    assert(iface->if_dev->offload);
    assert(iface->if_dev->socket_offload);

    return iface->if_dev->socket_offload(family, type, proto);
}

NET_SOCKET_REGISTER(devedge_switchable,
                    /* prio = */ 0,
                    PF_UNSPEC,
                    devedge_is_supported,
                    devedge_socket);

#endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS

#ifdef CONFIG_MODEM_MURATA_1SC
static struct net_if *find_murata_iface(void) {
    // There is no official API to find the net_if entry for the Murata modem.
    // Let's find it by name.
    extern struct net_if _net_if_list_start[];
    extern struct net_if _net_if_list_end[];

    for (struct net_if *iface = _net_if_list_start; iface < _net_if_list_end;
         ++iface) {
        if (iface->if_dev && iface->if_dev->dev && iface->if_dev->dev->name
                && (strcmp(iface->if_dev->dev->name, "murata,1sc") == 0
                    || strcmp(iface->if_dev->dev->name, "murata_1sc") == 0)) {
            return iface;
        }
    }

    AVS_UNREACHABLE("Could not find Murata 1SC network interface");
    return NULL;
}
#endif // CONFIG_MODEM_MURATA_1SC

int _anjay_zephyr_network_internal_platform_initialize(void) {
#ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
    // This is initialized by both murata_socket_offload_init() and
    // rs9116w_socket_offload_init() through socket_offload_dns_register().
    // Zephyr does not support setting two different DNS offload
    // implementations, and there are even assertions for that, so we resort to
    // some hacks...
    extern const struct socket_dns_offload *dns_offload;
#endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS

    int ret;

#ifdef CONFIG_MODEM_MURATA_1SC
    ret = murata_socket_offload_init();
    if (ret) {
        return ret;
    }
#    ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
    murata_dns_offload = dns_offload;
    dns_offload = NULL;
#    endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
    murata_iface = find_murata_iface();
#endif // CONFIG_MODEM_MURATA_1SC

#ifdef CONFIG_WIFI_RS9116W
    ret = rs9116w_socket_offload_init();
    if (ret) {
        return ret;
    }
#    ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
    rs9116w_dns_offload = dns_offload;
    dns_offload = NULL;
#    endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
    rs9116w_iface = rs9116w_by_iface_idx(0)->net_iface;
#endif // CONFIG_WIFI_RS9116W

#ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
    socket_offload_dns_register(&devedge_dns_offload);
#endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
    return 0;
}

#ifdef CONFIG_WIFI_RS9116W
static void rs9116w_keepalive_work_cb(struct k_work *work);

static K_WORK_DELAYABLE_DEFINE(rs9116w_keepalive_work,
                               rs9116w_keepalive_work_cb);

static struct wifi_connect_req_params rs9116w_wifi_params;
static char ssid_storage[SSID_STORAGE_SIZE];
static char password_storage[PASSWORD_STORAGE_SIZE];

static unsigned int rs9116w_connection_attempts;

static bool update_rs9116w_connected_state(void) {
    bool connected = rsi_wlan_get_state() >= RSI_WLAN_STATE_CONNECTED;

    if (++rs9116w_connection_attempts > 3 || connected) {
        enum bearer_state_t state =
                connected ? BEARER_STATE_CONNECTED : BEARER_STATE_FAILED;

        if (atomic_exchange(&bearer_states[ANJAY_ZEPHYR_NETWORK_BEARER_WIFI],
                            state)
                != state) {
            _anjay_zephyr_network_internal_connection_state_changed();
        }
    } else {
        if (atomic_compare_exchange_strong(
                    &bearer_states[ANJAY_ZEPHYR_NETWORK_BEARER_WIFI],
                    &(enum bearer_state_t) { BEARER_STATE_CONNECTED },
                    BEARER_STATE_FAILED)) {
            _anjay_zephyr_network_internal_connection_state_changed();
        }
    }

    return connected;
}

static void rs9116w_keepalive_work_cb(struct k_work *work) {
    if (!update_rs9116w_connected_state()) {
        net_mgmt(NET_REQUEST_WIFI_CONNECT, rs9116w_iface, &rs9116w_wifi_params,
                 sizeof(struct wifi_connect_req_params));
        update_rs9116w_connected_state();
    }

    _anjay_zephyr_k_work_schedule(
            &rs9116w_keepalive_work,
            K_SECONDS(CONFIG_ANJAY_ZEPHYR_NETWORK_KEEPALIVE_RATE));
}

static void rs9116w_disconnect_work_cb(struct k_work *work) {
    net_mgmt(NET_REQUEST_WIFI_DISCONNECT, rs9116w_iface, NULL, 0);
    rs9116w_connection_attempts = 0;
}

static K_WORK_DEFINE(rs9116w_disconnect_work, rs9116w_disconnect_work_cb);

static void rs9116w_disconnect(void) {
    struct k_work_sync sync;

    k_work_cancel_delayable_sync(&rs9116w_keepalive_work, &sync);
    _anjay_zephyr_k_work_submit(&rs9116w_disconnect_work);
    if (atomic_exchange(&bearer_states[ANJAY_ZEPHYR_NETWORK_BEARER_WIFI],
                        BEARER_STATE_DISABLED)
            != BEARER_STATE_DISABLED) {
        _anjay_zephyr_network_internal_connection_state_changed();
    }
}

static void rs9116w_connect_async(void) {
    struct k_work_sync sync;

    k_work_cancel_delayable_sync(&rs9116w_keepalive_work, &sync);
    k_work_cancel_sync(&rs9116w_disconnect_work, &sync);

    if (anjay_zephyr_config_get_wifi_ssid(ssid_storage, sizeof(ssid_storage))
            || anjay_zephyr_config_get_wifi_password(
                       password_storage, sizeof(password_storage))) {
        LOG_ERR("Failed to get Wi-Fi configuration from settings");
        return;
    }

    rs9116w_wifi_params.ssid = ssid_storage;
    rs9116w_wifi_params.ssid_length = strlen(ssid_storage);
    rs9116w_wifi_params.psk = password_storage;
    rs9116w_wifi_params.psk_length = strlen(password_storage);
    if (rs9116w_wifi_params.psk_length) {
        rs9116w_wifi_params.security = WIFI_SECURITY_TYPE_PSK;
    } else {
        rs9116w_wifi_params.security = WIFI_SECURITY_TYPE_NONE;
    }

    atomic_store(&bearer_states[ANJAY_ZEPHYR_NETWORK_BEARER_WIFI],
                 BEARER_STATE_CONNECTING);
    _anjay_zephyr_k_work_schedule(&rs9116w_keepalive_work, K_SECONDS(0));
}
#endif // CONFIG_WIFI_RS9116W

static void bearer_connect_async(enum anjay_zephyr_network_bearer_t bearer) {
    switch (bearer) {
#ifdef CONFIG_WIFI_RS9116W
    case ANJAY_ZEPHYR_NETWORK_BEARER_WIFI:
        rs9116w_connect_async();
        return;
#endif // CONFIG_WIFI_RS9116W

#ifdef CONFIG_MODEM_MURATA_1SC
    case ANJAY_ZEPHYR_NETWORK_BEARER_CELLULAR:
        atomic_store(&bearer_states[ANJAY_ZEPHYR_NETWORK_BEARER_CELLULAR],
                     BEARER_STATE_CONNECTED);
        return;
#endif // CONFIG_MODEM_MURATA_1SC

    case ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT:
        break;
    }

    AVS_UNREACHABLE("Invalid bearer");
}

static void bearer_disconnect(enum anjay_zephyr_network_bearer_t bearer) {
    switch (bearer) {
#ifdef CONFIG_WIFI_RS9116W
    case ANJAY_ZEPHYR_NETWORK_BEARER_WIFI:
        rs9116w_disconnect();
        break;
#endif // CONFIG_WIFI_RS9116W

#ifdef CONFIG_MODEM_MURATA_1SC
    case ANJAY_ZEPHYR_NETWORK_BEARER_CELLULAR:
        atomic_store(&bearer_states[ANJAY_ZEPHYR_NETWORK_BEARER_CELLULAR],
                     BEARER_STATE_DISABLED);
        break;
#endif // CONFIG_MODEM_MURATA_1SC

    case ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT:
        break;
    }
}

struct enabled_bearers_mask_t {
    bool bearers[ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT];
};

static void list_enabled_bearers(
        struct enabled_bearers_mask_t *out_enabled_bearers,
        const struct anjay_zephyr_network_preferred_bearer_list_t *bearers) {
    memset(out_enabled_bearers, 0, sizeof(*out_enabled_bearers));

    for (size_t i = 0;
         i < AVS_ARRAY_SIZE(bearers->bearers)
         && _anjay_zephyr_network_bearer_valid(bearers->bearers[i]);
         ++i) {
        out_enabled_bearers->bearers[bearers->bearers[i]] = true;
    }
}

static int _anjay_zephyr_network_set_preferred_bearer_list_impl(
        const struct anjay_zephyr_network_preferred_bearer_list_t *bearers,
        bool connect_if_disconnected) {
    if (!_anjay_zephyr_network_preferred_bearer_list_valid(bearers)) {
        // Invalid argument
        return -1;
    }

    struct enabled_bearers_mask_t old_enabled_bearers;
    struct enabled_bearers_mask_t new_enabled_bearers;

    list_enabled_bearers(&new_enabled_bearers, bearers);

    k_mutex_lock(&bearers_mutex, K_FOREVER);

    bool currently_connected = false;

    if (connect_if_disconnected) {
        currently_connected =
                atomic_exchange(&connection_administratively_requested, true);
    } else {
        currently_connected =
                atomic_load(&connection_administratively_requested);
    }

    struct anjay_zephyr_network_preferred_bearer_list_t old_bearers =
            preferred_bearers;

    list_enabled_bearers(&old_enabled_bearers, &old_bearers);
    preferred_bearers = *bearers;

    if (connect_if_disconnected || currently_connected) {
        for (size_t i = 0; i < AVS_ARRAY_SIZE(old_enabled_bearers.bearers);
             ++i) {
            if (currently_connected && old_enabled_bearers.bearers[i]
                    && !new_enabled_bearers.bearers[i]) {
                bearer_disconnect((enum anjay_zephyr_network_bearer_t) i);
            } else if (new_enabled_bearers.bearers[i]
                       && (!currently_connected
                           || !old_enabled_bearers.bearers[i])) {
                bearer_connect_async((enum anjay_zephyr_network_bearer_t) i);
            }
        }
    }

    k_mutex_unlock(&bearers_mutex);

    if (connect_if_disconnected || currently_connected) {
        _anjay_zephyr_network_internal_connection_state_changed();
    }

    return 0;
}

int _anjay_zephyr_network_connect_async(void) {
    struct anjay_zephyr_network_preferred_bearer_list_t bearers = { 0 };

#ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
    bearers = anjay_zephyr_config_get_preferred_bearers();

    if (!_anjay_zephyr_network_preferred_bearer_list_valid(&bearers)) {
        return -1;
    }
#endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS

    return _anjay_zephyr_network_set_preferred_bearer_list_impl(&bearers, true);
}

enum anjay_zephyr_network_bearer_t _anjay_zephyr_network_current_bearer(void) {
    if (!atomic_load(&connection_administratively_requested)) {
        return ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT;
    }

    enum bearer_state_t state;

    enum anjay_zephyr_network_bearer_t result =
            get_current_bearer_with_state(&state);

    return state >= BEARER_STATE_CONNECTED ? result
                                           : ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT;
}

void _anjay_zephyr_network_disconnect(void) {
    k_mutex_lock(&bearers_mutex, K_FOREVER);

    struct anjay_zephyr_network_preferred_bearer_list_t bearers =
            preferred_bearers;

    for (size_t i = 0;
         i < AVS_ARRAY_SIZE(bearers.bearers)
         && _anjay_zephyr_network_bearer_valid(bearers.bearers[i]);
         ++i) {
        bearer_disconnect(bearers.bearers[i]);
    }
    atomic_store(&connection_administratively_requested, false);

    k_mutex_unlock(&bearers_mutex);
}

#ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
int _anjay_zephyr_network_set_preferred_bearer_list(
        const struct anjay_zephyr_network_preferred_bearer_list_t *bearers) {
    return _anjay_zephyr_network_set_preferred_bearer_list_impl(bearers, false);
}
#endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
