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

#include "network.h"
#include "network_internal.h"

#include "../lwm2m_internal.h"
#include "../utils.h"

#ifndef ANJAY_ZEPHYR_NO_NETWORK_MGMT

AVS_STATIC_ASSERT(ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT > 0,
                  no_network_bearers_available);

K_MUTEX_DEFINE(anjay_zephyr_network_internal_connect_mutex);
K_CONDVAR_DEFINE(anjay_zephyr_network_internal_connect_condvar);

#    ifdef CONFIG_NET_NATIVE_IPV4
static struct net_mgmt_event_callback ipv4_mgmt_cb;
#    endif // CONFIG_NET_NATIVE_IPV4
#    ifdef CONFIG_NET_NATIVE_IPV6
static struct net_mgmt_event_callback ipv6_mgmt_cb;
#    endif // CONFIG_NET_NATIVE_IPV6

#    if defined(CONFIG_NET_NATIVE_IPV4) || defined(CONFIG_NET_NATIVE_IPV6)
static void net_mgmt_event_cb(struct net_mgmt_event_callback *cb,
                              uint32_t mgmt_event,
                              struct net_if *iface) {
    _anjay_zephyr_network_internal_connection_state_changed();
}

bool _anjay_zephyr_network_internal_has_ip_address(struct net_if *iface) {
#        ifdef CONFIG_NET_NATIVE_IPV4
    if (net_if_ipv4_get_global_addr(iface, NET_ADDR_ANY_STATE)
            || net_if_ipv4_get_ll(iface, NET_ADDR_ANY_STATE)) {
        return true;
    }
#        endif // CONFIG_NET_NATIVE_IPV4

#        ifdef CONFIG_NET_NATIVE_IPV6
    // Link-local IPv6 addresses are useless, as every interface always has one.
    // Also, NET_ADDR_ANY_STATE does not work with
    // net_if_ipv6_get_global_addr().
    if (net_if_ipv6_get_global_addr(NET_ADDR_PREFERRED, &iface)) {
        return true;
    }
#        endif // CONFIG_NET_NATIVE_IPV6

    return false;
}

__weak enum anjay_zephyr_network_bearer_t
_anjay_zephyr_network_current_bearer(void) {
    bool connected =
            _anjay_zephyr_network_internal_has_ip_address(net_if_get_default());

    return connected ? (enum anjay_zephyr_network_bearer_t) 0
                     : ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT;
}
#    endif // defined(CONFIG_NET_NATIVE_IPV4) || defined(CONFIG_NET_NATIVE_IPV6)

void _anjay_zephyr_network_interrupt_connect_wait_loop(void) {
    SYNCHRONIZED(anjay_zephyr_network_internal_connect_mutex) {
        k_condvar_broadcast(&anjay_zephyr_network_internal_connect_condvar);
    }
}

void _anjay_zephyr_network_internal_connection_state_changed(void) {
    _anjay_zephyr_sched_update_anjay_network_bearer();
    _anjay_zephyr_network_interrupt_connect_wait_loop();
}

int _anjay_zephyr_network_initialize(void) {
    int ret = _anjay_zephyr_network_internal_platform_initialize();

    if (ret) {
        return ret;
    }

#    ifdef CONFIG_NET_NATIVE_IPV4
    net_mgmt_init_event_callback(&ipv4_mgmt_cb, net_mgmt_event_cb,
                                 NET_EVENT_IPV4_ADDR_ADD
                                         | NET_EVENT_IPV4_ADDR_DEL);
    net_mgmt_add_event_callback(&ipv4_mgmt_cb);
#    endif // CONFIG_NET_NATIVE_IPV4
#    ifdef CONFIG_NET_NATIVE_IPV6
    net_mgmt_init_event_callback(&ipv6_mgmt_cb, net_mgmt_event_cb,
                                 NET_EVENT_IPV6_ADDR_ADD
                                         | NET_EVENT_IPV6_ADDR_DEL);
    net_mgmt_add_event_callback(&ipv6_mgmt_cb);
#    endif // CONFIG_NET_NATIVE_IPV6
    return 0;
}

int _anjay_zephyr_network_wait_for_connected_interruptible(void) {
    int ret = -EAGAIN;

    SYNCHRONIZED(anjay_zephyr_network_internal_connect_mutex) {
        do {
            if (_anjay_zephyr_network_is_connected()) {
                ret = 0;
            } else if (!atomic_load(&anjay_zephyr_anjay_running)) {
                ret = -ETIMEDOUT;
            } else {
                k_condvar_wait(&anjay_zephyr_network_internal_connect_condvar,
                               &anjay_zephyr_network_internal_connect_mutex,
                               K_FOREVER);
            }
        } while (ret == -EAGAIN);
    }

    return ret;
}

#else // ANJAY_ZEPHYR_NO_NETWORK_MGMT

void _anjay_zephyr_network_interrupt_connect_wait_loop(void) {}

int _anjay_zephyr_network_initialize(void) {
    return 0;
}

int _anjay_zephyr_network_connect_async(void) {
    return 0;
}

enum anjay_zephyr_network_bearer_t _anjay_zephyr_network_current_bearer(void) {
    return 0;
}

int _anjay_zephyr_network_wait_for_connected_interruptible(void) {
    return 0;
}

void _anjay_zephyr_network_disconnect(void) {}

#endif // ANJAY_ZEPHYR_NO_NETWORK_MGMT
