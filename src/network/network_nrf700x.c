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
#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi.h>
#include <zephyr/net/wifi_mgmt.h>

#include "../config.h"
#include "../utils.h"
#include "network.h"
#include "network_internal.h"

#define WIFI_MGMT_EVENTS \
    (NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT)

LOG_MODULE_REGISTER(anjay_zephyr_network_nrf700x);

static struct net_mgmt_event_callback wifi_sta_mgmt_cb;
static struct net_mgmt_event_callback net_addr_mgmt_cb;

static volatile atomic_bool connected;
static volatile atomic_bool disconnect_requested;

static void print_dhcp_ip(const struct net_if_dhcpv4 *info) {
    /* Get DHCP info from struct net_if_dhcpv4 and print */
    const struct in_addr *addr = &info->requested_ip;
    char dhcp_info[128] = { 0 };

    if (net_addr_ntop(AF_INET, addr, dhcp_info, sizeof(dhcp_info))) {
        LOG_DBG("IP address: %s", dhcp_info);
    } else {
        LOG_ERR("net_addr_ntop failed");
    }
}

static void net_mgmt_event_handler(struct net_mgmt_event_callback *cb,
                                   uint32_t mgmt_event,
                                   struct net_if *iface) {
    switch (mgmt_event) {
    case NET_EVENT_IPV4_DHCP_BOUND:
        print_dhcp_ip((const struct net_if_dhcpv4 *) cb->info);
        atomic_store(&connected, true);
        break;
    default:
        break;
    }
}

static void cmd_wifi_status(void) {
    struct net_if *iface = net_if_get_default();
    struct wifi_iface_status status = { 0 };

    if (net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface, &status,
                 sizeof(struct wifi_iface_status))) {
        LOG_ERR("Wi-Fi status request failed");
    } else {
        LOG_DBG("State: %s", wifi_state_txt(status.state));
        if (status.state >= WIFI_STATE_ASSOCIATED) {
            LOG_DBG("Interface Mode: %s", wifi_mode_txt(status.iface_mode));
            LOG_DBG("Link Mode: %s", wifi_link_mode_txt(status.link_mode));
            LOG_DBG("SSID: %-32s", status.ssid);
            LOG_DBG("Band: %s", wifi_band_txt(status.band));
            LOG_DBG("Channel: %d", status.channel);
            LOG_DBG("Security: %s", wifi_security_txt(status.security));
            LOG_DBG("MFP: %s", wifi_mfp_txt(status.mfp));
            LOG_DBG("RSSI: %d", status.rssi);
        }
    }
}

static void handle_wifi_connect_result(struct net_mgmt_event_callback *cb) {
    const struct wifi_status *status = (const struct wifi_status *) cb->info;

    if (status->status) {
        LOG_ERR("Connection request failed (%d)", status->status);
    } else {
        LOG_DBG("Connected");
    }

    cmd_wifi_status();
}

static void handle_wifi_disconnect_result(struct net_mgmt_event_callback *cb) {
    const struct wifi_status *status = (const struct wifi_status *) cb->info;

    if (atomic_load(&disconnect_requested)) {
        LOG_DBG("Disconnection request %s (%d)",
                status->status ? "failed" : "done",
                status->status);
        atomic_store(&disconnect_requested, false);
    } else {
        LOG_DBG("Disconnected");
        atomic_store(&connected, false);
    }

    cmd_wifi_status();
}

static void wifi_mgmt_event_handler(struct net_mgmt_event_callback *cb,
                                    uint32_t mgmt_event,
                                    struct net_if *iface) {
    switch (mgmt_event) {
    case NET_EVENT_WIFI_CONNECT_RESULT:
        handle_wifi_connect_result(cb);
        break;
    case NET_EVENT_WIFI_DISCONNECT_RESULT:
        handle_wifi_disconnect_result(cb);
        break;
    default:
        break;
    }
    _anjay_zephyr_network_internal_connection_state_changed();
}

int _anjay_zephyr_network_internal_platform_initialize(void) {
    atomic_store(&connected, false);
    atomic_store(&disconnect_requested, false);

    net_mgmt_init_event_callback(&wifi_sta_mgmt_cb, wifi_mgmt_event_handler,
                                 WIFI_MGMT_EVENTS);

    net_mgmt_add_event_callback(&wifi_sta_mgmt_cb);

    net_mgmt_init_event_callback(&net_addr_mgmt_cb,
                                 net_mgmt_event_handler,
                                 NET_EVENT_IPV4_DHCP_BOUND);

    net_mgmt_add_event_callback(&net_addr_mgmt_cb);

    /* HACK: Add temporary fix to prevent using Wi-Fi before WPA supplicant is
     * ready. */
    k_sleep(K_SECONDS(1));

    return 0;
}

int _anjay_zephyr_network_connect_async(void) {
    char ssid_storage[SSID_STORAGE_SIZE];
    char password_storage[PASSWORD_STORAGE_SIZE];
    struct wifi_connect_req_params wifi_params = { 0 };

    if (anjay_zephyr_config_get_wifi_ssid(ssid_storage, sizeof(ssid_storage))
            || anjay_zephyr_config_get_wifi_password(
                       password_storage, sizeof(password_storage))) {
        LOG_ERR("Failed to get Wi-Fi configuration from settings");
        return -1;
    }

    wifi_params.ssid = ssid_storage;
    wifi_params.ssid_length = strlen(ssid_storage);
    wifi_params.psk = password_storage;
    wifi_params.psk_length = strlen(password_storage);
    if (wifi_params.psk_length) {
        wifi_params.security = WIFI_SECURITY_TYPE_PSK;
    } else {
        wifi_params.security = WIFI_SECURITY_TYPE_NONE;
    }
    wifi_params.channel = WIFI_CHANNEL_ANY;
    wifi_params.timeout = SYS_FOREVER_MS;
    wifi_params.mfp = WIFI_MFP_OPTIONAL;

    int ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, net_if_get_default(),
                       &wifi_params, sizeof(struct wifi_connect_req_params));

    if (ret > 0 || ret == -EALREADY || ret == -EINPROGRESS) {
        ret = 0;
    }
    if (ret) {
        LOG_ERR("Failed to configure Wi-Fi");
    }

    return ret;
}

enum anjay_zephyr_network_bearer_t _anjay_zephyr_network_current_bearer(void) {
    return atomic_load(&connected) ? ANJAY_ZEPHYR_NETWORK_BEARER_WIFI
                                   : ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT;
}

void _anjay_zephyr_network_disconnect(void) {
    int status;

    atomic_store(&disconnect_requested, true);
    status = net_mgmt(NET_REQUEST_WIFI_DISCONNECT, net_if_get_default(), NULL,
                      0);

    if (status) {
        atomic_store(&disconnect_requested, false);

        if (status == -EALREADY) {
            LOG_DBG("Already disconnected");
        } else {
            LOG_ERR("Disconnect request failed");
        }
    } else {
        LOG_DBG("Disconnect requested");
    }
}
