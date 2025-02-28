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

#include <zephyr/logging/log.h>

#include <zephyr/net/wifi.h>
#include <zephyr/net/wifi_mgmt.h>

#include "network.h"
#include "network_internal.h"

#include "../config.h"
#include "../utils.h"

LOG_MODULE_REGISTER(anjay_zephyr_network_wifi);

int _anjay_zephyr_network_internal_platform_initialize(void) {
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

void _anjay_zephyr_network_disconnect(void) {
    net_mgmt(NET_REQUEST_WIFI_DISCONNECT, net_if_get_default(), NULL, 0);
}
