/*
 * Copyright 2020-2023 AVSystem <avsystem@avsystem.com>
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

#include <esp_event.h>
#include <esp_timer.h>
#include <esp_wifi.h>

#include <avsystem/commons/avs_utils.h>

#include "network.h"
#include "network_internal.h"

#include "../config.h"
#include "../utils.h"

LOG_MODULE_REGISTER(anjay_zephyr_network_esp32);

static void esp32_connect_work_cb(struct k_work *work) {
    net_dhcpv4_start(net_if_get_default());
}

static void esp32_disconnect_work_cb(struct k_work *work) {
    net_dhcpv4_stop(net_if_get_default());
}

static K_WORK_DEFINE(esp32_connect_work, esp32_connect_work_cb);
static K_WORK_DEFINE(esp32_disconnect_work, esp32_disconnect_work_cb);

struct net_mgmt_event_callback esp32_netif_updown_cb_obj = { 0 };

static void esp32_netif_updown_cb(struct net_mgmt_event_callback *cb,
                                  uint32_t mgmt_event,
                                  struct net_if *iface) {
    if (mgmt_event == NET_EVENT_IF_UP) {
        k_work_cancel(&esp32_disconnect_work);
        _anjay_zephyr_k_work_submit(&esp32_connect_work);
    } else if (mgmt_event == NET_EVENT_IF_DOWN) {
        k_work_cancel(&esp32_connect_work);
        _anjay_zephyr_k_work_submit(&esp32_disconnect_work);
    }
}

int _anjay_zephyr_network_internal_platform_initialize(void) {
    net_mgmt_init_event_callback(&esp32_netif_updown_cb_obj,
                                 esp32_netif_updown_cb,
                                 NET_EVENT_IF_UP | NET_EVENT_IF_DOWN);
    net_mgmt_add_event_callback(&esp32_netif_updown_cb_obj);

    AVS_STATIC_ASSERT(!IS_ENABLED(CONFIG_ESP32_WIFI_STA_AUTO),
                      esp32_wifi_auto_mode_incompatible_with_project);

    return 0;
}

int _anjay_zephyr_network_connect_async(void) {
    char ssid_storage[SSID_STORAGE_SIZE];
    char password_storage[PASSWORD_STORAGE_SIZE];
    wifi_config_t wifi_config = { 0 };

    if (anjay_zephyr_config_get_wifi_ssid(ssid_storage, sizeof(ssid_storage))
            || anjay_zephyr_config_get_wifi_password(
                       password_storage, sizeof(password_storage))) {
        LOG_ERR("Failed to get Wi-Fi configuration from settings");
        return -1;
    }

    // use strncpy with the maximum length of
    // sizeof(wifi_config.sta.{ssid|password}), because ESP32 Wi-Fi buffers
    // don't have to be null-terminated
    strncpy(wifi_config.sta.ssid, ssid_storage, sizeof(wifi_config.sta.ssid));
    strncpy(wifi_config.sta.password, password_storage,
            sizeof(wifi_config.sta.password));

    if (esp_wifi_set_mode(ESP32_WIFI_MODE_STA)
            || esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config)
            || esp_wifi_connect()) {
        LOG_ERR("connection failed");
        return -1;
    }
    return 0;
}

void _anjay_zephyr_network_disconnect(void) {
    esp_wifi_disconnect();
    esp_wifi_set_mode(ESP32_WIFI_MODE_NULL);
}
