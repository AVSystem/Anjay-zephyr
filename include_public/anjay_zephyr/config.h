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

/**
 * @file anjay_zephyr/config.h
 *
 * Header file with function declarations to access configuration values.
 *
 * These values can be set either by KConfig or by shell commands.
 *
 * Note: These functions return valid values after Anjay Zephyr initialization
 * or after entering "anjay config default" commend in shell, but please note
 * that this commend will also set the default values.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
#    include <anjay/dm.h>
#endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING

#ifdef CONFIG_WIFI
#    include <zephyr/net/wifi_mgmt.h>
#endif // CONFIG_WIFI

#ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
#    include "bearer_list.h"
#endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS

/**
 * Returns the default endpoint name.
 *
 * @return              String consisting of "anjay-zephyr-demo" and the device
 * ID, this string can be used as default LwM2M client endpoint name.
 */
const char *anjay_zephyr_config_default_ep_name(void);

#ifdef CONFIG_WIFI
/**
 * Get the Wi-Fi SSID stored in the settings.
 *
 * @param buf           Buffer where the Wi-Fi SSID will be stored.
 * @param buf_capacity  Size of @p buf .
 *
 * @return              0 on success, -1 in case of failure.
 */
int anjay_zephyr_config_get_wifi_ssid(char *buf, size_t buf_capacity);

/**
 * Get Wi-Fi password stored in the settings.
 *
 * @param buf           Buffer where the Wi-Fi password will be stored.
 * @param buf_capacity  Size of @p buf .
 *
 * @return              0 on success, -1 in case of failure.
 */
int anjay_zephyr_config_get_wifi_password(char *buf, size_t buf_capacity);
#endif // CONFIG_WIFI

#ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
/**
 * Get preferred network bearer stored in the settings.
 *
 * @return              Preferred network bearer.
 */
struct anjay_zephyr_network_preferred_bearer_list_t
anjay_zephyr_config_get_preferred_bearers(void);
#endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS

#ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
/**
 * Get the LwM2M client endpoint name stored in the settings.
 *
 * @param buf           Buffer where the endpoint name will be stored.
 * @param buf_capacity  Size of @p buf .
 *
 * @return              0 on success, -1 in case of failure.
 */
int anjay_zephyr_config_get_endpoint_name(char *buf, size_t buf_capacity);

/**
 * Get the LwM2M server URI stored in the settings.
 *
 * @param buf           Buffer where the LwM2M server URI will be stored.
 * @param buf_capacity  Size of @p buf .
 *
 * @return              0 on success, -1 in case of failure.
 */
int anjay_zephyr_config_get_server_uri(char *buf, size_t buf_capacity);

/**
 * Get the LwM2M device lifetime stored in the settings.
 *
 * @return              Device lifetime.
 */
uint32_t anjay_zephyr_config_get_lifetime(void);

/**
 * Get the LwM2M client PSK identity stored in the settings.
 *
 * @param buf           Buffer where the PSK identity will be stored.
 * @param buf_capacity  Size of @p buf .
 *
 * @return              0 on success, -1 in case of failure.
 */
int anjay_zephyr_config_get_psk_identity(char *buf, size_t buf_capacity);

/**
 * Get the LwM2M client PSK key and its length (without NULL terminator) stored
 * in the settings.
 *
 * @param buf           Buffer where the PSK key will be stored.
 * @param buf_capacity  Size of @p buf .
 * @param psk_len       Pointer to a variable into which the length of the PSK
 * key (without NULL terminator) will be written.
 *
 * @return              0 on success, -1 in case of failure.
 */
int anjay_zephyr_config_get_psk(char *buf,
                                size_t buf_capacity,
                                size_t *psk_len);

/**
 * Is the default LwM2M server set up as a bootstrap server?
 */
bool anjay_zephyr_config_is_bootstrap(void);

/**
 * Get Anjay security mode stored in the settings.
 *
 * @return              Anjay security mode.
 */
anjay_security_mode_t anjay_zephyr_config_get_security_mode(void);

#    ifdef CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
/**
 * Get the public certificate stored in the settings.
 *
 * @param buf           Buffer where the public certificate will be stored.
 * @param buf_capacity  Size of @p buf .
 *
 * @return              0 on success, -1 in case of failure.
 */
int anjay_zephyr_config_get_public_cert(char *buf, size_t buf_capacity);

/**
 * Get the private key stored in the settings.
 *
 * @param buf           Buffer where the private key will be stored.
 * @param buf_capacity  Size of @p buf .
 *
 * @return              0 on success, -1 in case of failure.
 */
int anjay_zephyr_config_get_private_key(char *buf, size_t buf_capacity);
#    endif // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
#endif     // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING

#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF
/**
 * Check if the GPS priority mode is permitted.
 *
 * @return              True if GPS priority mode is permitted.
 */
bool anjay_zephyr_config_is_gps_nrf_prio_mode_permitted(void);

/**
 * Get the GPS priority mode cooldown stored in the settings.
 *
 * @return              GPS priority mode cooldown.
 */
uint32_t anjay_zephyr_config_get_gps_nrf_prio_mode_cooldown(void);
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF

#ifdef CONFIG_ANJAY_ZEPHYR_PERSISTENCE
#    ifdef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
static inline bool anjay_zephyr_config_is_use_persistence(void) {
    return true;
}
#    else  // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
/**
 * Does the client use persistence?
 */
bool anjay_zephyr_config_is_use_persistence(void);
#    endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
#endif     // CONFIG_ANJAY_ZEPHYR_PERSISTENCE
