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

#pragma once

#include <stdint.h>

#include <zephyr/shell/shell.h>

#if defined(CONFIG_MODEM_MURATA_1SC) || defined(CONFIG_WIFI_RS9116W)
#    include "network/network_devedge.h"
#endif // defined(CONFIG_MODEM_MURATA_1SC) || defined(CONFIG_WIFI_RS9116W)

#include "anjay_zephyr/config.h"
#include "network/network.h"

#ifdef CONFIG_WIFI
#    define SSID_STORAGE_SIZE 33
#    define PASSWORD_STORAGE_SIZE 65

#    define OPTION_KEY_SSID wifi_ssid
#    define OPTION_KEY_PASSWORD wifi_password
#endif // CONFIG_WIFI
#ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
#    define URI_STORAGE_SIZE 129
#    define EP_NAME_STORAGE_SIZE 65
#    define PSK_IDENTITY_STORAGE_SIZE 65
#    define PSK_KEY_STORAGE_SIZE 32
#    define BOOTSTRAP_STORAGE_SIZE 1
#    define SECURITY_MODE_STORAGE_SIZE 6

#    define OPTION_KEY_URI uri
#    define OPTION_KEY_EP_NAME endpoint
#    define OPTION_KEY_LIFETIME lifetime
#    define OPTION_KEY_PSK_IDENTITY psk_identity
#    define OPTION_KEY_PSK psk
#    define OPTION_KEY_PSK_HEX psk_hex
#    define OPTION_KEY_BOOTSTRAP bootstrap
#    define OPTION_KEY_SECURITY_MODE security_mode
#    ifdef CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
#        define OPTION_KEY_PUBLIC_CERT public_cert
#        define OPTION_KEY_PRIVATE_KEY private_key
#    endif // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
#endif     // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF
#    define GPS_NRF_PRIO_MODE_PERMITTED_STORAGE_SIZE 1
#    define OPTION_KEY_GPS_NRF_PRIO_MODE_PERMITTED gps_prio_mode_permitted
#    define OPTION_KEY_GPS_NRF_PRIO_MODE_COOLDOWN gps_prio_mode_cooldown
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF
#if defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) \
        && !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
#    define USE_PERSISTENCE_STORAGE_SIZE 1
#    define OPTION_KEY_USE_PERSISTENCE use_persistence
#endif /* defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) &&        \
        * !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING) \
        */

#if defined(CONFIG_WIFI) || defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) \
        || !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
#    define WITH_ANJAY_ZEPHYR_CONFIG
#endif /* defined(CONFIG_WIFI) || defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) || \
        * !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)              \
        */

#ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
#    define DEFAULT_BEARER_LIST            \
        OPTION_VALUE_PREFERRED_BEARER_WIFI \
        "," OPTION_VALUE_PREFERRED_BEARER_CELLULAR
#endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS

#ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
#    define OPTION_KEY_PREFERRED_BEARER preferred_bearer

#    define OPTION_VALUE_PREFERRED_BEARER_WIFI "wifi"
#    define OPTION_VALUE_PREFERRED_BEARER_CELLULAR "cellular"

#    ifndef WITH_ANJAY_ZEPHYR_CONFIG
#        define WITH_ANJAY_ZEPHYR_CONFIG
#    endif // WITH_ANJAY_ZEPHYR_CONFIG
#endif     // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS

#ifdef WITH_ANJAY_ZEPHYR_CONFIG
void _anjay_zephyr_config_init(void);
void _anjay_zephyr_config_save(void);

void _anjay_zephyr_config_default_init(void);

void _anjay_zephyr_config_print_summary(const struct shell *shell);

int _anjay_zephyr_config_set_option(const struct shell *shell,
                                    size_t argc,
                                    char **argv);

void _anjay_zephyr_set_credential(const struct shell *shell, bool key);

#endif // WITH_ANJAY_ZEPHYR_CONFIG
