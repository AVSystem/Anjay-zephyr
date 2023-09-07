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

#include <ctype.h>
#include <stdio.h>

#include <avsystem/commons/avs_time.h>
#include <avsystem/commons/avs_utils.h>

#include <zephyr/device.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_uart.h>

#include <zephyr/console/console.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/settings/settings.h>

#include "config.h"
#include "lwm2m_internal.h"
#include "utils.h"

#define SETTINGS_ROOT_NAME "anjay"
#define SETTINGS_NAME(Name) SETTINGS_ROOT_NAME "/" AVS_QUOTE_MACRO(Name)

#define EP_NAME_PREFIX "anjay-zephyr-demo"

#define EOT_ASCII 4

#define NOSEC_MODE "nosec"
#define PSK_MODE "psk"
#define CERT_MODE "cert"

LOG_MODULE_REGISTER(anjay_zephyr_config);

static K_MUTEX_DEFINE(config_mutex);

const char *anjay_zephyr_config_default_ep_name(void) {
    struct anjay_zephyr_device_id id;
    static char ep_name[sizeof(id.value) + sizeof(EP_NAME_PREFIX) - sizeof('\0')
                        + sizeof('-')];

    if (!_anjay_zephyr_get_device_id(&id)) {
        (void) avs_simple_snprintf(ep_name, sizeof(ep_name),
                                   EP_NAME_PREFIX "-%s", id.value);
    } else {
        memcpy(ep_name, EP_NAME_PREFIX, sizeof(EP_NAME_PREFIX));
    }

    return ep_name;
}

#ifdef WITH_ANJAY_ZEPHYR_CONFIG
struct anjay_zephyr_option;

typedef int config_option_validate_t(const struct shell *shell,
                                     const char *value,
                                     size_t value_len,
                                     const struct anjay_zephyr_option *option);

struct string_option {
    char *value;
    size_t length;
    bool null_terminated;
};

struct anjay_zephyr_app_config {
#    ifdef CONFIG_WIFI
    struct string_option ssid;
    char ssid_storage[SSID_STORAGE_SIZE];
    struct string_option password;
    char password_storage[PASSWORD_STORAGE_SIZE];
#    endif // CONFIG_WIFI
#    ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
    struct string_option preferred_bearer;
    char preferred_bearer_storage[sizeof(DEFAULT_BEARER_LIST)];
#    endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
#    ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
    struct string_option uri;
    char uri_storage[URI_STORAGE_SIZE];
    struct string_option lifetime;
    char lifetime_storage[AVS_UINT_STR_BUF_SIZE(uint32_t)];
    struct string_option ep_name;
    char ep_name_storage[EP_NAME_STORAGE_SIZE];
    struct string_option psk_identity;
    char psk_identity_storage[PSK_IDENTITY_STORAGE_SIZE];
    struct string_option psk;
    char psk_storage[PSK_KEY_STORAGE_SIZE];
    struct string_option bootstrap;
    char bootstrap_storage[BOOTSTRAP_STORAGE_SIZE];
    struct string_option security_mode;
    char security_mode_storage[SECURITY_MODE_STORAGE_SIZE];
#        ifdef CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
    struct string_option public_cert;
    char public_cert_storage[CONFIG_ANJAY_ZEPHYR_MAX_PUBLIC_CERT_LEN];
    struct string_option private_key;
    char private_key_storage[CONFIG_ANJAY_ZEPHYR_MAX_PRIVATE_KEY_LEN];
#        endif // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
#    endif     // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
#    ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF
    struct string_option gps_nrf_prio_mode_permitted;
    char gps_nrf_prio_mode_permitted_storage
            [GPS_NRF_PRIO_MODE_PERMITTED_STORAGE_SIZE];
    struct string_option gps_nrf_prio_mode_cooldown;
    char gps_nrf_prio_mode_cooldown_storage[AVS_UINT_STR_BUF_SIZE(uint32_t)];
#    endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF
#    if defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) \
            && !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
    struct string_option use_persistence;
    char use_persistence_storage[USE_PERSISTENCE_STORAGE_SIZE];
#    endif /* defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) &&        \
            * !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING) \
            */
};

static struct anjay_zephyr_app_config app_config;

struct anjay_zephyr_option {
    const char *const key;
    const char *const desc;
    struct string_option *option;
    size_t value_capacity;
    config_option_validate_t *validator;
};

#    if defined(CONFIG_WIFI) \
            || !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
static config_option_validate_t string_validate;
#    endif // defined(CONFIG_WIFI) ||
           // !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
#    if defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) \
            || !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
static config_option_validate_t flag_validate;
#    endif // defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) ||
           // !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
#    ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
static config_option_validate_t preferred_bearer_validate;
#    endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
#    ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
static config_option_validate_t psk_hex_validate;
static config_option_validate_t security_mode_validate;
#    endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
#    if defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) \
            || !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
static config_option_validate_t uint32_validate;
#    endif // defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) ||
           // !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)

static struct anjay_zephyr_option string_options[] = {
#    ifdef CONFIG_WIFI
    { AVS_QUOTE_MACRO(OPTION_KEY_SSID), "Wi-Fi SSID", &app_config.ssid,
      sizeof(app_config.ssid_storage), string_validate },
    { AVS_QUOTE_MACRO(OPTION_KEY_PASSWORD), "Wi-Fi password",
      &app_config.password, sizeof(app_config.password_storage),
      string_validate },
#    endif // CONFIG_WIFI
#    ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
    { AVS_QUOTE_MACRO(OPTION_KEY_PREFERRED_BEARER), "Preferred network bearers",
      &app_config.preferred_bearer, sizeof(app_config.preferred_bearer_storage),
      preferred_bearer_validate },
#    endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
#    ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
    { AVS_QUOTE_MACRO(OPTION_KEY_URI), "LwM2M Server URI", &app_config.uri,
      sizeof(app_config.uri_storage), string_validate },
    { AVS_QUOTE_MACRO(OPTION_KEY_LIFETIME), "Device lifetime",
      &app_config.lifetime, sizeof(app_config.lifetime_storage),
      uint32_validate },
    { AVS_QUOTE_MACRO(OPTION_KEY_EP_NAME), "Endpoint name", &app_config.ep_name,
      sizeof(app_config.ep_name_storage), string_validate },
    { AVS_QUOTE_MACRO(OPTION_KEY_PSK_IDENTITY), "PSK identity",
      &app_config.psk_identity, sizeof(app_config.psk_identity_storage),
      string_validate },
    { AVS_QUOTE_MACRO(OPTION_KEY_PSK), "PSK (plaintext)", &app_config.psk,
      sizeof(app_config.psk_storage), string_validate },
    { AVS_QUOTE_MACRO(OPTION_KEY_PSK_HEX), "PSK (hex)", &app_config.psk,
      2 * sizeof(app_config.psk_storage), psk_hex_validate },
    { AVS_QUOTE_MACRO(OPTION_KEY_BOOTSTRAP), "Bootstrap", &app_config.bootstrap,
      sizeof(app_config.bootstrap_storage), flag_validate },
    { AVS_QUOTE_MACRO(OPTION_KEY_SECURITY_MODE),
      "Security mode (nosec/psk/cert)", &app_config.security_mode,
      sizeof(app_config.security_mode_storage), security_mode_validate },
#        ifdef CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
    { AVS_QUOTE_MACRO(OPTION_KEY_PUBLIC_CERT), "Public certificate",
      &app_config.public_cert, CONFIG_ANJAY_ZEPHYR_MAX_PUBLIC_CERT_LEN },
    { AVS_QUOTE_MACRO(OPTION_KEY_PRIVATE_KEY), "Private key",
      &app_config.private_key, CONFIG_ANJAY_ZEPHYR_MAX_PRIVATE_KEY_LEN },
#        endif // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
#    endif     // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
#    ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF
    { AVS_QUOTE_MACRO(OPTION_KEY_GPS_NRF_PRIO_MODE_PERMITTED),
      "GPS priority mode permitted", &app_config.gps_nrf_prio_mode_permitted,
      sizeof(app_config.gps_nrf_prio_mode_permitted_storage), flag_validate },
    { AVS_QUOTE_MACRO(OPTION_KEY_GPS_NRF_PRIO_MODE_COOLDOWN),
      "GPS priority mode cooldown", &app_config.gps_nrf_prio_mode_cooldown,
      sizeof(app_config.gps_nrf_prio_mode_cooldown_storage), uint32_validate },
#    endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF
#    if defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) \
            && !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
    { AVS_QUOTE_MACRO(OPTION_KEY_USE_PERSISTENCE), "Use persistence",
      &app_config.use_persistence, sizeof(app_config.use_persistence_storage),
      flag_validate },
#    endif /* defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) &&        \
            * !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING) \
            */
};

static int settings_set(const char *key,
                        size_t len,
                        settings_read_cb read_cb,
                        void *cb_arg) {
    if (key) {
        for (int i = 0; i < AVS_ARRAY_SIZE(string_options); ++i) {
            if (!strcmp(key, AVS_QUOTE_MACRO(OPTION_KEY_PSK_HEX))) {
                // PSK is saved only in binary format, we skip hexlified form
                return 0;
            }

            if (strcmp(key, string_options[i].key) == 0) {
                if (len > (string_options[i].option->null_terminated
                                   ? string_options[i].value_capacity - 1
                                   : string_options[i].value_capacity)) {
                    return -EINVAL;
                }

                int result = 0;
                SYNCHRONIZED(config_mutex) {
                    memset(string_options[i].option->value, 0,
                           string_options[i].value_capacity);
                    string_options[i].option->length = 0;

                    result = read_cb(cb_arg, string_options[i].option->value,
                                     len);

                    if (result >= 0) {
#    ifndef CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
                        if (!strcmp(key,
                                    AVS_QUOTE_MACRO(OPTION_KEY_SECURITY_MODE))
                                && !strcmp(string_options[i].option->value,
                                           CERT_MODE)) {
                            LOG_WRN("Runtime certificate is disabled, "
                                    "switching to Kconfig value");
#        if defined(CONFIG_ANJAY_ZEPHYR_SECURITY_MODE_NOSEC)
                            strcpy(app_config.security_mode.value, NOSEC_MODE);
#        elif defined(CONFIG_ANJAY_ZEPHYR_SECURITY_MODE_PSK)
                            strcpy(app_config.security_mode.value, PSK_MODE);
#        endif // defined(CONFIG_ANJAY_ZEPHYR_SECURITY_MODE_NOSEC)
                        }
#    endif // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
                        string_options[i].option->length = len;
                    }
                }
                return result >= 0 ? 0 : result;
            }
        }
    }
    return -ENOENT;
}

SETTINGS_STATIC_HANDLER_DEFINE(
        anjay, SETTINGS_ROOT_NAME, NULL, settings_set, NULL, NULL);

void _anjay_zephyr_config_save(void) {
    // This is a POSIX extension provided by newlib, but only visible with
    // #define _POSIX_C_SOURCE 200809L. That conflicts with some declarations in
    // Zephyr, though.
    size_t strnlen(const char *s, size_t maxlen);

    char key_buf[64];
    int result = 0;

    for (size_t i = 0; !result && i < AVS_ARRAY_SIZE(string_options); ++i) {
        if (!strcmp(string_options[i].key,
                    AVS_QUOTE_MACRO(OPTION_KEY_PSK_HEX))) {
            // PSK is saved only in binary format, we skip hexlified form
            continue;
        }

        result = avs_simple_snprintf(key_buf, sizeof(key_buf),
                                     SETTINGS_ROOT_NAME "/%s",
                                     string_options[i].key);
        if (result >= 0) {
            SYNCHRONIZED(config_mutex) {
                result = settings_save_one(key_buf,
                                           string_options[i].option->value,
                                           string_options[i].option->length);
            }
        }
    }

    if (result) {
        LOG_WRN("Cannot save the config");

        for (size_t i = 0; i < AVS_ARRAY_SIZE(string_options); ++i) {
            result = avs_simple_snprintf(key_buf, sizeof(key_buf),
                                         SETTINGS_ROOT_NAME "/%s",
                                         string_options[i].key);
            if (result >= 0) {
                settings_delete(key_buf);
            }
        }
    } else {
        LOG_INF("Configuration successfully saved");
    }
}

void _anjay_zephyr_config_default_init(void) {
#    ifdef CONFIG_WIFI
    AVS_STATIC_ASSERT(sizeof(CONFIG_ANJAY_ZEPHYR_WIFI_SSID)
                              <= SSID_STORAGE_SIZE,
                      wifi_ssid_length_check);
    AVS_STATIC_ASSERT(sizeof(CONFIG_ANJAY_ZEPHYR_WIFI_PASSWORD)
                              <= PASSWORD_STORAGE_SIZE,
                      wifi_password_length_check);
#    endif // CONFIG_WIFI
#    ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
    AVS_STATIC_ASSERT(sizeof(CONFIG_ANJAY_ZEPHYR_SERVER_URI)
                              <= URI_STORAGE_SIZE,
                      uri_length_check);
    AVS_STATIC_ASSERT(sizeof(AVS_QUOTE_MACRO(CONFIG_ANJAY_ZEPHYR_LIFETIME))
                              <= AVS_UINT_STR_BUF_SIZE(uint32_t),
                      lifetime_length_check);
    AVS_STATIC_ASSERT(sizeof(CONFIG_ANJAY_ZEPHYR_PSK_IDENTITY)
                              <= PSK_IDENTITY_STORAGE_SIZE,
                      psk_identity_length_check);
    AVS_STATIC_ASSERT(sizeof(CONFIG_ANJAY_ZEPHYR_PSK_KEY) - 1
                              <= PSK_KEY_STORAGE_SIZE,
                      psk_key_length_check);
#    endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
#    ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF
    AVS_STATIC_ASSERT(sizeof(AVS_QUOTE_MACRO(
                              CONFIG_ANJAY_ZEPHYR_GPS_NRF_PRIO_MODE_COOLDOWN))
                              <= AVS_UINT_STR_BUF_SIZE(uint32_t),
                      gps_cooldown_length_check);
#    endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF

    SYNCHRONIZED(config_mutex) {
        app_config = (struct anjay_zephyr_app_config) {
#    ifdef CONFIG_WIFI
            .ssid_storage = CONFIG_ANJAY_ZEPHYR_WIFI_SSID,
            .ssid.length = sizeof(CONFIG_ANJAY_ZEPHYR_WIFI_SSID),
            .ssid.null_terminated = true,
            .password_storage = CONFIG_ANJAY_ZEPHYR_WIFI_PASSWORD,
            .password.length = sizeof(CONFIG_ANJAY_ZEPHYR_WIFI_PASSWORD),
            .password.null_terminated = true,
#    endif // CONFIG_WIFI
#    ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
            .preferred_bearer_storage = DEFAULT_BEARER_LIST,
            .preferred_bearer.length = sizeof(DEFAULT_BEARER_LIST),
            .preferred_bearer.null_terminated = true,
#    endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
#    ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
            .uri_storage = CONFIG_ANJAY_ZEPHYR_SERVER_URI,
            .uri.length = sizeof(CONFIG_ANJAY_ZEPHYR_SERVER_URI),
            .uri.null_terminated = true,
            .lifetime_storage = AVS_QUOTE_MACRO(CONFIG_ANJAY_ZEPHYR_LIFETIME),
            .lifetime.length =
                    sizeof(AVS_QUOTE_MACRO(CONFIG_ANJAY_ZEPHYR_LIFETIME)),
            .lifetime.null_terminated = true,
            .psk_identity_storage = CONFIG_ANJAY_ZEPHYR_PSK_IDENTITY,
            .psk_identity.length = sizeof(CONFIG_ANJAY_ZEPHYR_PSK_IDENTITY),
            .psk_identity.null_terminated = true,
            .psk_storage = CONFIG_ANJAY_ZEPHYR_PSK_KEY,
            .psk.length = sizeof(CONFIG_ANJAY_ZEPHYR_PSK_KEY) - 1,
            .psk.null_terminated = false,
#        ifdef CONFIG_ANJAY_ZEPHYR_BOOTSTRAP_SERVER
            .bootstrap_storage = { 'y' },
#        else  // CONFIG_ANJAY_ZEPHYR_BOOTSTRAP_SERVER
            .bootstrap_storage = { 'n' },
#        endif // CONFIG_ANJAY_ZEPHYR_BOOTSTRAP_SERVER
            .bootstrap.length = 1,
            .bootstrap.null_terminated = false,
#    endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
#    ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF
#        ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_PRIO_MODE_PERMITTED
            .gps_nrf_prio_mode_permitted_storage = { 'y' },
#        else  // CONFIG_ANJAY_ZEPHYR_GPS_NRF_PRIO_MODE_PERMITTED
            .gps_nrf_prio_mode_permitted_storage = { 'n' },
#        endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_PRIO_MODE_PERMITTED
            .gps_nrf_prio_mode_permitted.length = 1,
            .gps_nrf_prio_mode_permitted.null_terminated = false,
            .gps_nrf_prio_mode_cooldown_storage = AVS_QUOTE_MACRO(
                    CONFIG_ANJAY_ZEPHYR_GPS_NRF_PRIO_MODE_COOLDOWN),
            .gps_nrf_prio_mode_cooldown.length = sizeof(AVS_QUOTE_MACRO(
                    CONFIG_ANJAY_ZEPHYR_GPS_NRF_PRIO_MODE_COOLDOWN)),
            .gps_nrf_prio_mode_cooldown.null_terminated = true,
#    endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF
#    if defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) \
            && !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
#        ifdef CONFIG_ANJAY_ZEPHYR_USE_PERSISTENCE
            .use_persistence_storage = { 'y' },
#        else  // CONFIG_ANJAY_ZEPHYR_USE_PERSISTENCE
            .use_persistence_storage = { 'n' },
#        endif // CONFIG_ANJAY_ZEPHYR_USE_PERSISTENCE
            .use_persistence.length = 1,
            .use_persistence.null_terminated = false,
#    endif /* defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) &&        \
            * !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING) \
            */
        };

#    ifdef CONFIG_WIFI
        app_config.ssid.value = app_config.ssid_storage;
        app_config.password.value = app_config.password_storage;
#    endif // CONFIG_WIFI
#    ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
        app_config.preferred_bearer.value = app_config.preferred_bearer_storage;
#    endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS

#    ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
        app_config.uri.value = app_config.uri_storage;
        app_config.lifetime.value = app_config.lifetime_storage;
        app_config.ep_name.value = app_config.ep_name_storage;
        app_config.bootstrap.value = app_config.bootstrap_storage;
        app_config.psk_identity.value = app_config.psk_identity_storage;
        app_config.psk.value = app_config.psk_storage;
        app_config.security_mode.value = app_config.security_mode_storage;
#        ifdef CONFIG_ANJAY_ZEPHYR_AUTOGENERATE_ENDPOINT_NAME
        const char *ep_name = anjay_zephyr_config_default_ep_name();
#        else  // CONFIG_ANJAY_ZEPHYR_AUTOGENERATE_ENDPOINT_NAME
        const char *ep_name = CONFIG_ANJAY_ZEPHYR_ENDPOINT_NAME;
#        endif // CONFIG_ANJAY_ZEPHYR_AUTOGENERATE_ENDPOINT_NAME
        assert(strlen(ep_name) < sizeof(app_config.ep_name_storage));
        strcpy(app_config.ep_name.value, ep_name);
        app_config.ep_name.length = strlen(ep_name);
        app_config.ep_name.null_terminated = true;
#        if defined(CONFIG_ANJAY_ZEPHYR_SECURITY_MODE_NOSEC)
        strcpy(app_config.security_mode.value, NOSEC_MODE);
#        elif defined(CONFIG_ANJAY_ZEPHYR_SECURITY_MODE_PSK)
        strcpy(app_config.security_mode.value, PSK_MODE);
#        elif defined(CONFIG_ANJAY_ZEPHYR_SECURITY_MODE_CERT)
        strcpy(app_config.security_mode.value, CERT_MODE);
#        endif // defined(CONFIG_ANJAY_ZEPHYR_SECURITY_MODE_NOSEC)
        app_config.security_mode.length =
                strlen(app_config.security_mode.value);
        app_config.security_mode.null_terminated = true;
#        ifdef CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
        app_config.public_cert.value = app_config.public_cert_storage;
        app_config.private_key.value = app_config.private_key_storage;
#        endif // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
#    endif     // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
#    ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF
        app_config.gps_nrf_prio_mode_permitted.value =
                app_config.gps_nrf_prio_mode_permitted_storage;
        app_config.gps_nrf_prio_mode_cooldown.value =
                app_config.gps_nrf_prio_mode_cooldown_storage;
#    endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF
#    if defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) \
            && !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
        app_config.use_persistence.value = app_config.use_persistence_storage;
#    endif /* defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) &&        \
            * !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING) \
            */
    }
}

#    ifdef CONFIG_ANJAY_ZEPHYR_SHELL
void _anjay_zephyr_config_print_summary(const struct shell *shell) {
    shell_print(shell, "\nCurrent Anjay config:\n");
    for (int i = 0; i < AVS_ARRAY_SIZE(string_options); i++) {
        SYNCHRONIZED(config_mutex) {
#        ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
            if (!strcmp(string_options[i].key,
                        AVS_QUOTE_MACRO(OPTION_KEY_PSK))) {
                bool printable = true;
                for (int j = 0; j < app_config.psk.length; j++) {
                    if (!isgraph((int) app_config.psk.value[j])) {
                        printable = false;
                        break;
                    }
                }
                if (printable) {
                    shell_print(shell, " %s: %.*s", string_options[i].desc,
                                string_options[i].option->length,
                                string_options[i].option->value);
                } else {
                    shell_print(shell, " %s: <not printable>",
                                string_options[i].desc);
                }
            } else if (!strcmp(string_options[i].key,
                               AVS_QUOTE_MACRO(OPTION_KEY_PSK_HEX))) {
                size_t bytes_consumed;
                char buffer[2 * sizeof(app_config.psk_storage) + 1];
                if (avs_hexlify(buffer, sizeof(buffer), &bytes_consumed,
                                app_config.psk.value, app_config.psk.length)
                        || bytes_consumed != app_config.psk.length) {
                    shell_error(shell, "PSK hexlification failed");
                    break;
                }
                shell_print(shell, " %s: %s", string_options[i].desc, buffer);
            } else {
#        endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
                shell_print(shell, " %s: %.*s", string_options[i].desc,
                            string_options[i].option->length,
                            string_options[i].option->value);
#        ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
            }
#        endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
        }
    }
}

int _anjay_zephyr_config_set_option(const struct shell *shell,
                                    size_t argc,
                                    char **argv) {
    if (argc != 2) {
        shell_error(shell, "Wrong number of arguments.\n");
        return -1;
    }

    const char *key = argv[0];

    for (size_t i = 0; i < AVS_ARRAY_SIZE(string_options); ++i) {
        if (strcmp(key, string_options[i].key) == 0) {
            const char *value = argv[1];
            size_t value_len = strlen(value);

            assert(string_options[i].validator);
            if (string_options[i].validator(shell, value, value_len,
                                            &string_options[i])) {
                return -1;
            }
#        ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
            if (!strcmp(string_options[i].key,
                        AVS_QUOTE_MACRO(OPTION_KEY_PSK_HEX))) {
                size_t bytes_written;
                char buffer[sizeof(app_config.psk_storage)];

                if (avs_unhexlify(&bytes_written, buffer, sizeof(buffer), value,
                                  value_len)
                        || bytes_written != value_len / 2) {
                    shell_error(shell, "Hex parsing error");
                    return -1;
                }
                value = buffer;
                SYNCHRONIZED(config_mutex) {
                    string_options[i].option->length = bytes_written;
                }
            } else {
#        endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
                SYNCHRONIZED(config_mutex) {
                    string_options[i].option->length = value_len;
                }
#        ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
            }
#        endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING

            SYNCHRONIZED(config_mutex) {
                memcpy(string_options[i].option->value, value,
                       string_options[i].option->length);

                if (string_options[i].option->null_terminated) {
                    string_options[i]
                            .option->value[string_options[i].option->length] =
                            '\0';
                }
            }
            return 0;
        }
    }

    AVS_UNREACHABLE("Invalid option key");
    return -1;
}
#    endif // CONFIG_ANJAY_ZEPHYR_SHELL

void _anjay_zephyr_config_init(void) {
    _anjay_zephyr_config_default_init();
    if (settings_subsys_init()) {
        LOG_WRN("Failed to initialize settings subsystem");
        return;
    }

    if (settings_load_subtree(SETTINGS_ROOT_NAME)) {
        LOG_WRN("Restoring default configuration");
        _anjay_zephyr_config_default_init();
    } else {
        LOG_INF("Configuration successfully restored");
    }
}

#    ifdef CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
static struct anjay_zephyr_option *credential;

static void
credential_reader(const struct shell *shell, uint8_t *data, size_t len) {
    static size_t pos = 0;
    static char last_char = '\0';
    SYNCHRONIZED(config_mutex) {
        for (size_t i = 0; i < len; i++) {
            if (data[i] == EOT_ASCII) {
                bool key = !strcmp(credential->key,
                                   AVS_QUOTE_MACRO(OPTION_KEY_PRIVATE_KEY));
                if (pos >= credential->value_capacity) {
                    shell_print(shell,
                                "%s too long, max len: %zu, provided "
                                "credential len: %zu ",
                                key ? "Private key" : "Certificate",
                                credential->value_capacity, pos);
                    credential->option->value[0] = '\0';
                } else {
                    shell_print(shell, "%s loaded, len = %zu\r\n",
                                key ? "Private key" : "Certificate", pos);
                    credential->option->value[pos] = '\0';
                    credential->option->length = pos;
                }
                shell_set_bypass(shell, NULL);
                pos = 0;
                last_char = '\0';
                break;
            }
            if (pos >= credential->value_capacity) {
                pos++;
                continue;
            }
            if (last_char == '\r' && data[i] != '\n') {
                credential->option->value[pos++] = '\n';
            }
            last_char = data[i];
            credential->option->value[pos++] = data[i];
        }
    }
}

void _anjay_zephyr_set_credential(const struct shell *shell, bool key) {
    for (size_t i = 0; i < AVS_ARRAY_SIZE(string_options); i++) {
        if (!strcmp(string_options[i].key,
                    key ? AVS_QUOTE_MACRO(OPTION_KEY_PRIVATE_KEY)
                        : AVS_QUOTE_MACRO(OPTION_KEY_PUBLIC_CERT))) {
            credential = &string_options[i];
        }
    }
    shell_print(shell,
                "Paste %s in PEM format, CTRL+D to finish sending",
                key ? "private key" : "public certificate");
    shell_set_bypass(shell, credential_reader);
}

#    endif // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
#endif     // WITH_ANJAY_ZEPHYR_CONFIG

#if defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) \
        || !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
static int parse_uint32(const char *value, uint32_t *out) {
    int ret = 0;
    SYNCHRONIZED(config_mutex) {
        ret = sscanf(value, "%" PRIu32, out);
    }
    return ret == 1 ? 0 : -1;
}
#endif // defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) ||
       // !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)

#ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
static enum anjay_zephyr_network_bearer_t
parse_preferred_bearer(const char *value) {
#    ifdef CONFIG_WIFI_RS9116W
    if (strcmp(value, OPTION_VALUE_PREFERRED_BEARER_WIFI) == 0) {
        return ANJAY_ZEPHYR_NETWORK_BEARER_WIFI;
    }
#    endif // CONFIG_WIFI_RS9116W

#    ifdef CONFIG_MODEM_MURATA_1SC
    if (strcmp(value, OPTION_VALUE_PREFERRED_BEARER_CELLULAR) == 0) {
        return ANJAY_ZEPHYR_NETWORK_BEARER_CELLULAR;
    }
#    endif // CONFIG_MODEM_MURATA_1SC

    return ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT;
}

static struct anjay_zephyr_network_preferred_bearer_list_t
invalid_preferred_bearer_list(void) {
    struct anjay_zephyr_network_preferred_bearer_list_t ret;

    for (size_t i = 0; i < AVS_ARRAY_SIZE(ret.bearers); ++i) {
        ret.bearers[i] = ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT;
    }

    return ret;
}

static struct anjay_zephyr_network_preferred_bearer_list_t
parse_preferred_bearer_list(const char *value) {
    // This is a BSD extension provided by newlib, but only visible with #define
    // _DEFAULT_SOURCE _DEFAULT_SOURCE conflicts with some POSIX-like
    // declarations in Zephyr, though.
    extern char *strsep(char **stringp, const char *delim);

    char preferred_bearer[sizeof(DEFAULT_BEARER_LIST)];
    struct anjay_zephyr_network_preferred_bearer_list_t ret =
            invalid_preferred_bearer_list();

    if (avs_simple_snprintf(preferred_bearer, sizeof(preferred_bearer), "%s",
                            value)
            < 0) {
        return invalid_preferred_bearer_list();
    }

    char *stringp = preferred_bearer;
    size_t i = 0;

    while (true) {
        char *token = strsep(&stringp, ",");

        if (!token) {
            break;
        }

        if (i >= AVS_ARRAY_SIZE(ret.bearers)) {
            // Invalid input - too many entries
            return invalid_preferred_bearer_list();
        }

        enum anjay_zephyr_network_bearer_t bearer =
                parse_preferred_bearer(token);

        if (!_anjay_zephyr_network_bearer_valid(bearer)) {
            return invalid_preferred_bearer_list();
        }

        ret.bearers[i++] = bearer;
    }

    return ret;
}
#endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS

#if !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING) || defined(CONFIG_WIFI)
int get_config(char *src, char *dst, size_t buf_capacity) {
    int ret = 0;

    SYNCHRONIZED(config_mutex) {
        if (!src || !dst
                || avs_simple_snprintf(dst, buf_capacity, "%s", src) < 0) {
            LOG_WRN("Getting configuration from settings failed");
            ret = -1;
        }
    }

    return ret;
}
#endif // !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING) ||
       // defined(CONFIG_WIFI)

#ifdef CONFIG_WIFI
int anjay_zephyr_config_get_wifi_ssid(char *buf, size_t buf_capacity) {
    return get_config(app_config.ssid.value, buf, buf_capacity);
}

int anjay_zephyr_config_get_wifi_password(char *buf, size_t buf_capacity) {
    return get_config(app_config.password.value, buf, buf_capacity);
}
#endif // CONFIG_WIFI

#ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
struct anjay_zephyr_network_preferred_bearer_list_t
anjay_zephyr_config_get_preferred_bearers(void) {
    struct anjay_zephyr_network_preferred_bearer_list_t ret = { 0 };
    SYNCHRONIZED(config_mutex) {
        ret = parse_preferred_bearer_list(app_config.preferred_bearer.value);
    }

    if (!_anjay_zephyr_network_preferred_bearer_list_valid(&ret)) {
        // use the defaults
        for (size_t i = 0; i < AVS_ARRAY_SIZE(ret.bearers); ++i) {
            ret.bearers[i] = (enum anjay_zephyr_network_bearer_t) i;
        }
    }

    return ret;
}
#endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS

#ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
int anjay_zephyr_config_get_endpoint_name(char *buf, size_t buf_capacity) {
    return get_config(app_config.ep_name.value, buf, buf_capacity);
}

int anjay_zephyr_config_get_server_uri(char *buf, size_t buf_capacity) {
    return get_config(app_config.uri.value, buf, buf_capacity);
}

uint32_t anjay_zephyr_config_get_lifetime(void) {
    uint32_t ret = 0;
    parse_uint32(app_config.lifetime.value, &ret);
    return ret;
}

int anjay_zephyr_config_get_psk_identity(char *buf, size_t buf_capacity) {
    return get_config(app_config.psk_identity.value, buf, buf_capacity);
}

int anjay_zephyr_config_get_psk(char *buf,
                                size_t buf_capacity,
                                size_t *psk_len) {
    int ret = 0;
    SYNCHRONIZED(config_mutex) {
        ret = get_config(app_config.psk.value, buf, buf_capacity);
        *psk_len = app_config.psk.length;
    }
    return ret;
}

bool anjay_zephyr_config_is_bootstrap(void) {
    bool ret = false;
    SYNCHRONIZED(config_mutex) {
        ret = app_config.bootstrap.value[0] == 'y';
    }
    return ret;
}

anjay_security_mode_t anjay_zephyr_config_get_security_mode(void) {
    anjay_security_mode_t ret = ANJAY_SECURITY_NOSEC;
    SYNCHRONIZED(config_mutex) {
        if (!strcmp(app_config.security_mode_storage, PSK_MODE)) {
            ret = ANJAY_SECURITY_PSK;
        } else if (!strcmp(app_config.security_mode_storage, CERT_MODE)) {
            ret = ANJAY_SECURITY_CERTIFICATE;
        }
    }

    return ret;
}

#    ifdef CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
int anjay_zephyr_config_get_public_cert(char *buf, size_t buf_capacity) {
    return get_config(app_config.public_cert.value, buf, buf_capacity);
}

int anjay_zephyr_config_get_private_key(char *buf, size_t buf_capacity) {
    return get_config(app_config.private_key.value, buf, buf_capacity);
}
#    endif // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
#endif     // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING

#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF
bool anjay_zephyr_config_is_gps_nrf_prio_mode_permitted(void) {
    bool ret = false;
    SYNCHRONIZED(config_mutex) {
        ret = app_config.gps_nrf_prio_mode_permitted.value[0] == 'y';
    }
    return ret;
}

uint32_t anjay_zephyr_config_get_gps_nrf_prio_mode_cooldown(void) {
    uint32_t ret = 0;
    parse_uint32(app_config.gps_nrf_prio_mode_cooldown.value, &ret);
    return ret;
}
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF

#if defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) \
        && !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
bool anjay_zephyr_config_is_use_persistence(void) {
    bool ret = false;
    SYNCHRONIZED(config_mutex) {
        ret = app_config.use_persistence.value[0] == 'y';
    }
    return ret;
}
#endif /* defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) &&        \
        * !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING) \
        */

#if defined(CONFIG_WIFI) || defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) \
        || !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
static int string_validate(const struct shell *shell,
                           const char *value,
                           size_t value_len,
                           const struct anjay_zephyr_option *option) {
    size_t max_len = option->option->null_terminated
                             ? option->value_capacity - 1
                             : option->value_capacity;
    if (value_len > max_len) {
        shell_error(shell, "Value too long, maximum length is %d\n", max_len);
        return -1;
    }

    return 0;
}
#endif /* defined(CONFIG_WIFI) || defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) || \
        * !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)              \
        */

#ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
static int preferred_bearer_validate(const struct shell *shell,
                                     const char *value,
                                     size_t value_len,
                                     const struct anjay_zephyr_option *option) {
    if (string_validate(shell, value, value_len, option)) {
        return -1;
    }

    struct anjay_zephyr_network_preferred_bearer_list_t out =
            parse_preferred_bearer_list(value);

    if (!_anjay_zephyr_network_preferred_bearer_list_valid(&out)) {
        shell_error(shell,
                    "Value invalid; please specify a comma-separated list of:"
#    ifdef CONFIG_WIFI_RS9116W
                    " '" OPTION_VALUE_PREFERRED_BEARER_WIFI "'"
#    endif // CONFIG_WIFI_RS9116W
#    ifdef CONFIG_MODEM_MURATA_1SC
                    " '" OPTION_VALUE_PREFERRED_BEARER_CELLULAR "'"
#    endif // CONFIG_MODEM_MURATA_1SC
                    "\n");
        return -1;
    }

    return 0;
}
#endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS

#if defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) \
        || !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
static int flag_validate(const struct shell *shell,
                         const char *value,
                         size_t value_len,
                         const struct anjay_zephyr_option *option) {
    if (value_len != 1 || (value[0] != 'y' && value[0] != 'n')) {
        shell_error(shell, "Value invalid, 'y' or 'n' is allowed\n");
        return -1;
    }

    return 0;
}
#endif // defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) ||
       // !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)

#ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
static int psk_hex_validate(const struct shell *shell,
                            const char *value,
                            size_t value_len,
                            const struct anjay_zephyr_option *option) {
    if (value_len % 2 != 0) {
        shell_error(shell, "Key in hex shall have an even number of signs");
        return -1;
    }

    if (value_len > option->value_capacity) {
        shell_error(shell, "Value too long, maximum length is %zu\n",
                    option->value_capacity);
        return -1;
    }

    return 0;
}

static int security_mode_validate(const struct shell *shell,
                                  const char *value,
                                  size_t value_len,
                                  const struct anjay_zephyr_option *option) {
    if (string_validate(shell, value, value_len, option)
            || (strcmp(value, NOSEC_MODE) && strcmp(value, PSK_MODE)
                && strcmp(value, CERT_MODE))) {
        shell_error(shell, "Wrong value, valid values: %s/%s/%s", NOSEC_MODE,
                    PSK_MODE, CERT_MODE);
        return -1;
    }
#    ifndef CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
    if (!strcmp(value, CERT_MODE)) {
        shell_error(shell, "Runtime certificate is disabled");
        return -1;
    }
#    endif // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
    return 0;
}

#endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING

#if defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) \
        || !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
static int uint32_validate(const struct shell *shell,
                           const char *value,
                           size_t value_len,
                           const struct anjay_zephyr_option *option) {
    if (string_validate(shell, value, value_len, option)) {
        return -1;
    }

    uint32_t out;

    if (parse_uint32(value, &out)) {
        shell_error(shell, "Argument is not a valid uint32_t value");
        return -1;
    }

    return 0;
}
#endif // defined(CONFIG_ANJAY_ZEPHYR_GPS_NRF) ||
       // !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
