/*
 * Copyright 2020-2024 AVSystem <avsystem@avsystem.com>
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

#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_uart.h>
#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
#    include <zephyr/logging/log.h>
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION

#include "version.h"
#if __has_include("ncs_version.h")
#    include "ncs_version.h"
#endif // __has_include("ncs_version.h")

#include "config.h"
#include "lwm2m_internal.h"
#include "persistence.h"
#include "utils.h"

#include "location_services.h"
#include "network/network.h"

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
LOG_MODULE_REGISTER(anjay_zephyr_shell);
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION

static int
cmd_anjay_start(const struct shell *shell, size_t argc, char **argv) {
    ARG_UNUSED(shell);
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    shell_print(shell, "Attempt to start Anjay");
    if (!anjay_zephyr_lwm2m_start()) {
        shell_print(shell, "Anjay started");
        return 0;
    }

    return -ENOEXEC;
}

static int cmd_anjay_stop(const struct shell *shell, size_t argc, char **argv) {
    ARG_UNUSED(shell);
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    shell_print(shell, "Attempt to stop Anjay\nIf a DTLS handshake is in "
                       "progress, it might take up to 15 s for it to time out");

    if (!anjay_zephyr_lwm2m_stop()) {
        shell_print(shell, "Anjay stopped");
        return 0;
    }

    return -ENOEXEC;
}

#ifdef WITH_ANJAY_ZEPHYR_CONFIG
static int
cmd_anjay_config_set(const struct shell *shell, size_t argc, char **argv) {
    if (atomic_load(&anjay_zephyr_anjay_running)) {
        shell_print(shell, "Cannot change the config while Anjay is running");
        return -1;
    }

    return _anjay_zephyr_config_set_option(shell, argc, argv);
}

#    ifdef CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
static int
cmd_anjay_public_cert(const struct shell *shell, size_t argc, char **argv) {
    if (atomic_load(&anjay_zephyr_anjay_running)) {
        shell_print(shell, "Cannot change the config while Anjay is running");
        return -1;
    }

    _anjay_zephyr_set_credential(shell, false);
    return 0;
}

static int
cmd_anjay_private_key(const struct shell *shell, size_t argc, char **argv) {
    if (atomic_load(&anjay_zephyr_anjay_running)) {
        shell_print(shell, "Cannot change the config while Anjay is running");
        return -1;
    }

    _anjay_zephyr_set_credential(shell, true);
    return 0;
}
#    endif // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG

#    ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
static int cmd_anjay_config_set_preferred_bearer(const struct shell *shell,
                                                 size_t argc,
                                                 char **argv) {
    // We allow setting preferred bearer even when Anjay is running
    int result = _anjay_zephyr_config_set_option(shell, argc, argv);

    if (result) {
        return result;
    }

    struct anjay_zephyr_network_preferred_bearer_list_t bearers =
            anjay_zephyr_config_get_preferred_bearers();

    if (_anjay_zephyr_network_set_preferred_bearer_list(&bearers)) {
        shell_print(shell,
                    "Could not change the currently used network bearer");
    }

    return 0;
}
#    endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS

static int
cmd_anjay_config_default(const struct shell *shell, size_t argc, char **argv) {
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    if (atomic_load(&anjay_zephyr_anjay_running)) {
        shell_print(shell, "Cannot change the config while Anjay is running");
        return -1;
    }

    _anjay_zephyr_config_default_init();
    return 0;
}

static int
cmd_anjay_config_show(const struct shell *shell, size_t argc, char **argv) {
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    _anjay_zephyr_config_print_summary(shell);

    return 0;
}

static int
cmd_anjay_config_save(const struct shell *shell, size_t argc, char **argv) {
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    shell_print(shell, "Saving config");
    _anjay_zephyr_config_save();
    _anjay_zephyr_config_print_summary(shell);

    return 0;
}
#endif // WITH_ANJAY_ZEPHYR_CONFIG

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
static void gf_location_request_cb(
        anjay_zephyr_location_services_request_result_t result,
        anjay_zephyr_location_services_ground_fix_location_t location) {
    if (result == ANJAY_ZEPHYR_LOCATION_SERVICES_SUCCESSFUL) {
        LOG_INF("Received ground fix location"
                ", lat: %.3f deg, lon: %.3f deg, acc: %.3f m",
                location.latitude, location.longitude, location.accuracy);
    } else {
        LOG_WRN("Ground fix location request failed, err: %d", (int) result);
    }
}

static int cmd_anjay_nls_gf_location_request(const struct shell *shell,
                                             size_t argc,
                                             char **argv,
                                             void *data) {
    int result = 0;
    SYNCHRONIZED(anjay_zephyr_global_anjay_mutex) {
        if (anjay_zephyr_global_anjay) {
            anjay_zephyr_location_services_gf_location_request_type_t req_type =
                    (anjay_zephyr_location_services_gf_location_request_type_t) (uintptr_t)
                            data;
            struct anjay_zephyr_gf_location_request_job_args args = {
                .anjay = anjay_zephyr_global_anjay,
                .cb = (req_type
                               == ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_REQUEST_SINGLE
                       || req_type
                                  == ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_REQUEST_MULTI)
                              ? gf_location_request_cb
                              : NULL,
                .request_type = req_type
            };
            AVS_SCHED_NOW(anjay_get_scheduler(anjay_zephyr_global_anjay), NULL,
                          _anjay_zephyr_gf_location_request_job, &args,
                          sizeof(args));

        } else {
            shell_warn(shell, "Anjay is not running");
            result = -ENOEXEC;
        }
    }
    return result;
}
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION

#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
static int cmd_anjay_nls_agps_request(const struct shell *shell,
                                      size_t argc,
                                      char **argv,
                                      void *data) {
    int result = 0;
    SYNCHRONIZED(anjay_zephyr_global_anjay_mutex) {
        if (anjay_zephyr_global_anjay) {
            anjay_t *anjay = anjay_zephyr_global_anjay;

            struct anjay_zephyr_agps_request_job_args args = {
                .anjay = anjay_zephyr_global_anjay,
                .cb = NULL,
                .request_mask = LOC_SERVICES_A_GPS_FULL_MASK,
                .exponential_backoff = false
            };

            if (result == 0) {
                AVS_SCHED_NOW(anjay_get_scheduler(anjay), NULL,
                              _anjay_zephyr_agps_request_job, &args,
                              sizeof(args));
            } else {
                shell_error(shell, "Wrong argument, request aborted");
            }
        } else {
            shell_warn(shell, "Anjay is not running");
            result = -ENOEXEC;
        }
    }
    return result;
}
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS

#ifdef CONFIG_ANJAY_ZEPHYR_PERSISTENCE
static int cmd_anjay_persistence_purge(const struct shell *shell,
                                       size_t argc,
                                       char **argv,
                                       void *data) {
    int err = 0;

    SYNCHRONIZED(anjay_zephyr_global_anjay_mutex) {
        if (atomic_load(&anjay_zephyr_anjay_running)
                || anjay_zephyr_global_anjay) {
            shell_warn(shell,
                       "Cannot purge persistence while Anjay is running");
        } else {
            err = _anjay_zephyr_persistence_purge();
            if (err) {
                shell_warn(shell, "Could not purge persistence");
            } else {
                shell_print(shell, "Successfully purged persistence");
            }
        }
    }
    return err;
}
#endif // CONFIG_ANJAY_ZEPHYR_PERSISTENCE

#if defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)
static int cmd_anjay_session_cache_purge(const struct shell *shell,
                                         size_t argc,
                                         char **argv) {
    ARG_UNUSED(argc);
    ARG_UNUSED(argv);

    int err = _anjay_zephyr_tls_session_cache_purge();

    if (err) {
        shell_warn(shell, "Could not purge the TLS session cache");
    } else {
        shell_print(shell, "Successfully purged the TLS session cache");
    }

    return err;
}
#endif // defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)

#ifdef WITH_ANJAY_ZEPHYR_CONFIG
SHELL_STATIC_SUBCMD_SET_CREATE(
        sub_anjay_config_set,
#    ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
        SHELL_CMD(OPTION_KEY_EP_NAME,
                  NULL,
                  "Endpoint name",
                  cmd_anjay_config_set),
#    endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
#    ifdef CONFIG_WIFI
        SHELL_CMD(OPTION_KEY_SSID, NULL, "Wi-Fi SSID", cmd_anjay_config_set),
        SHELL_CMD(OPTION_KEY_PASSWORD,
                  NULL,
                  "Wi-Fi password (empty for no-sec)",
                  cmd_anjay_config_set),
#    endif // CONFIG_WIFI
#    ifdef ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
        SHELL_CMD(OPTION_KEY_PREFERRED_BEARER,
                  NULL,
                  "Preferred network bearer",
                  cmd_anjay_config_set_preferred_bearer),
#    endif // ANJAY_ZEPHYR_DEVEDGE_MULTIPLE_BEARERS
#    ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
        SHELL_CMD(OPTION_KEY_URI, NULL, "Server URI", cmd_anjay_config_set),
        SHELL_CMD(OPTION_KEY_LIFETIME,
                  NULL,
                  "Device lifetime",
                  cmd_anjay_config_set),
        SHELL_CMD(OPTION_KEY_PSK_IDENTITY,
                  NULL,
                  "PSK Identity",
                  cmd_anjay_config_set),
        SHELL_CMD(OPTION_KEY_PSK, NULL, "PSK", cmd_anjay_config_set),
        SHELL_CMD(OPTION_KEY_PSK_HEX, NULL, "PSK in hex", cmd_anjay_config_set),
        SHELL_CMD(OPTION_KEY_SECURITY_MODE,
                  NULL,
                  "Security mode (nosec/psk/cert)",
                  cmd_anjay_config_set),
        SHELL_CMD(OPTION_KEY_BOOTSTRAP,
                  NULL,
                  "Perform bootstrap",
                  cmd_anjay_config_set),
#        ifdef CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
        SHELL_CMD(OPTION_KEY_PRIVATE_KEY,
                  NULL,
                  "Write private key",
                  cmd_anjay_private_key),
        SHELL_CMD(OPTION_KEY_PUBLIC_CERT,
                  NULL,
                  "Write public certificate",
                  cmd_anjay_public_cert),
#        endif // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
#    endif     // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
#    ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF
        SHELL_CMD(OPTION_KEY_GPS_NRF_PRIO_MODE_PERMITTED,
                  NULL,
                  "GPS priority mode permitted - if set, Anjay Zephyr will "
                  "temporarily activate the GPS priority over LTE idle mode in "
                  "case GPS fix cannot be produced. The mode will be "
                  "deactivated automatically after getting a GPS fix or after "
                  "40 seconds.",
                  cmd_anjay_config_set),
        SHELL_CMD(OPTION_KEY_GPS_NRF_PRIO_MODE_COOLDOWN,
                  NULL,
                  "GPS priority mode cooldown - determines (in seconds) how "
                  "much time must pass after a failed try to produce a GPS fix "
                  "to enable GPS priority mode again.",
                  cmd_anjay_config_set),
#    endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF
#    if defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) \
            && !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING)
        SHELL_CMD(OPTION_KEY_USE_PERSISTENCE,
                  NULL,
                  "Enables persistence of Access Control Object, "
#        ifdef CONFIG_ANJAY_ZEPHYR_PERSISTENCE_ATTR_STORAGE
                  "Attribute Storage, "
#        endif // CONFIG_ANJAY_ZEPHYR_PERSISTENCE_ATTR_STORAGE
                  "Security Object and Server Object.",
                  cmd_anjay_config_set),
#    endif /* defined(CONFIG_ANJAY_ZEPHYR_PERSISTENCE) &&        \
            * !defined(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING) \
            */
        SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(
        sub_anjay_config,
        SHELL_CMD(default,
                  NULL,
                  "Restore the default config",
                  cmd_anjay_config_default),
        SHELL_CMD(save, NULL, "Save Anjay config", cmd_anjay_config_save),
        SHELL_CMD(set, &sub_anjay_config_set, "Change Anjay config", NULL),
        SHELL_CMD(show, NULL, "Show Anjay config", cmd_anjay_config_show),
        SHELL_SUBCMD_SET_END);
#endif // WITH_ANJAY_ZEPHYR_CONFIG

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
#    if KERNEL_VERSION_NUMBER >= 0x30300 || NCS_VERSION_NUMBER >= 0x20263
#        define SUBCMD_DEF(Handler, Arg, Help) (Handler, Arg, Help)
#    else // KERNEL_VERSION_NUMBER >= 0x30300 || NCS_VERSION_NUMBER >= 0x20263
#        define SUBCMD_DEF(Handler, Arg, Help) (Handler, Arg)
#    endif // KERNEL_VERSION_NUMBER >= 0x30300 || NCS_VERSION_NUMBER >= 0x20263

SHELL_SUBCMD_DICT_SET_CREATE(
        sub_anjay_nls_gf_location_request,
        cmd_anjay_nls_gf_location_request,
        SUBCMD_DEF(
                inform_single,
                (void *) (uintptr_t)
                        ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_INFORM_SINGLE,
                "Inform single"),
        SUBCMD_DEF(
                inform_multi,
                (void *) (uintptr_t)
                        ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_INFORM_MULTI,
                "Inform multiple"),
        SUBCMD_DEF(
                request_single,
                (void *) (uintptr_t)
                        ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_REQUEST_SINGLE,
                "Request single"),
        SUBCMD_DEF(
                request_multi,
                (void *) (uintptr_t)
                        ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_REQUEST_MULTI,
                "Request multiple"));
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION

SHELL_STATIC_SUBCMD_SET_CREATE(
        sub_anjay,
        SHELL_CMD(start, NULL, "Save config and start Anjay", cmd_anjay_start),
        SHELL_CMD(stop, NULL, "Stop Anjay", cmd_anjay_stop),
#ifdef WITH_ANJAY_ZEPHYR_CONFIG
        SHELL_CMD(config, &sub_anjay_config, "Configure Anjay params", NULL),
#endif // WITH_ANJAY_ZEPHYR_CONFIG
#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
        SHELL_CMD(nls_gf_location_request,
                  &sub_anjay_nls_gf_location_request,
                  "Make a ground fix location request to Nordic Location "
                  "Services",
                  NULL),
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
        SHELL_CMD(nls_agps_request,
                  NULL,
                  "Make a manual A-GPS request to Nordic Location Services, "
                  "user can provide minimum elevation angle for visible "
                  "satellites as an additional argument",
                  cmd_anjay_nls_agps_request),
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
#ifdef CONFIG_ANJAY_ZEPHYR_PERSISTENCE
        SHELL_CMD(persistence_purge,
                  NULL,
                  "Purges persisted Anjay state",
                  cmd_anjay_persistence_purge),
#endif // CONFIG_ANJAY_ZEPHYR_PERSISTENCE
#if defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)
        SHELL_CMD(session_cache_purge,
                  NULL,
                  "Remove the TLS session data cached in the nRF modem",
                  cmd_anjay_session_cache_purge),
#endif // defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)
        SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(anjay, &sub_anjay, "Anjay commands", NULL);
