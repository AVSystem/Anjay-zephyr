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

#include <stdlib.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>

#include <zephyr/net/sntp.h>
#include <zephyr/posix/time.h>

#include <anjay/access_control.h>
#include <anjay/anjay.h>
#include <anjay/factory_provisioning.h>
#include <anjay/security.h>
#include <anjay/server.h>

#include <avsystem/commons/avs_crypto_psk.h>
#include <avsystem/commons/avs_prng.h>

#include "anjay_zephyr/factory_provisioning.h"
#include "anjay_zephyr/lwm2m.h"
#include "config.h"
#include "firmware_update.h"
#include "gps.h"
#include "location_services.h"
#include "lwm2m_internal.h"
#include "network/network.h"
#include "objects/objects.h"
#include "persistence.h"
#include "utils.h"

#ifdef CONFIG_DATE_TIME
#    include <date_time.h>
#endif // CONFIG_DATE_TIME

#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
#    include "nrf_lc_info.h"
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

#ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160
#    include "afu/nrf9160/afu_nrf9160.h"
#endif // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160

static const anjay_dm_object_def_t **device_obj;

#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
const anjay_dm_object_def_t **anjay_zephyr_ecid_obj;
const anjay_dm_object_def_t **anjay_zephyr_conn_mon_obj;
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
const anjay_dm_object_def_t **anjay_zephyr_ground_fix_location_obj;
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_ASSISTANCE
const anjay_dm_object_def_t **anjay_zephyr_gnss_assistance_obj;
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_ASSISTANCE

#define RETRY_SYNC_CLOCK_DELAY_TIME_S 1

LOG_MODULE_REGISTER(anjay_zephyr_lwm2m);

anjay_t *volatile anjay_zephyr_global_anjay;
K_MUTEX_DEFINE(anjay_zephyr_global_anjay_mutex);
volatile atomic_bool anjay_zephyr_anjay_running;

static volatile atomic_bool anjay_thread_running;
static K_MUTEX_DEFINE(anjay_thread_running_mutex);
static volatile atomic_bool device_initialized;
static anjay_zephyr_init_params_t anjay_zephyr_init_params;

static struct k_thread anjay_thread;
static K_THREAD_STACK_DEFINE(anjay_stack,
                             CONFIG_ANJAY_ZEPHYR_THREAD_STACK_SIZE);

static struct k_work_delayable sync_clock_work;
static K_SEM_DEFINE(synchronize_clock_sem, 0, 1);
static bool time_sync_failed;

#ifndef ANJAY_ZEPHYR_NO_NETWORK_MGMT
static enum anjay_zephyr_network_bearer_t anjay_last_known_bearer;
#endif // ANJAY_ZEPHYR_NO_NETWORK_MGMT

static avs_sched_handle_t update_internal_objects_and_persistence_handle;

static anjay_zephyr_lwm2m_cb_t *user_callback;

static K_MUTEX_DEFINE(user_callback_mutex);

void anjay_zephyr_lwm2m_set_user_callback(anjay_zephyr_lwm2m_cb_t *cb) {
    SYNCHRONIZED(user_callback_mutex) {
        user_callback = cb;
    }
}

int anjay_zephyr_lwm2m_execute_callback_with_locked_anjay(
        anjay_zephyr_lwm2m_callback_with_locked_anjay_t *cb, void *arg) {
    int err_code = -1;

    if (!cb) {
        return err_code;
    }

    SYNCHRONIZED(anjay_zephyr_global_anjay_mutex) {
        if (anjay_zephyr_global_anjay) {
            err_code = cb(anjay_zephyr_global_anjay, arg);
        }
    }
    return err_code;
}

static int
execute_user_callback(anjay_t *anjay,
                      enum anjay_zephyr_lwm2m_callback_reasons reason) {
    int result = 0;
    SYNCHRONIZED(user_callback_mutex) {
        if (user_callback) {
            result = user_callback(anjay, reason);
        }
    }
    return result;
}

#ifdef CONFIG_DATE_TIME
static void set_system_time(const struct sntp_time *time) {
    const struct tm *current_time = gmtime(&time->seconds);

    date_time_set(current_time);
    date_time_update_async(NULL);
}
#else  // CONFIG_DATE_TIME
static void set_system_time(const struct sntp_time *time) {
    struct timespec ts = {
        .tv_sec = time->seconds,
        .tv_nsec = ((uint64_t) time->fraction * 1000000000) >> 32
    };
    if (clock_settime(CLOCK_REALTIME, &ts)) {
        LOG_WRN("Failed to set time");
    }
}
#endif // CONFIG_DATE_TIME

static void synchronize_clock(void) {
    struct sntp_time time;
    const uint32_t timeout_ms = 5000;

    if (false
#if defined(CONFIG_NET_IPV6)
            || !_anjay_zephyr_sntp_simple_ipv6(CONFIG_ANJAY_ZEPHYR_NTP_SERVER,
                                               timeout_ms, &time)
#endif
#if defined(CONFIG_NET_IPV4)
            || !sntp_simple(CONFIG_ANJAY_ZEPHYR_NTP_SERVER, timeout_ms, &time)
#endif
    ) {
        set_system_time(&time);
        LOG_INF("Time synchronized");
        time_sync_failed = false;
        k_sem_give(&synchronize_clock_sem);
    } else {
        if (!time_sync_failed) {
            time_sync_failed = true;
            LOG_WRN("Failed to get current time");
        }
        _anjay_zephyr_k_work_schedule(&sync_clock_work,
                                      K_SECONDS(RETRY_SYNC_CLOCK_DELAY_TIME_S));
    }
}

static void retry_synchronize_clock_work_handler(struct k_work *work) {
    synchronize_clock();
}

static void deinitialize_anjay(anjay_t *anjay) {
    anjay_delete(anjay);

    struct k_work_sync sync;
    k_work_cancel_delayable_sync(&sync_clock_work, &sync);

    _anjay_zephyr_push_button_clean();
    _anjay_zephyr_basic_sensors_remove();
    _anjay_zephyr_three_axis_sensors_remove();

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES
    _anjay_zephyr_location_services_stop();
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES

#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
    _anjay_zephyr_conn_mon_object_release(&anjay_zephyr_conn_mon_obj);
    _anjay_zephyr_ecid_object_release(&anjay_zephyr_ecid_obj);
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
    _anjay_zephyr_ground_fix_location_object_release(
            &anjay_zephyr_ground_fix_location_obj);
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_ASSISTANCE
    _anjay_zephyr_gnss_assistance_object_release(
            &anjay_zephyr_gnss_assistance_obj);
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_ASSISTANCE

    _anjay_zephyr_device_object_release(&device_obj);

#if defined(CONFIG_ANJAY_COMPAT_ZEPHYR_TLS) && defined(CONFIG_NRF_MODEM_LIB) \
        && defined(CONFIG_MODEM_KEY_MGMT)
    if (avs_is_err(avs_crypto_psk_engine_key_rm(
                CONFIG_ANJAY_ZEPHYR_NRF_MODEM_PSK_QUERY))) {
        LOG_WRN("Removing PSK key failed");
    }

    if (avs_is_err(avs_crypto_psk_engine_identity_rm(
                CONFIG_ANJAY_ZEPHYR_NRF_MODEM_PSK_QUERY))) {
        LOG_WRN("Removing PSK identity failed");
    }
#endif /* defined(CONFIG_ANJAY_COMPAT_ZEPHYR_TLS) &&                      \
        * defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT) \
        */

    execute_user_callback(NULL, ANJAY_ZEPHYR_LWM2M_CALLBACK_REASON_CLEANUP);
}

#ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
static int
configure_servers_and_security_objects_from_settings(anjay_t *anjay) {
    const bool bootstrap = anjay_zephyr_config_is_bootstrap();

    char psk_key[PSK_KEY_STORAGE_SIZE + 1];
    size_t psk_size;
    char psk_identity[PSK_IDENTITY_STORAGE_SIZE];
    char server_uri[URI_STORAGE_SIZE];
#    ifdef CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
    char public_cert[CONFIG_ANJAY_ZEPHYR_MAX_PUBLIC_CERT_LEN];
    char private_key[CONFIG_ANJAY_ZEPHYR_MAX_PRIVATE_KEY_LEN];
    if (anjay_zephyr_config_get_public_cert(public_cert, sizeof(public_cert))
            || anjay_zephyr_config_get_private_key(private_key,
                                                   sizeof(private_key))
#    else  // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
    if (false
#    endif // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
            || anjay_zephyr_config_get_psk(psk_key, sizeof(psk_key), &psk_size)
            || anjay_zephyr_config_get_psk_identity(psk_identity,
                                                    sizeof(psk_identity))
            || anjay_zephyr_config_get_server_uri(server_uri,
                                                  sizeof(server_uri))) {
        LOG_ERR("Unable to configure servers and security objects");
        return -1;
    }
#    if defined(CONFIG_ANJAY_COMPAT_ZEPHYR_TLS) \
            && defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)
    avs_crypto_psk_key_info_t psk_key_info =
            avs_crypto_psk_key_info_from_buffer(psk_key, psk_size);
    if (avs_is_err(avs_crypto_psk_engine_key_store(
                CONFIG_ANJAY_ZEPHYR_NRF_MODEM_PSK_QUERY, &psk_key_info))) {
        LOG_ERR("Storing PSK key failed");
        return -1;
    }
    avs_crypto_psk_identity_info_t identity_info =
            avs_crypto_psk_identity_info_from_buffer(psk_identity,
                                                     strlen(psk_identity));
    if (avs_is_err(avs_crypto_psk_engine_identity_store(
                CONFIG_ANJAY_ZEPHYR_NRF_MODEM_PSK_QUERY, &identity_info))) {
        LOG_ERR("Storing PSK identity failed");
        return -1;
    }
#    endif /* defined(CONFIG_ANJAY_COMPAT_ZEPHYR_TLS) &&                      \
            * defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT) \
            */

    anjay_security_instance_t security_instance = {
        .ssid = 1,
        .bootstrap_server = bootstrap,
        .server_uri = server_uri,
        .security_mode = anjay_zephyr_config_get_security_mode()
    };
    switch (security_instance.security_mode) {
    case ANJAY_SECURITY_PSK:
#    if defined(CONFIG_ANJAY_COMPAT_ZEPHYR_TLS) \
            && defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)
        security_instance.psk_identity =
                avs_crypto_psk_identity_info_from_engine(
                        CONFIG_ANJAY_ZEPHYR_NRF_MODEM_PSK_QUERY);
        security_instance.psk_key = avs_crypto_psk_key_info_from_engine(
                CONFIG_ANJAY_ZEPHYR_NRF_MODEM_PSK_QUERY);
#    else  /* defined(CONFIG_ANJAY_COMPAT_ZEPHYR_TLS) &&                       \
            * defined(CONFIG_NRF_MODEM_LIB) &&  defined(CONFIG_MODEM_KEY_MGMT) \
            */
        security_instance.public_cert_or_psk_identity = psk_identity;
        security_instance.public_cert_or_psk_identity_size =
                strlen(security_instance.public_cert_or_psk_identity);
        security_instance.private_cert_or_psk_key = psk_key;
        security_instance.private_cert_or_psk_key_size = psk_size;
#    endif /* defined(CONFIG_ANJAY_COMPAT_ZEPHYR_TLS) &&                      \
            * defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT) \
            */
        break;
    case ANJAY_SECURITY_CERTIFICATE:
#    ifdef CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
        security_instance.public_cert_or_psk_identity = public_cert;
        security_instance.public_cert_or_psk_identity_size =
                strlen(public_cert);
        security_instance.private_cert_or_psk_key = private_key;
        security_instance.private_cert_or_psk_key_size = strlen(private_key);
#    else  // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
        LOG_ERR("Certificate security is not supported");
        return -1;
#    endif // CONFIG_ANJAY_ZEPHYR_RUNTIME_CERT_CONFIG
        break;

    default:
        break;
    }

    anjay_iid_t security_instance_id = ANJAY_ID_INVALID;

    if (anjay_security_object_add_instance(anjay, &security_instance,
                                           &security_instance_id)) {
        LOG_ERR("Failed to instantiate Security object");
        return -1;
    }

    if (!bootstrap) {
        const anjay_server_instance_t server_instance = {
            .ssid = 1,
            .lifetime = anjay_zephyr_config_get_lifetime(),
            .default_min_period = -1,
            .default_max_period = -1,
            .disable_timeout = -1,
            .binding = "U"
        };

        anjay_iid_t server_instance_id = ANJAY_ID_INVALID;

        if (anjay_server_object_add_instance(anjay, &server_instance,
                                             &server_instance_id)) {
            LOG_ERR("Failed to instantiate Server object");
            return -1;
        }
    }
    return 0;
}

static int configure_servers_and_security_objects_from_params(anjay_t *anjay) {
    if (anjay_zephyr_init_params.security_instances) {
        for (size_t i = 0;
             i < anjay_zephyr_init_params.security_instances_count;
             i++) {
            if (anjay_security_object_add_instance(
                        anjay,
                        &anjay_zephyr_init_params.security_instances[i],
                        &anjay_zephyr_init_params
                                 .inout_security_instance_ids[i])) {
                LOG_ERR("Failed to instantiate Security object with id: %d",
                        anjay_zephyr_init_params
                                .inout_security_instance_ids[i]);
                return -1;
            }
        }
    }

    if (anjay_zephyr_init_params.server_instances) {
        for (size_t i = 0; i < anjay_zephyr_init_params.server_instances_count;
             i++) {
            if (anjay_server_object_add_instance(
                        anjay,
                        &anjay_zephyr_init_params.server_instances[i],
                        &anjay_zephyr_init_params
                                 .inout_server_instance_ids[i])) {
                LOG_ERR("Failed to instantiate Server object with id: %d",
                        anjay_zephyr_init_params.inout_server_instance_ids[i]);
                return -1;
            }
        }
    }
    return 0;
}

static int configure_servers_and_security_objects(anjay_t *anjay) {
    if (!anjay_zephyr_init_params.security_instances
                    != !anjay_zephyr_init_params.inout_security_instance_ids
            || !anjay_zephyr_init_params.server_instances
                           != !anjay_zephyr_init_params
                                       .inout_server_instance_ids) {
        LOG_ERR("Wrong initialization parameters, if user provides "
                "Server/Security instances, instance IDs must also be passed");
        return -1;
    }

    if ((!anjay_zephyr_init_params.security_instances
         && anjay_zephyr_init_params.server_instances)
            || anjay_zephyr_init_params.security_instances_count
                           < anjay_zephyr_init_params.server_instances_count) {
        LOG_ERR("Wrong initialization parameters, lack of Security instances");
        return -1;
    } else if (!anjay_zephyr_init_params.security_instances
               && !anjay_zephyr_init_params.server_instances) {
        if (configure_servers_and_security_objects_from_settings(anjay)) {
            return -1;
        }
    } else {
        if (configure_servers_and_security_objects_from_params(anjay)) {
            return -1;
        }
    }
    return 0;
}
#endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING

static anjay_t *initialize_anjay(void) {
    anjay_t *anjay;
    if (anjay_zephyr_init_params.anjay_config) {
        anjay = anjay_new(anjay_zephyr_init_params.anjay_config);
    } else {
#ifndef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
        char endpoint_name[EP_NAME_STORAGE_SIZE];
        if (anjay_zephyr_config_get_endpoint_name(endpoint_name,
                                                  sizeof(endpoint_name))) {
            LOG_ERR("Unable to configure Anjay");
            return NULL;
        }
#endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
        const anjay_configuration_t config = {
#ifdef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
            .endpoint_name = anjay_zephyr_config_default_ep_name(),
#else  // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
            .endpoint_name = endpoint_name,
#endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
            .in_buffer_size = 4000,
            .out_buffer_size = 4000,
            .udp_dtls_hs_tx_params =
                    &(const avs_net_dtls_handshake_timeouts_t) {
                        // Change the default DTLS handshake parameters so that
                        // "anjay stop" is more responsive; note that an
                        // exponential backoff is implemented, so the maximum of
                        // 8 seconds adds up to up to 15 seconds in total.
                        .min = {
                            .seconds = 1,
                            .nanoseconds = 0
                        },
                        .max = {
                            .seconds = 8,
                            .nanoseconds = 0
                        }
                    },
            .disable_legacy_server_initiated_bootstrap = true
        };
        anjay = anjay_new(&config);
    }
    if (!anjay) {
        LOG_ERR("Could not create Anjay object");
        return NULL;
    }

    if (anjay_security_object_install(anjay)
            || anjay_server_object_install(anjay)
#ifdef CONFIG_ANJAY_ZEPHYR_PERSISTENCE
            // Access Control object is necessary if Server Object with many
            // servers is loaded
            || anjay_access_control_install(anjay)
#endif // CONFIG_ANJAY_ZEPHYR_PERSISTENCE
    ) {
        LOG_ERR("Failed to install necessary modules");
        goto error;
    }

#ifdef CONFIG_ANJAY_ZEPHYR_FOTA
    if (_anjay_zephyr_fw_update_install(anjay)) {
        LOG_ERR("Failed to initialize fw update module");
        goto error;
    }
#endif // CONFIG_ANJAY_ZEPHYR_FOTA

#ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160
    if (_anjay_zephyr_afu_nrf9160_install(anjay)) {
        LOG_ERR("Failed to initialize advanced fw update module");
        goto error;
    }
#endif // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160

    device_obj = _anjay_zephyr_device_object_create();
    if (!device_obj || anjay_register_object(anjay, device_obj)) {
        LOG_ERR("Failed to register Device object");
        goto error;
    }

#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
    struct anjay_zephyr_nrf_lc_info nrf_lc_info;

    _anjay_zephyr_nrf_lc_info_get(&nrf_lc_info);

    anjay_zephyr_conn_mon_obj =
            _anjay_zephyr_conn_mon_object_create(&nrf_lc_info);
    if (anjay_zephyr_conn_mon_obj) {
        anjay_register_object(anjay, anjay_zephyr_conn_mon_obj);
    }

    anjay_zephyr_ecid_obj = _anjay_zephyr_ecid_object_create(&nrf_lc_info);

    if (anjay_zephyr_ecid_obj) {
        anjay_register_object(anjay, anjay_zephyr_ecid_obj);
    }
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES
    _anjay_zephyr_location_services_init();
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
    anjay_zephyr_ground_fix_location_obj =
            _anjay_zephyr_ground_fix_location_object_create();
    if (anjay_zephyr_ground_fix_location_obj) {
        anjay_register_object(anjay, anjay_zephyr_ground_fix_location_obj);
    }
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_ASSISTANCE
    anjay_zephyr_gnss_assistance_obj =
            _anjay_zephyr_gnss_assistance_object_create();
    if (anjay_zephyr_gnss_assistance_obj) {
        anjay_register_object(anjay, anjay_zephyr_gnss_assistance_obj);
    }
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_ASSISTANCE

    if (execute_user_callback(anjay, ANJAY_ZEPHYR_LWM2M_CALLBACK_REASON_INIT)) {
        goto error;
    }

#ifdef CONFIG_ANJAY_ZEPHYR_PERSISTENCE
    if (anjay_zephyr_config_is_use_persistence()
            && !_anjay_zephyr_restore_anjay_from_persistence(anjay)) {
        return anjay;
    }
#endif // CONFIG_ANJAY_ZEPHYR_PERSISTENCE
#ifdef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
    if (!_anjay_zephyr_restore_anjay_from_factory_provisioning(anjay)) {
        return anjay;
    }
#else  // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
    if (!configure_servers_and_security_objects(anjay)) {
        return anjay;
    }
#endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING

error:
    LOG_ERR("Failed to initialize anjay zephyr");
    deinitialize_anjay(anjay);
    return NULL;
}

#ifndef ANJAY_ZEPHYR_NO_NETWORK_MGMT
static void update_anjay_network_bearer_unlocked(
        anjay_t *anjay, enum anjay_zephyr_network_bearer_t bearer) {
    static bool anjay_online;

    if (anjay_online && !_anjay_zephyr_network_bearer_valid(bearer)) {
        LOG_INF("Anjay is now offline");
        if (!anjay_transport_enter_offline(anjay, ANJAY_TRANSPORT_SET_ALL)) {
            anjay_online = false;
        }
    } else if (_anjay_zephyr_network_bearer_valid(bearer)
               && (!anjay_online || anjay_last_known_bearer != bearer)) {
        LOG_INF("Anjay is now online on bearer %d", (int) bearer);
        if (anjay_last_known_bearer != bearer) {
            if (!anjay_transport_schedule_reconnect(anjay,
                                                    ANJAY_TRANSPORT_SET_ALL)) {
                anjay_last_known_bearer = bearer;
                anjay_online = true;
            }
        } else if (!anjay_transport_exit_offline(anjay,
                                                 ANJAY_TRANSPORT_SET_ALL)) {
            anjay_online = true;
        }
    }
}

static void update_anjay_network_bearer_job(avs_sched_t *sched,
                                            const void *dummy) {
    ARG_UNUSED(dummy);

    SYNCHRONIZED(anjay_zephyr_global_anjay_mutex) {
        if (anjay_zephyr_global_anjay) {
            update_anjay_network_bearer_unlocked(
                    anjay_zephyr_global_anjay,
                    _anjay_zephyr_network_current_bearer());
        }
    }
}

void _anjay_zephyr_sched_update_anjay_network_bearer(void) {
    static avs_sched_handle_t job_handle;

    SYNCHRONIZED(anjay_zephyr_global_anjay_mutex) {
        if (anjay_zephyr_global_anjay) {
            AVS_SCHED_NOW(anjay_get_scheduler(anjay_zephyr_global_anjay),
                          &job_handle, update_anjay_network_bearer_job, NULL,
                          0);
        }
    }
}
#endif // ANJAY_ZEPHYR_NO_NETWORK_MGMT

#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
static void update_objects_nrf_lc_info(anjay_t *anjay) {
    struct anjay_zephyr_nrf_lc_info nrf_lc_info;
    if (_anjay_zephyr_nrf_lc_info_get_if_changed(&nrf_lc_info)) {
        _anjay_zephyr_conn_mon_object_update(anjay, anjay_zephyr_conn_mon_obj,
                                             &nrf_lc_info);
        _anjay_zephyr_ecid_object_update(anjay, anjay_zephyr_ecid_obj,
                                         &nrf_lc_info);
    }
}
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
static bool agps_requested;

static void
agps_request_cb(anjay_zephyr_location_services_request_result_t result) {
    static uint32_t exponential_backoff;
    static uint32_t request_result_failed_in_row;
    if (result == ANJAY_ZEPHYR_LOCATION_SERVICES_SUCCESSFUL) {
        _anjay_zephyr_gps_clear_modem_agps_request_mask();
        exponential_backoff = 0;
        request_result_failed_in_row = 0;
        agps_requested = false;
    } else if (result != ANJAY_ZEPHYR_LOCATION_SERVICES_PERMANENT_FAILURE
               && _anjay_zephyr_gps_fetch_modem_agps_request_mask()) {

        SYNCHRONIZED(anjay_zephyr_global_anjay_mutex) {
            if (anjay_zephyr_global_anjay) {
                exponential_backoff =
                        _anjay_zephyr_location_services_calculate_backoff(
                                request_result_failed_in_row++);

                LOG_WRN("A-GPS request failed, trying again with exponential "
                        "backoff "
                        "%" PRIu32 "s",
                        exponential_backoff);

                struct anjay_zephyr_agps_request_job_args args = {
                    .anjay = anjay_zephyr_global_anjay,
                    .cb = agps_request_cb,
                    .request_mask =
                            _anjay_zephyr_gps_fetch_modem_agps_request_mask(),
                    .exponential_backoff = true
                };

                AVS_SCHED_DELAYED(anjay_get_scheduler(args.anjay), NULL,
                                  avs_time_duration_from_scalar(
                                          exponential_backoff, AVS_TIME_S),
                                  _anjay_zephyr_agps_request_job, &args,
                                  sizeof(args));
            } else {
                LOG_WRN("Anjay is not running");
                exponential_backoff = 0;
                request_result_failed_in_row = 0;
                agps_requested = false;
            }
        }
    }
}

#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS

static void update_internal_objects_and_persistence(avs_sched_t *sched,
                                                    const void *anjay_ptr) {
    anjay_t *anjay = *(anjay_t *const *) anjay_ptr;

    _anjay_zephyr_device_object_update(anjay, device_obj);

#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
    update_objects_nrf_lc_info(anjay);
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
    uint32_t request_mask = _anjay_zephyr_gps_fetch_modem_agps_request_mask();

    if (request_mask && !agps_requested
            && !_anjay_zephyr_send_agps_request(anjay, agps_request_cb,
                                                request_mask, true)) {
        LOG_INF("Modem requests A-GPS data");
        agps_requested = true;
    }
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS

#ifdef CONFIG_ANJAY_ZEPHYR_PERSISTENCE
    if (anjay_zephyr_config_is_use_persistence()
            && _anjay_zephyr_persist_anjay_if_required(anjay)) {
        LOG_ERR("Couldn't persist Anjay's state!");
    }
#endif // CONFIG_ANJAY_ZEPHYR_PERSISTENCE

    AVS_SCHED_DELAYED(sched, &update_internal_objects_and_persistence_handle,
                      avs_time_duration_from_scalar(1, AVS_TIME_S),
                      update_internal_objects_and_persistence, &anjay,
                      sizeof(anjay));
}

static void run_anjay(void *arg1, void *arg2, void *arg3) {
    ARG_UNUSED(arg1);
    ARG_UNUSED(arg2);
    ARG_UNUSED(arg3);

    while (atomic_load(&anjay_zephyr_anjay_running)) {
        LOG_INF("Connecting to the network...");

        if (_anjay_zephyr_network_connect_async()) {
            LOG_ERR("Could not initiate connection");
            continue;
        }

        if (_anjay_zephyr_network_wait_for_connected_interruptible()) {
            LOG_ERR("Could not connect to the network");
            goto disconnect;
        }

        LOG_INF("Connected to network");

        k_sem_reset(&synchronize_clock_sem);
        synchronize_clock();
        if (k_sem_take(&synchronize_clock_sem, K_SECONDS(30))) {
            LOG_WRN("Could not synchronize system clock within timeout, "
                    "continuing without real time...");
        }

        anjay_t *anjay = initialize_anjay();

        if (!anjay) {
            goto disconnect;
        }

        LOG_INF("Successfully created thread");

        SYNCHRONIZED(anjay_zephyr_global_anjay_mutex) {
            anjay_zephyr_global_anjay = anjay;

#ifndef ANJAY_ZEPHYR_NO_NETWORK_MGMT
            anjay_last_known_bearer = (enum anjay_zephyr_network_bearer_t) 0;
            update_anjay_network_bearer_unlocked(
                    anjay, _anjay_zephyr_network_current_bearer());
#endif // ANJAY_ZEPHYR_NO_NETWORK_MGMT
        }

#ifdef CONFIG_ANJAY_ZEPHYR_PERSISTENCE
        if (anjay_zephyr_config_is_use_persistence()
                && _anjay_zephyr_persist_anjay(anjay)) {
            LOG_ERR("Couldn't persist Anjay's state!");
        }
#endif // CONFIG_ANJAY_ZEPHYR_PERSISTENCE

        // anjay stop could be called immediately after anjay start
        if (atomic_load(&anjay_zephyr_anjay_running)
                && !execute_user_callback(
                           anjay,
                           ANJAY_ZEPHYR_LWM2M_CALLBACK_REASON_ANJAY_READY)) {
            update_internal_objects_and_persistence(anjay_get_scheduler(anjay),
                                                    &anjay);
            anjay_event_loop_run_with_error_handling(
                    anjay, avs_time_duration_from_scalar(1, AVS_TIME_S));
        }
        execute_user_callback(
                anjay, ANJAY_ZEPHYR_LWM2M_CALLBACK_REASON_ANJAY_SHUTTING_DOWN);
        avs_sched_del(&update_internal_objects_and_persistence_handle);

#ifdef CONFIG_ANJAY_ZEPHYR_PERSISTENCE
        if (anjay_zephyr_config_is_use_persistence()
                && _anjay_zephyr_persist_anjay_if_required(anjay)) {
            LOG_ERR("Couldn't persist Anjay's state!");
        }
#endif // CONFIG_ANJAY_ZEPHYR_PERSISTENCE

        SYNCHRONIZED(anjay_zephyr_global_anjay_mutex) {
            anjay_zephyr_global_anjay = NULL;
        }
        deinitialize_anjay(anjay);

#ifdef CONFIG_ANJAY_ZEPHYR_FOTA
        if (_anjay_zephyr_fw_update_requested()) {
            _anjay_zephyr_fw_update_reboot();
        }
#endif // CONFIG_ANJAY_ZEPHYR_FOTA

#ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160
        if (_anjay_zephyr_afu_nrf9160_requested()) {
            _anjay_zephyr_afu_nrf9160_reboot();
        }
#endif // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160

    disconnect:
#ifdef CONFIG_ANJAY_ZEPHYR_GPS
        _anjay_zephyr_stop_gps();
#endif // CONFIG_ANJAY_ZEPHYR_GPS
        _anjay_zephyr_network_disconnect();
    }
    atomic_store(&anjay_thread_running, false);
}

static int anjay_zephyr_lwm2m_init(void) {
    if (atomic_load(&device_initialized)) {
        LOG_ERR("Device already initialized");
        return -1;
    }
#ifdef WITH_ANJAY_ZEPHYR_CONFIG
    _anjay_zephyr_config_init();
#endif // WITH_ANJAY_ZEPHYR_CONFIG

#ifdef CONFIG_ANJAY_ZEPHYR_PERSISTENCE
    if (anjay_zephyr_persistence_init()) {
        LOG_ERR("Can't initialize persistence");
    }
#endif // CONFIG_ANJAY_ZEPHYR_PERSISTENCE
    _anjay_zephyr_init_workqueue();

    time_sync_failed = false;
    k_work_init_delayable(&sync_clock_work,
                          retry_synchronize_clock_work_handler);

    if (_anjay_zephyr_network_initialize()) {
        LOG_ERR("Cannot initialize the network");
        LOG_PANIC();
        abort();
    }
#ifdef CONFIG_ANJAY_ZEPHYR_GPS
    _anjay_zephyr_initialize_gps();
#endif // CONFIG_ANJAY_ZEPHYR_GPS

#ifdef CONFIG_ANJAY_ZEPHYR_FOTA
    _anjay_zephyr_fw_update_apply();
#endif // CONFIG_ANJAY_ZEPHYR_FOTA

#ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160
    _anjay_zephyr_afu_nrf9160_application_apply();
    _anjay_zephyr_afu_nrf9160_modem_apply();
#endif // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160

#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
    if (_anjay_zephyr_initialize_nrf_lc_info_listener()) {
        LOG_ERR("Can't initialize Link Control info listener");
        LOG_PANIC();
        abort();
    }
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

    atomic_store(&device_initialized, true);
    return 0;
}

int anjay_zephyr_lwm2m_init_from_user_params(
        anjay_zephyr_init_params_t *user_params) {
    if (!user_params) {
        LOG_ERR("Initialization failed, NULL argument");
        return -1;
    }

    if (anjay_zephyr_lwm2m_init()) {
        return -1;
    }
    anjay_zephyr_init_params = *user_params;
    return 0;
}

int anjay_zephyr_lwm2m_init_from_settings(void) {
    if (anjay_zephyr_lwm2m_init()) {
        return -1;
    }
    return 0;
}

int anjay_zephyr_lwm2m_start(void) {
    if (!atomic_load(&device_initialized)) {
        LOG_WRN("Cannot start Anjay - device initialization is ongoing "
                "(perhaps it hasn't connected to network yet)");
        return -1;
    }

    if (!atomic_load(&anjay_zephyr_anjay_running)) {
#ifdef WITH_ANJAY_ZEPHYR_CONFIG
        LOG_INF("Saving config");
        _anjay_zephyr_config_save();
#endif // WITH_ANJAY_ZEPHYR_CONFIG
        LOG_INF("Starting Anjay");

        atomic_store(&anjay_zephyr_anjay_running, true);
        SYNCHRONIZED(anjay_thread_running_mutex) {
            k_tid_t tid;
            if (!(tid = k_thread_create(&anjay_thread, anjay_stack,
                                        CONFIG_ANJAY_ZEPHYR_THREAD_STACK_SIZE,
                                        run_anjay, NULL, NULL, NULL,
                                        CONFIG_ANJAY_ZEPHYR_THREAD_PRIORITY, 0,
                                        K_NO_WAIT))) {
                LOG_ERR("Failed to create Anjay thread");
                atomic_store(&anjay_zephyr_anjay_running, false);
                return -1;
            }
            k_thread_name_set(tid, "Anjay Zephyr");
            atomic_store(&anjay_thread_running, true);
        }
    } else {
        LOG_WRN("Cannot start Anjay - already running");
    }
    return 0;
}

static void interrupt_anjay(avs_sched_t *sched, const void *anjay_ptr) {
    anjay_event_loop_interrupt(*(anjay_t *const *) anjay_ptr);
}

int anjay_zephyr_lwm2m_stop(void) {
    if (atomic_load(&anjay_zephyr_anjay_running)) {
        // change the flag first to interrupt the thread if event loop is
        // not running yet
        atomic_store(&anjay_zephyr_anjay_running, false);
        _anjay_zephyr_network_interrupt_connect_wait_loop();

        SYNCHRONIZED(anjay_zephyr_global_anjay_mutex) {
            if (anjay_zephyr_global_anjay) {
                // hack to make sure that anjay_event_loop_interrupt() is
                // called only when the event loop is running
                anjay_t *anjay = anjay_zephyr_global_anjay;

                AVS_SCHED_NOW(anjay_get_scheduler(anjay), NULL, interrupt_anjay,
                              &anjay, sizeof(anjay));
            }
        }

        SYNCHRONIZED(anjay_thread_running_mutex) {
            if (atomic_load(&anjay_thread_running)) {
                k_thread_join(&anjay_thread, K_FOREVER);
            }
        }
    } else {
        LOG_WRN("Anjay is not running");
        return -1;
    }
    return 0;
}
