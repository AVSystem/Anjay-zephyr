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

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <anjay/lwm2m_send.h>

#include "location_services.h"
#include "lwm2m_internal.h"
#include "objects/objects.h"
#include "utils.h"

#define SERVER_RESPONSE_TIMEOUT 90

LOG_MODULE_REGISTER(anjay_zephyr_location_services);

static struct k_mutex gf_location_request_mutex;

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
static anjay_zephyr_location_services_gf_location_request_cb_t
        *g_gf_location_request_cb;
static avs_sched_clb_t g_gf_location_request_exponential_backoff_job;
static anjay_zephyr_location_services_gf_location_request_type_t
        g_last_gf_location_request_type;
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
static _anjay_zephyr_location_services_agps_request_cb_t *g_agps_request_cb;
static avs_sched_clb_t g_agps_request_exponential_backoff_job;
static uint32_t g_last_request_mask;
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS

static struct {
    const char *const name;
    bool in_progress;
    avs_sched_handle_t failed_due_to_no_response_from_server_handle;
    bool exponential_backoff;
    avs_sched_clb_t *const exponential_backoff_job;
} g_requests[] = {
#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
    [LOCATION_SERVICES_REQUESTS_AGPS_REQUEST] = {
        .name = "A-GPS",
        .exponential_backoff_job = g_agps_request_exponential_backoff_job,
    },
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_P_GPS
    [LOCATION_SERVICES_REQUESTS_PGPS_REQUEST] = {
        .name = "P-GPS",
        .exponential_backoff_job = NULL
    },
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_P_GPS
#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
    [LOCATION_SERVICES_REQUESTS_CELL_REQUEST] = {
        .name = "Ground fix location",
        .exponential_backoff_job = g_gf_location_request_exponential_backoff_job
    }
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
};

static void
process_callback(anjay_zephyr_location_services_request_result_t result,
                 anjay_zephyr_location_services_ground_fix_location_t *location,
                 enum anjay_zephyr_location_services_requests req_kind) {
    SYNCHRONIZED(gf_location_request_mutex) {
        switch (req_kind) {
#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
        case LOCATION_SERVICES_REQUESTS_CELL_REQUEST:
            if (g_gf_location_request_cb) {
                g_gf_location_request_cb(
                        result,
                        location
                                ? *location
                                : (anjay_zephyr_location_services_ground_fix_location_t) {
                                      .latitude = NAN,
                                      .longitude = NAN,
                                      .accuracy = NAN
                                  });
            }
            break;
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
        case LOCATION_SERVICES_REQUESTS_AGPS_REQUEST:
            if (g_agps_request_cb) {
                g_agps_request_cb(result);
            }
            break;
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
        }
    }
}

static void request_failed_due_to_no_response_from_server(avs_sched_t *sched,
                                                          const void *data) {
    SYNCHRONIZED(gf_location_request_mutex) {
        enum anjay_zephyr_location_services_requests req_kind =
                (enum anjay_zephyr_location_services_requests) (uintptr_t) data;
        LOG_WRN("No response to %s request received from the server.",
                g_requests[req_kind].name);
        g_requests[req_kind].in_progress = false;
        process_callback(ANJAY_ZEPHYR_LOCATION_SERVICES_NO_RESPONSE, NULL,
                         req_kind);
    }
}

static void send_finished_handler(anjay_t *anjay,
                                  anjay_ssid_t ssid,
                                  const anjay_send_batch_t *batch,
                                  int result,
                                  void *data) {
    SYNCHRONIZED(gf_location_request_mutex) {
        enum anjay_zephyr_location_services_requests req_kind =
                (enum anjay_zephyr_location_services_requests) (uintptr_t) data;

        if (result != ANJAY_SEND_SUCCESS) {
            LOG_WRN("Failed to send %s request to SSID=%" PRIu16,
                    g_requests[req_kind].name, ssid);
            g_requests[req_kind].in_progress = false;
            process_callback(ANJAY_ZEPHYR_LOCATION_SERVICES_UNABLE_TO_SEND,
                             NULL, req_kind);
        } else {
            LOG_INF("Sent the %s request to SSID=%" PRIu16,
                    g_requests[req_kind].name, ssid);
#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
            if (req_kind == LOCATION_SERVICES_REQUESTS_CELL_REQUEST
                    && (g_last_gf_location_request_type
                                == ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_INFORM_SINGLE
                        || g_last_gf_location_request_type
                                   == ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_INFORM_MULTI)) {
                g_requests[req_kind].in_progress = false;
                process_callback(ANJAY_ZEPHYR_LOCATION_SERVICES_SUCCESSFUL,
                                 NULL, req_kind);
            } else
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
            {
                AVS_SCHED_DELAYED(
                        anjay_get_scheduler(anjay),
                        &g_requests[req_kind]
                                 .failed_due_to_no_response_from_server_handle,
                        avs_time_duration_from_scalar(SERVER_RESPONSE_TIMEOUT,
                                                      AVS_TIME_S),
                        request_failed_due_to_no_response_from_server,
                        &req_kind, sizeof(req_kind));
            }
        }
    }
}

static int
batch_compile_and_send(anjay_t *anjay,
                       anjay_send_batch_builder_t **builder_ptr,
                       enum anjay_zephyr_location_services_requests req_kind) {
    int result = -1;
    anjay_send_batch_t *batch = anjay_send_batch_builder_compile(builder_ptr);

    if (!batch) {
        LOG_ERR("Batch compilation failed");
        return result;
    }

    anjay_send_result_t send_result = anjay_send_deferrable(
            anjay, CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_SERVER_SSID, batch,
            send_finished_handler, (void *) (uintptr_t) req_kind);

    if (send_result) {
        LOG_ERR("Couldn't send the %s request to SSID=%" PRIu16 ", err: %d",
                g_requests[req_kind].name,
                CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_SERVER_SSID,
                (int) send_result);
    } else {
        result = 0;
    }

    anjay_send_batch_release(&batch);
    return result;
}

static void received_req_response_from_server(
        anjay_t *anjay,
        bool successful,
        enum anjay_zephyr_location_services_requests req_kind,
        anjay_zephyr_location_services_ground_fix_location_t *location,
        int32_t result_code,
        uint32_t backoff_value) {
    SYNCHRONIZED(gf_location_request_mutex) {
        avs_sched_del(&g_requests[req_kind]
                               .failed_due_to_no_response_from_server_handle);
        g_requests[req_kind].in_progress = false;

        if (!successful) {
            process_callback(ANJAY_ZEPHYR_LOCATION_SERVICES_IMPROPER_RESPONSE,
                             NULL, req_kind);
        } else if (result_code == 0) {
            process_callback(ANJAY_ZEPHYR_LOCATION_SERVICES_SUCCESSFUL,
                             location, req_kind);
        } else if (result_code > 0) {
            if (g_requests[req_kind].exponential_backoff) {
                LOG_WRN("Due to temporary failure request %s data again with "
                        "exponential backoff %" PRIu32 "s",
                        g_requests[req_kind].name, backoff_value);
                g_requests[req_kind].in_progress = true;

                AVS_SCHED_DELAYED(anjay_get_scheduler(anjay), NULL,
                                  avs_time_duration_from_scalar(backoff_value,
                                                                AVS_TIME_S),
                                  g_requests[req_kind].exponential_backoff_job,
                                  &anjay, sizeof(anjay));
            } else {
                process_callback(
                        ANJAY_ZEPHYR_LOCATION_SERVICES_TEMPORARY_FAILURE, NULL,
                        req_kind);
            }
        } else {
            process_callback(ANJAY_ZEPHYR_LOCATION_SERVICES_PERMANENT_FAILURE,
                             NULL, req_kind);
        }
    }
}

uint32_t
_anjay_zephyr_location_services_calculate_backoff(uint8_t backoff_number) {
    uint32_t exponential_backoff =
            LOCATION_SERVICES_MAXIMUM_EXPONENTIAL_BACKOFF;
    if (backoff_number < sizeof(long unsigned) * 8
            && UINT32_MAX / LOCATION_SERVICES_EXPONENTIAL_BACKOFF_INTERVAL
                           >= (1LU << backoff_number)) {
        exponential_backoff = LOCATION_SERVICES_EXPONENTIAL_BACKOFF_INTERVAL
                              * (1LU << backoff_number);
        exponential_backoff =
                exponential_backoff
                                > LOCATION_SERVICES_MAXIMUM_EXPONENTIAL_BACKOFF
                        ? LOCATION_SERVICES_MAXIMUM_EXPONENTIAL_BACKOFF
                        : exponential_backoff;
    }
    return exponential_backoff;
}

void _anjay_zephyr_location_services_init(void) {
    k_mutex_init(&gf_location_request_mutex);
}

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
static int send_gf_location_request(
        anjay_t *anjay,
        anjay_zephyr_location_services_gf_location_request_type_t
                request_type) {
    if (!anjay) {
        return -1;
    }

    if (_anjay_zephyr_ground_fix_location_get_result_code(
                anjay_zephyr_ground_fix_location_obj)
            < 0) {
        LOG_WRN("Permanent failure result code received, device will not retry "
                "ground fix location request until reboot");
        return -1;
    }

    anjay_send_batch_builder_t *builder = anjay_send_batch_builder_new();

    if (!builder) {
        LOG_ERR("Failed to allocate batch builder");
        return -1;
    }

    int result = _anjay_zephyr_conn_mon_object_add_to_batch(
            anjay, builder, anjay_zephyr_conn_mon_obj);
    if (result) {
        goto finalize_batch;
    }
    bool request =
            request_type
                    == ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_REQUEST_SINGLE
            || request_type
                       == ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_REQUEST_MULTI;
    if ((result = anjay_send_batch_add_bool(
                 builder, OID_GROUND_FIX_LOC, 0,
                 RID_GROUND_FIX_LOC_SEND_LOCATION_BACK, UINT16_MAX,
                 avs_time_real_now(), request))) {
        LOG_ERR("Failed to add location back value to bach, err: %d", result);
        goto finalize_batch;
    }

    if ((request_type
                 == ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_INFORM_MULTI
         || request_type
                    == ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_REQUEST_MULTI)
            && (result = _anjay_zephyr_ecid_object_add_to_batch(
                        anjay, builder, anjay_zephyr_ecid_obj))) {
        goto finalize_batch;
    }

    result = batch_compile_and_send(anjay, &builder,
                                    LOCATION_SERVICES_REQUESTS_CELL_REQUEST);

finalize_batch:
    anjay_send_batch_builder_cleanup(&builder);
    return result;
}

int anjay_zephyr_location_services_gf_location_request(
        anjay_t *anjay,
        anjay_zephyr_location_services_gf_location_request_cb_t *cb,
        anjay_zephyr_location_services_gf_location_request_type_t request_type,
        bool exponential_backoff) {
    int result = -1;

    SYNCHRONIZED(gf_location_request_mutex) {
        if (g_requests[LOCATION_SERVICES_REQUESTS_CELL_REQUEST].in_progress) {
            LOG_WRN("Ground fix location request already in progress");
        } else if (!send_gf_location_request(anjay, request_type)) {
            g_requests[LOCATION_SERVICES_REQUESTS_CELL_REQUEST].in_progress =
                    true;
            g_requests[LOCATION_SERVICES_REQUESTS_CELL_REQUEST]
                    .exponential_backoff = exponential_backoff;
            g_last_gf_location_request_type = request_type;
            g_gf_location_request_cb = cb;
            result = 0;
        }
    }
    return result;
}

static void
g_gf_location_request_exponential_backoff_job(avs_sched_t *sched,
                                              const void *anjay_ptr) {
    SYNCHRONIZED(gf_location_request_mutex) {
        if (send_gf_location_request(*(anjay_t *const *) anjay_ptr,
                                     g_last_gf_location_request_type)) {
            g_requests[LOCATION_SERVICES_REQUESTS_CELL_REQUEST].in_progress =
                    false;
            process_callback(ANJAY_ZEPHYR_LOCATION_SERVICES_UNABLE_TO_SEND,
                             NULL, LOCATION_SERVICES_REQUESTS_CELL_REQUEST);
        }
    }
}

void _anjay_zephyr_gf_location_request_job(
        avs_sched_t *sched, const void *gf_location_request_job_args_ptr) {
    LOG_INF("Manual request Ground fix location");
    struct anjay_zephyr_gf_location_request_job_args args =
            *(const struct anjay_zephyr_gf_location_request_job_args *)
                    gf_location_request_job_args_ptr;

    anjay_zephyr_location_services_gf_location_request(
            args.anjay, args.cb, args.request_type, false);
}

void _anjay_zephyr_location_services_received_gf_location_req_response_from_server(
        anjay_t *anjay,
        bool successful,
        anjay_zephyr_location_services_ground_fix_location_t *location) {
    received_req_response_from_server(
            anjay, successful, LOCATION_SERVICES_REQUESTS_CELL_REQUEST,
            location,
            _anjay_zephyr_ground_fix_location_get_result_code(
                    anjay_zephyr_ground_fix_location_obj),
            _anjay_zephyr_ground_fix_location_get_exponential_backoff_value(
                    anjay_zephyr_ground_fix_location_obj));
}

#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION

#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
static int send_agps_request(anjay_t *anjay, uint32_t request_mask) {
    if (!anjay) {
        return -1;
    }

    if (_anjay_zephyr_gnss_assistance_get_result_code(
                anjay_zephyr_gnss_assistance_obj)
            < 0) {
        LOG_WRN("Permanent failure result code received, device will not retry "
                "A-GPS request until reboot");
        return -1;
    }

    static const struct {
        uint32_t req_flag;
        const char *name;
    } agps_flag_names[] = {
        {
            .req_flag = LOC_SERVICES_A_GPS_MASK_UTC,
            .name = "UTC parameters"
        },
        {
            .req_flag = LOC_SERVICES_A_GPS_MASK_KLOBUCHAR,
            .name = "Klobuchar ionospheric correction parameters"
        },
        {
            .req_flag = LOC_SERVICES_A_GPS_MASK_NEQUICK,
            .name = "NeQuick ionospheric correction parameters"
        },
        {
            .req_flag = LOC_SERVICES_A_GPS_MASK_TOW,
            .name = "SV time of week"
        },
        {
            .req_flag = LOC_SERVICES_A_GPS_MASK_CLOCK,
            .name = "GPS system time"
        },
        {
            .req_flag = LOC_SERVICES_A_GPS_MASK_LOCATION,
            .name = "Position assistance parameters"
        },
        {
            .req_flag = LOC_SERVICES_A_GPS_MASK_INTEGRITY,
            .name = "Integrity assistance parameters"
        },
        {
            .req_flag = LOC_SERVICES_A_GPS_MASK_EPHEMERIS,
            .name = "GPS ephemeris"
        },
        {
            .req_flag = LOC_SERVICES_A_GPS_MASK_ALMANAC,
            .name = "GPS almanac"
        }
    };

    LOG_INF("Requesting following types of A-GPS data:");
    for (size_t i = 0; i < AVS_ARRAY_SIZE(agps_flag_names); i++) {
        if (agps_flag_names[i].req_flag & request_mask) {
            LOG_INF("%s", agps_flag_names[i].name);
        }
    }

    anjay_send_batch_builder_t *builder = anjay_send_batch_builder_new();

    if (!builder) {
        LOG_ERR("Failed to allocate batch builder");
        return -1;
    }

    int result = _anjay_zephyr_conn_mon_object_add_to_batch(
            anjay, builder, anjay_zephyr_conn_mon_obj);
    if (result) {
        goto finalize_batch;
    }

    avs_time_real_t current_timestamp = avs_time_real_now();
    // FIXME: current spec uses int for this resource, but uint is more
    // appropriate
    if ((result = anjay_send_batch_add_int(
                 builder, OID_GNSS_ASSISTANCE, 0,
                 RID_GNSS_ASSISTANCE_A_GPS_ASSISTANCE_MASK, UINT16_MAX,
                 current_timestamp, request_mask))) {
        LOG_ERR("Failed to add assistance mask to batch, err: %d", result);
        goto finalize_batch;
    }

    if ((result = anjay_send_batch_add_int(
                 builder, OID_GNSS_ASSISTANCE, 0,
                 RID_GNSS_ASSISTANCE_SATELLITE_ELEVATION_MASK, UINT16_MAX,
                 current_timestamp,
                 CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS_SATELLITE_ELEVATION_MASK))) { // todo
        LOG_ERR("Failed to add satellite elevation mask to batch, err: %d",
                result);
        goto finalize_batch;
    }

    if ((result = anjay_send_batch_add_int(
                 builder, OID_GNSS_ASSISTANCE, 0,
                 RID_GNSS_ASSISTANCE_ASSISTANCE_TYPE, UINT16_MAX,
                 current_timestamp, LOCATION_SERVICES_REQUESTS_AGPS_REQUEST))) {
        LOG_ERR("Failed to add assistance type to batch, err: %d", result);
        goto finalize_batch;
    }

    result = batch_compile_and_send(anjay, &builder,
                                    LOCATION_SERVICES_REQUESTS_AGPS_REQUEST);

finalize_batch:
    anjay_send_batch_builder_cleanup(&builder);
    return result;
}

int _anjay_zephyr_send_agps_request(
        anjay_t *anjay,
        _anjay_zephyr_location_services_agps_request_cb_t *cb,
        uint32_t request_mask,
        bool exponential_backoff) {
    int result = -1;

    if (g_requests[LOCATION_SERVICES_REQUESTS_AGPS_REQUEST].in_progress) {
        LOG_WRN("A-GPS request already in progress");
    } else if (!send_agps_request(anjay, request_mask)) {
        g_requests[LOCATION_SERVICES_REQUESTS_AGPS_REQUEST].in_progress = true;
        g_requests[LOCATION_SERVICES_REQUESTS_AGPS_REQUEST]
                .exponential_backoff = exponential_backoff;
        g_last_request_mask = request_mask;
        g_agps_request_cb = cb;
        result = 0;
    }
    return result;
}

static void g_agps_request_exponential_backoff_job(avs_sched_t *sched,
                                                   const void *anjay_ptr) {
    if (send_agps_request(*(anjay_t *const *) anjay_ptr, g_last_request_mask)) {
        g_requests[LOCATION_SERVICES_REQUESTS_AGPS_REQUEST].in_progress = false;
        process_callback(ANJAY_ZEPHYR_LOCATION_SERVICES_UNABLE_TO_SEND, NULL,
                         LOCATION_SERVICES_REQUESTS_AGPS_REQUEST);
    }
}

void _anjay_zephyr_agps_request_job(avs_sched_t *sched,
                                    const void *agps_job_args_ptr) {
    LOG_INF("Manual request of A-GPS data");
    struct anjay_zephyr_agps_request_job_args args =
            *(const struct anjay_zephyr_agps_request_job_args *)
                    agps_job_args_ptr;

    _anjay_zephyr_send_agps_request(args.anjay, args.cb, args.request_mask,
                                    args.exponential_backoff);
}

void _anjay_zephyr_location_services_received_agps_req_response_from_server(
        anjay_t *anjay, bool successful) {
    received_req_response_from_server(
            anjay, successful, LOCATION_SERVICES_REQUESTS_AGPS_REQUEST, NULL,
            _anjay_zephyr_gnss_assistance_get_result_code(
                    anjay_zephyr_gnss_assistance_obj),
            _anjay_zephyr_gnss_assistance_get_exponential_backoff_value(
                    anjay_zephyr_gnss_assistance_obj));
}
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
