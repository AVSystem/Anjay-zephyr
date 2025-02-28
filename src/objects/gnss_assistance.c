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

#include <assert.h>
#include <stdbool.h>

#include <zephyr/logging/log.h>

#if __has_include("ncs_version.h")
#    include "ncs_version.h"
#endif // __has_include("ncs_version.h")

#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
#    if NCS_VERSION_NUMBER >= 0x20463
#        include <net/nrf_cloud_agnss.h>
#    else // NCS_VERSION_NUMBER >= 0x20463
#        include <net/nrf_cloud_agps.h>
#        define nrf_cloud_agnss_process nrf_cloud_agps_process
#    endif // NCS_VERSION_NUMBER >= 0x20463
#endif     // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS

#include <anjay/anjay.h>
#include <avsystem/commons/avs_defs.h>
#include <avsystem/commons/avs_memory.h>

#include "../utils.h"
#include "location_services.h"
#include "objects.h"

LOG_MODULE_REGISTER(anjay_zephyr_gnss_assistance);

#define ASSISTANCE_DATA_BUF_SIZE 4096

#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_P_GPS
#    error "P-GPS not implemented yet"
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_P_GPS

static int32_t result_code_backup;

typedef struct gnss_assistance_object_struct {
    const anjay_dm_object_def_t *def;
    uint8_t assistance_data_buf[ASSISTANCE_DATA_BUF_SIZE];
    size_t assistance_data_len;
    int32_t result_code;

    uint32_t exponential_backoff;
    uint32_t positive_result_code_in_row;

    bool new_result_code;
} gnss_assistance_object_t;

static inline gnss_assistance_object_t *
get_obj(const anjay_dm_object_def_t *const *obj_ptr) {
    assert(obj_ptr);
    return AVS_CONTAINER_OF(obj_ptr, gnss_assistance_object_t, def);
}

static int instance_reset(anjay_t *anjay,
                          const anjay_dm_object_def_t *const *obj_ptr,
                          anjay_iid_t iid) {
    (void) anjay;
    (void) iid;

    gnss_assistance_object_t *obj = get_obj(obj_ptr);
    assert(obj);
    assert(iid == 0);

    obj->positive_result_code_in_row = 0;
    obj->exponential_backoff = 0;
    obj->new_result_code = false;
    if (obj->result_code > 0) {
        obj->result_code = 0;
    }
    result_code_backup = obj->result_code;
    return 0;
}

static int list_resources(anjay_t *anjay,
                          const anjay_dm_object_def_t *const *obj_ptr,
                          anjay_iid_t iid,
                          anjay_dm_resource_list_ctx_t *ctx) {
    (void) anjay;
    (void) iid;

    anjay_dm_emit_res(ctx, RID_GNSS_ASSISTANCE_ASSISTANCE_TYPE, ANJAY_DM_RES_R,
                      ANJAY_DM_RES_ABSENT);
#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
    anjay_dm_emit_res(ctx, RID_GNSS_ASSISTANCE_A_GPS_ASSISTANCE_MASK,
                      ANJAY_DM_RES_R, ANJAY_DM_RES_ABSENT);
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_P_GPS
    anjay_dm_emit_res(ctx, RID_GNSS_ASSISTANCE_P_GPS_PREDICTION_COUNT,
                      ANJAY_DM_RES_R, ANJAY_DM_RES_ABSENT);
    anjay_dm_emit_res(ctx, RID_GNSS_ASSISTANCE_P_GPS_PREDICTION_INTERVAL,
                      ANJAY_DM_RES_R, ANJAY_DM_RES_ABSENT);
    anjay_dm_emit_res(ctx, RID_GNSS_ASSISTANCE_P_GPS_START_GPS_DAY,
                      ANJAY_DM_RES_R, ANJAY_DM_RES_ABSENT);
    anjay_dm_emit_res(ctx, RID_GNSS_ASSISTANCE_P_GPS_START_TIME, ANJAY_DM_RES_R,
                      ANJAY_DM_RES_ABSENT);
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_P_GPS
    anjay_dm_emit_res(ctx, RID_GNSS_ASSISTANCE_ASSISTANCE_DATA, ANJAY_DM_RES_W,
                      ANJAY_DM_RES_PRESENT);
    anjay_dm_emit_res(ctx, RID_GNSS_ASSISTANCE_RESULT_CODE, ANJAY_DM_RES_W,
                      ANJAY_DM_RES_PRESENT);
#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
    anjay_dm_emit_res(ctx, RID_GNSS_ASSISTANCE_SATELLITE_ELEVATION_MASK,
                      ANJAY_DM_RES_R, ANJAY_DM_RES_PRESENT);
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
    return 0;
}

static int resource_write(anjay_t *anjay,
                          const anjay_dm_object_def_t *const *obj_ptr,
                          anjay_iid_t iid,
                          anjay_rid_t rid,
                          anjay_riid_t riid,
                          anjay_input_ctx_t *ctx) {
    (void) anjay;
    (void) iid;

    gnss_assistance_object_t *obj = get_obj(obj_ptr);
    assert(obj);
    assert(iid == 0);

    int result = ANJAY_ERR_METHOD_NOT_ALLOWED;
    switch (rid) {
    case RID_GNSS_ASSISTANCE_ASSISTANCE_DATA: {
        assert(riid == ANJAY_ID_INVALID);
        bool finished;
        int err = anjay_get_bytes(ctx, &obj->assistance_data_len, &finished,
                                  obj->assistance_data_buf,
                                  sizeof(obj->assistance_data_buf));

        if (err) {
            result = ANJAY_ERR_INTERNAL;
        } else if (!finished) {
            result = ANJAY_ERR_BAD_REQUEST;
        } else {
            result = 0;
        }
        break;
    }

    case RID_GNSS_ASSISTANCE_RESULT_CODE: {
        assert(riid == ANJAY_ID_INVALID);
        obj->new_result_code = true;
        result = anjay_get_i32(ctx, &obj->result_code);
        break;
    }
    }
    return result;
}

static int transaction_validate(anjay_t *anjay,
                                const anjay_dm_object_def_t *const *obj_ptr) {
    (void) anjay;

    gnss_assistance_object_t *obj = get_obj(obj_ptr);
    // NOTE: we expect that if the server sends a non-zero result code then
    // it will not send assistance data
    if (obj->result_code && obj->assistance_data_len) {
        return ANJAY_ERR_BAD_REQUEST;
    }
    return 0;
}

static int transaction_commit(anjay_t *anjay,
                              const anjay_dm_object_def_t *const *obj_ptr) {
    (void) anjay;

    gnss_assistance_object_t *obj = get_obj(obj_ptr);
    result_code_backup = obj->result_code;

    if (obj->new_result_code) {
        obj->new_result_code = false;

        if (obj->result_code) {
            LOG_WRN("Received %" PRId32 " result code which means it is %s",
                    obj->result_code,
                    obj->result_code < 0 ? "permanent failure, further "
                                           "requests will not be processed"
                                         : "temporary failure");
        }

        if (obj->result_code > 0) {
            obj->exponential_backoff =
                    _anjay_zephyr_location_services_calculate_backoff(
                            obj->positive_result_code_in_row++);
        } else {
            obj->exponential_backoff = 0;
            obj->positive_result_code_in_row = 0;
        }

#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
        _anjay_zephyr_location_services_received_agps_req_response_from_server(
                anjay, true);
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
    }

#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
    if (obj->assistance_data_len > 0) {
        LOG_INF("Received %zu bytes of A-GPS data", obj->assistance_data_len);

        int err = nrf_cloud_agnss_process(obj->assistance_data_buf,
                                          obj->assistance_data_len);
        obj->assistance_data_len = 0;

        if (err) {
            LOG_ERR("Unable to process A-GPS data, error: %d", err);
            return ANJAY_ERR_INTERNAL;
        } else {
            LOG_INF("A-GPS data processed");
        }
    }
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
    return 0;
}

static int transaction_rollback(anjay_t *anjay,
                                const anjay_dm_object_def_t *const *obj_ptr) {
    (void) anjay;

    gnss_assistance_object_t *obj = get_obj(obj_ptr);

    obj->result_code = result_code_backup;
    obj->new_result_code = false;
#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
    obj->assistance_data_len = 0;
    _anjay_zephyr_location_services_received_agps_req_response_from_server(
            anjay, false);
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS

    return 0;
}

static const anjay_dm_object_def_t OBJ_DEF = {
    .oid = OID_GNSS_ASSISTANCE,
    .handlers = {
        .list_instances = anjay_dm_list_instances_SINGLE,
        .instance_reset = instance_reset,

        .list_resources = list_resources,
        .resource_write = resource_write,

        .transaction_begin = anjay_dm_transaction_NOOP,
        .transaction_commit = transaction_commit,
        .transaction_validate = transaction_validate,
        .transaction_rollback = transaction_rollback
    }
};

int32_t _anjay_zephyr_gnss_assistance_get_result_code(void) {
    return result_code_backup;
}

uint32_t _anjay_zephyr_gnss_assistance_get_exponential_backoff_value(
        const anjay_dm_object_def_t *const *obj_ptr) {
    gnss_assistance_object_t *obj = get_obj(obj_ptr);
    assert(obj);
    return obj->exponential_backoff;
}

const anjay_dm_object_def_t **
_anjay_zephyr_gnss_assistance_object_create(void) {
    gnss_assistance_object_t *obj = (gnss_assistance_object_t *) avs_calloc(
            1, sizeof(gnss_assistance_object_t));
    if (!obj) {
        return NULL;
    }
    obj->def = &OBJ_DEF;

    return &obj->def;
}

void _anjay_zephyr_gnss_assistance_object_release(
        const anjay_dm_object_def_t ***def) {
    if (def && *def) {
        gnss_assistance_object_t *obj = get_obj(*def);

        avs_free(obj);
        *def = NULL;
    }
}
