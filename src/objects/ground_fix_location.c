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
#include <inttypes.h>
#include <stdbool.h>

#include <anjay/anjay.h>
#include <anjay/server.h>
#include <avsystem/commons/avs_defs.h>
#include <avsystem/commons/avs_memory.h>

#include <zephyr/logging/log.h>

#include "../utils.h"
#include "location_services.h"
#include "objects.h"

LOG_MODULE_REGISTER(anjay_zephyr_ground_fix_location);

static int32_t result_code_backup;

typedef struct ground_fix_location_object_struct {
    const anjay_dm_object_def_t *def;
    int32_t result_code;
    anjay_zephyr_location_services_ground_fix_location_t location_current;
    anjay_zephyr_location_services_ground_fix_location_t location_backup;
    bool send_location_back;
    bool send_location_back_set;

    uint32_t exponential_backoff;
    uint32_t positive_result_code_in_row;

    bool new_result_code;

    struct k_mutex mutex;
} ground_fix_location_object_t;

static inline ground_fix_location_object_t *
get_obj(const anjay_dm_object_def_t *const *obj_ptr) {
    assert(obj_ptr);
    return AVS_CONTAINER_OF(obj_ptr, ground_fix_location_object_t, def);
}

static int instance_reset(anjay_t *anjay,
                          const anjay_dm_object_def_t *const *obj_ptr,
                          anjay_iid_t iid) {
    (void) anjay;
    (void) iid;

    ground_fix_location_object_t *obj = get_obj(obj_ptr);
    assert(obj);
    assert(iid == 0);
    SYNCHRONIZED(obj->mutex) {
        memset(&obj->location_current, 0, sizeof(obj->location_current));
        obj->send_location_back_set = false;
        obj->positive_result_code_in_row = 0;
        obj->exponential_backoff = 0;
        obj->new_result_code = false;
        if (obj->result_code > 0) {
            obj->result_code = 0;
        }
        result_code_backup = obj->result_code;
    }
    return 0;
}

static int list_resources(anjay_t *anjay,
                          const anjay_dm_object_def_t *const *obj_ptr,
                          anjay_iid_t iid,
                          anjay_dm_resource_list_ctx_t *ctx) {
    (void) anjay;
    (void) iid;

    anjay_dm_emit_res(ctx, RID_GROUND_FIX_LOC_SEND_LOCATION_BACK,
                      ANJAY_DM_RES_R, ANJAY_DM_RES_ABSENT);
    anjay_dm_emit_res(ctx, RID_GROUND_FIX_LOC_RESULT_CODE, ANJAY_DM_RES_W,
                      ANJAY_DM_RES_PRESENT);
    anjay_dm_emit_res(ctx, RID_GROUND_FIX_LOC_LATITUDE, ANJAY_DM_RES_W,
                      ANJAY_DM_RES_PRESENT);
    anjay_dm_emit_res(ctx, RID_GROUND_FIX_LOC_LONGITUDE, ANJAY_DM_RES_W,
                      ANJAY_DM_RES_PRESENT);
    anjay_dm_emit_res(ctx, RID_GROUND_FIX_LOC_ACCURACY, ANJAY_DM_RES_W,
                      ANJAY_DM_RES_PRESENT);
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

    ground_fix_location_object_t *obj = get_obj(obj_ptr);
    assert(obj);
    assert(iid == 0);
    int result = ANJAY_ERR_METHOD_NOT_ALLOWED;
    SYNCHRONIZED(obj->mutex) {
        switch (rid) {
        case RID_GROUND_FIX_LOC_RESULT_CODE: {
            assert(riid == ANJAY_ID_INVALID);
            obj->new_result_code = true;
            result = anjay_get_i32(ctx, &obj->result_code);
            break;
        }

        case RID_GROUND_FIX_LOC_LATITUDE: {
            assert(riid == ANJAY_ID_INVALID);
            result = anjay_get_double(ctx, &obj->location_current.latitude);
            break;
        }

        case RID_GROUND_FIX_LOC_LONGITUDE: {
            assert(riid == ANJAY_ID_INVALID);
            result = anjay_get_double(ctx, &obj->location_current.longitude);
            break;
        }

        case RID_GROUND_FIX_LOC_ACCURACY: {
            assert(riid == ANJAY_ID_INVALID);
            result = anjay_get_double(ctx, &obj->location_current.accuracy);
            break;
        }
        }
    }
    return result;
}

static int transaction_begin(anjay_t *anjay,
                             const anjay_dm_object_def_t *const *obj_ptr) {
    (void) anjay;

    ground_fix_location_object_t *obj = get_obj(obj_ptr);
    SYNCHRONIZED(obj->mutex) {
        obj->location_backup = obj->location_current;
    }
    return 0;
}

static inline int validate_latitude_angle(double angle) {
    return isfinite(angle) && angle >= -90.0 && angle <= 90.0 ? 0 : -1;
}

static inline int validate_longitude_angle(double angle) {
    return isfinite(angle) && angle >= -180.0 && angle <= 180.0 ? 0 : -1;
}

static inline int accuracy_validate(double accuracy) {
    return isfinite(accuracy) && accuracy >= 0 ? 0 : -1;
}

static int transaction_validate(anjay_t *anjay,
                                const anjay_dm_object_def_t *const *obj_ptr) {
    (void) anjay;

    ground_fix_location_object_t *obj = get_obj(obj_ptr);
    SYNCHRONIZED(obj->mutex) {
        // NOTE: we expect that if the server sends a non-zero result code then
        // it will not send the coordinates
        if ((obj->location_current.latitude != obj->location_backup.latitude
             || obj->location_current.longitude
                        != obj->location_backup.longitude
             || obj->location_current.accuracy != obj->location_backup.accuracy)
                && obj->result_code) {
            return ANJAY_ERR_BAD_REQUEST;
        }

        if (validate_latitude_angle(obj->location_current.latitude)
                || validate_longitude_angle(obj->location_current.longitude)
                || accuracy_validate(obj->location_current.accuracy)) {
            return ANJAY_ERR_BAD_REQUEST;
        }
    }
    return 0;
}

static int transaction_commit(anjay_t *anjay,
                              const anjay_dm_object_def_t *const *obj_ptr) {
    (void) anjay;

    ground_fix_location_object_t *obj = get_obj(obj_ptr);
    SYNCHRONIZED(obj->mutex) {
        result_code_backup = obj->result_code;

        if (obj->new_result_code) {
            obj->new_result_code = false;

            if (obj->result_code) {
                LOG_WRN("Received %" PRId32 " result code which means it is %s",
                        obj->result_code,
                        obj->result_code < 0
                                ? "permanent failure, further requests "
                                  "will not be processed"
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

            _anjay_zephyr_location_services_received_gf_location_req_response_from_server(
                    anjay, true, &obj->location_current);
        }
    }
    return 0;
}

static int transaction_rollback(anjay_t *anjay,
                                const anjay_dm_object_def_t *const *obj_ptr) {
    (void) anjay;

    ground_fix_location_object_t *obj = get_obj(obj_ptr);
    SYNCHRONIZED(obj->mutex) {
        obj->location_current = obj->location_backup;
        obj->result_code = result_code_backup;
        obj->new_result_code = false;
        _anjay_zephyr_location_services_received_gf_location_req_response_from_server(
                anjay, false, NULL);
    }
    return 0;
}

static const anjay_dm_object_def_t OBJ_DEF = {
    .oid = OID_GROUND_FIX_LOC,
    .handlers = {
        .list_instances = anjay_dm_list_instances_SINGLE,
        .instance_reset = instance_reset,

        .list_resources = list_resources,
        .resource_write = resource_write,

        .transaction_begin = transaction_begin,
        .transaction_validate = transaction_validate,
        .transaction_commit = transaction_commit,
        .transaction_rollback = transaction_rollback
    }
};

uint32_t _anjay_zephyr_ground_fix_location_get_exponential_backoff_value(
        const anjay_dm_object_def_t *const *obj_ptr) {
    uint32_t result = 0;
    ground_fix_location_object_t *obj = get_obj(obj_ptr);
    assert(obj);
    SYNCHRONIZED(obj->mutex) {
        result = obj->exponential_backoff;
    }
    return result;
}

int32_t _anjay_zephyr_ground_fix_location_get_result_code(
        const anjay_dm_object_def_t *const *obj_ptr) {
    int32_t result = 0;
    ground_fix_location_object_t *obj = get_obj(obj_ptr);
    assert(obj);
    SYNCHRONIZED(obj->mutex) {
        result = result_code_backup;
    }
    return result;
}

const anjay_dm_object_def_t **
_anjay_zephyr_ground_fix_location_object_create(void) {
    ground_fix_location_object_t *obj =
            (ground_fix_location_object_t *) avs_calloc(
                    1, sizeof(ground_fix_location_object_t));
    if (!obj) {
        return NULL;
    }
    obj->def = &OBJ_DEF;
    k_mutex_init(&obj->mutex);

    return &obj->def;
}

void _anjay_zephyr_ground_fix_location_object_release(
        const anjay_dm_object_def_t ***def) {
    if (def && *def) {
        ground_fix_location_object_t *obj = get_obj(*def);

        avs_free(obj);
        *def = NULL;
    }
}
