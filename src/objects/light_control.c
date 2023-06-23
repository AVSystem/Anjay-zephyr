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
#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include <anjay/anjay.h>
#include <avsystem/commons/avs_defs.h>
#include <avsystem/commons/avs_list.h>
#include <avsystem/commons/avs_memory.h>
#include <avsystem/commons/avs_utils.h>

#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>

#include "objects.h"

/**
 * On/Off value: RW, Single, Mandatory
 * type: Boolean, range: N/A, unit: N/A
 * On/off control. Boolean value where True is On and False is Off.
 */
#define RID_ON_OFF 5850

struct light_control_instance {
    struct gpio_dt_spec led;
    bool led_value;
    bool led_backup_value;
};

struct light_control_object {
    const anjay_dm_object_def_t *def;
    uint16_t number_of_instances;
    struct light_control_instance instances[];
};

static inline struct light_control_object *
get_obj(const anjay_dm_object_def_t *const *obj_ptr) {
    assert(obj_ptr);
    return AVS_CONTAINER_OF(obj_ptr, struct light_control_object, def);
}

static void led_set(struct light_control_instance *inst) {
    gpio_pin_set_dt(&inst->led, inst->led_value);
}

static int configure_led(struct light_control_object *obj,
                         const struct gpio_dt_spec *led,
                         anjay_iid_t iid) {
    if (!device_is_ready(led->port)) {
        return -1;
    }
    if (gpio_pin_configure_dt(led, GPIO_OUTPUT_INACTIVE)) {
        return -1;
    }

    struct light_control_instance *inst = &obj->instances[iid];
    inst->led = *led;
    inst->led_value = false;

    return 0;
}

static int resource_read(anjay_t *anjay,
                         const anjay_dm_object_def_t *const *obj_ptr,
                         anjay_iid_t iid,
                         anjay_rid_t rid,
                         anjay_riid_t riid,
                         anjay_output_ctx_t *ctx) {
    (void) anjay;

    struct light_control_object *obj = get_obj(obj_ptr);
    assert(obj);

    struct light_control_instance *inst = &obj->instances[iid];

    switch (rid) {
    case RID_ON_OFF:
        assert(riid == ANJAY_ID_INVALID);
        return anjay_ret_bool(ctx, inst->led_value);

    default:
        return ANJAY_ERR_METHOD_NOT_ALLOWED;
    }
}

static int resource_write(anjay_t *anjay,
                          const anjay_dm_object_def_t *const *obj_ptr,
                          anjay_iid_t iid,
                          anjay_rid_t rid,
                          anjay_riid_t riid,
                          anjay_input_ctx_t *ctx) {
    (void) anjay;

    struct light_control_object *obj = get_obj(obj_ptr);
    assert(obj);

    struct light_control_instance *inst = &obj->instances[iid];

    switch (rid) {
    case RID_ON_OFF: {
        assert(riid == ANJAY_ID_INVALID);
        return anjay_get_bool(ctx, &inst->led_value);
    }
    default:
        return ANJAY_ERR_METHOD_NOT_ALLOWED;
    }
}

static int list_resources(anjay_t *anjay,
                          const anjay_dm_object_def_t *const *obj_ptr,
                          anjay_iid_t iid,
                          anjay_dm_resource_list_ctx_t *ctx) {
    (void) anjay;
    (void) obj_ptr;
    (void) iid;

    anjay_dm_emit_res(ctx, RID_ON_OFF, ANJAY_DM_RES_RW, ANJAY_DM_RES_PRESENT);
    return 0;
}

static int list_instances(anjay_t *anjay,
                          const anjay_dm_object_def_t *const *obj_ptr,
                          anjay_dm_list_ctx_t *ctx) {
    (void) anjay;

    struct light_control_object *obj = get_obj(obj_ptr);
    for (uint16_t i = 0; i < obj->number_of_instances; i++) {
        anjay_dm_emit(ctx, i);
    }

    return 0;
}

static int transaction_begin(anjay_t *anjay,
                             const anjay_dm_object_def_t *const *obj_ptr) {
    (void) anjay;

    struct light_control_object *obj = get_obj(obj_ptr);

    for (uint16_t i = 0; i < obj->number_of_instances; i++) {
        obj->instances[i].led_backup_value = obj->instances[i].led_value;
    }

    return 0;
}

static int transaction_commit(anjay_t *anjay,
                              const anjay_dm_object_def_t *const *obj_ptr) {
    (void) anjay;

    struct light_control_object *obj = get_obj(obj_ptr);

    for (uint16_t i = 0; i < obj->number_of_instances; i++) {
        led_set(&obj->instances[i]);
    }

    return 0;
}

static int transaction_rollback(anjay_t *anjay,
                                const anjay_dm_object_def_t *const *obj_ptr) {
    (void) anjay;

    struct light_control_object *obj = get_obj(obj_ptr);

    for (uint16_t i = 0; i < obj->number_of_instances; i++) {
        obj->instances[i].led_value = obj->instances[i].led_backup_value;
    }

    return 0;
}

static const anjay_dm_object_def_t obj_def = {
    .oid = 3311,
    .handlers = {
        .list_instances = list_instances,
        .list_resources = list_resources,
        .resource_read = resource_read,
        .resource_write = resource_write,

        .transaction_begin = transaction_begin,
        .transaction_validate = anjay_dm_transaction_NOOP,
        .transaction_commit = transaction_commit,
        .transaction_rollback = transaction_rollback
    }
};

static const anjay_dm_object_def_t *obj_def_ptr = &obj_def;

const anjay_dm_object_def_t **
anjay_zephyr_light_control_object_create(const struct gpio_dt_spec *user_leds,
                                         uint16_t user_leds_len) {
    struct light_control_object *obj =
            (struct light_control_object *) avs_calloc(
                    1,
                    sizeof(struct light_control_object)
                            + sizeof(struct light_control_instance)
                                      * user_leds_len);
    if (!obj) {
        return NULL;
    }
    obj->def = obj_def_ptr;

    for (anjay_iid_t iid = 0; iid < user_leds_len; iid++) {
        if (configure_led(obj, &user_leds[iid], iid)) {
            const anjay_dm_object_def_t **out_def = &obj_def_ptr;
            anjay_zephyr_light_control_object_release(&out_def);
            return NULL;
        }
    }
    obj->number_of_instances = user_leds_len;

    return &obj->def;
}

void anjay_zephyr_light_control_object_release(
        const anjay_dm_object_def_t ***out_def) {
    const anjay_dm_object_def_t **def = *out_def;

    if (def) {
        struct light_control_object *obj = get_obj(def);
        avs_free(obj);
        *out_def = NULL;
    }
}
