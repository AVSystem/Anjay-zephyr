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

#include <anjay/anjay.h>
#include <anjay/ipso_objects.h>

#include <zephyr/drivers/sensor.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "objects.h"
#include "utils.h"

LOG_MODULE_REGISTER(anjay_zephyr_sensors);

enum axes { x_axis, y_axis, z_axis };

struct user_sensors {
    struct anjay_zephyr_ipso_sensor_oid_set *oid_sensors_sets;
    size_t user_oid_sensors_length;
};

static struct user_sensors user_basic_sensors;
static struct user_sensors user_three_axis_sensors;

static void basic_sensor_work_handler(struct k_work *work) {
    struct anjay_zephyr_ipso_sensor_sync_context *sync_ctx = CONTAINER_OF(
            work, struct anjay_zephyr_ipso_sensor_sync_context, work);
    struct anjay_zephyr_ipso_sensor_context *ctx = CONTAINER_OF(
            sync_ctx, struct anjay_zephyr_ipso_sensor_context, sync);

    struct sensor_value value;

    if (sensor_sample_fetch_chan(ctx->device, ctx->channel)
            || sensor_channel_get(ctx->device, ctx->channel, &value)) {
        sync_ctx->value[x_axis] = NAN;
    } else {
        sync_ctx->value[x_axis] = sensor_value_to_double(&value);
    }

    k_sem_give(&sync_ctx->sem);
}

static void three_axis_sensor_work_handler(struct k_work *work) {
    struct anjay_zephyr_ipso_sensor_sync_context *sync_ctx = CONTAINER_OF(
            work, struct anjay_zephyr_ipso_sensor_sync_context, work);
    struct anjay_zephyr_ipso_sensor_context *ctx = CONTAINER_OF(
            sync_ctx, struct anjay_zephyr_ipso_sensor_context, sync);

    struct sensor_value values[3];

    if (sensor_sample_fetch_chan(ctx->device, ctx->channel)
            || sensor_channel_get(ctx->device, ctx->channel, values)) {
        sync_ctx->value[x_axis] = NAN;
        sync_ctx->value[y_axis] = NAN;
        sync_ctx->value[z_axis] = NAN;
    } else {
        sync_ctx->value[x_axis] = sensor_value_to_double(&values[x_axis]);
        sync_ctx->value[y_axis] = sensor_value_to_double(&values[y_axis]);
        sync_ctx->value[z_axis] = sensor_value_to_double(&values[z_axis]);
    }

    k_sem_give(&sync_ctx->sem);
}

static int basic_sensor_get_value(anjay_iid_t iid, void *_ctx, double *value) {
    struct anjay_zephyr_ipso_sensor_context *ctx =
            (struct anjay_zephyr_ipso_sensor_context *) _ctx;

    _anjay_zephyr_k_work_submit(&ctx->sync.work);
    k_sem_take(&ctx->sync.sem, K_FOREVER);

    *value = ctx->sync.value[x_axis];

    if (isnan(*value)) {
        return -1;
    }

    if (ctx->scale_factor) {
        *value = (*value) * ctx->scale_factor;
    }

    return 0;
}

static int three_axis_sensor_get_values(anjay_iid_t iid,
                                        void *_ctx,
                                        double *x_value,
                                        double *y_value,
                                        double *z_value) {
    struct anjay_zephyr_ipso_sensor_context *ctx =
            (struct anjay_zephyr_ipso_sensor_context *) _ctx;

    _anjay_zephyr_k_work_submit(&ctx->sync.work);
    k_sem_take(&ctx->sync.sem, K_FOREVER);

    *x_value = ctx->sync.value[x_axis];
    *y_value = ctx->sync.value[y_axis];
    *z_value = ctx->sync.value[z_axis];

    if (isnan(*x_value) && isnan(*y_value) && isnan(*z_value)) {
        return -1;
    }

    if (ctx->scale_factor) {
        *x_value = (*x_value) * ctx->scale_factor;
        *y_value = (*y_value) * ctx->scale_factor;
        *z_value = (*z_value) * ctx->scale_factor;
    }

    return 0;
}

static int
sensor_sync_context_init(struct anjay_zephyr_ipso_sensor_sync_context *ctx,
                         bool three_axis) {
    ctx->value[x_axis] = NAN;
    ctx->value[y_axis] = NAN;
    ctx->value[z_axis] = NAN;
    if (three_axis) {
        k_work_init(&ctx->work, three_axis_sensor_work_handler);
    } else {
        k_work_init(&ctx->work, basic_sensor_work_handler);
    }
    return k_sem_init(&ctx->sem, 0, 1);
}

static int
sensors_install(anjay_t *anjay,
                struct anjay_zephyr_ipso_sensor_oid_set *user_oid_sensors,
                size_t user_oid_sensors_length,
                bool three_axis) {
    if (!anjay || !user_oid_sensors) {
        LOG_ERR("Sensors could not be installed");
        return -1;
    }

    if (three_axis && !user_three_axis_sensors.oid_sensors_sets) {
        user_three_axis_sensors.oid_sensors_sets = user_oid_sensors;
        user_three_axis_sensors.user_oid_sensors_length =
                user_oid_sensors_length;
    } else if (!three_axis && !user_basic_sensors.oid_sensors_sets) {
        user_basic_sensors.oid_sensors_sets = user_oid_sensors;
        user_basic_sensors.user_oid_sensors_length = user_oid_sensors_length;
    } else {
        LOG_ERR("%s sensors already installed",
                three_axis ? "Three-axis" : "Basic");
        return -1;
    }

    for (size_t oid_sensor_set = 0; oid_sensor_set < user_oid_sensors_length;
         oid_sensor_set++) {
        struct anjay_zephyr_ipso_sensor_oid_set *ctx_oid =
                &user_oid_sensors[oid_sensor_set];

        if (ctx_oid->user_sensors_array_length == 0) {
            continue;
        }

        if (three_axis) {
            if (anjay_ipso_3d_sensor_install(
                        anjay,
                        ctx_oid->oid,
                        ctx_oid->user_sensors_array_length)) {
                LOG_ERR("Object with oid: %d could not be installed",
                        ctx_oid->oid);
                _anjay_zephyr_three_axis_sensors_remove();
                return -1;
            }
        } else {
            if (anjay_ipso_basic_sensor_install(
                        anjay,
                        ctx_oid->oid,
                        ctx_oid->user_sensors_array_length)) {
                LOG_ERR("Object with oid: %d could not be installed",
                        ctx_oid->oid);
                _anjay_zephyr_basic_sensors_remove();
                return -1;
            }
        }

        for (size_t sensor = 0; sensor < ctx_oid->user_sensors_array_length;
             sensor++) {
            struct anjay_zephyr_ipso_sensor_context *ctx =
                    &ctx_oid->user_sensors[sensor];
            if (!device_is_ready(ctx->device)) {
                LOG_WRN("Sensor %s with oid %d could not be installed",
                        ctx->name,
                        ctx_oid->oid);
                continue;
            }

            if (sensor_sync_context_init(&ctx->sync, three_axis)) {
                LOG_WRN("Sensor %s with oid %d could not be installed",
                        ctx->name,
                        ctx_oid->oid);
                continue;
            }

            if (three_axis) {
                anjay_ipso_3d_sensor_impl_t impl = {
                    .unit = ctx->unit,
                    .use_y_value = ctx->use_y_value,
                    .use_z_value = ctx->use_y_value,
                    .user_context = ctx,
                    .min_range_value = ctx->min_range_value,
                    .max_range_value = ctx->max_range_value,
                    .get_values = three_axis_sensor_get_values
                };
                if (!anjay_ipso_3d_sensor_instance_add(
                            anjay, ctx_oid->oid, sensor, impl)) {
                    continue;
                }
            } else {
                anjay_ipso_basic_sensor_impl_t impl = {
                    .unit = ctx->unit,
                    .user_context = ctx,
                    .min_range_value = ctx->min_range_value,
                    .max_range_value = ctx->max_range_value,
                    .get_value = basic_sensor_get_value
                };
                if (!anjay_ipso_basic_sensor_instance_add(
                            anjay, ctx_oid->oid, sensor, impl)) {
                    continue;
                }
            }
            LOG_WRN("Instance %d of object with oid %d could not be added",
                    sensor,
                    ctx_oid->oid);
        }
    }
    return 0;
}

int anjay_zephyr_ipso_basic_sensors_install(
        anjay_t *anjay,
        struct anjay_zephyr_ipso_sensor_oid_set *user_oid_sensors,
        size_t user_oid_sensors_length) {
    return sensors_install(
            anjay, user_oid_sensors, user_oid_sensors_length, false);
}

int anjay_zephyr_ipso_three_axis_sensors_install(
        anjay_t *anjay,
        struct anjay_zephyr_ipso_sensor_oid_set *user_oid_sensors,
        size_t user_oid_sensors_length) {
    return sensors_install(
            anjay, user_oid_sensors, user_oid_sensors_length, true);
}

static void sensors_update(anjay_t *anjay,
                           struct user_sensors *user_sensors_ptr,
                           bool three_axis) {
    for (int oid_sensor_set = 0;
         oid_sensor_set < user_sensors_ptr->user_oid_sensors_length;
         oid_sensor_set++) {
        struct anjay_zephyr_ipso_sensor_oid_set *ctx_oid =
                &user_sensors_ptr->oid_sensors_sets[oid_sensor_set];
        for (int sensor = 0; sensor < ctx_oid->user_sensors_array_length;
             sensor++) {
            if (three_axis) {
                if (!anjay_ipso_3d_sensor_update(anjay, ctx_oid->oid, sensor)) {
                    continue;
                }
            } else {
                if (!anjay_ipso_basic_sensor_update(
                            anjay, ctx_oid->oid, sensor)) {
                    continue;
                }
            }
            LOG_WRN("Instance %d of object with oid %d could not be updated",
                    sensor,
                    ctx_oid->oid);
        }
    }
}

void anjay_zephyr_ipso_sensors_update(anjay_t *anjay) {
    if (!anjay) {
        LOG_ERR("Sensors could not be updated");
        return;
    }

    if (!user_basic_sensors.oid_sensors_sets
            && !user_three_axis_sensors.oid_sensors_sets) {
        LOG_ERR("Sensors could not be updated, they are not initialized");
    }

    if (user_basic_sensors.oid_sensors_sets) {
        sensors_update(anjay, &user_basic_sensors, false);
    }

    if (user_three_axis_sensors.oid_sensors_sets) {
        sensors_update(anjay, &user_three_axis_sensors, true);
    }
}

void _anjay_zephyr_basic_sensors_remove(void) {
    user_basic_sensors.oid_sensors_sets = NULL;
}

void _anjay_zephyr_three_axis_sensors_remove(void) {
    user_three_axis_sensors.oid_sensors_sets = NULL;
}
