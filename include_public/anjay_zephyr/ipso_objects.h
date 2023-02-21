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

#include <anjay/dm.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/sensor.h>
#include <zephyr/kernel.h>

struct anjay_zephyr_ipso_sensor_sync_context {
    /**
     * On some platforms, access to buses like I2C is not inherently
     * synchronized. To allow accessing peripherals from multiple contexts (e.g.
     * react to GPS messages), we only access those buses through k_sys_work_q
     * by convention.
     */
    struct k_work work;
    struct k_sem sem;
    volatile double value[3];
};

/**
 * This structure defines the parameters for a single sensor.
 */
struct anjay_zephyr_ipso_sensor_context {
    /**
     * User defined sensor name.
     */
    const char *name;
    /**
     * Unit of the measured values.
     */
    const char *unit;
    /**
     * Enables usage of the optional Y axis.
     *
     * This field is only meaningful for 3D sensors.
     */
    bool use_y_value;
    /**
     * Enables usage of the optional Z axis.
     *
     * This field is only meaningful for 3D sensors.
     */
    bool use_z_value;
    /**
     * The minimum value that can be measured by the sensor.
     *
     * If the value is NaN the resource won't be created.
     */
    double min_range_value;
    /**
     * The maximum value that can be measured by the sensor.
     *
     * If the value is NaN the resource won't be created.
     */
    double max_range_value;
    /**
     * Pointer to a device object.
     */
    const struct device *device;
    /**
     * Sensor channel.
     */
    enum sensor_channel channel;
    /**
     * The measurements are multiplied by this value before being passed to the
     * corresponding IPSO object.
     */
    double scale_factor;
    /**
     * This structure contains fields used for synchronous data collection
     * from a sensor.
     *
     * It shouldn't be modified by the user.
     */
    struct anjay_zephyr_ipso_sensor_sync_context sync;
};

/**
 * This structure collects basic/three-axis sensors with the same OID.
 */
struct anjay_zephyr_ipso_sensor_oid_set {
    /**
     * OID of the installed sensors.
     */
    anjay_oid_t oid;
    /**
     * Pointer to an array in which user sensors with the same OID are defined.
     */
    struct anjay_zephyr_ipso_sensor_context *user_sensors;
    /**
     * Length of @p user_sensors array.
     */
    size_t user_sensors_array_length;
};

/**
 * Install basic sensors and IPSO objects for them.
 *
 * @param anjay                         Anjay object for which the sensor
 * objects are installed.
 * @param user_oid_sensors              Pointer to an array with basic sensors
 * configurations. Note: Contents of the array are NOT copied, so it needs to
 * remain valid for the lifetime of Anjay.
 * @param user_oid_sensors_length       Length of @p user_oid_sensors array.
 *
 * @return                              0 for success, or -1 in case of error.
 *
 * @attention                           Due to the limitations of Anjay IPSO
 * objects, this function can only be called once during the lifetime of Anjay.
 */
int anjay_zephyr_ipso_basic_sensors_install(
        anjay_t *anjay,
        struct anjay_zephyr_ipso_sensor_oid_set *user_oid_sensors,
        size_t user_oid_sensors_length);

/**
 * Install three-axis sensors and IPSO objects for them.
 *
 * @param anjay                         Anjay object for which the sensor
 * objects are installed.
 * @param user_oid_sensors              Pointer to an array with three-axis
 * sensors configurations. Note: Contents of the array are NOT copied, so it
 * needs to remain valid for the lifetime of Anjay.
 * @param user_oid_sensors_length       Length of @p user_oid_sensors array.
 *
 * @return                              0 for success, or -1 in case of error.
 *
 * @attention                           Due to the limitations of Anjay IPSO
 * objects, this function can only be called once during the lifetime of Anjay.
 */
int anjay_zephyr_ipso_three_axis_sensors_install(
        anjay_t *anjay,
        struct anjay_zephyr_ipso_sensor_oid_set *user_oid_sensors,
        size_t user_oid_sensors_length);
/**
 * Update all sensors, both basic and three-axis. This function should be called
 * repeatedly to update the object resource values.
 *
 * @param anjay                         Anjay object with the installed the
 * sensor objects.
 */
void anjay_zephyr_ipso_sensors_update(anjay_t *anjay);

/**
 * Configuration structure for push buttons.
 */
struct anjay_zephyr_ipso_button_instance {
    /**
     * Pointer to a device object.
     */
    const struct device *device;
    /**
     * Button pin.
     */
    int gpio_pin;
    /**
     * Flags for pin configuration.
     */
    int gpio_flags;
};

/**
 * Install push buttons and IPSO object for them.
 *
 * @param anjay                         Anjay object for which the push button
 * object is installed.
 * @param user_buttons                  Pointer to an array with push buttons
 * configurations. Note: Contents of the array are NOT copied, so it needs to
 * remain valid for the lifetime of Anjay.
 * @param user_buttons_array_length     Length of @p user_buttons array.
 * @return                              0 for success, or -1 in case of error.
 *
 * @attention                           Due to the limitations of Anjay IPSO
 * objects, this function can only be called once during the lifetime of Anjay.
 */
int anjay_zephyr_ipso_push_button_object_install(
        anjay_t *anjay,
        struct anjay_zephyr_ipso_button_instance *user_buttons,
        size_t user_buttons_array_length);
