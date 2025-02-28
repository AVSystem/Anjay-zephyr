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

#pragma once

#include <anjay/dm.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/sensor.h>
#include <zephyr/kernel.h>

/**
 * Configuration structure for switches.
 */
struct anjay_zephyr_switch_instance {
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
 * Create LwM2M On/Off switch object.
 *
 * @param user_switches                 Pointer to an array with switches
 * configurations.
 * @param user_switches_array_length    Length of @p user_switches array.
 * @return                              Pointer to pointer to a structure
 * defining a LwM2M On/Off switch object.
 */
const anjay_dm_object_def_t **anjay_zephyr_switch_object_create(
        struct anjay_zephyr_switch_instance *user_switches,
        size_t user_switches_array_length);

/**
 * Release memory related to LwM2M On/Off switch object.
 *
 * @param out_def                       Pointer to definition of LwM2M On/Off
 * switch object previously obtained by @ref anjay_zephyr_switch_object_create.
 */
void anjay_zephyr_switch_object_release(const anjay_dm_object_def_t ***out_def);

/**
 * Update LwM2M On/Off switch object. This function should be called repeatedly
 * to update the LwM2M On/Off switch objects resource values.
 *
 * @param anjay                         Anjay object with the installed the
 * switch object.
 * @param def                           Definition of LwM2M On/Off switch object
 * previously obtained by @ref anjay_zephyr_switch_object_create.
 */
void anjay_zephyr_switch_object_update(anjay_t *anjay,
                                       const anjay_dm_object_def_t *const *def);

/**
 * Configuration structure for buzzer.
 */
struct anjay_zephyr_buzzer_device {
    /**
     * Pointer to a device object.
     */
    const struct device *device;
    /**
     * Buzzer pin.
     */
    uint32_t pin;
};

/**
 * Create LwM2M Buzzer object.
 *
 * @param user_device                   Pointer to a structure with buzzer
 * configuration. Note: Content of the structure is NOT copied, so it needs to
 * remain valid for the lifetime of Anjay.
 * @return                              Pointer to pointer to a structure
 * defining a LwM2M Buzzer object.
 *
 */
const anjay_dm_object_def_t **anjay_zephyr_buzzer_object_create(
        const struct anjay_zephyr_buzzer_device *user_device);
/**
 * Release memory related to LwM2M Buzzer object.
 *
 * @param out_def                       Pointer to definition of LwM2M Buzzer
 * object previously obtained by @ref anjay_zephyr_buzzer_object_create.
 */
void anjay_zephyr_buzzer_object_release(const anjay_dm_object_def_t ***out_def);
/**
 * Update LwM2M Buzzer object. This function should be called repeatedly to
 * update the object resource values.
 *
 * @param anjay                         Anjay object with the installed the
 * LwM2M Buzzer object.
 * @param def                           Definition of LwM2M Buzzer object
 * previously obtained by @ref anjay_zephyr_buzzer_object_create.
 */
void anjay_zephyr_buzzer_object_update(anjay_t *anjay,
                                       const anjay_dm_object_def_t *const *def);

/**
 * Create LwM2M LED color light object.
 *
 * @param user_device                   Pointer to a device RGB object.
 * @return                              Pointer to pointer to a structure
 * defining a LwM2M LED color light object.
 */
const anjay_dm_object_def_t **
anjay_zephyr_led_color_light_object_create(const struct device *user_device);
/**
 * Release memory related to LwM2M LED color light object.
 *
 * @param out_def                       Pointer to definition of LwM2M LED color
 * light object previously obtained by @ref
 * anjay_zephyr_led_color_light_object_create.
 */
void anjay_zephyr_led_color_light_object_release(
        const anjay_dm_object_def_t ***out_def);

/**
 * Create LwM2M Location object.
 *
 * @return                              Pointer to pointer to a structure
 * defining a LwM2M Location object.
 */
const anjay_dm_object_def_t **anjay_zephyr_location_object_create(void);
/**
 * Release memory related to LwM2M Location object.
 *
 * @param out_def                       Pointer to definition of LwM2M Location
 * object previously obtained by @ref anjay_zephyr_location_object_create.
 */
void anjay_zephyr_location_object_release(
        const anjay_dm_object_def_t ***out_def);
/**
 * Update LwM2M Location object. This function should be called repeatedly to
 * update the object resource values.
 *
 * @param anjay                         Anjay object with the installed the
 * LwM2M Location object.
 * @param def                           Definition of LwM2M Location object
 * previously obtained by @ref anjay_zephyr_location_object_create.
 */
void anjay_zephyr_location_object_update(
        anjay_t *anjay, const anjay_dm_object_def_t *const *def);

/**
 * Create LwM2M Light Control object.
 *
 * @param user_leds                     Pointer to an array with LED
 * configurations.
 * @param user_leds_len                 Length of @p user_leds array.
 * @return                              Pointer to pointer to a structure
 * defining a LwM2M Light Control object.
 */
const anjay_dm_object_def_t **
anjay_zephyr_light_control_object_create(const struct gpio_dt_spec *user_leds,
                                         uint16_t user_leds_len);
/**
 * Release memory related to LwM2M light control object.
 *
 * @param out_def                       Pointer to definition of LwM2M light
 * Control object previously obtained by @ref
 * anjay_zephyr_light_control_object_create.
 */
void anjay_zephyr_light_control_object_release(
        const anjay_dm_object_def_t ***out_def);
