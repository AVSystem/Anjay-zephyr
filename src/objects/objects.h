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

#pragma once

#include <anjay/dm.h>
#include <anjay/lwm2m_send.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/sys/util.h>

#include "anjay_zephyr/ipso_objects.h"
#include "anjay_zephyr/objects.h"

#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
#    include "../nrf_lc_info.h"
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

void _anjay_zephyr_push_button_clean(void);

void _anjay_zephyr_basic_sensors_remove(void);
void _anjay_zephyr_three_axis_sensors_remove(void);

const anjay_dm_object_def_t **_anjay_zephyr_device_object_create(void);
void _anjay_zephyr_device_object_release(
        const anjay_dm_object_def_t ***out_def);
void _anjay_zephyr_device_object_reboot_if_requested(void);

#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

#    define OID_CONN_MON 4

#    define RID_CONN_MON_NETWORK_BEARER 0
#    define RID_CONN_MON_AVAILABLE_NETWORK_BEARER 1
#    define RID_CONN_MON_RSS 2
#    define RID_CONN_MON_LINK_QUALITY 3
#    define RID_CONN_MON_IP_ADDRESSES 4
#    define RID_CONN_MON_CELL_ID 8
#    define RID_CONN_MON_SMNC 9
#    define RID_CONN_MON_SMCC 10
#    define RID_CONN_MON_LAC 12

const anjay_dm_object_def_t **_anjay_zephyr_conn_mon_object_create(
        const struct anjay_zephyr_nrf_lc_info *nrf_lc_info);
void _anjay_zephyr_conn_mon_object_release(
        const anjay_dm_object_def_t ***out_def);
void _anjay_zephyr_conn_mon_object_update(
        anjay_t *anjay,
        const anjay_dm_object_def_t *const *def,
        const struct anjay_zephyr_nrf_lc_info *nrf_lc_info);
#    ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES
int _anjay_zephyr_conn_mon_object_add_to_batch(
        anjay_t *anjay,
        anjay_send_batch_builder_t *builder,
        const anjay_dm_object_def_t *const *obj_ptr);
#    endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES
#    define OID_ECID 10256

#    define RID_ECID_PHYSCELLID 0
#    define RID_ECID_ARFCNEUTRA 2
#    define RID_ECID_RSRP_RESULT 3
#    define RID_ECID_RSRQ_RESULT 4
#    define RID_ECID_UE_RXTXTIMEDIFF 5

const anjay_dm_object_def_t **_anjay_zephyr_ecid_object_create(
        const struct anjay_zephyr_nrf_lc_info *nrf_lc_info);
void _anjay_zephyr_ecid_object_release(const anjay_dm_object_def_t ***out_def);
void _anjay_zephyr_ecid_object_update(
        anjay_t *anjay,
        const anjay_dm_object_def_t *const *def,
        const struct anjay_zephyr_nrf_lc_info *nrf_lc_info);
#    ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
int _anjay_zephyr_ecid_object_add_to_batch(
        anjay_t *anjay,
        anjay_send_batch_builder_t *builder,
        const anjay_dm_object_def_t *const *obj_ptr);
#    endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
#endif     // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
#    define OID_GROUND_FIX_LOC 33626

#    define RID_GROUND_FIX_LOC_SEND_LOCATION_BACK 0
#    define RID_GROUND_FIX_LOC_RESULT_CODE 1
#    define RID_GROUND_FIX_LOC_LATITUDE 2
#    define RID_GROUND_FIX_LOC_LONGITUDE 3
#    define RID_GROUND_FIX_LOC_ACCURACY 4

const anjay_dm_object_def_t **
_anjay_zephyr_ground_fix_location_object_create(void);
void _anjay_zephyr_ground_fix_location_object_release(
        const anjay_dm_object_def_t ***def);
int32_t _anjay_zephyr_ground_fix_location_get_result_code(
        const anjay_dm_object_def_t *const *obj_ptr);
uint32_t _anjay_zephyr_ground_fix_location_get_exponential_backoff_value(
        const anjay_dm_object_def_t *const *obj_ptr);
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION

#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
#    define LOC_SERVICES_A_GPS_MASK_UTC BIT(0)
#    define LOC_SERVICES_A_GPS_MASK_EPHEMERIS BIT(1)
#    define LOC_SERVICES_A_GPS_MASK_ALMANAC BIT(2)
#    define LOC_SERVICES_A_GPS_MASK_KLOBUCHAR BIT(3)
#    define LOC_SERVICES_A_GPS_MASK_NEQUICK BIT(4)
#    define LOC_SERVICES_A_GPS_MASK_TOW BIT(5)
#    define LOC_SERVICES_A_GPS_MASK_CLOCK BIT(6)
#    define LOC_SERVICES_A_GPS_MASK_LOCATION BIT(7)
#    define LOC_SERVICES_A_GPS_MASK_INTEGRITY BIT(8)

#    define LOC_SERVICES_A_GPS_FULL_MASK                                    \
        (LOC_SERVICES_A_GPS_MASK_UTC | LOC_SERVICES_A_GPS_MASK_KLOBUCHAR    \
         | LOC_SERVICES_A_GPS_MASK_NEQUICK | LOC_SERVICES_A_GPS_MASK_TOW    \
         | LOC_SERVICES_A_GPS_MASK_CLOCK | LOC_SERVICES_A_GPS_MASK_LOCATION \
         | LOC_SERVICES_A_GPS_MASK_INTEGRITY                                \
         | LOC_SERVICES_A_GPS_MASK_EPHEMERIS                                \
         | LOC_SERVICES_A_GPS_MASK_ALMANAC)

#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_ASSISTANCE

#    define OID_GNSS_ASSISTANCE 33625

#    define RID_GNSS_ASSISTANCE_ASSISTANCE_TYPE 0
#    define RID_GNSS_ASSISTANCE_A_GPS_ASSISTANCE_MASK 1
#    define RID_GNSS_ASSISTANCE_P_GPS_PREDICTION_COUNT 2
#    define RID_GNSS_ASSISTANCE_P_GPS_PREDICTION_INTERVAL 3
#    define RID_GNSS_ASSISTANCE_P_GPS_START_GPS_DAY 4
#    define RID_GNSS_ASSISTANCE_P_GPS_START_TIME 5
#    define RID_GNSS_ASSISTANCE_ASSISTANCE_DATA 6
#    define RID_GNSS_ASSISTANCE_RESULT_CODE 7
#    define RID_GNSS_ASSISTANCE_SATELLITE_ELEVATION_MASK 8

const anjay_dm_object_def_t **_anjay_zephyr_gnss_assistance_object_create(void);
void _anjay_zephyr_gnss_assistance_object_release(
        const anjay_dm_object_def_t ***def);
uint32_t _anjay_zephyr_gnss_assistance_get_exponential_backoff_value(
        const anjay_dm_object_def_t *const *obj_ptr);
int32_t _anjay_zephyr_gnss_assistance_get_result_code(void);
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_ASSISTANCE
