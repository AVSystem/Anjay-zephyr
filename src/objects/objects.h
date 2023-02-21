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
void _anjay_zephyr_device_object_update(
        anjay_t *anjay, const anjay_dm_object_def_t *const *def);

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
uint8_t _anjay_zephyr_ecid_object_instance_count(
        const anjay_dm_object_def_t *const *def);
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES
const anjay_dm_object_def_t **_anjay_zephyr_loc_assist_object_create(void);
void _anjay_zephyr_loc_assist_object_release(
        const anjay_dm_object_def_t ***out_def);

#    ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
#        define LOC_ASSIST_A_GPS_MASK_UTC BIT(0)
#        define LOC_ASSIST_A_GPS_MASK_EPHEMERIS BIT(1)
#        define LOC_ASSIST_A_GPS_MASK_ALMANAC BIT(2)
#        define LOC_ASSIST_A_GPS_MASK_KLOBUCHAR BIT(3)
#        define LOC_ASSIST_A_GPS_MASK_NEQUICK BIT(4)
#        define LOC_ASSIST_A_GPS_MASK_TOW BIT(5)
#        define LOC_ASSIST_A_GPS_MASK_CLOCK BIT(6)
#        define LOC_ASSIST_A_GPS_MASK_LOCATION BIT(7)
#        define LOC_ASSIST_A_GPS_MASK_INTEGRITY BIT(8)

void _anjay_zephyr_loc_assist_object_send_agps_request(
        anjay_t *anjay,
        const anjay_dm_object_def_t *const *obj_def,
        uint32_t request_mask);
#    endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS

#    ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_MANUAL_CELL_BASED
enum anjay_zephyr_loc_assist_cell_request_type {
    LOC_ASSIST_CELL_REQUEST_INFORM_SINGLE = 1,
    LOC_ASSIST_CELL_REQUEST_INFORM_MULTI = 2,
    LOC_ASSIST_CELL_REQUEST_REQUEST_SINGLE = 3,
    LOC_ASSIST_CELL_REQUEST_REQUEST_MULTI = 4
};

void _anjay_zephyr_loc_assist_object_send_cell_request(
        anjay_t *anjay,
        const anjay_dm_object_def_t *const *loc_assist_def,
        const anjay_dm_object_def_t *const *ecid_def,
        enum anjay_zephyr_loc_assist_cell_request_type request_type);
#    endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_MANUAL_CELL_BASED
#endif     // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES
