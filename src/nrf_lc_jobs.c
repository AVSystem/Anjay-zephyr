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

#include "lwm2m_internal.h"
#include "nrf_lc_jobs.h"
#include "objects/objects.h"

LOG_MODULE_REGISTER(anjay_zephyr_nrf_lc_jobs);

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_MANUAL_CELL_BASED
void _anjay_zephyr_cell_request_job(avs_sched_t *sched,
                                    const void *cell_request_job_args_ptr) {
    struct anjay_zephyr_cell_request_job_args args =
            *(const struct anjay_zephyr_cell_request_job_args *)
                    cell_request_job_args_ptr;
    _anjay_zephyr_loc_assist_object_send_cell_request(
            args.anjay, anjay_zephyr_loc_assist_obj, anjay_zephyr_ecid_obj,
            args.request_type);
}
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_MANUAL_CELL_BASED

#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
void _anjay_zephyr_agps_request_job(avs_sched_t *sched, const void *anjay_ptr) {
    static const uint32_t full_mask =
            LOC_ASSIST_A_GPS_MASK_UTC | LOC_ASSIST_A_GPS_MASK_KLOBUCHAR
            | LOC_ASSIST_A_GPS_MASK_NEQUICK | LOC_ASSIST_A_GPS_MASK_TOW
            | LOC_ASSIST_A_GPS_MASK_CLOCK | LOC_ASSIST_A_GPS_MASK_LOCATION
            | LOC_ASSIST_A_GPS_MASK_INTEGRITY | LOC_ASSIST_A_GPS_MASK_EPHEMERIS
            | LOC_ASSIST_A_GPS_MASK_ALMANAC;
    LOG_INF("Manual request of A-GPS data");
    _anjay_zephyr_loc_assist_object_send_agps_request(
            *(anjay_t *const *) anjay_ptr, anjay_zephyr_loc_assist_obj,
            full_mask);
}
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
