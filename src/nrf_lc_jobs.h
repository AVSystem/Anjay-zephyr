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

#include "objects/objects.h"
#include <anjay/anjay.h>

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_MANUAL_CELL_BASED
struct anjay_zephyr_cell_request_job_args {
    anjay_t *anjay;
    enum anjay_zephyr_loc_assist_cell_request_type request_type;
};
avs_sched_clb_t _anjay_zephyr_cell_request_job;
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_MANUAL_CELL_BASED
#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
avs_sched_clb_t _anjay_zephyr_agps_request_job;
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
