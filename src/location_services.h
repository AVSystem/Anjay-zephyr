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

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES

#    include "anjay_zephyr/location_services.h"
#    include "objects/objects.h"
#    include <anjay/anjay.h>

#    define LOCATION_SERVICES_MAXIMUM_EXPONENTIAL_BACKOFF 86400
#    define LOCATION_SERVICES_EXPONENTIAL_BACKOFF_INTERVAL 20

enum anjay_zephyr_location_services_requests {
#    ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
    LOCATION_SERVICES_REQUESTS_AGPS_REQUEST,
#    endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
#    ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_P_GPS
    LOCATION_SERVICES_REQUESTS_PGPS_REQUEST,
#    endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_P_GPS
#    ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
    LOCATION_SERVICES_REQUESTS_CELL_REQUEST
#    endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
};

void _anjay_zephyr_location_services_init(void);
void _anjay_zephyr_location_services_stop(void);

uint32_t
_anjay_zephyr_location_services_calculate_backoff(uint8_t backoff_number);

#    ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
struct anjay_zephyr_gf_location_request_job_args {
    anjay_t *anjay;
    anjay_zephyr_location_services_gf_location_request_cb_t *cb;
    anjay_zephyr_location_services_gf_location_request_type_t request_type;
};
avs_sched_clb_t _anjay_zephyr_gf_location_request_job;

void _anjay_zephyr_location_services_received_gf_location_req_response_from_server(
        anjay_t *anjay,
        bool successful,
        anjay_zephyr_location_services_ground_fix_location_t *location);
#    endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION

#    ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
typedef void _anjay_zephyr_location_services_agps_request_cb_t(
        anjay_zephyr_location_services_request_result_t result);
struct anjay_zephyr_agps_request_job_args {
    anjay_t *anjay;
    _anjay_zephyr_location_services_agps_request_cb_t *cb;
    uint32_t request_mask;
    bool exponential_backoff;
};
avs_sched_clb_t _anjay_zephyr_agps_request_job;

int _anjay_zephyr_send_agps_request(
        anjay_t *anjay,
        _anjay_zephyr_location_services_agps_request_cb_t *cb,
        uint32_t request_mask,
        bool exponential_backoff);
void _anjay_zephyr_location_services_received_agps_req_response_from_server(
        anjay_t *anjay, bool successful);
#    endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF_A_GPS
#endif     // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES
