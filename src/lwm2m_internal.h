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

#include <anjay/anjay.h>
#include <stdatomic.h>
#include <stdlib.h>

#include "anjay_zephyr/lwm2m.h"

extern anjay_t *volatile anjay_zephyr_global_anjay;
extern struct k_mutex anjay_zephyr_global_anjay_mutex;
extern volatile atomic_bool anjay_zephyr_anjay_running;

#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
extern const anjay_dm_object_def_t **anjay_zephyr_ecid_obj;
extern const anjay_dm_object_def_t **anjay_zephyr_conn_mon_obj;
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION
extern const anjay_dm_object_def_t **anjay_zephyr_ground_fix_location_obj;
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_ASSISTANCE
extern const anjay_dm_object_def_t **anjay_zephyr_gnss_assistance_obj;
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_ASSISTANCE

void _anjay_zephyr_sched_update_anjay_network_bearer(void);
