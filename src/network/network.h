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

#include <stdbool.h>

#include <avsystem/commons/avs_defs.h>

#include <anjay_zephyr/bearer_list.h>

static inline bool
_anjay_zephyr_network_bearer_valid(enum anjay_zephyr_network_bearer_t bearer) {
    return bearer >= (enum anjay_zephyr_network_bearer_t) 0
           && bearer < ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT;
}

void _anjay_zephyr_network_interrupt_connect_wait_loop(void);
int _anjay_zephyr_network_initialize(void);
int _anjay_zephyr_network_connect_async(void);
enum anjay_zephyr_network_bearer_t _anjay_zephyr_network_current_bearer(void);
int _anjay_zephyr_network_wait_for_connected_interruptible(void);
void _anjay_zephyr_network_disconnect(void);

static inline bool _anjay_zephyr_network_is_connected(void) {
    return _anjay_zephyr_network_bearer_valid(
            _anjay_zephyr_network_current_bearer());
}
