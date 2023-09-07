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

#include <anjay/core.h>

#include <anjay_zephyr/factory_provisioning.h>

#ifdef CONFIG_ANJAY_ZEPHYR_PERSISTENCE
int _anjay_zephyr_persistence_purge(void);
int _anjay_zephyr_restore_anjay_from_persistence(anjay_t *anjay);
int _anjay_zephyr_persist_anjay_if_required(anjay_t *anjay);
int _anjay_zephyr_persist_anjay(anjay_t *anjay);

#    ifdef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
int _anjay_zephyr_restore_anjay_from_factory_provisioning(anjay_t *anjay);
#    endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING
#endif     // CONFIG_ANJAY_ZEPHYR_PERSISTENCE
