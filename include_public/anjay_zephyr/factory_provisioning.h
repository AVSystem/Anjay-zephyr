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

#include <anjay/anjay.h>

/**
 * @file anjay_zephyr/factory_provisioning.h
 *
 * Header file with function declarations that can be utilized to develop an
 * application to pre-provision credentials to the device.
 */

#ifdef CONFIG_ANJAY_ZEPHYR_PERSISTENCE
/**
 * Initializes the Zephyr settings subsystem for persistence.
 * This function should be called before restoring/persisting Anjay.
 *
 * @return              0 for success, or -1 in case of error.
 */
int anjay_zephyr_persistence_init(void);

#    ifdef CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING_INITIAL_FLASH
/**
 * Check if factory provisioning data is already stored.
 * By calling this function, the user can determine whether the data has already
 * been persisted in settings submodule, e.g. by another application uploaded
 * earlier.
 *
 * @return              True if provisioning data is already stored, false
 *                      otherwise.
 */
bool anjay_zephyr_is_factory_provisioning_info_present(void);

/**
 * Persist factory provisioning data in settings subsystem.
 * This function should be called after a successful data provisioning process.
 *
 * @param anjay         Anjay Object to operate on.
 *
 * @return              0 for success, or -1 in case of error.
 */
int anjay_zephyr_persist_factory_provisioning_info(anjay_t *anjay);
#    endif // CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING_INITIAL_FLASH
#endif     // CONFIG_ANJAY_ZEPHYR_PERSISTENCE
