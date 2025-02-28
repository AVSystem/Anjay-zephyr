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

#include <anjay/advanced_fw_update.h>

#ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160

#    define AFU_NRF9160_IID_APPLICATION 0
#    define AFU_NRF9160_IID_MODEM 1
#    define AFU_NRF9160_INSTANCE_COUNT 2

int _anjay_zephyr_afu_nrf9160_application_install(anjay_t *anjay);
void _anjay_zephyr_afu_nrf9160_application_apply(void);

int _anjay_zephyr_afu_nrf9160_modem_install(anjay_t *anjay);
void _anjay_zephyr_afu_nrf9160_modem_save_result(
        anjay_advanced_fw_update_result_t result);
void _anjay_zephyr_afu_nrf9160_modem_apply(void);

#    ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM
void _anjay_zephyr_afu_nrf9160_full_modem_apply(void);
#    endif // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM

int _anjay_zephyr_afu_nrf9160_install(anjay_t *anjay);
int _anjay_zephyr_afu_nrf9160_common_open(int expected_image_type_mask);
int _anjay_zephyr_afu_nrf9160_common_write(anjay_iid_t iid,
                                           void *user_ptr,
                                           const void *data,
                                           size_t length);
int _anjay_zephyr_afu_nrf9160_common_finish(anjay_iid_t iid, void *anjay_);
void _anjay_zephyr_afu_nrf9160_common_reset(anjay_iid_t iid, void *anjay_);
int _anjay_zephyr_afu_nrf9160_common_perform(
        anjay_iid_t iid,
        void *anjay_,
        const anjay_iid_t *requested_supplemental_iids,
        size_t requested_supplemental_iids_count);
bool _anjay_zephyr_afu_nrf9160_requested(void);
void _anjay_zephyr_afu_nrf9160_reboot(void);

int _anjay_zephyr_afu_nrf9160_update_linked_instances(
        anjay_t *anjay,
        anjay_iid_t source_iid,
        anjay_advanced_fw_update_state_t source_state);

#endif // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160
