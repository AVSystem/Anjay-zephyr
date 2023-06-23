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
#include <stdbool.h>

#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/sys/reboot.h>

#include <dfu/dfu_target.h>
#include <dfu/dfu_target_mcuboot.h>
#include <dfu/dfu_target_modem_delta.h>

#ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM
#    include <dfu/dfu_target_full_modem.h>
#endif // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM

#include "afu_nrf9160.h"

LOG_MODULE_REGISTER(afu_nrf9160);

static int fw_update_expected_target_mask = -1;
static int fw_update_current_target = -1;

#define MINUSONE(...) -1
static int fw_update_finished_targets[AFU_NRF9160_INSTANCE_COUNT] = {
    LISTIFY(AFU_NRF9160_INSTANCE_COUNT, MINUSONE, (, ))
};

static uint8_t identify_buf[32] __aligned(__alignof(avs_max_align_t));
static size_t identify_buf_count;

static bool update_requested;

int _anjay_zephyr_afu_nrf9160_install(anjay_t *anjay) {
    int result = anjay_advanced_fw_update_install(anjay, NULL);

    if (!result) {
        result = _anjay_zephyr_afu_nrf9160_application_install(anjay);
    }
    if (!result) {
        result = _anjay_zephyr_afu_nrf9160_modem_install(anjay);
    }

    return result;
}

int _anjay_zephyr_afu_nrf9160_common_open(int expected_image_type_mask) {
    if (fw_update_expected_target_mask >= 0) {
        LOG_ERR("Concurrent firmware updates are not supported");
        return ANJAY_ADVANCED_FW_UPDATE_ERR_OUT_OF_MEMORY;
    }

    fw_update_expected_target_mask = expected_image_type_mask;
    fw_update_current_target = -1;
    identify_buf_count = 0;
    return 0;
}

static void dfu_target_cb(enum dfu_target_evt_id evt) {
    (void) evt;
}

int _anjay_zephyr_afu_nrf9160_common_write(anjay_iid_t iid,
                                           void *user_ptr,
                                           const void *data,
                                           size_t length) {
    (void) iid;
    (void) user_ptr;

    assert(fw_update_expected_target_mask >= 0);

    if (identify_buf_count < sizeof(identify_buf)) {
        assert(fw_update_current_target < 0);

        size_t identify_data_length =
                AVS_MIN(length, sizeof(identify_buf) - identify_buf_count);

        memcpy(identify_buf + identify_buf_count, data, identify_data_length);
        identify_buf_count += identify_data_length;
        data = (const char *) data + identify_data_length;
        length -= identify_data_length;

        if (identify_buf_count >= sizeof(identify_buf)) {
            enum dfu_target_image_type target =
                    dfu_target_img_type(identify_buf, sizeof(identify_buf));

            if (!(target & fw_update_expected_target_mask)) {
                LOG_ERR("Unsupported or unexpected image format");
                identify_buf_count = 0;
                return ANJAY_ADVANCED_FW_UPDATE_ERR_UNSUPPORTED_PACKAGE_TYPE;
            }

            int result = dfu_target_init(target, 0, 0, dfu_target_cb);

            if (result) {
                identify_buf_count = 0;
                return result;
            }

            fw_update_current_target = target;

            if (dfu_target_write(identify_buf, sizeof(identify_buf))) {
                return -1;
            }
        }
    }

    if (identify_buf_count >= sizeof(identify_buf)) {
        assert(fw_update_current_target >= 0
               && (fw_update_current_target & fw_update_expected_target_mask));
        if (length && dfu_target_write(data, length)) {
            return -1;
        }
    }
    return 0;
}

int _anjay_zephyr_afu_nrf9160_common_finish(anjay_iid_t iid, void *anjay_) {
    (void) iid;

    anjay_t *anjay = (anjay_t *) anjay_;

    assert(fw_update_expected_target_mask >= 0);
    assert(identify_buf_count < sizeof(identify_buf)
           || (fw_update_current_target >= 0
               && (fw_update_current_target & fw_update_expected_target_mask)));
    assert(iid < AVS_ARRAY_SIZE(fw_update_finished_targets));

    int result = 0;

    if (identify_buf_count < sizeof(identify_buf)) {
        // Format not yet determined, fail
        return ANJAY_ADVANCED_FW_UPDATE_ERR_UNSUPPORTED_PACKAGE_TYPE;
    } else if (dfu_target_done(true)) {
        result = -1;
    }

    if (!result) {
        fw_update_finished_targets[iid] = fw_update_current_target;
    } else {
        fw_update_finished_targets[iid] = -1;
    }

    int result2 = _anjay_zephyr_afu_nrf9160_update_linked_instances(
            anjay, iid,
            result ? ANJAY_ADVANCED_FW_UPDATE_STATE_IDLE
                   : ANJAY_ADVANCED_FW_UPDATE_STATE_DOWNLOADED);

    fw_update_expected_target_mask = -1;
    fw_update_current_target = -1;
    return result ? result : result2;
}

void _anjay_zephyr_afu_nrf9160_common_reset(anjay_iid_t iid, void *anjay_) {
    (void) iid;
    assert(iid < AVS_ARRAY_SIZE(fw_update_finished_targets));

    anjay_t *anjay = (anjay_t *) anjay_;

    if (fw_update_expected_target_mask >= 0) {
        if (identify_buf_count >= sizeof(identify_buf)) {
            assert(fw_update_current_target >= 0
                   && (fw_update_current_target
                       & fw_update_expected_target_mask));
            dfu_target_done(false);
            dfu_target_reset();
        }
        fw_update_current_target = -1;
        fw_update_expected_target_mask = -1;
    }

    fw_update_finished_targets[iid] = -1;

    _anjay_zephyr_afu_nrf9160_update_linked_instances(
            anjay, iid, ANJAY_ADVANCED_FW_UPDATE_STATE_IDLE);
}

int _anjay_zephyr_afu_nrf9160_common_perform(
        anjay_iid_t iid,
        void *anjay_,
        const anjay_iid_t *requested_supplemental_iids,
        size_t requested_supplemental_iids_count) {
    anjay_t *anjay = (anjay_t *) anjay_;
    bool do_update[AFU_NRF9160_INSTANCE_COUNT] = { 0 };
    int result = 0;

    assert(iid < AVS_ARRAY_SIZE(do_update));

    do_update[iid] = true;

    if (!requested_supplemental_iids) {
        result = anjay_advanced_fw_update_get_linked_instances(
                anjay, iid, &requested_supplemental_iids,
                &requested_supplemental_iids_count);
        if (result) {
            return result;
        }
    }

    assert(!requested_supplemental_iids_count || requested_supplemental_iids);

    for (size_t i = 0; i < requested_supplemental_iids_count; ++i) {
        assert(requested_supplemental_iids[i] < AVS_ARRAY_SIZE(do_update));
        do_update[requested_supplemental_iids[i]] = true;
    }

    if (!result && do_update[AFU_NRF9160_IID_APPLICATION]) {
        result = dfu_target_mcuboot_schedule_update(0);
    }
    if (!result && do_update[AFU_NRF9160_IID_MODEM]) {
#ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM
        if (fw_update_finished_targets[AFU_NRF9160_IID_MODEM]
                == DFU_TARGET_IMAGE_TYPE_FULL_MODEM) {
            result = dfu_target_full_modem_schedule_update(0);
        } else
#endif // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM
            result = dfu_target_modem_delta_schedule_update(0);

        if (!result) {
            _anjay_zephyr_afu_nrf9160_modem_save_result(
                    ANJAY_ADVANCED_FW_UPDATE_RESULT_FAILED);
        }
    }
    if (!result) {
        update_requested = true;
        anjay_event_loop_interrupt(anjay);
    }

    return result;
}

bool _anjay_zephyr_afu_nrf9160_requested(void) {
    return update_requested;
}

void _anjay_zephyr_afu_nrf9160_reboot(void) {
#ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM
    if (fw_update_finished_targets[AFU_NRF9160_IID_MODEM]
            == DFU_TARGET_IMAGE_TYPE_FULL_MODEM) {
        _anjay_zephyr_afu_nrf9160_full_modem_apply();
    }
#endif // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM

    LOG_INF("Rebooting to perform a firmware upgrade...");
    LOG_PANIC();
    sys_reboot(SYS_REBOOT_WARM);
}

int _anjay_zephyr_afu_nrf9160_update_linked_instances(
        anjay_t *anjay,
        anjay_iid_t source_iid,
        anjay_advanced_fw_update_state_t source_state) {
    anjay_advanced_fw_update_state_t states[AFU_NRF9160_INSTANCE_COUNT];

    assert(source_iid < AVS_ARRAY_SIZE(states));

    states[source_iid] = source_state;

    for (anjay_iid_t i = 0; i < AVS_ARRAY_SIZE(states); ++i) {
        if (i != source_iid) {
            if (anjay_advanced_fw_update_get_state(anjay, i, &states[i])) {
                states[i] = ANJAY_ADVANCED_FW_UPDATE_STATE_IDLE;
            }
        }
    }

    int result = 0;

    for (anjay_iid_t i = 0; i < AVS_ARRAY_SIZE(states); ++i) {
        anjay_iid_t linked_instances[AFU_NRF9160_INSTANCE_COUNT - 1];
        size_t linked_instances_count = 0;

        // Make all downloaded instances linked
        if (states[i] == ANJAY_ADVANCED_FW_UPDATE_STATE_DOWNLOADED) {
            for (anjay_iid_t j = 0; j < AVS_ARRAY_SIZE(states); ++j) {
                if (i != j
                        && states[j] == ANJAY_ADVANCED_FW_UPDATE_STATE_DOWNLOADED) {
                    linked_instances[linked_instances_count++] = j;
                }
            }
        }

        int partial_result = anjay_advanced_fw_update_set_linked_instances(
                anjay, i, linked_instances, linked_instances_count);

        if (!result) {
            result = partial_result;
        }
    }

    return result;
}
