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
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include <dfu/dfu_target.h>
#include <dfu/dfu_target_mcuboot.h>

#include "../../utils.h"
#include "afu_nrf9160.h"

LOG_MODULE_REGISTER(afu_nrf9160_app);

#define SETTINGS_ROOT_NAME "anjay_afu_nrf9160_app"
#define SETTINGS_APP_JUST_UPDATED_KEY "app_just_updated"

static bool just_updated;

static uint32_t dfu_buf[CONFIG_IMG_BLOCK_BUF_SIZE / sizeof(uint32_t)];

#define EXPECTED_IMAGE_TYPE DFU_TARGET_IMAGE_TYPE_MCUBOOT

static int fw_stream_open(anjay_iid_t iid, void *user_ptr) {
    (void) iid;
    (void) user_ptr;

    int result = _anjay_zephyr_afu_nrf9160_common_open(EXPECTED_IMAGE_TYPE);

    if (!result) {
        memset(dfu_buf, 0, sizeof(dfu_buf));
    }

    return result;
}

static const char *fw_get_current_version(anjay_iid_t iid, void *user_ptr) {
    (void) iid;
    (void) user_ptr;

    static char fw_version[BOOT_IMG_VER_STRLEN_MAX];

    if (_anjay_zephyr_get_fw_version_image_0(fw_version, sizeof(fw_version))) {
        return NULL;
    }

    return fw_version;
}

static const char *fw_get_pkg_version(anjay_iid_t iid, void *user_ptr) {
    (void) iid;
    (void) user_ptr;

    static char fw_version[BOOT_IMG_VER_STRLEN_MAX];

    if (_anjay_zephyr_get_fw_version_image_1(fw_version, sizeof(fw_version))) {
        return NULL;
    }

    return fw_version;
}

static const anjay_advanced_fw_update_handlers_t handlers = {
    .stream_open = fw_stream_open,
    .stream_write = _anjay_zephyr_afu_nrf9160_common_write,
    .stream_finish = _anjay_zephyr_afu_nrf9160_common_finish,
    .reset = _anjay_zephyr_afu_nrf9160_common_reset,
    .get_pkg_version = fw_get_pkg_version,
    .get_current_version = fw_get_current_version,
    .perform_upgrade = _anjay_zephyr_afu_nrf9160_common_perform
};

int _anjay_zephyr_afu_nrf9160_application_install(anjay_t *anjay) {
    anjay_advanced_fw_update_initial_state_t state = { 0 };

    if (just_updated) {
        state.result = ANJAY_ADVANCED_FW_UPDATE_RESULT_SUCCESS;
    }

    int result =
            dfu_target_mcuboot_set_buf((uint8_t *) dfu_buf, sizeof(dfu_buf));

    if (!result) {
        result = anjay_advanced_fw_update_instance_add(
                anjay, AFU_NRF9160_IID_APPLICATION, "application", &handlers,
                anjay, &state);
    }

    if (!result && just_updated) {
        if (settings_delete(SETTINGS_ROOT_NAME
                            "/" SETTINGS_APP_JUST_UPDATED_KEY)) {
            LOG_ERR("Couldn't delete the just_updated flag");
        }

        just_updated = false;
    }

    return result;
}

static int fw_settings_set(const char *key,
                           size_t len,
                           settings_read_cb read_cb,
                           void *cb_arg) {
    if (strcmp(key, SETTINGS_APP_JUST_UPDATED_KEY) != 0) {
        return -ENOENT;
    }

    if (len > 1) {
        return -EINVAL;
    }

    char value = 0;

    int result = read_cb(cb_arg, &value, len);

    if (result < 0) {
        return result;
    }

    if (value != 0) {
        just_updated = true;
    }

    return 0;
}

SETTINGS_STATIC_HANDLER_DEFINE(
        anjay_fw_update, SETTINGS_ROOT_NAME, NULL, fw_settings_set, NULL, NULL);

void _anjay_zephyr_afu_nrf9160_application_apply(void) {
    int settings_state = settings_subsys_init();

    if (settings_state) {
        LOG_ERR("Couldn't init settings subsystem");
    } else {
        settings_load_subtree(SETTINGS_ROOT_NAME);
    }

    if (just_updated) {
        LOG_INF("Undelivered previous firmware update success");
    }

    // Image may be unconfirmed, because:
    // - we've just did a FOTA of the device and new
    //   firmware is being run
    // - the firmware was flashed using external programmer
    //
    // In both cases we want to mark the image as
    // confirmed (to either accept the new firmware,
    // or put MCUBoot in consistent state after flashing),
    // but only in the former case we should notify the
    // server that we've successfully updated the firmware.
    //
    // We can differentiate these two situations by taking
    // the retval of boot_write_img_confirmed().
    if (!boot_is_img_confirmed() && !boot_write_img_confirmed()) {
        LOG_INF("Successfully updated firmware");

        if (!just_updated) {
            just_updated = true;

            if (settings_save_one(SETTINGS_ROOT_NAME
                                  "/" SETTINGS_APP_JUST_UPDATED_KEY,
                                  "1", 1)) {
                LOG_ERR("Couldn't save the just_updated flag");
            }
        }
    }
}
