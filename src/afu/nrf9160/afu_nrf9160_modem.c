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
#include <dfu/dfu_target_modem_delta.h>
#ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM
#    include <dfu/dfu_target_full_modem.h>
#    include <dfu/fmfu_fdev.h>
#endif // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM

#include <modem/modem_info.h>
#include <modem/nrf_modem_lib.h>

#include "afu_nrf9160.h"

#include <pm_config.h>

#ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM
#    if !defined(PM_DFU_TARGET_FMFU_DEV)           \
            || !defined(PM_DFU_TARGET_FMFU_OFFSET) \
            || !defined(PM_DFU_TARGET_FMFU_SIZE)
#        error "dfu_target_fmfu partition must be defined in Partition Manager config"
#    endif // !defined(PM_DFU_TARGET_FMFU_DEV) ||
           // !defined(PM_DFU_TARGET_FMFU_OFFSET) ||
           // !defined(PM_DFU_TARGET_FMFU_SIZE)
#endif     // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM

LOG_MODULE_REGISTER(afu_nrf9160_modem);

#define SETTINGS_ROOT_NAME "anjay_afu_nrf9160_modem"
#define SETTINGS_RESULT_KEY "result"

#define EXPECTED_IMAGE_TYPE_MASK DFU_TARGET_IMAGE_TYPE_ANY_MODEM

#ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM
static uint8_t temp_full_modem_buf[4096];
#endif // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM

NRF_MODEM_LIB_ON_INIT(serial_lte_modem_init_hook, on_modem_lib_init, NULL);

/* Initialized to value different than success (0) */
static int modem_lib_init_result = -1;
static anjay_advanced_fw_update_result_t restored_update_result;

static void on_modem_lib_init(int ret, void *ctx) {
    modem_lib_init_result = ret;
}

static int fw_stream_open(anjay_iid_t iid, void *user_ptr) {
    (void) iid;
    (void) user_ptr;

    int result =
            _anjay_zephyr_afu_nrf9160_common_open(EXPECTED_IMAGE_TYPE_MASK);

    if (!result) {
        // A file from previous delta upgrade attempt may be left dormant,
        // try to remove it just in case
        dfu_target_modem_delta_reset();
    }

    return result;
}

static const char *fw_get_current_version(anjay_iid_t iid, void *user_ptr) {
    (void) iid;
    (void) user_ptr;

    static char buf[MODEM_INFO_MAX_RESPONSE_SIZE];

    if (modem_info_init()
            || modem_info_string_get(MODEM_INFO_FW_VERSION, buf, sizeof(buf))
                           < 0) {
        return NULL;
    }

    return buf;
}

void _anjay_zephyr_afu_nrf9160_modem_save_result(
        anjay_advanced_fw_update_result_t result) {
    uint8_t result8 = (uint8_t) result;

    if ((anjay_advanced_fw_update_result_t) result8 != result) {
        LOG_ERR("Invalid result");
    } else if (settings_subsys_init()) {
        LOG_ERR("Couldn't init settings subsystem");
    } else if (settings_save_one(SETTINGS_ROOT_NAME "/" SETTINGS_RESULT_KEY,
                                 &result8, 1)) {
        LOG_ERR("Couldn't save update result");
    }
}

static const anjay_advanced_fw_update_handlers_t handlers = {
    .stream_open = fw_stream_open,
    .stream_write = _anjay_zephyr_afu_nrf9160_common_write,
    .stream_finish = _anjay_zephyr_afu_nrf9160_common_finish,
    .reset = _anjay_zephyr_afu_nrf9160_common_reset,
    .get_current_version = fw_get_current_version,
    .perform_upgrade = _anjay_zephyr_afu_nrf9160_common_perform
};

static int fw_settings_set(const char *key,
                           size_t len,
                           settings_read_cb read_cb,
                           void *cb_arg) {
    if (strcmp(key, SETTINGS_RESULT_KEY) != 0) {
        return -ENOENT;
    }

    if (len > 1) {
        return -EINVAL;
    }

    uint8_t value = 0;

    int result = read_cb(cb_arg, &value, len);

    if (result < 0) {
        return result;
    }

    restored_update_result = (anjay_advanced_fw_update_result_t) value;
    return 0;
}

SETTINGS_STATIC_HANDLER_DEFINE(anjay_fw_update_modem,
                               SETTINGS_ROOT_NAME,
                               NULL,
                               fw_settings_set,
                               NULL,
                               NULL);

int _anjay_zephyr_afu_nrf9160_modem_install(anjay_t *anjay) {
    int result = 0;

#ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM
    result = dfu_target_full_modem_cfg(
            &(const struct dfu_target_full_modem_params) {
                .buf = temp_full_modem_buf,
                .len = sizeof(temp_full_modem_buf),
                .dev = &(struct dfu_target_fmfu_fdev) {
                    .dev = DEVICE_DT_GET(PM_DFU_TARGET_FMFU_DEV),
                    .offset = PM_DFU_TARGET_FMFU_OFFSET,
                    .size = PM_DFU_TARGET_FMFU_SIZE
                }
            });
    if (result) {
        return result;
    }
#endif // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM

    int settings_state = settings_subsys_init();

    if (settings_state) {
        LOG_ERR("Couldn't init settings subsystem");
    } else {
        settings_load_subtree(SETTINGS_ROOT_NAME);
    }

    anjay_advanced_fw_update_initial_state_t state = {
        .result = restored_update_result
    };

    result = anjay_advanced_fw_update_instance_add(
            anjay, AFU_NRF9160_IID_MODEM, "modem", &handlers, anjay, &state);
    if (!result && !settings_state
            && settings_delete(SETTINGS_ROOT_NAME "/" SETTINGS_RESULT_KEY)) {
        LOG_ERR("Couldn't delete the update result");
    }

    return result;
}

static int fw_update_process_init_result(int err) {
    switch (err) {
    case 0:
    case NRF_MODEM_DFU_RESULT_OK:
        printk("Modem update suceeded, reboot\r\n");
        _anjay_zephyr_afu_nrf9160_modem_save_result(
                ANJAY_ADVANCED_FW_UPDATE_RESULT_SUCCESS);
        return 0;
    case NRF_MODEM_DFU_RESULT_UUID_ERROR:
    case NRF_MODEM_DFU_RESULT_AUTH_ERROR:
        printk("Modem update failed, error: %d\r\n", err);
        printk("Modem will use old firmware\r\n");
        _anjay_zephyr_afu_nrf9160_modem_save_result(
                ANJAY_ADVANCED_FW_UPDATE_RESULT_INTEGRITY_FAILURE);
        return 0;
    case NRF_MODEM_DFU_RESULT_HARDWARE_ERROR:
    case NRF_MODEM_DFU_RESULT_INTERNAL_ERROR:
        printk("Modem update malfunction, error: %d, reboot\r\n", err);
        _anjay_zephyr_afu_nrf9160_modem_save_result(
                ANJAY_ADVANCED_FW_UPDATE_RESULT_FAILED);
        return 0;
    default:
        return -1;
    }
}

void _anjay_zephyr_afu_nrf9160_modem_apply(void) {
    int err = modem_lib_init_result;

    if (err && !fw_update_process_init_result(err)) {
        _anjay_zephyr_afu_nrf9160_reboot();
    }
}

#ifdef CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM
void _anjay_zephyr_afu_nrf9160_full_modem_apply(void) {
    int result = nrf_modem_lib_shutdown();

    if (result) {
        LOG_ERR("Could not shut down nrf_modem_lib: %d", result);
        goto finish;
    }

    result = nrf_modem_lib_init(BOOTLOADER_MODE);
    if (result) {
        LOG_ERR("Could not initialize nrf_modem_lib in Bootloader (full DFU) "
                "mode: %d",
                result);
        goto finish;
    }

    result = fmfu_fdev_load(temp_full_modem_buf, sizeof(temp_full_modem_buf),
                            DEVICE_DT_GET(PM_DFU_TARGET_FMFU_DEV),
                            PM_DFU_TARGET_FMFU_OFFSET);
    if (result) {
        LOG_ERR("Could not perform Full Modem DFU: %d", result);
        goto finish;
    }

    result = nrf_modem_lib_shutdown();
    if (result) {
        LOG_ERR("Could not shut down nrf_modem_lib for the second time: %d",
                result);
        goto finish;
    }

    result = nrf_modem_lib_init(NORMAL_MODE);
    if (result) {
        LOG_ERR("Could not reinitialize nrf_modem_lib in normal mode: %d",
                result);
    }
finish:
    fw_update_process_init_result(result);
}
#endif // CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160_APP_DELTA_FULL_MODEM
