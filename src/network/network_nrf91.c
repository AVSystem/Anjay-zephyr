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

#include <zephyr/logging/log.h>

#include <modem/lte_lc.h>

#if defined(CONFIG_LTE_LINK_CONTROL) && !defined(CONFIG_NRF_MODEM_LIB_SYS_INIT)
#    include <modem/nrf_modem_lib.h>
#endif // defined(CONFIG_LTE_LINK_CONTROL) &&
       // !defined(CONFIG_NRF_MODEM_LIB_SYS_INIT)

#include "network.h"
#include "network_internal.h"

#include "../gps.h"
#include "../utils.h"

#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
#    include "../nrf_lc_info.h"
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

#if __has_include("ncs_version.h")
#    include "ncs_version.h"
#endif // __has_include("ncs_version.h")

LOG_MODULE_REGISTER(anjay_zephyr_network_nrf91);

static volatile atomic_int lte_nw_reg_status; // enum lte_lc_nw_reg_status
static volatile atomic_int lte_mode;          // enum lte_lc_lte_mode
#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
static volatile atomic_uint_least32_t lte_cell_id;
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

static bool is_network_connected(void) {
    if (atomic_load(&lte_mode) == LTE_LC_LTE_MODE_NONE) {
        return false;
    }

    int nw_reg_status = atomic_load(&lte_nw_reg_status);
    return nw_reg_status == LTE_LC_NW_REG_REGISTERED_HOME
           || nw_reg_status == LTE_LC_NW_REG_REGISTERED_ROAMING;
}

static void lte_evt_handler(const struct lte_lc_evt *const evt) {
    if (evt) {
#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
        if (evt->type == LTE_LC_EVT_NEIGHBOR_CELL_MEAS) {
            atomic_store(&lte_cell_id, evt->cells_info.current_cell.id);
        } else {
            // NOTE: This may look suspicious, as we are carelessly reading
            // atomic variables without even trying to consider that they might
            // change in between calls. However, please note that
            // lte_nw_reg_status and lte_mode are only ever modified from this
            // function, so this is actually safe. Those variables are atomic
            // to allow safely reading them from other threads, but this code
            // does not cause a race condition.
            bool was_connected = is_network_connected();
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
            if (evt->type == LTE_LC_EVT_NW_REG_STATUS) {
                atomic_store(&lte_nw_reg_status, (int) evt->nw_reg_status);
            } else if (evt->type == LTE_LC_EVT_LTE_MODE_UPDATE) {
                atomic_store(&lte_mode, (int) evt->lte_mode);
            }
#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
            if (!was_connected && is_network_connected()) {
                _anjay_zephyr_nrf_lc_info_schedule_refresh_now();
            }
        }
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
    }
    _anjay_zephyr_network_internal_connection_state_changed();
}

int _anjay_zephyr_network_internal_platform_initialize(void) {
    int ret;

#if defined(CONFIG_LTE_LINK_CONTROL) && !defined(CONFIG_NRF_MODEM_LIB_SYS_INIT)
#    if NCS_VERSION_NUMBER >= 0x20400
    ret = nrf_modem_lib_init();
#    else  // NCS_VERSION_NUMBER >= 0x20400
    ret = nrf_modem_lib_init(NORMAL_MODE);
#    endif // NCS_VERSION_NUMBER >= 0x20400
    if (ret) {
#    if NCS_VERSION_NUMBER < 0x20500 \
            && defined(CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160)
        // nrf_modem_init (called indirectly) returns a positive code in case
        // there was a modem DFU attempt (see
        // https://developer.nordicsemi.com/nRF_Connect_SDK/doc/2.4.3/nrfxlib/nrf_modem/doc/delta_dfu.html#checking-the-result-of-the-update),
        // those codes will be handled appropriately in
        // _anjay_zephyr_afu_nrf9160_modem_apply(), so immediately return a 0
        // instead
        return ret < 0 ? ret : 0;
#    else  // NCS_VERSION_NUMBER < 0x20500 &&
           // defined(CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160)
        return ret;
#    endif // NCS_VERSION_NUMBER < 0x20500 &&
           // defined(CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160)
    }
#endif // defined(CONFIG_LTE_LINK_CONTROL) &&
       // !defined(CONFIG_NRF_MODEM_LIB_SYS_INIT)

#if NCS_VERSION_NUMBER < 0x20600
    ret = lte_lc_init();
    if (ret) {
        return ret;
    }
#endif // NCS_VERSION_NUMBER < 0x20600

    lte_lc_register_handler(lte_evt_handler);

#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
    atomic_store(&lte_cell_id, LTE_LC_CELL_EUTRAN_ID_INVALID);
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

    return 0;
}

int _anjay_zephyr_network_connect_async(void) {
    int ret = 0;

    // Note: this is supposed to be handled by lte_lc_connect_async(),
    // but there is a nasty bug in in_progress flag handling
    if (!_anjay_zephyr_network_is_connected()) {
        ret = lte_lc_connect_async(lte_evt_handler);
    }

    if (ret > 0 || ret == -EALREADY || ret == -EINPROGRESS) {
        ret = 0;
    }
    if (ret) {
        LOG_ERR("LTE link could not be established.");
    }
    return ret;
}

enum anjay_zephyr_network_bearer_t _anjay_zephyr_network_current_bearer(void) {
#ifdef CONFIG_ANJAY_ZEPHYR_GPS_NRF
    if (atomic_load(&anjay_zephyr_gps_prio_mode)) {
        return ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT;
    }
#endif // CONFIG_ANJAY_ZEPHYR_GPS_NRF

    if (!is_network_connected()) {
        return ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT;
    }

#ifdef CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO
    // When CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO is enabled, the Connectivity
    // Monitoring object is present in the data model. That object is only
    // filled with data if the cell ID is available. For this reason, we only
    // treat the connection as valid and connected if the cell ID is available,
    // to avoid populating the object with null data.
    if (atomic_load(&lte_cell_id) == LTE_LC_CELL_EUTRAN_ID_INVALID) {
        return ANJAY_ZEPHYR_NETWORK_BEARER_LIMIT;
    }
#endif // CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO

    return ANJAY_ZEPHYR_NETWORK_BEARER_CELLULAR;
}

void _anjay_zephyr_network_disconnect(void) {
    int ret =
            lte_lc_func_mode_set(LTE_LC_FUNC_MODE_DEACTIVATE_LTE) ? -EFAULT : 0;

    if (ret) {
        LOG_WRN("LTE link could not be disconnected: %d", ret);
    }
}
