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

#include "utils.h"
#include <avsystem/commons/avs_utils.h>
#include <zephyr/drivers/hwinfo.h>

#include <stdint.h>
#include <string.h>

#ifdef CONFIG_ANJAY_ZEPHYR_OTA_MCUBOOT
#    include <zephyr/dfu/mcuboot.h>
#    include <zephyr/storage/flash_map.h>

#    include <stdio.h>
#endif // CONFIG_ANJAY_ZEPHYR_OTA_MCUBOOT

#ifdef CONFIG_NRF_MODEM_LIB
#    include <modem/modem_info.h>
#    ifdef CONFIG_MODEM_KEY_MGMT
#        include <nrf_socket.h>
#    endif // CONFIG_MODEM_KEY_MGMT
#endif     // CONFIG_NRF_MODEM_LIB

#ifdef CONFIG_NET_IPV6
#    include <zephyr/net/socketutils.h>
#endif // CONFIG_NET_IPV6

#ifdef CONFIG_ANJAY_ZEPHYR_WORKQUEUE_ENABLE
static struct k_work_q anjay_zephyr_workqueue;
static K_THREAD_STACK_DEFINE(anjay_workqueue_stack,
                             CONFIG_ANJAY_ZEPHYR_WORKQUEUE_STACK_SIZE);
#endif // CONFIG_ANJAY_ZEPHYR_WORKQUEUE_ENABLE

int _anjay_zephyr_get_device_id(struct anjay_zephyr_device_id *out_id) {
    memset(out_id->value, 0, sizeof(out_id->value));

#ifdef CONFIG_NRF_MODEM_LIB
    return (modem_info_init()
            || modem_info_string_get(MODEM_INFO_IMEI, out_id->value,
                                     sizeof(out_id->value))
                       < 0)
                   ? -1
                   : 0;
#else  // CONFIG_NRF_MODEM_LIB
    uint8_t id[12];
    ssize_t retval = hwinfo_get_device_id(id, sizeof(id));

    if (retval <= 0) {
        return -1;
    }

    return avs_hexlify(out_id->value, sizeof(out_id->value), NULL, id,
                       (size_t) retval);
#endif // CONFIG_NRF_MODEM_LIB
}

#ifdef CONFIG_ANJAY_ZEPHYR_OTA_MCUBOOT
static int get_fw_version(char *out_buf, size_t buf_size, uint8_t area_id) {
    // apparently BOOT_IMG_VER_STRLEN_MAX accounts for the nullchar too
    if (buf_size < BOOT_IMG_VER_STRLEN_MAX) {
        return -1;
    }

    struct mcuboot_img_header header;

    if (boot_read_bank_header(area_id, &header, sizeof(header))) {
        return -1;
    }

    assert(header.mcuboot_version == 1);

    struct mcuboot_img_sem_ver *ver = &header.h.v1.sem_ver;

    // workaround: 8-bit (hhu/hhd) format specifiers are not supported,
    // (see explanation in inttypes.h), so we can't pass major/minor values
    // directly
    uint16_t major = ver->major;
    uint16_t minor = ver->minor;
    static const char *const fmt =
            "%" PRIu16 ".%" PRIu16 ".%" PRIu16 "+%" PRIu32;

    if (snprintf(out_buf, BOOT_IMG_VER_STRLEN_MAX, fmt, major, minor,
                 ver->revision, ver->build_num)
            < 0) {
        return -1;
    }
    return 0;
}

int _anjay_zephyr_get_fw_version_image_0(char *out_buf, size_t buf_size) {
#    ifdef FIXED_PARTITION_ID
    uint8_t area_id = FIXED_PARTITION_ID(slot0_partition);
#    else
    uint8_t area_id = FLASH_AREA_ID(image_0);
#    endif
    return get_fw_version(out_buf, buf_size, area_id);
}

int _anjay_zephyr_get_fw_version_image_1(char *out_buf, size_t buf_size) {
#    ifdef FIXED_PARTITION_ID
    uint8_t area_id = FIXED_PARTITION_ID(slot1_partition);
#    else
    uint8_t area_id = FLASH_AREA_ID(image_1);
#    endif
    return get_fw_version(out_buf, buf_size, area_id);
}
#endif // CONFIG_ANJAY_ZEPHYR_OTA_MCUBOOT

#if defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)
int _anjay_zephyr_tls_session_cache_purge(void) {
    int dummy_socket_fd =
            nrf_socket(NRF_AF_INET, NRF_SOCK_STREAM, NRF_SPROTO_TLS1v2);

    if (dummy_socket_fd == -1) {
        return -1;
    }

    int dummy_integer = 42;
    int result = nrf_setsockopt(dummy_socket_fd, NRF_SOL_SECURE,
                                NRF_SO_SEC_SESSION_CACHE_PURGE, &dummy_integer,
                                sizeof(dummy_integer));
    int close_result = nrf_close(dummy_socket_fd);

    if (result) {
        return result;
    } else {
        return close_result;
    }
}
#endif // defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)

/*
 * Copyright (c) 2019 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This sntp_simple_ipv6 function is a copy of sntp_simple function from Zephyr
 * (https://github.com/zephyrproject-rtos/zephyr/blob/zephyr-v3.0.0/subsys/net/lib/sntp/sntp_simple.c)
 * repository. The only change is the desired address family.
 */

#ifdef CONFIG_NET_IPV6
int _anjay_zephyr_sntp_simple_ipv6(const char *server,
                                   uint32_t timeout,
                                   struct sntp_time *time) {
    int res;
    static struct addrinfo hints;
    struct addrinfo *addr;
    struct sntp_ctx sntp_ctx;
    uint64_t deadline;
    uint32_t iter_timeout;

    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    /* 123 is the standard SNTP port per RFC4330 */
    res = net_getaddrinfo_addr_str(server, "123", &hints, &addr);

    if (res < 0) {
        /* Just in case, as namespace for getaddrinfo errors is
         * different from errno errors.
         */
        errno = EDOM;
        return res;
    }

    res = sntp_init(&sntp_ctx, addr->ai_addr, addr->ai_addrlen);
    if (res < 0) {
        goto freeaddr;
    }

    if (timeout == SYS_FOREVER_MS) {
        deadline = (uint64_t) timeout;
    } else {
        deadline = k_uptime_get() + (uint64_t) timeout;
    }

    /* Timeout for current iteration */
    iter_timeout = 100;

    while (k_uptime_get() < deadline) {
        res = sntp_query(&sntp_ctx, iter_timeout, time);

        if (res != -ETIMEDOUT) {
            break;
        }

        /* Exponential backoff with limit */
        if (iter_timeout < 1000) {
            iter_timeout *= 2;
        }
    }

    sntp_close(&sntp_ctx);

freeaddr:
    freeaddrinfo(addr);

    return res;
}
#endif // CONFIG_NET_IPV6

void _anjay_zephyr_init_workqueue(void) {
#ifdef CONFIG_ANJAY_ZEPHYR_WORKQUEUE_ENABLE
    k_work_queue_init(&anjay_zephyr_workqueue);

    k_work_queue_start(&anjay_zephyr_workqueue, anjay_workqueue_stack,
                       CONFIG_ANJAY_ZEPHYR_WORKQUEUE_STACK_SIZE,
                       CONFIG_ANJAY_ZEPHYR_WORKQUEUE_PRIORITY, NULL);
#endif // CONFIG_ANJAY_ZEPHYR_WORKQUEUE_ENABLE
}

int _anjay_zephyr_k_work_submit(struct k_work *work) {
#ifdef CONFIG_ANJAY_ZEPHYR_WORKQUEUE_ENABLE
    return k_work_submit_to_queue(&anjay_zephyr_workqueue, work);
#else
    return k_work_submit(work);
#endif // CONFIG_ANJAY_ZEPHYR_WORKQUEUE_ENABLE
}

int _anjay_zephyr_k_work_schedule(struct k_work_delayable *dwork,
                                  k_timeout_t delay) {
#ifdef CONFIG_ANJAY_ZEPHYR_WORKQUEUE_ENABLE
    return k_work_schedule_for_queue(&anjay_zephyr_workqueue, dwork, delay);
#else
    return k_work_schedule(dwork, delay);
#endif // CONFIG_ANJAY_ZEPHYR_WORKQUEUE_ENABLE
}

int _anjay_zephyr_k_work_reschedule(struct k_work_delayable *dwork,
                                    k_timeout_t delay) {
#ifdef CONFIG_ANJAY_ZEPHYR_WORKQUEUE_ENABLE
    return k_work_reschedule_for_queue(&anjay_zephyr_workqueue, dwork, delay);
#else
    return k_work_reschedule(dwork, delay);
#endif // CONFIG_ANJAY_ZEPHYR_WORKQUEUE_ENABLE
}
