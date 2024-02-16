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

#include <mbedtls/entropy.h>
#include <mbedtls/platform.h>
#include <mbedtls/timing.h>

#include <avsystem/commons/avs_defs.h>
#include <avsystem/commons/avs_errno.h>
#include <avsystem/commons/avs_memory.h>
#include <avsystem/commons/avs_time.h>

#include <zephyr/drivers/entropy.h>
#include <zephyr/random/rand32.h>

typedef struct anjay_mbedtls_timing_delay_context_struct {
    avs_time_monotonic_t timer;
    uint32_t int_ms;
    uint32_t fin_ms;
} anjay_mbedtls_timing_delay_context_t;

/*
 * Set delays to watch
 */
void mbedtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms) {
    anjay_mbedtls_timing_delay_context_t *ctx =
            (anjay_mbedtls_timing_delay_context_t *) data;

    ctx->int_ms = int_ms;
    ctx->fin_ms = fin_ms;

    if (fin_ms != 0) {
        ctx->timer = avs_time_monotonic_now();
    }
}

/*
 * Get number of delays expired
 */
int mbedtls_timing_get_delay(void *data) {
    anjay_mbedtls_timing_delay_context_t *ctx =
            (anjay_mbedtls_timing_delay_context_t *) data;

    if (ctx->fin_ms == 0) {
        return -1;
    }

    int64_t elapsed_ms_signed;
    if (avs_time_duration_to_scalar(
                &elapsed_ms_signed, AVS_TIME_MS,
                avs_time_monotonic_diff(avs_time_monotonic_now(),
                                        ctx->timer))) {
        return -1;
    }

    assert(elapsed_ms_signed >= 0);
    uint64_t elapsed_ms = (uint64_t) elapsed_ms_signed;
    if (elapsed_ms >= ctx->fin_ms) {
        return 2;
    } else if (elapsed_ms >= ctx->int_ms) {
        return 1;
    } else {
        return 0;
    }
}

static int entropy_callback(void *dev,
                            unsigned char *out_buf,
                            size_t out_buf_len,
                            size_t *out_buf_out_len) {
    *out_buf_out_len = out_buf_len;
#ifdef CONFIG_ENTROPY_HAS_DRIVER
    assert(dev);
    return entropy_get_entropy((const struct device *) dev, out_buf,
                               out_buf_len);
#else // CONFIG_ENTROPY_HAS_DRIVER
    // NOTE: This is not at all cryptographically secure. But Zephyr itself does
    // something like this with their TLS socket implementation, see:
    // https://github.com/zephyrproject-rtos/zephyr/blob/zephyr-v2.6.0/subsys/net/lib/sockets/sockets_tls.c#L207
#    warning "No cryptographically secure entropy source; TLS may be insecure"
    (void) dev;
    sys_rand_get(out_buf, out_buf_len);
    return 0;
#endif // CONFIG_ENTROPY_HAS_DRIVER
}

void anjay_zephyr_mbedtls_entropy_init__(mbedtls_entropy_context *ctx) {
    const struct device *entropy_dev = NULL;
#ifdef CONFIG_ENTROPY_HAS_DRIVER
    entropy_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));
    AVS_ASSERT(entropy_dev, "Failed to acquire entropy device");
#endif // CONFIG_ENTROPY_HAS_DRIVER
    int result =
            mbedtls_entropy_add_source(ctx, entropy_callback,
                                       (struct device *) (intptr_t) entropy_dev,
                                       1, MBEDTLS_ENTROPY_SOURCE_STRONG);
    (void) result;
    AVS_ASSERT(!result, "Failed to add entropy source");
}

#if defined(MBEDTLS_PLATFORM_MEMORY)                  \
        && !(defined(MBEDTLS_PLATFORM_CALLOC_MACRO)   \
             && defined(MBEDTLS_PLATFORM_FREE_MACRO)) \
        && !(defined(MBEDTLS_PLATFORM_STD_CALLOC)     \
             && defined(MBEDTLS_PLATFORM_STD_FREE))   \
        && !defined(CONFIG_MBEDTLS_ENABLE_HEAP)
static int mbedtls_alloc_init(void) {
    mbedtls_platform_set_calloc_free(avs_calloc, avs_free);
    return 0;
}

SYS_INIT(mbedtls_alloc_init, POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEVICE);
#endif // defined(MBEDTLS_PLATFORM_MEMORY) &&
       // !(defined(MBEDTLS_PLATFORM_CALLOC_MACRO) &&
       // defined(MBEDTLS_PLATFORM_FREE_MACRO)) &&
       // !(defined(MBEDTLS_PLATFORM_STD_CALLOC) &&
       // defined(MBEDTLS_PLATFORM_STD_FREE)) &&
       // !defined(CONFIG_MBEDTLS_ENABLE_HEAP)
