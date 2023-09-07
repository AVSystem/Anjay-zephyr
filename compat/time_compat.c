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

#include <avsystem/commons/avs_time.h>
#include <zephyr/kernel.h>

#ifdef CONFIG_POSIX_CLOCK
#    include <zephyr/posix/time.h>
#endif // CONFIG_POSIX_CLOCK

#ifdef CONFIG_DATE_TIME
#    include <date_time.h>
#endif // CONFIG_DATE_TIME

avs_time_monotonic_t avs_time_monotonic_now(void) {
    return avs_time_monotonic_from_scalar(k_uptime_get(), AVS_TIME_MS);
}

avs_time_real_t avs_time_real_now(void) {
#if defined(CONFIG_DATE_TIME)
    int64_t time_ms;
    if (!date_time_now(&time_ms)) {
        return avs_time_real_from_scalar(time_ms, AVS_TIME_MS);
    }
#elif defined(CONFIG_POSIX_CLOCK)
    struct timespec system_value;
    avs_time_real_t result;
    clock_gettime(CLOCK_REALTIME, &system_value);
    result.since_real_epoch.seconds = system_value.tv_sec;
    result.since_real_epoch.nanoseconds = (int32_t) system_value.tv_nsec;
    return result;
#endif // defined(CONFIG_DATE_TIME) || defined(CONFIG_POSIX_CLOCK)
#if defined(CONFIG_DATE_TIME) || !defined(CONFIG_POSIX_CLOCK)
    return avs_time_real_from_scalar(k_uptime_get(), AVS_TIME_MS);
#endif // defined(CONFIG_DATE_TIME) || !defined(CONFIG_POSIX_CLOCK)
}
