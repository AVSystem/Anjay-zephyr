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

#include <avsystem/commons/avs_condvar.h>
#include <avsystem/commons/avs_init_once.h>
#include <avsystem/commons/avs_memory.h>
#include <avsystem/commons/avs_mutex.h>

#include <zephyr/kernel.h>

struct avs_condvar {
    struct k_condvar zephyr_condvar;
};

struct avs_mutex {
    struct k_mutex zephyr_mutex;
};

int avs_condvar_create(avs_condvar_t **out_condvar) {
    AVS_ASSERT(!*out_condvar,
               "possible attempt to reinitialize a condition variable");

    *out_condvar = (avs_condvar_t *) avs_calloc(1, sizeof(avs_condvar_t));
    if (!*out_condvar) {
        return -1;
    }

    if (k_condvar_init(&(*out_condvar)->zephyr_condvar)) {
        avs_free(*out_condvar);
        *out_condvar = NULL;
        return -1;
    }

    return 0;
}

int avs_condvar_notify_all(avs_condvar_t *condvar) {
    int result = k_condvar_broadcast(&condvar->zephyr_condvar);
    return result < 0 ? result : 0;
}

int avs_condvar_wait(avs_condvar_t *condvar,
                     avs_mutex_t *mutex,
                     avs_time_monotonic_t deadline) {
    k_timeout_t timeout = K_FOREVER;
    avs_time_duration_t avs_timeout =
            avs_time_monotonic_diff(deadline, avs_time_monotonic_now());
    int64_t timeout_ms;
    if (!avs_time_duration_to_scalar(&timeout_ms, AVS_TIME_MS, avs_timeout)) {
        if (timeout_ms < 0) {
            timeout_ms = 0;
        }
        timeout = K_MSEC(timeout_ms);
    }
    return k_condvar_wait(
                   &condvar->zephyr_condvar, &mutex->zephyr_mutex, timeout)
                   ? 1
                   : 0;
}

void avs_condvar_cleanup(avs_condvar_t **condvar) {
    if (*condvar) {
        avs_free(*condvar);
    }
    *condvar = NULL;
}

int avs_mutex_create(avs_mutex_t **out_mutex) {
    AVS_ASSERT(!*out_mutex, "possible attempt to reinitialize a mutex");

    *out_mutex = (avs_mutex_t *) avs_calloc(1, sizeof(avs_mutex_t));
    if (!*out_mutex) {
        return -1;
    }

    if (k_mutex_init(&(*out_mutex)->zephyr_mutex)) {
        avs_free(*out_mutex);
        *out_mutex = NULL;
        return -1;
    }

    return 0;
}

int avs_mutex_lock(avs_mutex_t *mutex) {
    return k_mutex_lock(&mutex->zephyr_mutex, K_FOREVER);
}

int avs_mutex_try_lock(avs_mutex_t *mutex) {
    return k_mutex_lock(&mutex->zephyr_mutex, K_NO_WAIT) ? 1 : 0;
}

int avs_mutex_unlock(avs_mutex_t *mutex) {
    return k_mutex_unlock(&mutex->zephyr_mutex);
}

void avs_mutex_cleanup(avs_mutex_t **mutex) {
    if (*mutex) {
        avs_free(*mutex);
    }
    *mutex = NULL;
}

static K_MUTEX_DEFINE(g_mutex);

int avs_init_once(volatile avs_init_once_handle_t *handle,
                  avs_init_once_func_t *func,
                  void *func_arg) {
    if (k_mutex_lock(&g_mutex, K_FOREVER)) {
        return -1;
    }

    int result = 0;
    if (*handle == NULL) {
        result = func(func_arg);
        if (result == 0) {
            *handle = (avs_init_once_handle_t) ~(intptr_t) NULL;
        }
    }

    k_mutex_unlock(&g_mutex);
    return result;
}
