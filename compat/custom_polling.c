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

#include <zephyr/net/socket.h>

#include <avsystem/commons/avs_time.h>

// HACK: the eswifi driver is not able to handle more than one socket at once,
// so we're repeatedly polling individual sockets in a loop, in short bursts to
// throttle down the loop that would be otherwise a busy spin

static int64_t calculate_timeout(avs_time_monotonic_t deadline) {
    static const int64_t quantum_ms = 50;

    if (!avs_time_monotonic_valid(deadline)) {
        // for AVS_TIME_MONOTONIC_INVALID always return quantum to implement
        // infinite timeout
        return quantum_ms;
    }

    avs_time_duration_t until_deadline =
            avs_time_monotonic_diff(deadline, avs_time_monotonic_now());
    if (avs_time_duration_less(until_deadline, AVS_TIME_DURATION_ZERO)) {
        until_deadline = AVS_TIME_DURATION_ZERO;
    }

    int64_t until_deadline_ms;
    int res = avs_time_duration_to_scalar(
            &until_deadline_ms, AVS_TIME_MS, until_deadline);
    assert(!res);
    (void) res;

    return AVS_MIN(until_deadline_ms, quantum_ms);
}

static int nonblocking_sweep(struct zsock_pollfd *fds, int nfds) {
    int ready = 0;
    for (size_t i = 0; i < nfds; i++) {
        int res = zsock_poll(&fds[i], 1, 0);
        if (res < 0 && errno != ETIMEDOUT) {
            return res;
        }

        if (res > 0) {
            ready += res;
        }
    }
    return ready;
}

static int throttled_sweep(struct zsock_pollfd *fds,
                           int nfds,
                           avs_time_monotonic_t deadline) {
    for (size_t i = 0; i < nfds; i++) {
        int res = zsock_poll(&fds[i], 1, calculate_timeout(deadline));
        // we can return early here for responsiveness; other ready sockets will
        // be captured by next nonblocking_sweep() call
        if (res > 0 || (res < 0 && errno != ETIMEDOUT)) {
            return res;
        }
    }
    return 0;
}

static int
poll_multiple_individually(struct zsock_pollfd *fds, int nfds, int timeout_ms) {
    // treat AVS_TIME_MONOTIC_INVALID as infinite deadline
    const avs_time_monotonic_t deadline =
            timeout_ms < 0
                    ? AVS_TIME_MONOTONIC_INVALID
                    : avs_time_monotonic_add(avs_time_monotonic_now(),
                                             avs_time_duration_from_scalar(
                                                     timeout_ms, AVS_TIME_MS));

    // attempt to return immediately if some sockets are already ready, this
    // also collects sockets that could be missed in the last iteration of
    // throttled_sweep()
    int res = nonblocking_sweep(fds, nfds);
    if (res) {
        return res;
    }

    while (!avs_time_monotonic_before(deadline, avs_time_monotonic_now())) {
        res = throttled_sweep(fds, nfds, deadline);
        if (res) {
            return res;
        }
    }

    return 0;
}

int zsock_poll_workaround(struct zsock_pollfd *fds, int nfds, int timeout_ms) {
    return nfds <= 1 ? zsock_poll(fds, nfds, timeout_ms)
                     : poll_multiple_individually(fds, nfds, timeout_ms);
}
