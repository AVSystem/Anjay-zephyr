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

#ifndef CONFIG_BOARD_TMO_DEV_EDGE
#    error "This GPS implementation is not supported by selected board"
#endif // CONFIG_BOARD_TMO_DEV_EDGE

#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/timeutil.h>

#include <avsystem/commons/avs_utils.h>

#include "../gps.h"
#include "../utils.h"

LOG_MODULE_REGISTER(anjay_zephyr_gps_cxd5605);

// This is a BSD extension provided by newlib, but only visible with #define
// _DEFAULT_SOURCE. _DEFAULT_SOURCE conflicts with some POSIX-like declarations
// in Zephyr, though.
char *strsep(char **stringp, const char *delim);

#define GNSS_INT 7
#define GNSS_BOOT_REC 6
#define GNSS_1PPS 9
#define GNSS_PWR_ON 10
#define GNSS_GPIO_NAME "GPIO_F"
#define GNSS_ADDRESS 0x24

enum gps_cxd5605_state {
    CXD5605_SENT_BSSL,
    CXD5605_SENT_GNS,
    CXD5605_SENT_GSP,
    CXD5605_SENT_WUP,
    CXD5605_OPERATIONAL
};

K_MUTEX_DEFINE(anjay_zephyr_gps_read_last_mtx);
struct anjay_zephyr_gps_data anjay_zephyr_gps_read_last = {
    .valid = false
};

static struct gpio_callback gpio_cb_obj;
static const struct device *const i2c_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));

static void gps_incoming_work_handler(struct k_work *work);

static K_WORK_DEFINE(gps_incoming_work, gps_incoming_work_handler);
static atomic_uint gps_incoming_count;

static char gps_incoming_buffer[128];
static uint8_t gps_incoming_buffer_ptr;

static enum gps_cxd5605_state gps_incoming_state;
AVS_STATIC_ASSERT(CXD5605_SENT_BSSL == 0, zero_state_is_sent_ver);

static const char bssl_message[] = "@BSSL 0xFF\r\n";
static bool bssl_failed_once;

struct internal_gps_fix_timestamp {
    uint8_t hours;
    uint8_t minutes;
    uint8_t seconds;
    uint8_t centiseconds;
};

struct internal_gps_fix_latlon {
    uint8_t degrees;
    double minutes;
    char hemisphere;
};

struct internal_gps_gns_data {
    struct internal_gps_fix_timestamp timestamp;
    struct internal_gps_fix_latlon latitude;
    struct internal_gps_fix_latlon longitude;
    double altitude;
};

struct internal_gps_date {
    uint8_t day;
    uint8_t month;
    uint16_t year;
};

#define VALID_FIELD_GNS ((unsigned int) (1 << 0))
#define VALID_FIELD_ZDA ((unsigned int) (1 << 1))
#define VALID_FIELD_VTG ((unsigned int) (1 << 2))

struct internal_gps_data {
    struct internal_gps_gns_data gns;
    struct internal_gps_date zda;
    double vtg_speed;
    unsigned int valid_fields;
};

static struct internal_gps_data gps_last_state_internal;

static int send_message(const char *msg_str) {
    struct i2c_msg msg = {
        .buf = (uint8_t *) (uintptr_t) msg_str,
        .len = strlen(msg_str),
        .flags = I2C_MSG_WRITE | I2C_MSG_STOP
    };

    return i2c_transfer(i2c_dev, &msg, 1, GNSS_ADDRESS);
}

static int recv_message(uint8_t *out_data, size_t data_size) {
    struct i2c_msg msg = {
        .buf = out_data,
        .len = data_size,
        .flags = I2C_MSG_READ | I2C_MSG_STOP
    };

    return i2c_transfer(i2c_dev, &msg, 1, GNSS_ADDRESS);
}

static void gpio_cb(const struct device *port,
                    struct gpio_callback *cb,
                    gpio_port_pins_t pins) {
    unsigned int previous_value = atomic_fetch_add(&gps_incoming_count, 1);

    assert(previous_value < UINT_MAX);
    _anjay_zephyr_k_work_submit(&gps_incoming_work);
}

static int parse_gps_fix_timestamp(struct internal_gps_fix_timestamp *out,
                                   const char *token) {
    int chars_read;

    if (sscanf(token, "%2hhu%2hhu%2hhu.%2hhu%n", &out->hours, &out->minutes,
               &out->seconds, &out->centiseconds, &chars_read)
                    < 4
            || token[chars_read]) {
        return -1;
    }
    return 0;
}

static int
parse_gps_fix_latlon_without_hemisphere(struct internal_gps_fix_latlon *out,
                                        const char *token) {
    char format_string[16];
    int chars_read;
    const char *token_end = token + strlen(token);
    const char *dot = strchr(token, '.');

    if (!dot) {
        dot = token_end;
    }
    if (dot <= token + 2) {
        return -1;
    }
    // NOTE: The resulting format string is something like "%2hhu%lf%n"
    if (avs_simple_snprintf(format_string, sizeof(format_string),
                            "%%%uhhu%%lf%%n", (unsigned int) (dot - 2 - token))
                    < 0
            || sscanf(token, format_string, &out->degrees, &out->minutes,
                      &chars_read)
                           < 2
            || token[chars_read]) {
        return -1;
    }
    return 0;
}

static void gps_process_gns_sentence(char **strsepptr) {
    struct internal_gps_gns_data data = { 0 };
    size_t token_idx = 0;

    // Example sentence:
    // $GNGNS,170416.00,5005.0070,N,01954.0800,E,AN,04,4.9,225.4,M,41.8,M,,,V
    while (true) {
        const char *token = strsep(strsepptr, ",");

        if (!token) {
            break;
        }

        switch (token_idx++) {
        case 0: // UTC of position (hhmmss.ss)
            if (parse_gps_fix_timestamp(&data.timestamp, token)) {
                return;
            }
            break;

        case 1: // Latitude
            if (parse_gps_fix_latlon_without_hemisphere(&data.latitude,
                                                        token)) {
                return;
            }
            break;

        case 2: // Latitude - N/S
            if ((token[0] != 'N' && token[0] != 'S') || token[1] != '\0') {
                return;
            }
            data.latitude.hemisphere = token[0];
            break;

        case 3: // Longitude
            if (parse_gps_fix_latlon_without_hemisphere(&data.longitude,
                                                        token)) {
                return;
            }
            break;

        case 4: // Longitude - E/W
            if ((token[0] != 'E' && token[0] != 'W') || token[1] != '\0') {
                return;
            }
            data.longitude.hemisphere = token[0];
            break;

        case 8: { // Altitude
            int chars_read;

            if (sscanf(token, "%lf%n", &data.altitude, &chars_read) < 1
                    || token[chars_read]) {
                return;
            }
            break;
        }

        case 5: // Mode indicator
        case 6: // Number of satellites in use
        case 7: // HDOP
        default:
            // Ignore those
            break;
        }
    }

    if (token_idx >= 9) {
        // We have latitude, longitude and altitude, so post this
        gps_last_state_internal.gns = data;
        gps_last_state_internal.valid_fields |= VALID_FIELD_GNS;
    }
}

static void gps_process_zda_sentence(char **strsepptr) {
    struct internal_gps_date date = { 0 };
    size_t token_idx = 0;
    int chars_read;

    // Example sentence: $GNZDA,132405.00,23,08,2022,,
    while (true) {
        const char *token = strsep(strsepptr, ",");

        if (!token) {
            break;
        }

        switch (token_idx++) {
        case 1: // Day
            if (sscanf(token, "%hhu%n", &date.day, &chars_read) < 1
                    || token[chars_read]) {
                return;
            }
            break;

        case 2: // Month
            if (sscanf(token, "%hhu%n", &date.month, &chars_read) < 1
                    || token[chars_read]) {
                return;
            }
            break;

        case 3: // Year
            if (sscanf(token, "%hu%n", &date.year, &chars_read) < 1
                    || token[chars_read]) {
                return;
            }
            break;

        case 0: // UTC (hhmmss.ss)
        default:
            // Ignore those
            break;
        }
    }

    if (token_idx >= 3) {
        // We have day, month and year, so post this
        gps_last_state_internal.zda = date;
        gps_last_state_internal.valid_fields |= VALID_FIELD_ZDA;
    }
}

static void gps_process_vtg_sentence(char **strsepptr) {
    double speed;
    size_t token_idx = 0;
    int chars_read;

    // Example sentence: $GNVTG,321.3,T,,M,1.2,N,2.2,K,A
    while (true) {
        const char *token = strsep(strsepptr, ",");

        if (!token) {
            break;
        }

        switch (token_idx++) {
        case 4: // Speed over ground [knot]
            if (sscanf(token, "%lf%n", &speed, &chars_read) < 1
                    || token[chars_read]) {
                return;
            }
            break;

        case 0: // Course over ground - True
        case 1: // T
        case 2: // Course over ground - Magnetic
        case 3: // M
        default:
            // Ignore those
            break;
        }
    }

    if (token_idx >= 4) {
        gps_last_state_internal.vtg_speed = speed;
        gps_last_state_internal.valid_fields |= VALID_FIELD_VTG;
    }
}

static struct anjay_zephyr_gps_data convert_gps_data(void) {
    static const double MPS_IN_KNOT = 463.0 / 900.0;

    return (const struct anjay_zephyr_gps_data) {
        .valid = true,
        .timestamp = timeutil_timegm64(&(const struct tm) {
            .tm_sec = gps_last_state_internal.gns.timestamp.seconds,
            .tm_min = gps_last_state_internal.gns.timestamp.minutes,
            .tm_hour = gps_last_state_internal.gns.timestamp.hours,
            .tm_mday = gps_last_state_internal.zda.day,
            .tm_mon = gps_last_state_internal.zda.month - 1,
            .tm_year = gps_last_state_internal.zda.year - 1900
        }),
        .latitude = (gps_last_state_internal.gns.latitude.hemisphere == 'S' ? -1
                                                                            : 1)
                    * (gps_last_state_internal.gns.latitude.degrees
                       + gps_last_state_internal.gns.latitude.minutes / 60.0),
        .longitude =
                (gps_last_state_internal.gns.longitude.hemisphere == 'W' ? -1
                                                                         : 1)
                * (gps_last_state_internal.gns.longitude.degrees
                   + gps_last_state_internal.gns.longitude.minutes / 60.0),
        .altitude = gps_last_state_internal.gns.altitude,
        .speed = gps_last_state_internal.vtg_speed * MPS_IN_KNOT
    };
}

static void gps_process_sentence(char *msg) {
    // NOTE: The string is passed non-const so that we can use strsep()
    size_t len = strlen(msg);
    uint8_t checksum_calculated = 0;
    uint8_t checksum_incoming;
    int chars_read;

    if (len < 4 || msg[0] != '$' || msg[len - 3] != '*'
            || sscanf(&msg[len - 2], "%hhx%n", &checksum_incoming, &chars_read)
                           < 1
            || chars_read != 2) {
        // No checksum
        return;
    }

    msg[len - 3] = '\0';
    len -= 3;

    for (size_t i = 1; i < len; ++i) {
        checksum_calculated = checksum_calculated ^ ((uint8_t *) msg)[i];
    }

    if (checksum_calculated != checksum_incoming) {
        // Wrong checksum
        return;
    }

    char *saveptr = msg;
    const char *token = strsep(&saveptr, ",");

    if (!token || strlen(token) != 6) {
        return;
    }

    // Example full set of sentences:
    // $GPGGA,133120.03,5005.0134,N,01954.1126,E,1,05,6.1,189.9,M,41.8,M,,*60
    // $GNGLL,5005.0134,N,01954.1126,E,133120.03,A,A*7D
    // $GNGSA,A,3,06,09,17,19,,,,,,,,,7.7,6.1,4.8,1*3B
    // $GNGSA,A,3,71,,,,,,,,,,,,7.7,6.1,4.8,2*3F
    // $GPGSV,3,2,11,09,45,235,21,17,17,243,32,19,24,269,24,21,04,159,,0*60
    // $GPGSV,3,3,11,22,00,055,,26,04,088,,31,23,046,10,,,,,0*55
    // $GLGSV,3,1,09,69,15,067,,70,70,014,,71,41,273,28,78,05,005,00,0*7D
    // $GLGSV,3,2,09,79,27,051,00,80,20,115,,85,40,213,,86,52,288,,0*73
    // $GNGNS,133120.03,5005.0134,N,01954.1126,E,AA,05,6.1,189.9,M,41.8,M,,,V*2E
    // $GNRMC,133120.03,A,5005.0134,N,01954.1126,E,1.2,321.3,230822,,,A,V*39
    // $GNVTG,321.3,T,,M,1.2,N,2.2,K,A*13
    // $GNZDA,133120.03,23,08,2022,,*72

    if (strcmp(&token[3], "GNS") == 0) {
        gps_process_gns_sentence(&saveptr);
    } else if (strcmp(&token[3], "ZDA") == 0) {
        gps_process_zda_sentence(&saveptr);
    } else if (strcmp(&token[3], "VTG") == 0) {
        gps_process_vtg_sentence(&saveptr);
    }

    if ((~gps_last_state_internal.valid_fields
         & (VALID_FIELD_GNS | VALID_FIELD_ZDA | VALID_FIELD_VTG))
            == 0) {
        SYNCHRONIZED(anjay_zephyr_gps_read_last_mtx) {
            if (!anjay_zephyr_gps_read_last.valid) {
                LOG_INF("First valid GPS fix produced");
            }
            anjay_zephyr_gps_read_last = convert_gps_data();
            gps_last_state_internal.valid_fields = 0;
        }
    }
}

static void gps_process_message(char *msg) {
    // NOTE: The supported messages are referenced here:
    // https://reyax.com/upload/products_download/download_file/RYS8830_RYS8833_Software_Guide_draft.pdf
    // (RYS8830 is based on CXD5605AGF)

    if (*msg == '$') {
        gps_process_sentence(msg);
        return;
    }

    switch (gps_incoming_state) {
    case CXD5605_SENT_BSSL: {
        if (strcmp(msg, "[BSSL] Done") != 0) {
            if (!bssl_failed_once) {
                LOG_ERR("Could not select output sentences, will retry...");
            }
            // Suppress further log if GPS is inoperational
            bssl_failed_once = true;
            goto restart;
        } else if (send_message("@GNS 0x83\r\n")) {
            // GPS (0x1) + GLONASS (0x2) + Galileo (0x80)
            LOG_ERR("Could not send the message selecting the satellite "
                    "systems");
        } else {
            gps_incoming_state = CXD5605_SENT_GNS;
        }
        break;
    }

    case CXD5605_SENT_GNS: {
        if (strcmp(msg, "[GNS] Done") != 0) {
            LOG_ERR("Could not select satellite systems");
            goto restart;
        } else if (send_message("@GSP\r\n")) {
            LOG_ERR("Could not send the message starting the positioning");
            goto restart;
        } else {
            gps_incoming_state = CXD5605_SENT_GSP;
        }
        break;
    }

    case CXD5605_SENT_GSP: {
        if (strcmp(msg, "[GSP] Done") != 0) {
            LOG_ERR("Could not start positioning");
            goto restart;
        } else if (send_message("@WUP\r\n")) {
            LOG_ERR("Could not send the wake-up message");
            goto restart;
        } else {
            gps_incoming_state = CXD5605_SENT_WUP;
        }
        break;
    }

    case CXD5605_SENT_WUP: {
        if (strcmp(msg, "[WUP] Done") != 0) {
            LOG_ERR("Could not wake up the GPS module");
            goto restart;
        } else {
            gps_incoming_state = CXD5605_OPERATIONAL;
        }
        break;
    }

    case CXD5605_OPERATIONAL:
        break;
    }
    return;
restart:
    send_message(bssl_message);
    gps_incoming_state = CXD5605_SENT_BSSL;
}

static void gps_try_consume_line(void) {
    while (true) {
        char *lf = gps_incoming_buffer_ptr ? memchr(gps_incoming_buffer, '\n',
                                                    gps_incoming_buffer_ptr)
                                           : NULL;

        if (!lf) {
            return;
        }

        if (lf == gps_incoming_buffer || lf[-1] != '\r') {
            LOG_ERR("Invalid line termination");
        } else {
            // Null-terminate the line
            lf[-1] = '\0';
            gps_process_message(gps_incoming_buffer);
        }

        gps_incoming_buffer_ptr =
                gps_incoming_buffer_ptr - (lf - gps_incoming_buffer) - 1;
        memmove(gps_incoming_buffer, lf + 1, gps_incoming_buffer_ptr);
    }
}

static void gps_incoming_work_handler(struct k_work *work) {
    unsigned int to_consume;

    do {
        to_consume = atomic_fetch_sub(&gps_incoming_count, 1) - 1;

        // For description of the incoming data format, see
        // http://reyax.com.cn/wp-content/uploads/2019/09/RYS8838-Software-Guide.pdf
        // (RYS8838 uses a similar Sony CXD chip)
        uint8_t response[74];
        int result = recv_message(response, sizeof(response));

        if (result) {
            LOG_ERR("Receiving I2C data failed");
            continue;
        }

        if (response[0] != 0xA5) {
            LOG_ERR("Invalid data packet received");
            continue;
        }

        uint8_t checksum = 0;

        for (size_t i = 0; i < sizeof(response); ++i) {
            checksum += response[i];
        }
        if (checksum != 0xFF) {
            LOG_ERR("Invalid checksum of incoming data");
            continue;
        }

        // Extract the NMEA messages
        const uint8_t *const end = &response[sizeof(response) - 1];
        uint8_t *ptr = &response[1];

        static const uint8_t message_begin_marker = 0x0F;

        while (ptr + 1 < end && ptr[0] == message_begin_marker) {
            const uint8_t msg_len = ptr[1];
            uint8_t *msg_end = ptr + 2 + msg_len;

            if (msg_end > end) {
                LOG_ERR("Invalid response length");
                break;
            }

            if (gps_incoming_buffer_ptr + msg_len
                    > sizeof(gps_incoming_buffer)) {
                // Overlong line. Truncate the beginning - it'll be invalid,
                // but we'll be able to track the line ending that way.
                size_t to_truncate = gps_incoming_buffer_ptr + msg_len
                                     - sizeof(gps_incoming_buffer);
                if (to_truncate < sizeof(gps_incoming_buffer)) {
                    memmove(gps_incoming_buffer,
                            &gps_incoming_buffer[to_truncate],
                            sizeof(gps_incoming_buffer) - to_truncate);
                }
                gps_incoming_buffer_ptr = sizeof(gps_incoming_buffer) - msg_len;
            }
            memcpy(&gps_incoming_buffer[gps_incoming_buffer_ptr], &ptr[2],
                   msg_len);
            gps_incoming_buffer_ptr += msg_len;

            gps_try_consume_line();

            ptr = msg_end;
        }
    } while (to_consume);
}

int _anjay_zephyr_initialize_gps(void) {
    const struct device *gpio = device_get_binding(GNSS_GPIO_NAME);

    if (!gpio) {
        LOG_ERR("GPS GPIO node not found");
        return -1;
    }

    gpio_init_callback(&gpio_cb_obj, gpio_cb, BIT(GNSS_INT));

    if (gpio_pin_interrupt_configure(gpio, GNSS_INT, GPIO_INT_DISABLE)
            || gpio_pin_configure(gpio, GNSS_INT, GPIO_INPUT | GPIO_PULL_UP)
            || gpio_add_callback(gpio, &gpio_cb_obj)
            || gpio_pin_interrupt_configure(gpio, GNSS_INT,
                                            GPIO_INT_EDGE_RISING)) {
        LOG_ERR("Could not configure GPIO");
        return -1;
    }

    if (send_message(bssl_message)) {
        LOG_ERR("Could not send the message starting the positioning");
        return -1;
    }

    return 0;
}

int _anjay_zephyr_stop_gps(void) {
    return 0;
}
