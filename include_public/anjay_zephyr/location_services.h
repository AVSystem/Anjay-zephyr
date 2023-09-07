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

#pragma once

#ifdef CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES
#    include <stdbool.h>

/**
 * Enumeration that specifies the result of the location services request.
 */
typedef enum {
    /**
     * Request completed successfully.
     */
    ANJAY_ZEPHYR_LOCATION_SERVICES_SUCCESSFUL,
    /**
     * Anjay was unable to send a request to the server.
     */
    ANJAY_ZEPHYR_LOCATION_SERVICES_UNABLE_TO_SEND,
    /**
     * No response obtained from the server within 90 seconds after sending
     * request.
     */
    ANJAY_ZEPHYR_LOCATION_SERVICES_NO_RESPONSE,
    /**
     * Response from the server had invalid data.
     */
    ANJAY_ZEPHYR_LOCATION_SERVICES_IMPROPER_RESPONSE,
    /**
     * Response from the server contained a result code that indicates a
     * temporary failure. It means that user should utilize exponential backoff
     * while retrying the request. This value will only be passed to user
     * callback when user disables the exponential backoff mechanism implemented
     * in Anjay-zephyr when calling anjay_zephyr_location_services_..._request
     * with exponential_backoff set to false.
     */
    ANJAY_ZEPHYR_LOCATION_SERVICES_TEMPORARY_FAILURE,
    /**
     * Response from the server contained a result code that indicates a
     * permanent failure. It means that further location services requests will
     * not be processed before device reboot.
     */
    ANJAY_ZEPHYR_LOCATION_SERVICES_PERMANENT_FAILURE,
    /**
     * Anjay was stopped during the request.
     */
    ANJAY_ZEPHYR_LOCATION_SERVICES_ANJAY_STOPPED
} anjay_zephyr_location_services_request_result_t;

/**
 * Enumeration that specifies the available ground fix location request types.
 */
typedef enum {
    /**
     * Request update of location of the device only on the server side (new
     * location will not be sent back to the device) based on the nearest
     * cellular tower.
     */
    ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_INFORM_SINGLE,
    /**
     * Request update of location of the device only on the server side (new
     * location will not be sent to the device) based on the nearest cellular
     * tower and its neighbor cellular towers.
     */
    ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_INFORM_MULTI,
    /**
     * Request location of the device based on the nearest cellular tower.
     */
    ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_REQUEST_SINGLE,
    /**
     * Request location of the device based on the nearest cellular tower and
     * its neighbor cellular towers.
     */
    ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_REQUEST_MULTI
} anjay_zephyr_location_services_gf_location_request_type_t;

/**
 * Structure with location based on cellular towers.
 */
typedef struct {
    /**
     * Location latitude angle.
     */
    double latitude;
    /**
     * Location longitude angle.
     */
    double longitude;
    /**
     * The radius of the uncertainty circle around the location in meters.
     */
    double accuracy;
} anjay_zephyr_location_services_ground_fix_location_t;

/**
 * Callback function type used by @ref
 * anjay_zephyr_location_services_gf_location_request. It is called when the
 * ground fix location request is completed.
 *
 * @param result    Specifies the result with which the request processing was
 * completed.
 *
 * @param location  Received location. This structure contains a valid value
 * only if @p result is equal to ANJAY_ZEPHYR_LOCATION_SERVICES_SUCCESSFUL and
 * user has selected a type of request that sends the location to the device
 * (ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_REQUEST_SINGLE or
 * ANJAY_ZEPHYR_LOC_SERVICES_GF_LOCATION_REQUEST_REQUEST_MULTI).
 */
typedef void anjay_zephyr_location_services_gf_location_request_cb_t(
        anjay_zephyr_location_services_request_result_t result,
        anjay_zephyr_location_services_ground_fix_location_t location);

/**
 * Request ground fix location.
 *
 * @param anjay                 Anjay Object to operate on.
 *
 * @param cb                    User callback called when the request is
 * completed.
 *
 * @param request_type          Request type.
 *
 * @param exponential_backoff   Specifies whether the exponential backoff
 * mechanism is enabled. If so, and if the server response contains a result
 * code indicating a temporary failure, the request will be rescheduled with an
 * appropriate delay without calling user callback.
 *
 * @return                      0 for success, or -1 in case of error.
 */
int anjay_zephyr_location_services_gf_location_request(
        anjay_t *anjay,
        anjay_zephyr_location_services_gf_location_request_cb_t *cb,
        anjay_zephyr_location_services_gf_location_request_type_t request_type,
        bool exponential_backoff);
#endif // CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES
