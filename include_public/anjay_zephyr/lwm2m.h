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

/**
 * @file anjay_zephyr/lwm2m.h
 *
 * Anjay Zephyr can be initialized either by
 * @p anjay_zephyr_lwm2m_init_from_settings or
 * @p anjay_zephyr_lwm2m_init_from_user_params function.
 *
 * When user selects @p anjay_zephyr_lwm2m_init_from_settings , default values
 * and values provided by KConfig will be used to initialize Anjay, Security
 * object and Server object. If user enables the Anjay shell, they will be able
 * to change values of individual settings at runtime. New values provided at
 * runtime are persisted and will be restored after restarting the device.
 *
 * When user selects @p anjay_zephyr_lwm2m_init_from_user_params , they can
 * pass:
 * - configuration for Anjay,
 * - Security instances,
 * - Server instances
 * by @p user_params arguments. If this function is used, values ​​passed by
 * the Anjay shell or by KConfig have no effect on the above-mentioned
 * components. Initialization for Anjay and Security/Server instances are
 * separate from each other. It means that user has the option to configure only
 * Anjay or Security/Server instances, then the other one (Security/Server
 * instances or Anjay respectively) will behave as described in the comment for
 * @p anjay_zephyr_lwm2m_init_with_internal_config function.
 */

#pragma once

#include <anjay/anjay.h>
#include <anjay/security.h>
#include <anjay/server.h>

/**
 * Enumeration that specifies the reason for the user callback invocation.
 */
enum anjay_zephyr_lwm2m_callback_reasons {
    /**
     * Passed to the user callback during initialization of Anjay.
     */
    ANJAY_ZEPHYR_LWM2M_CALLBACK_REASON_INIT,
    /**
     * Passed to the user callback before entering Anjay event loop.
     */
    ANJAY_ZEPHYR_LWM2M_CALLBACK_REASON_ANJAY_READY,
    /**
     * Passed to the user callback right after exiting Anjay event loop.
     */
    ANJAY_ZEPHYR_LWM2M_CALLBACK_REASON_ANJAY_SHUTTING_DOWN,
    /**
     * Passed to the user callback when exiting Anjay thread or if something
     * goes wrong during Anjay initialization.
     *
     * @attention       If this enumerator is passed to the user callback then
     * the anjay callback argument is a NULL pointer.
     */
    ANJAY_ZEPHYR_LWM2M_CALLBACK_REASON_CLEANUP,
};

/**
 * Callback function type used by @ref anjay_zephyr_lwm2m_set_user_callback. It
 * is user callback called from Anjay thread, after @ref
 * anjay_zephyr_lwm2m_start has been executed.
 *
 * @param anjay     Anjay Object to operate on.
 *
 * @param reason    Enumeration specifying the reason for the call.
 *
 * @return          Should return 0 or an error code on failure.
 *
 * @attention       If the @p reason for the call is @ref
 * ANJAY_ZEPHYR_LWM2M_CALLBACK_REASON_CLEANUP then @p anjay is NULL!
 */
typedef int
anjay_zephyr_lwm2m_cb_t(anjay_t *anjay,
                        enum anjay_zephyr_lwm2m_callback_reasons reason);

/**
 * Configuration structure for Anjay Zephyr.
 */
typedef struct {
    /**
     * Pointer to a structure with Anjay configuration.
     */
    const anjay_configuration_t *anjay_config;
    /**
     * Pointer to an array of Security instance structures.
     */
    const anjay_security_instance_t *security_instances;
    /**
     * Pointer to an array of Security instance Ids.
     *
     * Note: If for some Security instance the value of an element of this array
     * is set to ANJAY_ID_INVALID then the Instance Id is generated
     * automatically, otherwise value of *inout_iid is used as a new Security
     * Instance Id.
     */
    anjay_iid_t *inout_security_instance_ids;
    /**
     * Length of @p security_instances and @p inout_security_instance_ids (their
     * lengths must be equal).
     */
    size_t security_instances_count;
    /**
     * Pointer to an array of Server instance structures.
     */
    const anjay_server_instance_t *server_instances;
    /**
     * Pointer to an array of Server instance Ids.
     *
     * Note: If for some Server instance the value of an element of this array
     * is set to ANJAY_ID_INVALID then the Instance Id is generated
     * automatically, otherwise value of *inout_iid is used as a new Server
     * Instance Id.
     */
    anjay_iid_t *inout_server_instance_ids;
    /**
     * Length of @p server_instances and @p inout_server_instance_ids (their
     * lengths must be equal).
     */
    size_t server_instances_count;
} anjay_zephyr_init_params_t;

/**
 * Initialize Anjay Zephyr with user-defined parameters.
 *
 * @param user_params    Anjay Zephyr parameters. Content of the structure is
 * copied, but contents under @p user_params pointers are NOT copied and must
 * remain valid for the lifetime of Anjay.
 *
 * @return          0 on success, a negative value in case of failure.
 */
int anjay_zephyr_lwm2m_init_from_user_params(
        anjay_zephyr_init_params_t *user_params);

/**
 * Initialize Anjay Zephyr.
 *
 * @return          0 on success, a negative value in case of failure.
 */
int anjay_zephyr_lwm2m_init_from_settings(void);

/**
 * Start Anjay thread.
 *
 * @return          0 for success, or -1 in case of error.
 */
int anjay_zephyr_lwm2m_start(void);

/**
 * Stop Anjay thread.
 *
 * @return          0 for success, or -1 in case of error.
 */
int anjay_zephyr_lwm2m_stop(void);

/**
 * Callback function type used by @ref
 * anjay_zephyr_lwm2m_execute_callback_with_locked_anjay.
 *
 * @param anjay     Anjay Object to operate on.
 *
 * @param arg       Opaque argument with user data.
 *
 * @return          Should return 0 or an error code on failure.
 */
typedef int anjay_zephyr_lwm2m_callback_with_locked_anjay_t(anjay_t *anjay,
                                                            void *arg);

/**
 * Set user callback.
 *
 * @param cb        Pointer to user callback.
 *
 */
void anjay_zephyr_lwm2m_set_user_callback(anjay_zephyr_lwm2m_cb_t *cb);

/**
 * Execute user function with locked Anjay.
 *
 * @param cb        User callback.
 * @param arg       Opaque argument with user data that will be passed to @p cb.
 *
 * @return          Value return by @p cb.
 */
int anjay_zephyr_lwm2m_execute_callback_with_locked_anjay(
        anjay_zephyr_lwm2m_callback_with_locked_anjay_t *cb, void *arg);
