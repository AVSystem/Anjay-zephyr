# Copyright 2020-2024 AVSystem <avsystem@avsystem.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if(CONFIG_ANJAY)
    zephyr_library()

    file(GLOB_RECURSE ANJAY_SOURCES "deps/anjay/src/*.c")
    file(GLOB_RECURSE AVS_COMMONS_SOURCES "deps/anjay/deps/avs_commons/src/*.c")
    file(GLOB_RECURSE AVS_COAP_SOURCES "deps/anjay/deps/avs_coap/src/*.c")


    if(CONFIG_ANJAY_ZEPHYR_FACTORY_PROVISIONING_INITIAL_FLASH)
        set(CLIENT_SOURCES
            src/config.c
            src/config.h
            src/persistence.c
            src/persistence.h
            src/utils.c
            src/utils.h)
    else()
        set(CLIENT_SOURCES
            include_public/anjay_zephyr/ipso_objects.h
            src/config.c
            src/config.h
            src/firmware_update.h
            src/gps.h
            src/lwm2m.c
            src/lwm2m_internal.h
            src/network/network.c
            src/network/network.h
            src/network/network_internal.h
            src/objects/buzzer.c
            src/objects/device.c
            src/objects/led_color_light.c
            src/objects/light_control.c
            src/objects/location.c
            src/objects/objects.h
            src/objects/push_button.c
            src/objects/sensors.c
            src/objects/switch.c
            src/persistence.h
            src/utils.c
            src/utils.h)

        if(CONFIG_ANJAY_ZEPHYR_SHELL)
            list(APPEND CLIENT_SOURCES
                 src/anjay_shell.c)
        endif()

        if(CONFIG_ANJAY_ZEPHYR_PERSISTENCE)
            list(APPEND CLIENT_SOURCES
                 src/persistence.c)
        endif()

        if(CONFIG_ANJAY_ZEPHYR_GPS_NRF)
            list(APPEND CLIENT_SOURCES
                 src/gps_impl/gps_nrf.c)
        endif()

        if(CONFIG_ANJAY_ZEPHYR_GPS_CXD5605)
            list(APPEND CLIENT_SOURCES
                 src/gps_impl/gps_cxd5605.c)
        endif()

        if(CONFIG_ANJAY_ZEPHYR_NRF_LC_INFO)
            list(APPEND CLIENT_SOURCES
                 src/nrf_lc_info.c
                 src/nrf_lc_info.h
                 src/objects/conn_mon.c
                 src/objects/ecid.c)
        endif()

        if(CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_GROUND_FIX_LOCATION)
            list(APPEND CLIENT_SOURCES
            src/objects/ground_fix_location.c)
        endif()

        if(CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES_ASSISTANCE)
            list(APPEND CLIENT_SOURCES
            src/objects/gnss_assistance.c)
        endif()

        if(CONFIG_ANJAY_ZEPHYR_LOCATION_SERVICES)
            list(APPEND CLIENT_SOURCES
                 src/location_services.c
                 src/location_services.h)
        endif()

        if(CONFIG_ANJAY_ZEPHYR_FOTA)
            list(APPEND CLIENT_SOURCES
                 src/firmware_update.c)
        endif()

        if(CONFIG_ANJAY_ZEPHYR_ADVANCED_FOTA_NRF9160)
            list(APPEND CLIENT_SOURCES
                 src/afu/nrf9160/afu_nrf9160_application.c
                 src/afu/nrf9160/afu_nrf9160_modem.c
                 src/afu/nrf9160/afu_nrf9160.c
                 src/afu/nrf9160/afu_nrf9160.h)
        endif()

        if(CONFIG_LTE_LINK_CONTROL)
            list(APPEND CLIENT_SOURCES
                 src/network/network_nrf91.c)
        elseif(CONFIG_NET_L2_OPENTHREAD)
            list(APPEND CLIENT_SOURCES
                 src/network/network_openthread.c)
        elseif(CONFIG_MODEM_MURATA_1SC OR CONFIG_WIFI_RS9116W)
            list(APPEND CLIENT_SOURCES
                 src/network/network_devedge.c
                 src/network/network_devedge.h)
        elseif(CONFIG_WIFI_ESP32)
            list(APPEND CLIENT_SOURCES
                 src/network/network_esp32.c)
        elseif(CONFIG_WIFI_ESWIFI)
            list(APPEND CLIENT_SOURCES
                 src/network/network_eswifi.c)
        elseif(CONFIG_WIFI_NRF700X)
            list(APPEND CLIENT_SOURCES
                 src/network/network_nrf700x.c)
        elseif(CONFIG_WIFI)
            list(APPEND CLIENT_SOURCES
                 src/network/network_wifi.c)
        else()
            add_compile_definitions(ANJAY_ZEPHYR_NO_NETWORK_MGMT)
            message(WARNING "Your application is using network bearer unsupported by anjay-zephyr. Features related to link management and availability detection will be disabled.")
        endif()
    endif()


    zephyr_library_sources(
        ${ANJAY_SOURCES}
        ${AVS_COMMONS_SOURCES}
        ${AVS_COAP_SOURCES}
        ${CLIENT_SOURCES}
        compat/log_impl.c
        compat/threading_compat.c
        )

    zephyr_library_sources_ifdef(CONFIG_ANJAY_COMPAT_NET_LIMITED_POLL_WORKAROUND    compat/custom_polling.c)
    zephyr_library_sources_ifdef(CONFIG_ANJAY_COMPAT_MBEDTLS    compat/mbedtls_compat.c)
    zephyr_library_sources_ifdef(CONFIG_ANJAY_COMPAT_NET        compat/net_impl.c
                                                                compat/net_impl.h)
    zephyr_library_sources_ifdef(CONFIG_ANJAY_COMPAT_TIME       compat/time_compat.c)
    zephyr_library_sources_ifdef(CONFIG_ANJAY_COMPAT_ZEPHYR_TLS compat/zephyr_tls_compat.c
                                                                compat/zephyr_tls_compat.h)

    zephyr_include_directories(config
                               deps/anjay/deps/avs_coap/include_public
                               deps/anjay/deps/avs_commons/include_public
                               deps/anjay/include_public
                               include_public
                               include_public/anjay_zephyr
                               )

    target_include_directories(${ZEPHYR_CURRENT_LIBRARY}
                               PRIVATE
                               deps/anjay/deps/avs_coap/src
                               deps/anjay/deps/avs_commons/src
                               deps/anjay/src
                               src
                               )

    if(NOT CONFIG_ASSERT)
        target_compile_definitions(${ZEPHYR_CURRENT_LIBRARY} PRIVATE NDEBUG)
    endif()

    # It seems that since Zephyr 3.6 mbedTLS is not linked implicitly
    # to libraries, see https://github.com/zephyrproject-rtos/zephyr/issues/69375
    zephyr_library_link_libraries_ifdef(CONFIG_MBEDTLS mbedTLS)
endif()
