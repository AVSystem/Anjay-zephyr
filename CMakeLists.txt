# Copyright 2020-2021 AVSystem <avsystem@avsystem.com>
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

zephyr_library_sources(
    ${ANJAY_SOURCES}
    ${AVS_COMMONS_SOURCES}
    ${AVS_COAP_SOURCES}
    compat/threading_compat.c
    )

zephyr_library_sources_ifdef(CONFIG_ANJAY_COMPAT_MBEDTLS compat/mbedtls_compat.c)
zephyr_library_sources_ifdef(CONFIG_ANJAY_COMPAT_NET     compat/net_impl.c)
zephyr_library_sources_ifdef(CONFIG_ANJAY_COMPAT_TIME    compat/time_compat.c)

zephyr_include_directories(config
                           deps/anjay/src
                           deps/anjay/deps/avs_commons/src
                           deps/anjay/deps/avs_coap/src
                           deps/anjay/include_public
                           deps/anjay/deps/avs_commons/include_public
                           deps/anjay/deps/avs_coap/include_public
                           )

set_source_files_properties(${AVS_COMMONS_SOURCES}
                            PROPERTIES INCLUDE_DIRECTORIES ${ZEPHYR_BASE}/include/posix)

endif()
