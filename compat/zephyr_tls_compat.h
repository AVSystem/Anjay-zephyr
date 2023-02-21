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

#ifndef ZEPHYR_TLS_COMPAT_H
#define ZEPHYR_TLS_COMPAT_H

#if defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)
#    include <modem/lte_lc.h>
#    include <modem/modem_key_mgmt.h>
#    include <nrf_errno.h>
#    include <nrf_modem_gnss.h>
#else // defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)
#    include <zephyr/net/tls_credentials.h>
#endif // defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)

#include <avsystem/commons/avs_socket.h>

#if defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)
typedef nrf_sec_cipher_t anjay_zephyr_ciphersuite_id_t;
#else  // defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)
typedef int anjay_zephyr_ciphersuite_id_t;
#endif // defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)

struct net_socket_impl_struct;

avs_error_t
anjay_zephyr_configure_security__(struct net_socket_impl_struct *socket,
                                  const avs_net_ssl_configuration_t *config);

avs_error_t anjay_zephyr_set_dane_tlsa_array__(
        struct net_socket_impl_struct *socket,
        const avs_net_socket_dane_tlsa_array_t *dane_tlsa_array);

avs_error_t
anjay_zephyr_init_sockfd_security__(struct net_socket_impl_struct *socket,
                                    const char *host);

void anjay_zephyr_cleanup_security__(struct net_socket_impl_struct *socket);

#endif /* ZEPHYR_TLS_COMPAT_H */
