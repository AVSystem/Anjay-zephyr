/*
 * Copyright 2020-2022 AVSystem <avsystem@avsystem.com>
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

#ifndef NET_IMPL_H
#define NET_IMPL_H

#include <zephyr/net/socket.h>

#include <avsystem/commons/avs_socket_v_table.h>

#ifdef CONFIG_ANJAY_COMPAT_ZEPHYR_TLS
#    include "zephyr_tls_compat.h"
#endif // CONFIG_ANJAY_COMPAT_ZEPHYR_TLS

typedef union {
    struct sockaddr addr;
#ifdef CONFIG_NET_IPV4
    struct sockaddr_in in;
#endif // CONFIG_NET_IPV4
#ifdef CONFIG_NET_IPV6
    struct sockaddr_in6 in6;
#endif // CONFIG_NET_IPV6
    struct sockaddr_storage storage;
} sockaddr_union_t;

typedef struct net_socket_impl_struct {
    const avs_net_socket_v_table_t *operations;
    int socktype;
    int sockproto;
    int fd;
    avs_time_duration_t recv_timeout;
    uint8_t address_family;
    sockaddr_union_t local_addr;
    sockaddr_union_t peer_addr;
    char peer_hostname[256];
    bool shut_down;
    size_t bytes_sent;
    size_t bytes_received;
    avs_net_resolved_endpoint_t *preferred_endpoint;
#ifdef CONFIG_ANJAY_COMPAT_ZEPHYR_TLS
    void *sec_tags;
    size_t sec_tags_size;
    anjay_zephyr_ciphersuite_id_t *ciphersuites;
    size_t ciphersuites_size;
    avs_net_dtls_handshake_timeouts_t dtls_handshake_timeouts;
    bool server_cert_validation;
    bool dane;
    char server_name_indication[256];
#endif // CONFIG_ANJAY_COMPAT_ZEPHYR_TLS
} net_socket_impl_t;

#endif /* NET_IMPL_H */
