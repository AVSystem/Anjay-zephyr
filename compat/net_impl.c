/*
 * Copyright 2020-2021 AVSystem <avsystem@avsystem.com>
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

#include <net/socket.h>

#include <avsystem/commons/avs_socket_v_table.h>
#include <avsystem/commons/avs_utils.h>

#ifdef AVS_COMMONS_NET_WITH_POSIX_AVS_SOCKET
#    error "Custom implementation of the network layer conflicts with AVS_COMMONS_NET_WITH_POSIX_AVS_SOCKET"
#endif // AVS_COMMONS_NET_WITH_POSIX_AVS_SOCKET

avs_error_t _avs_net_initialize_global_compat_state(void);
void _avs_net_cleanup_global_compat_state(void);
avs_error_t _avs_net_create_tcp_socket(avs_net_socket_t **socket,
                                       const void *socket_configuration);
avs_error_t _avs_net_create_udp_socket(avs_net_socket_t **socket,
                                       const void *socket_configuration);

avs_error_t _avs_net_initialize_global_compat_state(void) {
    return AVS_OK;
}

void _avs_net_cleanup_global_compat_state(void) {}

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

typedef struct {
    const avs_net_socket_v_table_t *operations;
    int socktype;
    int fd;
    avs_time_duration_t recv_timeout;
    uint8_t ai_family;
    sockaddr_union_t local_addr;
    sockaddr_union_t peer_addr;
    char peer_hostname[256];
    bool shut_down;
    size_t bytes_sent;
    size_t bytes_received;
    avs_net_resolved_endpoint_t *preferred_endpoint;
} net_socket_impl_t;

static avs_error_t
net_connect(avs_net_socket_t *sock_, const char *host, const char *port) {
    net_socket_impl_t *sock = (net_socket_impl_t *) sock_;
    struct zsock_addrinfo hints = {
        .ai_socktype = sock->socktype
    };

    struct zsock_addrinfo *addrs = NULL;

    int result = -1;

    if (sock->fd >= 0) {
        hints.ai_family = sock->ai_family;
        if (!zsock_getaddrinfo(host, port, &hints, &addrs) && addrs) {
            result = 0;
        }
    } else {
#ifdef CONFIG_NET_IPV6
        hints.ai_family = AF_INET6;
        if (!zsock_getaddrinfo(host, port, &hints, &addrs) && addrs) {
            sock->ai_family = AF_INET6;
            result = 0;
        }
#endif // CONFIG_NET_IPV6
#ifdef CONFIG_NET_IPV4
        if (result) {
            hints.ai_family = AF_INET;
            if (!zsock_getaddrinfo(host, port, &hints, &addrs) && addrs) {
                sock->ai_family = AF_INET;
                result = 0;
            }
        }
#endif // CONFIG_NET_IPV4
    }

    if (result) {
        return avs_errno(AVS_EADDRNOTAVAIL);
    }

    avs_error_t err = AVS_OK;
    const struct zsock_addrinfo *addr = addrs;
    if (sock->fd < 0
            && (sock->fd = zsock_socket(addrs->ai_family, addrs->ai_socktype,
                                        addrs->ai_socktype == SOCK_DGRAM
                                                ? IPPROTO_UDP
                                                : IPPROTO_TCP))
                           < 0) {
        err = avs_errno(AVS_UNKNOWN_ERROR);
    } else {
        if (sock->preferred_endpoint
                && sock->preferred_endpoint->size == sizeof(sockaddr_union_t)) {
            while (addr) {
                if (addr->ai_addrlen <= sizeof(sockaddr_union_t)
                        && memcmp(addr->ai_addr,
                                  sock->preferred_endpoint->data.buf,
                                  addr->ai_addrlen)
                                       == 0) {
                    break;
                }
                addr = addr->ai_next;
            }
        }
        if (!addr) {
            // Preferred endpoint not found, use the first one
            addr = addrs;
        }
        if (addr->ai_addrlen > sizeof(sock->peer_addr)
                || zsock_connect(sock->fd, addr->ai_addr, addr->ai_addrlen)) {
            err = avs_errno(AVS_ECONNREFUSED);
        }
        if (sock->preferred_endpoint && avs_is_ok(err)) {
            assert(addr->ai_addrlen <= sizeof(sockaddr_union_t));
            memcpy(sock->preferred_endpoint->data.buf, addr->ai_addr,
                   addr->ai_addrlen);
            sock->preferred_endpoint->size = sizeof(sockaddr_union_t);
        }
    }
    if (avs_is_ok(err)) {
        sock->shut_down = false;
        memset(&sock->peer_addr, 0, sizeof(sock->peer_addr));
        memcpy(&sock->peer_addr, addr->ai_addr, addr->ai_addrlen);
        snprintf(sock->peer_hostname, sizeof(sock->peer_hostname), "%s", host);
    }
    zsock_freeaddrinfo(addrs);
    return err;
}

static avs_error_t
net_send(avs_net_socket_t *sock_, const void *buffer, size_t buffer_length) {
    net_socket_impl_t *sock = (net_socket_impl_t *) sock_;
    ssize_t written = zsock_send(sock->fd, buffer, buffer_length, 0);
    if (written >= 0) {
        sock->bytes_sent += (size_t) written;
        if ((size_t) written == buffer_length) {
            return AVS_OK;
        }
    }
    return avs_errno(AVS_EIO);
}

static avs_error_t net_receive(avs_net_socket_t *sock_,
                               size_t *out_bytes_received,
                               void *buffer,
                               size_t buffer_length) {
    net_socket_impl_t *sock = (net_socket_impl_t *) sock_;
    struct zsock_pollfd pfd = {
        .fd = sock->fd,
        .events = ZSOCK_POLLIN
    };
    int64_t timeout_ms;
    if (avs_time_duration_to_scalar(&timeout_ms, AVS_TIME_MS,
                                    sock->recv_timeout)) {
        timeout_ms = -1;
    } else if (timeout_ms < 0) {
        timeout_ms = 0;
    }
    if (zsock_poll(&pfd, 1, (int) timeout_ms) == 0) {
        return avs_errno(AVS_ETIMEDOUT);
    }
    ssize_t bytes_received = zsock_recv(sock->fd, buffer, buffer_length, 0);
    if (bytes_received < 0) {
#ifdef CONFIG_WIFI_ESWIFI
        // Although poll succeeded, recv may fail with errno set to EAGAIN when
        // eswifi modem is used.
        if (errno == EAGAIN) {
            return avs_errno(AVS_ETIMEDOUT);
        }
#endif // CONFIG_WIFI_ESWIFI
        return avs_errno(AVS_EIO);
    }
    *out_bytes_received = (size_t) bytes_received;
    sock->bytes_received += (size_t) bytes_received;
    if (buffer_length > 0 && sock->socktype == SOCK_DGRAM
            && (size_t) bytes_received == buffer_length) {
        return avs_errno(AVS_EMSGSIZE);
    }
    return AVS_OK;
}

static avs_error_t net_close(avs_net_socket_t *sock_) {
    net_socket_impl_t *sock = (net_socket_impl_t *) sock_;
    avs_error_t err = AVS_OK;
    if (sock->fd >= 0) {
        if (zsock_close(sock->fd)) {
            err = avs_errno(AVS_EIO);
        }
        sock->fd = -1;
        sock->shut_down = false;
        memset(&sock->peer_addr, 0, sizeof(sock->peer_addr));
        memset(&sock->local_addr, 0, sizeof(sock->local_addr));
    }
    return err;
}

static avs_error_t net_shutdown(avs_net_socket_t *sock_) {
    net_socket_impl_t *sock = (net_socket_impl_t *) sock_;
    avs_error_t err = avs_errno(AVS_EBADF);
    if (sock->fd >= 0) {
        err = zsock_shutdown(sock->fd, ZSOCK_SHUT_RDWR) ? avs_errno(AVS_EIO)
                                                        : AVS_OK;
        sock->shut_down = true;
    }
    return err;
}

static int get_bind_family(net_socket_impl_t *sock, const char *address) {
    if (sock->peer_addr.addr.sa_family != AF_UNSPEC) {
        return sock->peer_addr.addr.sa_family;
    }
    if (sock->local_addr.addr.sa_family != AF_UNSPEC) {
        return sock->local_addr.addr.sa_family;
    }
#ifdef CONFIG_NET_IPV6
    if (!address || !*address || strchr(address, ':')) {
        return AF_INET6;
    }
#endif // CONFIG_NET_IPV6
#ifdef CONFIG_NET_IPV4
    return AF_INET;
#else  // CONFIG_NET_IPV4
    return AF_UNSPEC;
#endif // CONFIG_NET_IPV4
}

static avs_error_t
net_bind(avs_net_socket_t *sock_, const char *address, const char *port) {
    net_socket_impl_t *sock = (net_socket_impl_t *) sock_;
    sockaddr_union_t addr = {
        .addr.sa_family = get_bind_family(sock, address)
    };
    socklen_t addrlen = 0;
    uint16_t port_be = 0;
    if (port) {
        port_be = htons((uint16_t) strtol(port ? port : "", NULL, 10));
    }

    avs_error_t err = AVS_OK;
#ifdef CONFIG_NET_IPV4
    if (addr.addr.sa_family == AF_INET) {
        if (zsock_inet_pton(AF_INET,
                            (address && *address) ? address : "0.0.0.0",
                            &addr.in.sin_addr)
                != 1) {
            return avs_errno(AVS_EADDRNOTAVAIL);
        } else {
            addrlen = sizeof(addr.in);
            addr.in.sin_port = port_be;
        }
    }
#endif // CONFIG_NET_IPV4
#ifdef CONFIG_NET_IPV6
    if (addr.addr.sa_family == AF_INET6) {
        if (zsock_inet_pton(AF_INET6, (address && *address) ? address : "::",
                            &addr.in6.sin6_addr)
                != 1) {
            return avs_errno(AVS_EADDRNOTAVAIL);
        } else {
            addrlen = sizeof(addr.in6);
            addr.in6.sin6_port = port_be;
        }
    }
#endif // CONFIG_NET_IPV6
    if (avs_is_ok(err)) {
        if (sock->fd < 0
                && (sock->fd = zsock_socket(addr.addr.sa_family, sock->socktype,
                                            sock->socktype == SOCK_DGRAM
                                                    ? IPPROTO_UDP
                                                    : IPPROTO_TCP))
                               < 0) {
            err = avs_errno(AVS_UNKNOWN_ERROR);
        } else if (zsock_bind(sock->fd, &addr.addr, addrlen)) {
            err = avs_errno(AVS_ECONNREFUSED);
        } else {
            sock->shut_down = false;
            sock->ai_family = addr.addr.sa_family;
            sock->local_addr = addr;
            memset(&sock->peer_addr, 0, sizeof(sock->peer_addr));
        }
    }
    if (avs_is_err(err) && sock->fd >= 0) {
        net_close(sock_);
    }
    return err;
}

static avs_error_t net_cleanup(avs_net_socket_t **sock_ptr) {
    avs_error_t err = AVS_OK;
    if (sock_ptr && *sock_ptr) {
        err = net_close(*sock_ptr);
        avs_free(*sock_ptr);
        *sock_ptr = NULL;
    }
    return err;
}

static const void *net_system_socket(avs_net_socket_t *sock_) {
    net_socket_impl_t *sock = (net_socket_impl_t *) sock_;
    return &sock->fd;
}

static avs_error_t stringify_sockaddr_host(const sockaddr_union_t *addr,
                                           char *out_buffer,
                                           size_t out_buffer_size) {
    if (false
#ifdef CONFIG_NET_IPV4
            || (addr->in.sin_family == AF_INET
                && zsock_inet_ntop(AF_INET, &addr->in.sin_addr, out_buffer,
                                   (socklen_t) out_buffer_size))
#endif // CONFIG_NET_IPV4
#ifdef CONFIG_NET_IPV6
            || (addr->in6.sin6_family == AF_INET6
                && zsock_inet_ntop(AF_INET6, &addr->in6.sin6_addr, out_buffer,
                                   (socklen_t) out_buffer_size))
#endif // CONFIG_NET_IPV6
    ) {
        return AVS_OK;
    }
    return avs_errno(AVS_UNKNOWN_ERROR);
}

static avs_error_t stringify_sockaddr_port(const sockaddr_union_t *addr,
                                           char *out_buffer,
                                           size_t out_buffer_size) {
    if (false
#ifdef CONFIG_NET_IPV4
            || (addr->in.sin_family == AF_INET && ntohs(addr->in.sin_port) > 0
                && avs_simple_snprintf(out_buffer, out_buffer_size, "%" PRIu16,
                                       ntohs(addr->in.sin_port))
                           >= 0)
#endif // CONFIG_NET_IPV4
#ifdef CONFIG_NET_IPV6
            || (addr->in6.sin6_family == AF_INET6
                && ntohs(addr->in6.sin6_port) > 0
                && avs_simple_snprintf(out_buffer, out_buffer_size, "%" PRIu16,
                                       ntohs(addr->in6.sin6_port))
                           >= 0)
#endif // CONFIG_NET_IPV6
    ) {
        return AVS_OK;
    }
    return avs_errno(AVS_UNKNOWN_ERROR);
}

static avs_error_t net_remote_host(avs_net_socket_t *sock_,
                                   char *out_buffer,
                                   size_t out_buffer_size) {
    net_socket_impl_t *sock = (net_socket_impl_t *) sock_;
    return stringify_sockaddr_host(&sock->peer_addr, out_buffer,
                                   out_buffer_size);
}

static avs_error_t net_remote_hostname(avs_net_socket_t *sock_,
                                       char *out_buffer,
                                       size_t out_buffer_size) {
    net_socket_impl_t *sock = (net_socket_impl_t *) sock_;
    return avs_simple_snprintf(out_buffer, out_buffer_size, "%s",
                               sock->peer_hostname)
                           < 0
                   ? avs_errno(AVS_UNKNOWN_ERROR)
                   : AVS_OK;
}

static avs_error_t net_remote_port(avs_net_socket_t *sock_,
                                   char *out_buffer,
                                   size_t out_buffer_size) {
    net_socket_impl_t *sock = (net_socket_impl_t *) sock_;
    return stringify_sockaddr_port(&sock->peer_addr, out_buffer,
                                   out_buffer_size);
}

static avs_error_t net_local_port(avs_net_socket_t *sock_,
                                  char *out_buffer,
                                  size_t out_buffer_size) {
    net_socket_impl_t *sock = (net_socket_impl_t *) sock_;
    return stringify_sockaddr_port(&sock->local_addr, out_buffer,
                                   out_buffer_size);
}

static avs_error_t net_get_opt(avs_net_socket_t *sock_,
                               avs_net_socket_opt_key_t option_key,
                               avs_net_socket_opt_value_t *out_option_value) {
    net_socket_impl_t *sock = (net_socket_impl_t *) sock_;
    switch (option_key) {
    case AVS_NET_SOCKET_OPT_RECV_TIMEOUT:
        out_option_value->recv_timeout = sock->recv_timeout;
        return AVS_OK;
    case AVS_NET_SOCKET_OPT_STATE:
        if (sock->fd < 0) {
            out_option_value->state = AVS_NET_SOCKET_STATE_CLOSED;
        } else if (sock->shut_down) {
            out_option_value->state = AVS_NET_SOCKET_STATE_SHUTDOWN;
        } else {
            if (sock->peer_addr.addr.sa_family != AF_UNSPEC) {
                out_option_value->state = AVS_NET_SOCKET_STATE_CONNECTED;
            } else {
                out_option_value->state = AVS_NET_SOCKET_STATE_BOUND;
            }
        }
        return AVS_OK;
    case AVS_NET_SOCKET_OPT_INNER_MTU:
        out_option_value->mtu = 1464;
        return AVS_OK;
    case AVS_NET_SOCKET_OPT_BYTES_SENT:
        out_option_value->bytes_sent = sock->bytes_sent;
        return AVS_OK;
    case AVS_NET_SOCKET_OPT_BYTES_RECEIVED:
        out_option_value->bytes_received = sock->bytes_received;
        return AVS_OK;
    default:
        return avs_errno(AVS_ENOTSUP);
    }
}

static avs_error_t net_set_opt(avs_net_socket_t *sock_,
                               avs_net_socket_opt_key_t option_key,
                               avs_net_socket_opt_value_t option_value) {
    net_socket_impl_t *sock = (net_socket_impl_t *) sock_;
    switch (option_key) {
    case AVS_NET_SOCKET_OPT_RECV_TIMEOUT:
        sock->recv_timeout = option_value.recv_timeout;
        return AVS_OK;
    default:
        return avs_errno(AVS_ENOTSUP);
    }
}

static const avs_net_socket_v_table_t NET_SOCKET_VTABLE = {
    .connect = net_connect,
    .send = net_send,
    .receive = net_receive,
    .bind = net_bind,
    .close = net_close,
    .shutdown = net_shutdown,
    .cleanup = net_cleanup,
    .get_system_socket = net_system_socket,
    .get_remote_host = net_remote_host,
    .get_remote_hostname = net_remote_hostname,
    .get_remote_port = net_remote_port,
    .get_local_port = net_local_port,
    .get_opt = net_get_opt,
    .set_opt = net_set_opt
};

static avs_error_t
net_create_socket(avs_net_socket_t **socket_ptr,
                  const avs_net_socket_configuration_t *configuration,
                  int socktype) {
    assert(socket_ptr);
    assert(!*socket_ptr);
    (void) configuration;
    net_socket_impl_t *socket =
            (net_socket_impl_t *) avs_calloc(1, sizeof(net_socket_impl_t));
    if (!socket) {
        return avs_errno(AVS_ENOMEM);
    }
    socket->operations = &NET_SOCKET_VTABLE;
    socket->socktype = socktype;
    socket->fd = -1;
    socket->recv_timeout = avs_time_duration_from_scalar(30, AVS_TIME_S);
    *socket_ptr = (avs_net_socket_t *) socket;
    return AVS_OK;
}

avs_error_t _avs_net_create_udp_socket(avs_net_socket_t **socket_ptr,
                                       const void *configuration) {
    return net_create_socket(
            socket_ptr, (const avs_net_socket_configuration_t *) configuration,
            SOCK_DGRAM);
}

avs_error_t _avs_net_create_tcp_socket(avs_net_socket_t **socket_ptr,
                                       const void *configuration) {
    return net_create_socket(
            socket_ptr, (const avs_net_socket_configuration_t *) configuration,
            SOCK_STREAM);
}

avs_error_t
avs_net_resolved_endpoint_get_host_port(const avs_net_resolved_endpoint_t *endp,
                                        char *host,
                                        size_t hostlen,
                                        char *serv,
                                        size_t servlen) {
    AVS_STATIC_ASSERT(sizeof(endp->data.buf) >= sizeof(sockaddr_union_t),
                      data_buffer_big_enough);
    if (endp->size != sizeof(sockaddr_union_t)) {
        return avs_errno(AVS_EINVAL);
    }
    const sockaddr_union_t *addr = (const sockaddr_union_t *) &endp->data.buf;
    avs_error_t err = AVS_OK;
    (void) ((host
             && avs_is_err(
                        (err = stringify_sockaddr_host(addr, host, hostlen))))
            || (serv
                && avs_is_err((err = stringify_sockaddr_port(addr, serv,
                                                             servlen)))));
    return err;
}
