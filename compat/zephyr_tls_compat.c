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

#include <avs_commons_init.h>

#include "crypto/avs_crypto_global.h"
#include "net/avs_net_global.h"
#include "net/avs_net_impl.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>

#include <version.h>
#if KERNEL_VERSION_NUMBER >= ZEPHYR_VERSION(3, 5, 0)
#    include <zephyr/random/random.h>
#else // KERNEL_VERSION_NUMBER >= ZEPHYR_VERSION(3, 5, 0)
#    include <zephyr/random/rand32.h>
#endif // KERNEL_VERSION_NUMBER >= ZEPHYR_VERSION(3, 5, 0)

#include <avsystem/commons/avs_base64.h>
#include <avsystem/commons/avs_crypto_psk.h>
#include <avsystem/commons/avs_errno_map.h>
#include <avsystem/commons/avs_stream_membuf.h>
#include <avsystem/commons/avs_utils.h>

#include "net_impl.h"
#include "zephyr_tls_compat.h"

#if __has_include("ncs_version.h")
#    include "ncs_version.h"
#endif // __has_include("ncs_version.h")

avs_error_t _avs_crypto_initialize_global_state(void) {
    return AVS_OK;
}

void _avs_crypto_cleanup_global_state(void) {}

avs_error_t _avs_net_initialize_global_ssl_state(void) {
    return AVS_OK;
}

void _avs_net_cleanup_global_ssl_state(void) {}

#if defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)
// nRF modem sockets
typedef nrf_sec_tag_t anjay_zephyr_sec_tag_t;
typedef enum modem_key_mgmt_cred_type anjay_zephyr_tls_credential_type_t;
typedef nrf_sec_peer_verify_t anjay_zephyr_sec_peer_verify_t;
typedef nrf_sec_session_cache_t anjay_zephyr_sec_session_cache_t;

#    define ANJAY_ZEPHYR_TLS_CRED_CA_CERT MODEM_KEY_MGMT_CRED_TYPE_CA_CHAIN
#    define ANJAY_ZEPHYR_TLS_CRED_SERVER_CERT \
        MODEM_KEY_MGMT_CRED_TYPE_PUBLIC_CERT
#    define ANJAY_ZEPHYR_TLS_CRED_PRIVATE_KEY \
        MODEM_KEY_MGMT_CRED_TYPE_PRIVATE_CERT
#    define ANJAY_ZEPHYR_TLS_CRED_PSK MODEM_KEY_MGMT_CRED_TYPE_PSK
#    define ANJAY_ZEPHYR_TLS_CRED_PSK_ID MODEM_KEY_MGMT_CRED_TYPE_IDENTITY

#    define EPHEMERAL_SEC_TAG_COUNT \
        CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_EPHEMERAL_SEC_TAG_COUNT

typedef struct {
    enum lte_lc_func_mode last_func_mode;
    bool needs_gnss_restart;
} anjay_zephyr_security_credential_transaction_state_t;

static avs_error_t security_credential_transaction_begin(
        anjay_zephyr_security_credential_transaction_state_t *state) {
    memset(state, 0, sizeof(*state));
    int result = lte_lc_func_mode_get(&state->last_func_mode);
    if (result) {
        return avs_errno(avs_map_errno(-result));
    }
    return AVS_OK;
}

static avs_error_t security_credential_transaction_finish(
        anjay_zephyr_security_credential_transaction_state_t *state) {
    enum lte_lc_func_mode mode;
    int result = lte_lc_func_mode_get(&mode);
    if (result || mode != state->last_func_mode) {
        if (state->last_func_mode == LTE_LC_FUNC_MODE_NORMAL) {
            result = lte_lc_connect();
        } else {
            result = lte_lc_func_mode_set(state->last_func_mode);
        }
    }
    if (!result && state->needs_gnss_restart) {
        result = nrf_modem_gnss_start();
    }
    if (result) {
        return avs_errno(avs_map_errno(-result));
    }
    return AVS_OK;
}

static int ensure_modem_deactivated(
        anjay_zephyr_security_credential_transaction_state_t *state) {
    enum lte_lc_func_mode mode;
    int result = lte_lc_func_mode_get(&mode);
    if (!result && mode != LTE_LC_FUNC_MODE_POWER_OFF
            && mode != LTE_LC_FUNC_MODE_OFFLINE) {
        // Enter flight mode - managing credentials is not allowed while modem
        // is activated
        result = nrf_modem_gnss_stop();
        if (!result) {
            state->needs_gnss_restart = true;
        }
        if (!result
                || result ==
#    if NCS_VERSION_NUMBER >= 0x20300
                               -NRF_EACCES
#    else  // NCS_VERSION_NUMBER >= 0x20300
                               -NRF_EPERM
#    endif // NCS_VERSION_NUMBER >= 0x20300
        ) {
            result = lte_lc_offline();
        }
    }
    return result;
}

static const char PEM_BEGIN_TAG_PRE[] = "-----BEGIN ";

static bool looks_like_pem_data(const void *data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = ((const uint8_t *) data)[i];
        if (!isgraph(byte) && !isspace(byte)) {
            return false;
        }
    }
    const char *pem_begin_tag = strstr((const char *) data, PEM_BEGIN_TAG_PRE);
    return pem_begin_tag && *pem_begin_tag
           && (pem_begin_tag == (const char *) data
               || pem_begin_tag[-1] == '\n');
}

static ptrdiff_t read_asn1_length(const uint8_t **ptr, const uint8_t *end) {
    if (*ptr >= end) {
        return -1;
    }

    uint8_t first_byte = **ptr;
    ++*ptr;

    // See X.690 (02/21) <https://www.itu.int/rec/T-REC-X.690-202102-I/en>
    // sections 8.1.3.3 and 10.1 for an authoritative spec of this encoding.

    // Short form - the highest bit is zero, and the rest encode the length
    if (!(first_byte & 0x80)) {
        return first_byte;
    }

    // Long form - the highest bit is 1, the rest encode the "length of the
    // length", and the subsequent bytes are the length encoded as big-endian
    first_byte &= 0x7F;
    if (first_byte > sizeof(ptrdiff_t) || *ptr + first_byte > end) {
        return -1;
    }

    ptrdiff_t result = 0;

    for (size_t i = 0; i < first_byte; ++i) {
        result *= 256;
        result += **ptr;
        ++*ptr;
    }

    return result;
}

typedef enum {
    DER_PRIVATE_KEY_UNKNOWN = -1,
    DER_PRIVATE_KEY_PKCS8 = 0,
    DER_PRIVATE_KEY_ECPK,
    DER_PRIVATE_KEY_PKCS1
} der_private_key_format_t;

#    define ASN1_TAG_INTEGER 0x02
#    define ASN1_TAG_OCTET_STRING 0x04
#    define ASN1_TAG_CONSTRUCTED_SEQUENCE 0x30

// data may be one of:
// a) PKCS#8 private key format, as per RFC 5958:
//
// OneAsymmetricKey ::= SEQUENCE {
//  version                  Version,
//  privateKeyAlgorithm      SEQUENCE {
//   algorithm                 PUBLIC-KEY.&id({PublicKeySet}),
//    parameters               PUBLIC-KEY.&Params({PublicKeySet}
//                               {@privateKeyAlgorithm.algorithm})
//                               OPTIONAL}
//  privateKey               OCTET STRING (CONTAINING
//                             PUBLIC-KEY.&PrivateKey({PublicKeySet}
//                             {@privateKeyAlgorithm.algorithm})),
//  attributes           [0] Attributes OPTIONAL,
//  ...,
//  [[2: publicKey       [1] BIT STRING (CONTAINING
//                             PUBLIC-KEY.&Params({PublicKeySet}
//                             {@privateKeyAlgorithm.algorithm})
//                             OPTIONAL,
//  ...
//    }
//
// b) ECPrivateKey, as per SECG1 or RFC 5915:
//
// ECPrivateKey ::= SEQUENCE {
//       version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//       privateKey OCTET STRING,
//       parameters [0] ECDomainParameters {{ SECGCurveNames }} OPTIONAL,
//       publicKey [1] BIT STRING OPTIONAL
// }
//
// c) PKCS#1 RSA private key format, as per RFC 8017:
//
// RSAPrivateKey ::= SEQUENCE {
//     version           Version,
//     modulus           INTEGER,  -- n
//     publicExponent    INTEGER,  -- e
//     privateExponent   INTEGER,  -- d
//     prime1            INTEGER,  -- p
//     prime2            INTEGER,  -- q
//     exponent1         INTEGER,  -- d mod (p-1)
//     exponent2         INTEGER,  -- d mod (q-1)
//     coefficient       INTEGER,  -- (inverse of q) mod p
//     otherPrimeInfos   OtherPrimeInfos OPTIONAL
// }
//
// So we can assume that:
// - the outermost structure is always an ASN.1 SEQUENCE
// - the first field is always an INTEGER specifying the version
// - the second field will be:
//   a) SEQUENCE in case of PKCS#8
//   b) OCTET STRING in case of ECPrivateKey
//   c) INTEGER in case of PKCS#1
static der_private_key_format_t detect_private_key_format(const void *data_,
                                                          size_t length) {
    const uint8_t *data = (const uint8_t *) data_;
    const uint8_t *const data_end = data + length;
    // skip over the outer SEQUENCE header
    if (data >= data_end || *data++ != ASN1_TAG_CONSTRUCTED_SEQUENCE
            || read_asn1_length(&data, data_end) < 0) {
        return DER_PRIVATE_KEY_UNKNOWN;
    }
    // skip over the version field
    if (data >= data_end || *data++ != ASN1_TAG_INTEGER) {
        return DER_PRIVATE_KEY_UNKNOWN;
    }
    ptrdiff_t version_length = read_asn1_length(&data, data_end);
    if (version_length < 0 || data + version_length >= data_end) {
        return DER_PRIVATE_KEY_UNKNOWN;
    }
    data += version_length;

    switch (*data) {
    case ASN1_TAG_CONSTRUCTED_SEQUENCE:
        return DER_PRIVATE_KEY_PKCS8;
    case ASN1_TAG_OCTET_STRING:
        return DER_PRIVATE_KEY_ECPK;
    case ASN1_TAG_INTEGER:
        return DER_PRIVATE_KEY_PKCS1;
    default:
        return DER_PRIVATE_KEY_UNKNOWN;
    }
}

static avs_error_t encode_pem_data(void **out_pem,
                                   size_t *out_pem_length,
                                   const char *label,
                                   const void *data,
                                   size_t length) {
    static const char END_TAG_PRE[] = "\r\n-----END ";
    static const char TAG_POST[] = "-----";
    size_t base64_bytes = avs_base64_encoded_size(length) - 1;
    size_t newline_bytes = 2 * ((base64_bytes + 63) / 64);
    size_t required_bytes = strlen(PEM_BEGIN_TAG_PRE) + strlen(END_TAG_PRE)
                            + 2 * strlen(label) + 2 * strlen(TAG_POST)
                            + base64_bytes + newline_bytes;
    char *pem = (char *) avs_malloc(required_bytes);
    if (!pem) {
        return avs_errno(AVS_ENOMEM);
    }
    const char *const pem_end = pem + required_bytes;
    *out_pem = pem;
    *out_pem_length = required_bytes;
    pem += sprintf(pem, "%s%s%s", PEM_BEGIN_TAG_PRE, label, TAG_POST);
    const uint8_t *input_data = (const uint8_t *) data;
    const uint8_t *const input_data_end = (const uint8_t *) data + length;
    while (input_data < input_data_end) {
        size_t input_line_length =
                AVS_MIN((size_t) (input_data_end - input_data), 48);
        size_t output_line_length =
                avs_base64_encoded_size(input_line_length) - 1;
        *pem++ = '\r';
        *pem++ = '\n';
        avs_base64_encode(pem, (size_t) (pem_end - pem), input_data,
                          input_line_length);
        input_data += input_line_length;
        pem += output_line_length;
    }
    pem += sprintf(pem, "%s%s", END_TAG_PRE, label);
    assert(pem_end - pem == strlen(TAG_POST));
    memcpy(pem, TAG_POST, strlen(TAG_POST));
    return AVS_OK;
}

static avs_error_t security_credential_set(
        anjay_zephyr_security_credential_transaction_state_t *transaction,
        anjay_zephyr_sec_tag_t tag,
        anjay_zephyr_tls_credential_type_t type,
        const void *data,
        size_t length) {
    void *processed_data = NULL;
    size_t processed_length = 0;
    switch (type) {
    case ANJAY_ZEPHYR_TLS_CRED_CA_CERT:
    case ANJAY_ZEPHYR_TLS_CRED_SERVER_CERT: {
        if (looks_like_pem_data((const uint8_t *) data, length)) {
            processed_data = (void *) (intptr_t) data;
            processed_length = length;
        } else {
            avs_error_t err =
                    encode_pem_data(&processed_data, &processed_length,
                                    "CERTIFICATE", data, length);
            if (avs_is_err(err)) {
                return err;
            }
        }
        break;
    }
    case ANJAY_ZEPHYR_TLS_CRED_PRIVATE_KEY: {
        if (looks_like_pem_data((const uint8_t *) data, length)) {
            processed_data = (void *) (intptr_t) data;
            processed_length = length;
        } else {
            const char *label = NULL;
            switch (detect_private_key_format(data, length)) {
            case DER_PRIVATE_KEY_PKCS8:
                label = "PRIVATE KEY";
                break;
            case DER_PRIVATE_KEY_ECPK:
                label = "EC PRIVATE KEY";
                break;
            case DER_PRIVATE_KEY_PKCS1:
                label = "RSA PRIVATE KEY";
                break;
            case DER_PRIVATE_KEY_UNKNOWN:
                break;
            }
            avs_error_t err = avs_errno(AVS_EINVAL);
            if (label) {
                err = encode_pem_data(&processed_data, &processed_length, label,
                                      data, length);
            }
            if (avs_is_err(err)) {
                return err;
            }
        }
        break;
    }
    case ANJAY_ZEPHYR_TLS_CRED_PSK:
        processed_length = 2 * length;
        processed_data = avs_malloc(processed_length + 1);
        if (!processed_data) {
            return avs_errno(AVS_ENOMEM);
        }
        if (avs_hexlify((char *) processed_data, processed_length + 1, NULL,
                        data, length)) {
            avs_free(processed_data);
            return avs_errno(AVS_EINVAL);
        }
        break;
    case ANJAY_ZEPHYR_TLS_CRED_PSK_ID:
        processed_data = (void *) (intptr_t) data;
        processed_length = length;
        break;
    default:
        return avs_errno(AVS_EINVAL);
    }
    int result = ensure_modem_deactivated(transaction);
    if (!result) {
        result = modem_key_mgmt_write(tag, type, processed_data,
                                      processed_length);
        if (processed_data && processed_data != data) {
            avs_free(processed_data);
        }
    }
    if (!result) {
        return AVS_OK;
    }
    return avs_errno(avs_map_errno(-result));
}

static void security_credential_delete(
        anjay_zephyr_security_credential_transaction_state_t *transaction,
        anjay_zephyr_sec_tag_t tag,
        anjay_zephyr_tls_credential_type_t type) {
    ensure_modem_deactivated(transaction);
    modem_key_mgmt_delete(tag, type);
}
#else // defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)
// Upstream Zephyr sockets
typedef sec_tag_t anjay_zephyr_sec_tag_t;
typedef enum tls_credential_type anjay_zephyr_tls_credential_type_t;
typedef int anjay_zephyr_sec_peer_verify_t;
typedef int anjay_zephyr_sec_session_cache_t;

#    define ANJAY_ZEPHYR_TLS_CRED_CA_CERT TLS_CREDENTIAL_CA_CERTIFICATE
#    define ANJAY_ZEPHYR_TLS_CRED_SERVER_CERT TLS_CREDENTIAL_SERVER_CERTIFICATE
#    define ANJAY_ZEPHYR_TLS_CRED_PRIVATE_KEY TLS_CREDENTIAL_PRIVATE_KEY
#    define ANJAY_ZEPHYR_TLS_CRED_PSK TLS_CREDENTIAL_PSK
#    define ANJAY_ZEPHYR_TLS_CRED_PSK_ID TLS_CREDENTIAL_PSK_ID

#    define EPHEMERAL_SEC_TAG_COUNT                                     \
        AVS_MIN(CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_EPHEMERAL_SEC_TAG_COUNT, \
                CONFIG_TLS_MAX_CREDENTIALS_NUMBER)

typedef struct {
    void *ptr;
    size_t length;
} cached_credential_buf_t;

typedef struct {
    cached_credential_buf_t ca_cert;
    cached_credential_buf_t server_cert;
    cached_credential_buf_t private_key;
} cached_cert_data_t;

typedef struct {
    cached_credential_buf_t psk;
    cached_credential_buf_t psk_id;
} cached_psk_data_t;

typedef union {
    cached_cert_data_t cert;
    cached_psk_data_t psk;
} cached_credential_data_t;

static cached_credential_data_t CACHED_CREDENTIAL_DATA[EPHEMERAL_SEC_TAG_COUNT];

static cached_credential_buf_t *
get_cached_credential_buf(anjay_zephyr_sec_tag_t tag,
                          anjay_zephyr_tls_credential_type_t type) {
    assert(tag >= CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_EPHEMERAL_SEC_TAG_BASE);
    uint32_t relative_tag =
            tag - CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_EPHEMERAL_SEC_TAG_BASE;
    assert(relative_tag < EPHEMERAL_SEC_TAG_COUNT);
    switch (type) {
    case ANJAY_ZEPHYR_TLS_CRED_CA_CERT:
        return &CACHED_CREDENTIAL_DATA[relative_tag].cert.ca_cert;
    case ANJAY_ZEPHYR_TLS_CRED_SERVER_CERT:
        return &CACHED_CREDENTIAL_DATA[relative_tag].cert.server_cert;
    case ANJAY_ZEPHYR_TLS_CRED_PRIVATE_KEY:
        return &CACHED_CREDENTIAL_DATA[relative_tag].cert.private_key;
    case ANJAY_ZEPHYR_TLS_CRED_PSK:
        return &CACHED_CREDENTIAL_DATA[relative_tag].psk.psk;
    case ANJAY_ZEPHYR_TLS_CRED_PSK_ID:
        return &CACHED_CREDENTIAL_DATA[relative_tag].psk.psk_id;
    default:;
        AVS_UNREACHABLE("invalid credential type");
    }
    return NULL;
}

typedef struct {
} anjay_zephyr_security_credential_transaction_state_t;

static avs_error_t security_credential_transaction_begin(
        anjay_zephyr_security_credential_transaction_state_t *state) {
    (void) state;
    return AVS_OK;
}

static avs_error_t security_credential_transaction_finish(
        anjay_zephyr_security_credential_transaction_state_t *state) {
    (void) state;
    return AVS_OK;
}

static avs_error_t security_credential_set(
        anjay_zephyr_security_credential_transaction_state_t *transaction,
        anjay_zephyr_sec_tag_t tag,
        anjay_zephyr_tls_credential_type_t type,
        const void *data,
        size_t length) {
    (void) transaction;
    cached_credential_buf_t *credential_buf =
            get_cached_credential_buf(tag, type);
    assert(credential_buf);
    void *copied_data = avs_malloc(length);
    if (!copied_data) {
        return avs_errno(AVS_ENOMEM);
    }
    memcpy(copied_data, data, length);
    int result = tls_credential_add(tag, type, copied_data, length);
    if (!result) {
        if (credential_buf->ptr) {
            memset(credential_buf->ptr, 0, credential_buf->length);
            avs_free(credential_buf->ptr);
        }
        credential_buf->ptr = copied_data;
        credential_buf->length = length;
        return AVS_OK;
    } else {
        memset(copied_data, 0, length);
        avs_free(copied_data);
        return avs_errno(avs_map_errno(-result));
    }
}

static void security_credential_delete(
        anjay_zephyr_security_credential_transaction_state_t *transaction,
        anjay_zephyr_sec_tag_t tag,
        anjay_zephyr_tls_credential_type_t type) {
    (void) transaction;
    if (!tls_credential_delete(tag, type)) {
        cached_credential_buf_t *credential_buf =
                get_cached_credential_buf(tag, type);
        if (credential_buf && credential_buf->ptr) {
            memset(credential_buf->ptr, 0, credential_buf->length);
            avs_free(credential_buf->ptr);
            memset(credential_buf, 0, sizeof(*credential_buf));
        }
    }
}
#endif // defined(CONFIG_NRF_MODEM_LIB) && defined(CONFIG_MODEM_KEY_MGMT)

static bool USED_SEC_TAGS_MAP[EPHEMERAL_SEC_TAG_COUNT];
static K_MUTEX_DEFINE(USED_SEC_TAGS_MAP_MUTEX);

static avs_error_t
find_free_security_tag_unlocked(anjay_zephyr_sec_tag_t *out_tag) {
    for (size_t i = 0; i < AVS_ARRAY_SIZE(USED_SEC_TAGS_MAP); ++i) {
        if (!USED_SEC_TAGS_MAP[i]) {
            *out_tag =
                    CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_EPHEMERAL_SEC_TAG_BASE + i;
            return AVS_OK;
        }
    }
    return avs_errno(AVS_ENOENT);
}

static bool security_tag_is_ephemeral(anjay_zephyr_sec_tag_t tag) {
    return tag >= CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_EPHEMERAL_SEC_TAG_BASE
           && tag - CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_EPHEMERAL_SEC_TAG_BASE
                      < EPHEMERAL_SEC_TAG_COUNT;
}

static const anjay_zephyr_sec_tag_t SEC_TAG_INVALID =
        CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_EPHEMERAL_SEC_TAG_BASE == 0
                ? CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_EPHEMERAL_SEC_TAG_BASE
                          + EPHEMERAL_SEC_TAG_COUNT
                : 0;

static void mark_tag_as_used_unlocked(anjay_zephyr_sec_tag_t tag) {
    assert(security_tag_is_ephemeral(tag));
    uint32_t relative_tag =
            tag - CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_EPHEMERAL_SEC_TAG_BASE;
    assert(relative_tag < AVS_ARRAY_SIZE(USED_SEC_TAGS_MAP));
    USED_SEC_TAGS_MAP[relative_tag] = true;
}

static void mark_tag_as_unused_unlocked(anjay_zephyr_sec_tag_t tag) {
    assert(security_tag_is_ephemeral(tag));
    uint32_t relative_tag =
            tag - CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_EPHEMERAL_SEC_TAG_BASE;
    assert(relative_tag < AVS_ARRAY_SIZE(USED_SEC_TAGS_MAP));
    USED_SEC_TAGS_MAP[relative_tag] = false;
}

static void security_credential_delete_all_unlocked(
        anjay_zephyr_security_credential_transaction_state_t *transaction,
        anjay_zephyr_sec_tag_t tag) {
    security_credential_delete(transaction, tag, ANJAY_ZEPHYR_TLS_CRED_CA_CERT);
    security_credential_delete(transaction, tag,
                               ANJAY_ZEPHYR_TLS_CRED_SERVER_CERT);
    security_credential_delete(transaction, tag,
                               ANJAY_ZEPHYR_TLS_CRED_PRIVATE_KEY);
    security_credential_delete(transaction, tag, ANJAY_ZEPHYR_TLS_CRED_PSK);
    security_credential_delete(transaction, tag, ANJAY_ZEPHYR_TLS_CRED_PSK_ID);
    mark_tag_as_unused_unlocked(tag);
}

static avs_error_t load_credential_unlocked(
        anjay_zephyr_security_credential_transaction_state_t *transaction,
        avs_stream_t *out_tag_list_membuf,
        anjay_zephyr_sec_tag_t preselected_tag,
        anjay_zephyr_sec_tag_t *single_tag_buf,
        anjay_zephyr_tls_credential_type_t cred_type,
        const avs_crypto_security_info_union_t *credential) {
    switch (credential->source) {
    case AVS_CRYPTO_DATA_SOURCE_EMPTY:
        return AVS_OK;
    case AVS_CRYPTO_DATA_SOURCE_BUFFER: {
        if (credential->info.buffer.password) {
            return avs_errno(AVS_ENOTSUP);
        }
        if (single_tag_buf && security_tag_is_ephemeral(*single_tag_buf)) {
            return avs_errno(AVS_EINVAL);
        }
        avs_error_t err = AVS_OK;
        anjay_zephyr_sec_tag_t tag;
        if (security_tag_is_ephemeral(preselected_tag)) {
            tag = preselected_tag;
        } else {
            if (avs_is_err((err = find_free_security_tag_unlocked(&tag)))) {
                return err;
            }
            security_credential_delete_all_unlocked(transaction, tag);
        }
        if (avs_is_err((err = security_credential_set(
                                transaction, tag, cred_type,
                                credential->info.buffer.buffer,
                                credential->info.buffer.buffer_size)))
                || (!security_tag_is_ephemeral(preselected_tag)
                    && out_tag_list_membuf
                    && avs_is_err(
                               (err = avs_stream_write(out_tag_list_membuf,
                                                       &tag, sizeof(tag)))))) {
            security_credential_delete_all_unlocked(transaction, tag);
        } else {
            mark_tag_as_used_unlocked(tag);
            if (single_tag_buf) {
                *single_tag_buf = tag;
            }
        }
        return err;
    }
    case AVS_CRYPTO_DATA_SOURCE_ARRAY: {
        if (credential->type == AVS_CRYPTO_SECURITY_INFO_PRIVATE_KEY) {
            return avs_errno(AVS_EINVAL);
        }
        avs_error_t err = AVS_OK;
        for (size_t i = 0;
             avs_is_ok(err) && i < credential->info.array.element_count;
             ++i) {
            err = load_credential_unlocked(
                    transaction, out_tag_list_membuf, preselected_tag,
                    single_tag_buf, cred_type,
                    &credential->info.array.array_ptr[i]);
        }
        return err;
    }
#ifdef AVS_COMMONS_WITH_AVS_LIST
    case AVS_CRYPTO_DATA_SOURCE_LIST: {
        if (credential->type == AVS_CRYPTO_SECURITY_INFO_PRIVATE_KEY) {
            return avs_errno(AVS_EINVAL);
        }
        AVS_LIST(avs_crypto_security_info_union_t) entry;
        AVS_LIST_FOREACH(entry, credential->info.list.list_head) {
            avs_error_t err =
                    load_credential_unlocked(transaction, out_tag_list_membuf,
                                             preselected_tag, single_tag_buf,
                                             cred_type, entry);
            if (avs_is_err(err)) {
                return err;
            }
        }
        return AVS_OK;
    }
#endif // AVS_COMMONS_WITH_AVS_LIST
    case AVS_CRYPTO_DATA_SOURCE_ENGINE: {
        if (!out_tag_list_membuf || !credential->info.engine.query
                || !*credential->info.engine.query
                || isspace(*(const uint8_t *) credential->info.engine.query)) {
            return avs_errno(AVS_EINVAL);
        }
        char *endptr = NULL;
        errno = 0;
        long long tag = strtoll(credential->info.engine.query, &endptr, 0);
        if (errno || !endptr || *endptr) {
            return avs_errno(AVS_EINVAL);
        }
        return avs_stream_write(out_tag_list_membuf,
                                &(anjay_zephyr_sec_tag_t) { tag },
                                sizeof(anjay_zephyr_sec_tag_t));
    }
    case AVS_CRYPTO_DATA_SOURCE_FILE:
    case AVS_CRYPTO_DATA_SOURCE_PATH:
        return avs_errno(AVS_ENOTSUP);
    default:
        return avs_errno(AVS_EINVAL);
    }
}

static avs_error_t apply_membuf(net_socket_impl_t *socket,
                                avs_stream_t **membuf_ptr,
                                avs_error_t err) {
    if (avs_is_ok(err)) {
        void *tag_list = NULL;
        size_t tag_list_size;
        err = avs_stream_membuf_take_ownership(*membuf_ptr, &tag_list,
                                               &tag_list_size);
        if (avs_is_ok(err)) {
            assert(((intptr_t) tag_list) % AVS_ALIGNOF(anjay_zephyr_sec_tag_t)
                   == 0);
            socket->sec_tags = (anjay_zephyr_sec_tag_t *) tag_list;
            socket->sec_tags_size = tag_list_size;
        }
    }
    avs_stream_cleanup(membuf_ptr);
    return err;
}

static avs_error_t
load_psk(anjay_zephyr_security_credential_transaction_state_t *transaction,
         net_socket_impl_t *socket,
         const avs_net_psk_info_t *info) {
    avs_stream_t *membuf = avs_stream_membuf_create();
    if (!membuf) {
        return avs_errno(AVS_ENOMEM);
    }
    k_mutex_lock(&USED_SEC_TAGS_MAP_MUTEX, K_FOREVER);
    anjay_zephyr_sec_tag_t tag = SEC_TAG_INVALID;
    avs_error_t err;
    (void) (avs_is_err((err = load_credential_unlocked(
                                transaction, membuf, SEC_TAG_INVALID, &tag,
                                ANJAY_ZEPHYR_TLS_CRED_PSK, &info->key.desc)))
            || avs_is_err(
                       (err = load_credential_unlocked(
                                transaction, membuf, tag,
                                &(anjay_zephyr_sec_tag_t) { SEC_TAG_INVALID },
                                ANJAY_ZEPHYR_TLS_CRED_PSK_ID,
                                &info->identity.desc))));
    k_mutex_unlock(&USED_SEC_TAGS_MAP_MUTEX);
    return apply_membuf(socket, &membuf, err);
}

static avs_error_t
load_certs(anjay_zephyr_security_credential_transaction_state_t *transaction,
           net_socket_impl_t *socket,
           const avs_net_certificate_info_t *info) {
    if (info->cert_revocation_lists.desc.source != AVS_CRYPTO_DATA_SOURCE_EMPTY
            && (info->cert_revocation_lists.desc.source
                        != AVS_CRYPTO_DATA_SOURCE_ARRAY
                || info->cert_revocation_lists.desc.info.array.element_count)
            && (info->cert_revocation_lists.desc.source
                        != AVS_CRYPTO_DATA_SOURCE_LIST
                || info->cert_revocation_lists.desc.info.list.list_head)) {
        return avs_errno(AVS_ENOTSUP);
    }
    avs_stream_t *membuf = avs_stream_membuf_create();
    if (!membuf) {
        return avs_errno(AVS_ENOMEM);
    }
    k_mutex_lock(&USED_SEC_TAGS_MAP_MUTEX, K_FOREVER);
    avs_error_t err = AVS_OK;
    if (info->server_cert_validation) {
        err = load_credential_unlocked(transaction, membuf, SEC_TAG_INVALID,
                                       NULL, ANJAY_ZEPHYR_TLS_CRED_CA_CERT,
                                       &info->trusted_certs.desc);
    }
    anjay_zephyr_sec_tag_t own_cert_key_tag = SEC_TAG_INVALID;
    if (avs_is_ok(err)) {
        err = load_credential_unlocked(transaction, membuf, SEC_TAG_INVALID,
                                       &own_cert_key_tag,
                                       ANJAY_ZEPHYR_TLS_CRED_SERVER_CERT,
                                       &info->client_cert.desc);
    }
    if (avs_is_ok(err)) {
        err = load_credential_unlocked(
                transaction, membuf, own_cert_key_tag,
                &(anjay_zephyr_sec_tag_t) { SEC_TAG_INVALID },
                ANJAY_ZEPHYR_TLS_CRED_PRIVATE_KEY, &info->client_key.desc);
    }
    k_mutex_unlock(&USED_SEC_TAGS_MAP_MUTEX);
    err = apply_membuf(socket, &membuf, err);
    socket->server_cert_validation = info->server_cert_validation;
    socket->dane = info->dane;
    return err;
}

static avs_error_t load_credentials(net_socket_impl_t *socket,
                                    const avs_net_security_info_t *info) {
    anjay_zephyr_security_credential_transaction_state_t transaction_state;
    avs_error_t err = security_credential_transaction_begin(&transaction_state);
    if (avs_is_err(err)) {
        return err;
    }
    switch (info->mode) {
    case AVS_NET_SECURITY_CERTIFICATE:
        err = load_certs(&transaction_state, socket, &info->data.cert);
        break;
    case AVS_NET_SECURITY_PSK:
        err = load_psk(&transaction_state, socket, &info->data.psk);
        break;
    default:
        AVS_UNREACHABLE("invalid enum value");
        err = avs_errno(AVS_EINVAL);
    }
    avs_error_t transaction_err =
            security_credential_transaction_finish(&transaction_state);
    if (avs_is_ok(err) && avs_is_err(transaction_err)) {
        err = transaction_err;
    }
    return err;
}

avs_error_t anjay_zephyr_set_dane_tlsa_array__(
        struct net_socket_impl_struct *socket,
        const avs_net_socket_dane_tlsa_array_t *dane_tlsa_array) {
    if (!socket->server_cert_validation || !socket->dane) {
        return AVS_OK;
    }
    size_t original_sec_tags_size = socket->sec_tags_size;
    anjay_zephyr_security_credential_transaction_state_t transaction;
    avs_error_t err = security_credential_transaction_begin(&transaction);
    if (avs_is_err(err)) {
        return err;
    }
    k_mutex_lock(&USED_SEC_TAGS_MAP_MUTEX, K_FOREVER);
    // Zephyr sockets don't really support DANE. We emulate a couple of common
    // cases to maintain some level of compatibility with LwM2M 1.0.
    for (size_t i = 0;
         avs_is_ok(err) && i < dane_tlsa_array->array_element_count;
         ++i) {
        if (dane_tlsa_array->array_ptr[i].certificate_usage
                        == AVS_NET_SOCKET_DANE_CA_CONSTRAINT
                || dane_tlsa_array->array_ptr[i].certificate_usage
                               == AVS_NET_SOCKET_DANE_SERVICE_CERTIFICATE_CONSTRAINT) {
            // Ignore certificates that require PKIX validation - let's rely on
            // that PKIX validation alone for those cases.
            continue;
        }
        if (dane_tlsa_array->array_ptr[i].selector
                        != AVS_NET_SOCKET_DANE_CERTIFICATE
                || dane_tlsa_array->array_ptr[i].matching_type
                               != AVS_NET_SOCKET_DANE_MATCH_FULL) {
            // Partial matching is not supported at all
            err = avs_errno(AVS_ENOTSUP);
            break;
        }
        // We have a certificate configured for either mode 2 (trust anchor
        // assertion) or mode 3 (domain-issued certificate). Let's add it to the
        // trust store as an approximation of the desired semantics.
        anjay_zephyr_sec_tag_t tag = SEC_TAG_INVALID;
        avs_crypto_certificate_chain_info_t chain =
                avs_crypto_certificate_chain_info_from_buffer(
                        dane_tlsa_array->array_ptr[i].association_data,
                        dane_tlsa_array->array_ptr[i].association_data_size);
        if (avs_is_ok((err = load_credential_unlocked(
                               &transaction, NULL, SEC_TAG_INVALID, &tag,
                               ANJAY_ZEPHYR_TLS_CRED_CA_CERT, &chain.desc)))) {
            void *new_sec_tags =
                    avs_realloc(socket->sec_tags,
                                socket->sec_tags_size + sizeof(tag));
            if (!new_sec_tags) {
                err = avs_errno(AVS_ENOMEM);
                break;
            }
            memcpy((char *) new_sec_tags + socket->sec_tags_size, &tag,
                   sizeof(tag));
            socket->sec_tags = new_sec_tags;
            socket->sec_tags_size += sizeof(tag);
        }
    }
    if (avs_is_err(err)) {
        for (size_t i = original_sec_tags_size; i < socket->sec_tags_size;
             i += sizeof(anjay_zephyr_sec_tag_t)) {
            security_credential_delete_all_unlocked(
                    &transaction,
                    *(const anjay_zephyr_sec_tag_t *) ((const char *)
                                                               socket->sec_tags
                                                       + i));
        }
    }
    k_mutex_unlock(&USED_SEC_TAGS_MAP_MUTEX);
    avs_error_t transaction_err =
            security_credential_transaction_finish(&transaction);
    if (avs_is_ok(err) && avs_is_err(transaction_err)) {
        err = transaction_err;
    }
    if (avs_is_err(err)) {
        socket->sec_tags_size = original_sec_tags_size;
        if (!original_sec_tags_size) {
            avs_free(socket->sec_tags);
            socket->sec_tags = NULL;
        } else {
            void *new_sec_tags =
                    avs_realloc(socket->sec_tags, original_sec_tags_size);
            if (new_sec_tags) {
                socket->sec_tags = new_sec_tags;
            }
        }
    }
    return err;
}

avs_error_t
anjay_zephyr_configure_security__(net_socket_impl_t *socket,
                                  const avs_net_ssl_configuration_t *config) {
    avs_error_t err = load_credentials(socket, &config->security);
    if (avs_is_err(err)) {
        return err;
    }
    if (config->ciphersuites.num_ids) {
        size_t ciphersuites_size =
                config->ciphersuites.num_ids * sizeof(*socket->ciphersuites);
        if (!(socket->ciphersuites = avs_malloc(ciphersuites_size))) {
            err = avs_errno(AVS_ENOMEM);
            goto finish;
        }
        socket->ciphersuites_size = ciphersuites_size;
        for (size_t i = 0; i < config->ciphersuites.num_ids; ++i) {
            socket->ciphersuites[i] =
                    (anjay_zephyr_ciphersuite_id_t) config->ciphersuites.ids[i];
        }
    }
    if (config->dtls_handshake_timeouts) {
        socket->dtls_handshake_timeouts = *config->dtls_handshake_timeouts;
    } else {
        socket->dtls_handshake_timeouts.min = AVS_TIME_DURATION_INVALID;
        socket->dtls_handshake_timeouts.max = AVS_TIME_DURATION_INVALID;
    }
    if (config->server_name_indication) {
        size_t len = strlen(config->server_name_indication);
        if (len >= sizeof(socket->server_name_indication)) {
            err = avs_errno(AVS_ERANGE);
            goto finish;
        }
        memcpy(socket->server_name_indication, config->server_name_indication,
               len + 1);
    }
finish:
    if (avs_is_err(err)) {
        anjay_zephyr_cleanup_security__(socket);
    }
    return err;
}

#ifdef TLS_DTLS_HANDSHAKE_TIMEO
static avs_error_t configure_dtls_handshake_timeouts(
        int fd, const avs_net_dtls_handshake_timeouts_t *timeouts) {
    if (avs_time_duration_valid(timeouts->min)
            && (timeouts->min.seconds != 1 || timeouts->min.nanoseconds != 0)) {
        // The minimum timeout on nRF modem sockets needs to always be 1 s
        return avs_errno(AVS_EINVAL);
    }
    if (avs_time_duration_valid(timeouts->max)) {
        if (timeouts->max.nanoseconds != 0) {
            return avs_errno(AVS_EINVAL);
        }
        uint32_t dtls_handshake_timeo_value;
        switch (timeouts->max.seconds) {
        case 1:
            dtls_handshake_timeo_value = TLS_DTLS_HANDSHAKE_TIMEO_1S;
            break;
        case 2:
            dtls_handshake_timeo_value = TLS_DTLS_HANDSHAKE_TIMEO_3S;
            break;
        case 4:
            dtls_handshake_timeo_value = TLS_DTLS_HANDSHAKE_TIMEO_7S;
            break;
        case 8:
            dtls_handshake_timeo_value = TLS_DTLS_HANDSHAKE_TIMEO_15S;
            break;
        case 16:
            dtls_handshake_timeo_value = TLS_DTLS_HANDSHAKE_TIMEO_31S;
            break;
        case 32:
            dtls_handshake_timeo_value = TLS_DTLS_HANDSHAKE_TIMEO_63S;
            break;
        case 60:
            // Some earlier versions of nRF91 modem firmware don't support the
            // TLS_DTLS_HANDSHAKE_TIMEO option. 1-60 seconds is the default
            // anyway, so it's OK to do nothing in this case. This provides some
            // basic compatibility with these earlier firmwares.
            return AVS_OK;
        default:
            return avs_errno(AVS_EINVAL);
        }
        int result = zsock_setsockopt(fd, SOL_TLS, TLS_DTLS_HANDSHAKE_TIMEO,
                                      &dtls_handshake_timeo_value,
                                      sizeof(dtls_handshake_timeo_value));
        if (result) {
            return avs_errno(avs_map_errno(-result));
        }
    }
    return AVS_OK;
}
#else  // TLS_DTLS_HANDSHAKE_TIMEO
static avs_error_t configure_dtls_handshake_timeout(
        int fd, int optname, avs_time_duration_t timeout) {
    int64_t timeout_ms;
    if (avs_time_duration_to_scalar(&timeout_ms, AVS_TIME_MS, timeout)
            || timeout_ms < 0 || timeout_ms > UINT32_MAX) {
        return avs_errno(AVS_EINVAL);
    }
    int result = zsock_setsockopt(fd, SOL_TLS, optname,
                                  &(uint32_t) { (uint32_t) timeout_ms },
                                  sizeof(uint32_t));
    if (result) {
        return avs_errno(avs_map_errno(-result));
    }
    return AVS_OK;
}

static avs_error_t configure_dtls_handshake_timeouts(
        int fd, const avs_net_dtls_handshake_timeouts_t *timeouts) {
    avs_error_t err;
    if (avs_time_duration_valid(timeouts->min)
            && avs_is_err((err = configure_dtls_handshake_timeout(
                                   fd, TLS_DTLS_HANDSHAKE_TIMEOUT_MIN,
                                   timeouts->min)))) {
        return err;
    }
    if (avs_time_duration_valid(timeouts->max)
            && avs_is_err((err = configure_dtls_handshake_timeout(
                                   fd, TLS_DTLS_HANDSHAKE_TIMEOUT_MAX,
                                   timeouts->max)))) {
        return err;
    }
    return AVS_OK;
}
#endif // TLS_DTLS_HANDSHAKE_TIMEO

avs_error_t anjay_zephyr_init_sockfd_security__(net_socket_impl_t *socket,
                                                const char *host) {
    assert(socket->fd >= 0);
    int result = zsock_setsockopt(socket->fd, SOL_TLS, TLS_SEC_TAG_LIST,
                                  socket->sec_tags, socket->sec_tags_size);
    if (result) {
        return avs_errno(avs_map_errno(-result));
    }
    if (socket->server_name_indication[0]) {
        host = socket->server_name_indication;
    }
    if (host
            && (result = zsock_setsockopt(socket->fd, SOL_TLS, TLS_HOSTNAME,
                                          host, strlen(host)))) {
        return avs_errno(avs_map_errno(-result));
    }
    if ((result = zsock_setsockopt(socket->fd, SOL_TLS, TLS_PEER_VERIFY,
                                   &(anjay_zephyr_sec_peer_verify_t) {
                                           socket->server_cert_validation
                                                   ? TLS_PEER_VERIFY_REQUIRED
                                                   : TLS_PEER_VERIFY_NONE },
                                   sizeof(anjay_zephyr_sec_peer_verify_t)))) {
        return avs_errno(avs_map_errno(-result));
    }
    if (socket->ciphersuites_size
            && (result = zsock_setsockopt(
                        socket->fd, SOL_TLS, TLS_CIPHERSUITE_LIST,
                        socket->ciphersuites, socket->ciphersuites_size))) {
        return avs_errno(avs_map_errno(-result));
    }
#ifdef TLS_SESSION_CACHE
    if ((result = zsock_setsockopt(socket->fd, SOL_TLS, TLS_SESSION_CACHE,
                                   &(anjay_zephyr_sec_session_cache_t) {
#    ifdef CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_SESSION_CACHE
                                           TLS_SESSION_CACHE_ENABLED
#    else  // CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_SESSION_CACHE
                                           TLS_SESSION_CACHE_DISABLED
#    endif // CONFIG_ANJAY_COMPAT_ZEPHYR_TLS_SESSION_CACHE
                                   },
                                   sizeof(anjay_zephyr_sec_session_cache_t)))) {
        return avs_errno(avs_map_errno(-result));
    }
#endif // TLS_SESSION_CACHE
    return configure_dtls_handshake_timeouts(socket->fd,
                                             &socket->dtls_handshake_timeouts);
}

void anjay_zephyr_cleanup_security__(net_socket_impl_t *socket) {
    anjay_zephyr_security_credential_transaction_state_t transaction_state;
    if (avs_is_ok(security_credential_transaction_begin(&transaction_state))) {
        k_mutex_lock(&USED_SEC_TAGS_MAP_MUTEX, K_FOREVER);
        for (size_t i = 0;
             i < socket->sec_tags_size / sizeof(anjay_zephyr_sec_tag_t);
             ++i) {
            anjay_zephyr_sec_tag_t tag =
                    ((const anjay_zephyr_sec_tag_t *) socket->sec_tags)[i];
            if (security_tag_is_ephemeral(tag)) {
                security_credential_delete_all_unlocked(&transaction_state,
                                                        tag);
            }
        }
        k_mutex_unlock(&USED_SEC_TAGS_MAP_MUTEX);
        security_credential_transaction_finish(&transaction_state);
    }
    avs_free(socket->sec_tags);
    socket->sec_tags = NULL;
    socket->sec_tags_size = 0;
    avs_free(socket->ciphersuites);
    socket->ciphersuites = NULL;
    socket->ciphersuites_size = 0;
}

avs_error_t
avs_crypto_psk_engine_key_store(const char *query,
                                const avs_crypto_psk_key_info_t *key_info) {
    if (key_info->desc.source != AVS_CRYPTO_DATA_SOURCE_BUFFER
            || key_info->desc.info.buffer.password) {
        return avs_errno(AVS_ENOTSUP);
    }

    char *endptr;
    errno = 0;
    long long tag = strtoll(query, &endptr, 0);
    if (errno || !endptr || *endptr) {
        return avs_errno(AVS_EINVAL);
    }

    anjay_zephyr_security_credential_transaction_state_t transaction;
    avs_error_t err = security_credential_transaction_begin(&transaction);
    if (avs_is_err(err)) {
        return err;
    }

    err = security_credential_set(&transaction, tag, ANJAY_ZEPHYR_TLS_CRED_PSK,
                                  key_info->desc.info.buffer.buffer,
                                  key_info->desc.info.buffer.buffer_size);

    avs_error_t transaction_err =
            security_credential_transaction_finish(&transaction);
    if (avs_is_ok(err) && avs_is_err(transaction_err)) {
        err = transaction_err;
    }

    return err;
}

avs_error_t avs_crypto_psk_engine_key_rm(const char *query) {
    char *endptr;
    errno = 0;
    long long tag = strtoll(query, &endptr, 0);
    if (errno || !endptr || *endptr) {
        return avs_errno(AVS_EINVAL);
    }

    anjay_zephyr_security_credential_transaction_state_t transaction;
    avs_error_t err = security_credential_transaction_begin(&transaction);
    if (avs_is_err(err)) {
        return err;
    }

    security_credential_delete(&transaction, tag, ANJAY_ZEPHYR_TLS_CRED_PSK);

    return security_credential_transaction_finish(&transaction);
}

avs_error_t avs_crypto_psk_engine_identity_store(
        const char *query,
        const avs_crypto_psk_identity_info_t *identity_info) {
    if (identity_info->desc.source != AVS_CRYPTO_DATA_SOURCE_BUFFER
            || identity_info->desc.info.buffer.password) {
        return avs_errno(AVS_ENOTSUP);
    }

    char *endptr;
    errno = 0;
    long long tag = strtoll(query, &endptr, 0);
    if (errno || !endptr || *endptr) {
        return avs_errno(AVS_EINVAL);
    }

    anjay_zephyr_security_credential_transaction_state_t transaction;
    avs_error_t err = security_credential_transaction_begin(&transaction);
    if (avs_is_err(err)) {
        return err;
    }

    err = security_credential_set(&transaction, tag,
                                  ANJAY_ZEPHYR_TLS_CRED_PSK_ID,
                                  identity_info->desc.info.buffer.buffer,
                                  identity_info->desc.info.buffer.buffer_size);

    avs_error_t transaction_err =
            security_credential_transaction_finish(&transaction);
    if (avs_is_ok(err) && avs_is_err(transaction_err)) {
        err = transaction_err;
    }

    return err;
}

avs_error_t avs_crypto_psk_engine_identity_rm(const char *query) {
    char *endptr;
    errno = 0;
    long long tag = strtoll(query, &endptr, 0);
    if (errno || !endptr || *endptr) {
        return avs_errno(AVS_EINVAL);
    }

    anjay_zephyr_security_credential_transaction_state_t transaction;
    avs_error_t err = security_credential_transaction_begin(&transaction);
    if (avs_is_err(err)) {
        return err;
    }

    security_credential_delete(&transaction, tag, ANJAY_ZEPHYR_TLS_CRED_PSK_ID);

    return security_credential_transaction_finish(&transaction);
}
