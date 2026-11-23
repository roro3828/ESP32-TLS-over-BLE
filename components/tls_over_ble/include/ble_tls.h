/*
 * TLS over BLE - TLS layer
 *
 * TLS 1.3 client (mbedTLS) running over the BLE tunnel. TLS 1.3 is enforced
 * per connection, so global mbedTLS settings of the firmware are untouched.
 * Requires CONFIG_MBEDTLS_SSL_PROTO_TLS1_3 and a 16 KB mbedTLS input buffer.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return values of ble_tls_read() / ble_tls_write() follow mbedtls_ssl_read():
 *   > 0  number of bytes
 *   0    the server closed the connection (read only)
 *   < 0  an mbedTLS error code; a timeout is MBEDTLS_ERR_SSL_TIMEOUT
 */

typedef struct ble_tls ble_tls_t;

typedef struct {
    const char *host;           /* server name: SNI, certificate check, OPEN_REQ */
    uint16_t port;              /* usually 443 */

    /* Trusted root CAs: either a PEM/DER buffer (PEM length includes the NUL)... */
    const uint8_t *ca_cert;
    size_t ca_cert_len;
    /* ...or a bundle attach function such as esp_crt_bundle_attach. */
    esp_err_t (*crt_bundle_attach)(void *conf);

    /* mTLS (optional): client certificate chain and key, owned by the app. */
    mbedtls_x509_crt *client_cert;
    mbedtls_pk_context *client_key;

    uint32_t timeout_ms;        /* tunnel open + handshake; also write timeout */
} ble_tls_config_t;

/** Opens the tunnel session and performs the TLS 1.3 handshake. */
esp_err_t ble_tls_open(const ble_tls_config_t *cfg, ble_tls_t **out);

/**
 * Writes all len bytes within cfg->timeout_ms. Returns len or a negative mbedTLS
 * error (MBEDTLS_ERR_SSL_TIMEOUT on timeout). After an error part of the data
 * may have been sent, so the connection must be closed.
 */
int ble_tls_write(ble_tls_t *tls, const void *buf, size_t len);

/**
 * Reads up to len bytes. Returns the number of bytes, 0 when the server closed
 * the connection, MBEDTLS_ERR_SSL_TIMEOUT when no data arrived before
 * timeout_ms (the connection stays usable), or another negative mbedTLS error.
 * NewSessionTicket messages are handled internally.
 */
int ble_tls_read(ble_tls_t *tls, void *buf, size_t len, uint32_t timeout_ms);

/** Sends close_notify, closes the tunnel session and frees everything. */
void ble_tls_close(ble_tls_t *tls);

#ifdef __cplusplus
}
#endif
