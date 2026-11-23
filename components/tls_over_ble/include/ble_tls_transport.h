/*
 * TLS over BLE - esp_transport adapter
 *
 * Wraps ble_tls_* as an esp_transport, so that esp_http_client (and
 * esp_https_ota, which uses it) run over the BLE tunnel:
 *
 *   esp_transport_handle_t tr = ble_tls_transport_create(&tcfg);
 *   esp_http_client_config_t cfg = {};
 *   cfg.host = "example.com";
 *   cfg.path = "/";
 *   cfg.transport_type = HTTP_TRANSPORT_OVER_SSL;  // or an https:// url
 *   cfg.transport = tr;      // needs CONFIG_ESP_HTTP_CLIENT_ENABLE_CUSTOM_TRANSPORT
 *   ...
 *   esp_http_client_cleanup(client);
 *   esp_transport_destroy(tr);                     // not freed by the client
 *
 * Notes for esp_http_client:
 *  - TLS settings in esp_http_client_config_t (cert_pem, crt_bundle_attach,
 *    client_cert_pem, client_key ...) are NOT used; set them here instead.
 *    (esp_https_ota still requires cert_pem or crt_bundle_attach to be set.)
 *  - Do not set save_client_session; ble_tls does its own session resumption.
 *  - The host and port of the request are what the central is asked to open,
 *    so they must be on the central's allowlist.
 */
#pragma once

#include <stdint.h>

#include "esp_err.h"
#include "esp_transport.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* Trusted root CAs: a PEM/DER buffer (PEM length includes the NUL)... */
    const uint8_t *ca_cert;
    size_t ca_cert_len;
    /* ...or a bundle attach function such as esp_crt_bundle_attach. */
    esp_err_t (*crt_bundle_attach)(void *conf);

    /* mTLS (optional): client certificate chain and key, owned by the app. */
    mbedtls_x509_crt *client_cert;
    mbedtls_pk_context *client_key;

    /*
     * Tunnel open + TLS handshake, and the write timeout. A BLE handshake is
     * much slower than over IP, so this is separate from the client's
     * timeout_ms (which is used for reads). 0 = 30000 ms.
     */
    uint32_t open_timeout_ms;
} ble_tls_transport_config_t;

/**
 * Creates the transport. cfg is copied; the buffers and objects it points to
 * must stay valid until the transport is destroyed.
 * Returns NULL on invalid arguments or out of memory.
 */
esp_transport_handle_t ble_tls_transport_create(const ble_tls_transport_config_t *cfg);

/** Last mbedTLS error seen by the transport (0 if none), for diagnostics. */
int ble_tls_transport_last_error(esp_transport_handle_t t);

#ifdef __cplusplus
}
#endif
