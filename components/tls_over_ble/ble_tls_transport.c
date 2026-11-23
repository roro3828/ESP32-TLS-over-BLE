/*
 * TLS over BLE - esp_transport adapter (see ble_tls_transport.h)
 *
 * Return value mapping (ble_tls follows mbedTLS, esp_transport does not):
 *
 *   ble_tls_read()               esp_transport read
 *   > 0  bytes                   > 0  bytes
 *   0    server closed           ERR_TCP_TRANSPORT_CONNECTION_CLOSED_BY_FIN (-1)
 *   MBEDTLS_ERR_SSL_TIMEOUT      ERR_TCP_TRANSPORT_CONNECTION_TIMEOUT (0)
 *   other < 0                    ERR_TCP_TRANSPORT_CONNECTION_FAILED (-2)
 */
#include "sdkconfig.h"

#if CONFIG_TLS_OVER_BLE_TLS_LAYER && CONFIG_TLS_OVER_BLE_ESP_TRANSPORT

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "esp_log.h"

#include "ble_tls.h"
#include "ble_tls_transport.h"
#include "ble_tunnel.h"

static const char *TAG = "ble_tls_tr";

#define DEFAULT_OPEN_TIMEOUT_MS 30000

typedef struct {
    ble_tls_transport_config_t cfg;
    ble_tls_t *tls;
    bool broken;        /* a write failed midway: the TLS stream is unusable */
    int last_error;     /* last mbedTLS error */
} ctx_t;

static ctx_t *get_ctx(esp_transport_handle_t t)
{
    return (ctx_t *)esp_transport_get_context_data(t);
}

static int tr_close(esp_transport_handle_t t)
{
    ctx_t *c = get_ctx(t);
    if (c && c->tls) {
        ble_tls_close(c->tls);
        c->tls = NULL;
    }
    if (c) {
        c->broken = false;
    }
    return 0;
}

static int tr_connect(esp_transport_handle_t t, const char *host, int port, int timeout_ms)
{
    (void)timeout_ms;   /* the BLE handshake uses cfg.open_timeout_ms */
    ctx_t *c = get_ctx(t);
    if (!c || !host || port <= 0 || port > 65535) {
        return -1;
    }
    tr_close(t);
    if (!ble_tunnel_is_ready()) {
        ESP_LOGE(TAG, "tunnel not ready (no relay app connected)");
        return -1;
    }

    ble_tls_config_t tc = {
        .host = host,
        .port = (uint16_t)port,
        .ca_cert = c->cfg.ca_cert,
        .ca_cert_len = c->cfg.ca_cert_len,
        .crt_bundle_attach = c->cfg.crt_bundle_attach,
        .client_cert = c->cfg.client_cert,
        .client_key = c->cfg.client_key,
        .timeout_ms = c->cfg.open_timeout_ms,
    };
    esp_err_t err = ble_tls_open(&tc, &c->tls);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ble_tls_open(%s:%d) failed: %s (open result 0x%02x)", host, port,
                 esp_err_to_name(err), ble_tunnel_last_open_result());
        c->tls = NULL;
        return -1;
    }
    c->last_error = 0;
    return 0;
}

static int tr_read(esp_transport_handle_t t, char *buffer, int len, int timeout_ms)
{
    ctx_t *c = get_ctx(t);
    if (!c || !c->tls || c->broken || len <= 0) {
        return ERR_TCP_TRANSPORT_CONNECTION_FAILED;
    }
    uint32_t to = timeout_ms < 0 ? UINT32_MAX : (uint32_t)timeout_ms;
    int r = ble_tls_read(c->tls, buffer, (size_t)len, to);
    if (r > 0) {
        return r;
    }
    if (r == 0) {
        return ERR_TCP_TRANSPORT_CONNECTION_CLOSED_BY_FIN;
    }
    if (r == MBEDTLS_ERR_SSL_TIMEOUT) {
        return ERR_TCP_TRANSPORT_CONNECTION_TIMEOUT;
    }
    c->last_error = r;
    ESP_LOGE(TAG, "read failed: -0x%04x", (unsigned)-r);
    return ERR_TCP_TRANSPORT_CONNECTION_FAILED;
}

static int tr_write(esp_transport_handle_t t, const char *buffer, int len, int timeout_ms)
{
    (void)timeout_ms;   /* ble_tls_write uses cfg.open_timeout_ms */
    ctx_t *c = get_ctx(t);
    if (!c || !c->tls || c->broken || len < 0) {
        return ERR_TCP_TRANSPORT_CONNECTION_FAILED;
    }
    if (len == 0) {
        return 0;
    }
    int r = ble_tls_write(c->tls, buffer, (size_t)len);
    if (r >= 0) {
        return r;
    }
    /*
     * Part of the data may already be in the TLS stream, so retrying would
     * corrupt it. Report a hard error (not a timeout) and refuse further I/O
     * until the connection is closed.
     */
    c->broken = true;
    c->last_error = r;
    ESP_LOGE(TAG, "write failed: -0x%04x", (unsigned)-r);
    return ERR_TCP_TRANSPORT_CONNECTION_FAILED;
}

/* esp_http_client does not poll; these only report whether I/O is possible. */
static int tr_poll_read(esp_transport_handle_t t, int timeout_ms)
{
    (void)timeout_ms;
    ctx_t *c = get_ctx(t);
    return (c && c->tls && !c->broken) ? 1 : -1;
}

static int tr_poll_write(esp_transport_handle_t t, int timeout_ms)
{
    return tr_poll_read(t, timeout_ms);
}

static int tr_destroy(esp_transport_handle_t t)
{
    tr_close(t);
    free(get_ctx(t));
    esp_transport_set_context_data(t, NULL);
    return 0;
}

static esp_transport_handle_t tr_parent(esp_transport_handle_t t)
{
    return t;   /* no underlying transport */
}

esp_transport_handle_t ble_tls_transport_create(const ble_tls_transport_config_t *cfg)
{
    if (!cfg || (!cfg->ca_cert && !cfg->crt_bundle_attach)) {
        return NULL;
    }
    ctx_t *c = calloc(1, sizeof(*c));
    if (!c) {
        return NULL;
    }
    c->cfg = *cfg;
    if (c->cfg.open_timeout_ms == 0) {
        c->cfg.open_timeout_ms = DEFAULT_OPEN_TIMEOUT_MS;
    }

    esp_transport_handle_t t = esp_transport_init();
    if (!t) {
        free(c);
        return NULL;
    }
    esp_transport_set_context_data(t, c);
    esp_transport_set_func(t, tr_connect, tr_read, tr_write, tr_close,
                           tr_poll_read, tr_poll_write, tr_destroy);
    esp_transport_set_parent_transport_func(t, tr_parent);
    esp_transport_set_default_port(t, 443);
    return t;
}

int ble_tls_transport_last_error(esp_transport_handle_t t)
{
    ctx_t *c = t ? get_ctx(t) : NULL;
    return c ? c->last_error : 0;
}

#endif /* CONFIG_TLS_OVER_BLE_TLS_LAYER && CONFIG_TLS_OVER_BLE_ESP_TRANSPORT */
