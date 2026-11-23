/*
 * TLS over BLE - TLS layer (mbedTLS 4.x client over the tunnel)
 */
#include "sdkconfig.h"

#if CONFIG_TLS_OVER_BLE_TLS_LAYER

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "psa/crypto.h"

#include "ble_tls.h"
#include "ble_tunnel.h"

#if !CONFIG_MBEDTLS_SSL_PROTO_TLS1_3
#error "ble_tls needs CONFIG_MBEDTLS_SSL_PROTO_TLS1_3=y (or turn off CONFIG_TLS_OVER_BLE_TLS_LAYER)"
#endif

#define HOST_MAX 254   /* DNS name (253) + NUL; same limit as OPEN_REQ */

#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
/* Defined (non-static) in esp_crt_bundle.c but not declared in its header. */
int esp_crt_verify_callback(void *buf, mbedtls_x509_crt *crt, int depth, uint32_t *flags);
#endif

static const char *TAG = "ble_tls";

#define IO_SLICE_MS 200

struct ble_tls {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca;
    bool use_bundle;
    bool got_ticket;
    uint32_t io_timeout_ms;
    uint32_t write_timeout_ms;
    char host[HOST_MAX];
    uint16_t port;
};

/* ------------------------------------------------------------- time */

static int64_t days_from_civil(int y, unsigned m, unsigned d)
{
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static int64_t x509_time_to_unix(const mbedtls_x509_time *t)
{
    return days_from_civil(t->year, (unsigned)t->mon, (unsigned)t->day) * 86400 +
           t->hour * 3600 + t->min * 60 + t->sec;
}

/* Build time of this component: the lower bound for "now". */
static int64_t build_time(void)
{
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const char *date = __DATE__;   /* "Mmm dd yyyy" */
    const char *tm = __TIME__;     /* "hh:mm:ss" */
    unsigned mon = 1;
    for (unsigned i = 0; i < 12; i++) {
        if (strncmp(date, months + i * 3, 3) == 0) {
            mon = i + 1;
            break;
        }
    }
    int day = atoi(date + 4);
    int year = atoi(date + 7);
    mbedtls_x509_time t = {
        .year = year, .mon = (int)mon, .day = day,
        .hour = atoi(tm), .min = atoi(tm + 3), .sec = atoi(tm + 6),
    };
    return x509_time_to_unix(&t);
}

/* Central's time (untrusted) bounded below by the build time. */
static int64_t effective_now(void)
{
    int64_t lower = build_time();
    int64_t central = 0;
    if (ble_tunnel_get_central_time(&central) && central > lower) {
        return central;
    }
    return lower;
}

/*
 * The ESP32 has no trustworthy clock, so validity is re-evaluated here
 * against effective_now() instead of the system time.
 */
static int verify_cb(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    ble_tls_t *t = (ble_tls_t *)ctx;
    *flags &= ~(uint32_t)(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);
    if (crt->valid_from.year != 0) {   /* year 0: synthetic bundle entry */
        int64_t now = effective_now();
        if (now < x509_time_to_unix(&crt->valid_from)) {
            *flags |= MBEDTLS_X509_BADCERT_FUTURE;
        }
        if (now > x509_time_to_unix(&crt->valid_to)) {
            *flags |= MBEDTLS_X509_BADCERT_EXPIRED;
        }
    }
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    if (t->use_bundle) {
        return esp_crt_verify_callback(NULL, crt, depth, flags);
    }
#else
    (void)t;
    (void)depth;
#endif
    return 0;
}

/* ------------------------------------------------------------- BIO */

static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    ble_tls_t *t = (ble_tls_t *)ctx;
    int n = ble_tunnel_send(buf, len, t->io_timeout_ms);
    if (n >= 0) {
        return n;
    }
    if (n == BLE_TUNNEL_ERR_TIMEOUT) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    return MBEDTLS_ERR_SSL_CONN_EOF;
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    ble_tls_t *t = (ble_tls_t *)ctx;
    int n = ble_tunnel_recv(buf, len, t->io_timeout_ms);
    if (n >= 0) {
        return n;   /* 0 = EOF */
    }
    if (n == BLE_TUNNEL_ERR_TIMEOUT) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    return MBEDTLS_ERR_SSL_CONN_EOF;
}

/* ---------------------------------------------------- session cache */

#if CONFIG_TLS_OVER_BLE_SESSION_RESUMPTION && defined(MBEDTLS_SSL_SESSION_TICKETS)
static mbedtls_ssl_session s_cached;
static bool s_cached_valid;
static char s_cached_host[HOST_MAX];
static uint16_t s_cached_port;

static void cache_load(ble_tls_t *t)
{
    if (s_cached_valid && t->port == s_cached_port && strcmp(t->host, s_cached_host) == 0) {
        if (mbedtls_ssl_set_session(&t->ssl, &s_cached) == 0) {
            ESP_LOGI(TAG, "trying session resumption");
        }
    }
}

static void cache_store(ble_tls_t *t)
{
    if (!t->got_ticket) {
        return;
    }
    if (s_cached_valid) {
        mbedtls_ssl_session_free(&s_cached);
        s_cached_valid = false;
    }
    mbedtls_ssl_session_init(&s_cached);
    if (mbedtls_ssl_get_session(&t->ssl, &s_cached) == 0) {
        strlcpy(s_cached_host, t->host, sizeof(s_cached_host));
        s_cached_port = t->port;
        s_cached_valid = true;
    } else {
        mbedtls_ssl_session_free(&s_cached);
    }
}
#else
static void cache_load(ble_tls_t *t) { (void)t; }
static void cache_store(ble_tls_t *t) { (void)t; }
#endif

/* ------------------------------------------------------------- API */

static void tls_free(ble_tls_t *t)
{
    mbedtls_ssl_free(&t->ssl);
    mbedtls_ssl_config_free(&t->conf);
    mbedtls_x509_crt_free(&t->ca);
    free(t);
}

esp_err_t ble_tls_open(const ble_tls_config_t *cfg, ble_tls_t **out)
{
    if (!cfg || !cfg->host || !out || (!cfg->ca_cert && !cfg->crt_bundle_attach)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (strlen(cfg->host) >= sizeof(((ble_tls_t *)0)->host)) {
        return ESP_ERR_INVALID_ARG;
    }
    *out = NULL;

    psa_status_t ps = psa_crypto_init();
    if (ps != PSA_SUCCESS) {
        ESP_LOGE(TAG, "psa_crypto_init failed: %d", (int)ps);
        return ESP_FAIL;
    }

    ble_tls_t *t = calloc(1, sizeof(*t));
    if (!t) {
        return ESP_ERR_NO_MEM;
    }
    strlcpy(t->host, cfg->host, sizeof(t->host));
    t->port = cfg->port;
    t->write_timeout_ms = cfg->timeout_ms ? cfg->timeout_ms : 30000;
    mbedtls_ssl_init(&t->ssl);
    mbedtls_ssl_config_init(&t->conf);
    mbedtls_x509_crt_init(&t->ca);

    esp_err_t err = ESP_FAIL;
    int ret = mbedtls_ssl_config_defaults(&t->conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        ESP_LOGE(TAG, "config_defaults: -0x%04x", -ret);
        goto fail;
    }
    /* TLS 1.3 only, for this connection only. */
    mbedtls_ssl_conf_min_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(&t->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    if (cfg->crt_bundle_attach) {
        if (cfg->crt_bundle_attach(&t->conf) != ESP_OK) {
            ESP_LOGE(TAG, "certificate bundle attach failed");
            goto fail;
        }
        t->use_bundle = true;
    } else {
        ret = mbedtls_x509_crt_parse(&t->ca, cfg->ca_cert, cfg->ca_cert_len);
        if (ret < 0) {
            ESP_LOGE(TAG, "CA parse: -0x%04x", -ret);
            goto fail;
        }
        mbedtls_ssl_conf_ca_chain(&t->conf, &t->ca, NULL);
    }
#if !CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    if (t->use_bundle) {
        ESP_LOGE(TAG, "crt_bundle_attach given but CONFIG_MBEDTLS_CERTIFICATE_BUNDLE is off");
        goto fail;
    }
#endif
    /* Must come after crt_bundle_attach, which installs its own callback. */
    mbedtls_ssl_conf_verify(&t->conf, verify_cb, t);

    if (cfg->client_cert && cfg->client_key) {
        ret = mbedtls_ssl_conf_own_cert(&t->conf, cfg->client_cert, cfg->client_key);
        if (ret != 0) {
            ESP_LOGE(TAG, "own cert: -0x%04x", -ret);
            goto fail;
        }
    }

    ret = mbedtls_ssl_setup(&t->ssl, &t->conf);
    if (ret != 0) {
        ESP_LOGE(TAG, "ssl_setup: -0x%04x", -ret);
        err = ESP_ERR_NO_MEM;
        goto fail;
    }
    ret = mbedtls_ssl_set_hostname(&t->ssl, cfg->host);
    if (ret != 0) {
        goto fail;
    }
    cache_load(t);
    mbedtls_ssl_set_bio(&t->ssl, t, bio_send, bio_recv, NULL);

    int64_t deadline = esp_timer_get_time() + (int64_t)t->write_timeout_ms * 1000;
    err = ble_tunnel_open(cfg->host, cfg->port, t->write_timeout_ms);
    if (err != ESP_OK) {
        goto fail;
    }

    t->io_timeout_ms = IO_SLICE_MS;
    while ((ret = mbedtls_ssl_handshake(&t->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            uint32_t vr = mbedtls_ssl_get_verify_result(&t->ssl);
            ESP_LOGE(TAG, "handshake failed: -0x%04x (verify flags 0x%08" PRIx32 ")", -ret, vr);
            err = ESP_FAIL;
            ble_tunnel_close();
            goto fail;
        }
        if (esp_timer_get_time() > deadline) {
            ESP_LOGE(TAG, "handshake timeout");
            err = ESP_ERR_TIMEOUT;
            ble_tunnel_close();
            goto fail;
        }
    }
    ESP_LOGI(TAG, "TLS established with %s (%s)", cfg->host,
             mbedtls_ssl_get_ciphersuite(&t->ssl));
    *out = t;
    return ESP_OK;

fail:
    tls_free(t);
    return err;
}

int ble_tls_write(ble_tls_t *t, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t off = 0;
    int64_t deadline = esp_timer_get_time() + (int64_t)t->write_timeout_ms * 1000;
    t->io_timeout_ms = IO_SLICE_MS;
    while (off < len) {
        int ret = mbedtls_ssl_write(&t->ssl, p + off, len - off);
        if (ret > 0) {
            off += (size_t)ret;
            continue;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
            return ret;
        }
        if (esp_timer_get_time() > deadline) {
            return MBEDTLS_ERR_SSL_TIMEOUT;
        }
    }
    return (int)len;
}

int ble_tls_read(ble_tls_t *t, void *buf, size_t len, uint32_t timeout_ms)
{
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    t->io_timeout_ms = timeout_ms < IO_SLICE_MS ? timeout_ms : IO_SLICE_MS;
    for (;;) {
        int ret = mbedtls_ssl_read(&t->ssl, (unsigned char *)buf, len);
        if (ret > 0) {
            return ret;
        }
        if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            return 0;
        }
        if (ret == MBEDTLS_ERR_SSL_CONN_EOF) {
            ESP_LOGW(TAG, "connection closed without close_notify");
            return 0;
        }
        if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
            t->got_ticket = true;
            continue;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return ret;
        }
        if (esp_timer_get_time() >= deadline) {
            return MBEDTLS_ERR_SSL_TIMEOUT;
        }
    }
}

void ble_tls_close(ble_tls_t *t)
{
    if (!t) {
        return;
    }
    t->io_timeout_ms = 500;
    mbedtls_ssl_close_notify(&t->ssl);
    cache_store(t);
    ble_tunnel_close();
    tls_free(t);
}

#endif /* CONFIG_TLS_OVER_BLE_TLS_LAYER */
