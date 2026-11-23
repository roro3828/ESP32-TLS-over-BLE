/*
 * Sample: BLE HID keyboard + TLS over BLE tunnel (AtomS3 Lite)
 *
 *  - Short press of the button: sends 'A' as a BLE keyboard.
 *  - Long press (3 s): deletes all bonds (unpair) and restarts advertising.
 *  - When the central relay app connects (HELLO), runs one HTTPS GET through
 *    the tunnel (CONFIG_APP_TLS_DEMO) to show "TLS only when needed".
 *  - Then checks for a firmware update through the tunnel (CONFIG_APP_OTA_DEMO)
 *    and, if the served image has a different version, installs it and restarts.
 *  - Device identity (key + certificate) from the "fctry" partition, if present:
 *    answers the central's device authentication and is the TLS client
 *    certificate for the update server (mTLS).
 */
#include <cstdio>
#include <cstring>

#include "driver/gpio.h"
#include "esp_app_desc.h"
#include "esp_crt_bundle.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "nvs_flash.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "ble_tls.h"
#include "ble_tunnel.h"
#include "hid_kbd.h"

#if (CONFIG_APP_TLS_DEMO && !CONFIG_APP_TLS_DEMO_RAW) || CONFIG_APP_OTA_DEMO
#include "esp_http_client.h"
#include "ble_tls_transport.h"
#if !CONFIG_ESP_HTTP_CLIENT_ENABLE_CUSTOM_TRANSPORT
#error "The esp_http_client / OTA demos need CONFIG_ESP_HTTP_CLIENT_ENABLE_CUSTOM_TRANSPORT=y"
#endif
#endif
#if CONFIG_APP_OTA_DEMO
#include "esp_https_ota.h"
#endif

/* Defined in NimBLE (C code); no public header, so declare with C linkage */
extern "C" void ble_store_config_init(void);

static const char *TAG = "app";

static constexpr gpio_num_t BUTTON_GPIO = static_cast<gpio_num_t>(CONFIG_APP_BUTTON_GPIO);
static constexpr int64_t LONG_PRESS_US = 3000 * 1000;
static constexpr int64_t SHORT_PRESS_MAX_US = 1000 * 1000;

static uint8_t s_own_addr_type;
static volatile uint16_t s_conn = BLE_HS_CONN_HANDLE_NONE;
static volatile bool s_unpair_pending;
static SemaphoreHandle_t s_ready_sem;

static int gap_event(struct ble_gap_event *event, void *arg);

/* ------------------------------------------------------------ advertising */

static void advertise(void)
{
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.appearance = HID_KBD_APPEARANCE;
    fields.appearance_is_present = 1;
    static const ble_uuid16_t hid_uuid[] = { BLE_UUID16_INIT(HID_KBD_SVC_UUID16) };
    fields.uuids16 = hid_uuid;
    fields.num_uuids16 = 1;
    fields.uuids16_is_complete = 1;
    const char *name = ble_svc_gap_device_name();
    fields.name = reinterpret_cast<const uint8_t *>(name);
    fields.name_len = static_cast<uint8_t>(strlen(name));
    fields.name_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv fields: %d", rc);
        return;
    }

    /* The tunnel UUID goes into the scan response (optional per spec). */
    struct ble_hs_adv_fields rsp;
    memset(&rsp, 0, sizeof(rsp));
    rsp.uuids128 = ble_tunnel_service_uuid();
    rsp.num_uuids128 = 1;
    rsp.uuids128_is_complete = 1;
    rc = ble_gap_adv_rsp_set_fields(&rsp);
    if (rc != 0) {
        ESP_LOGE(TAG, "scan response fields: %d", rc);
        return;
    }

    struct ble_gap_adv_params params;
    memset(&params, 0, sizeof(params));
    params.conn_mode = BLE_GAP_CONN_MODE_UND;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    rc = ble_gap_adv_start(s_own_addr_type, nullptr, BLE_HS_FOREVER, &params, gap_event, nullptr);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGE(TAG, "adv start: %d", rc);
    } else {
        ESP_LOGI(TAG, "advertising as \"%s\"", name);
    }
}

static void delete_all_bonds(void)
{
    int rc = ble_store_clear();
    ESP_LOGW(TAG, "all bonds deleted (rc=%d). Remove the device on the PC side too.", rc);
}

/* Called from the button task. */
static void unpair_all(void)
{
    uint16_t conn = s_conn;
    if (conn != BLE_HS_CONN_HANDLE_NONE) {
        /* Delete the bonds after the link is down (in the DISCONNECT event). */
        s_unpair_pending = true;
        ble_gap_terminate(conn, BLE_ERR_REM_USER_CONN_TERM);
        return;
    }
    ble_gap_adv_stop();
    delete_all_bonds();
    advertise();
}

/* ------------------------------------------------------------- GAP events */

static int gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    hid_kbd_on_gap_event(event);
    ble_tunnel_on_gap_event(event);

    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_conn = event->connect.conn_handle;
            ESP_LOGI(TAG, "connected (handle %d)", event->connect.conn_handle);
            /* Ask for encryption: pairs on first use, restores the bond later. */
            ble_gap_security_initiate(event->connect.conn_handle);
        } else {
            advertise();
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "disconnected (reason 0x%x)", event->disconnect.reason);
        s_conn = BLE_HS_CONN_HANDLE_NONE;
        if (s_unpair_pending) {
            s_unpair_pending = false;
            delete_all_bonds();
        }
        advertise();
        break;

    case BLE_GAP_EVENT_ADV_COMPLETE:
        advertise();
        break;

    case BLE_GAP_EVENT_ENC_CHANGE:
        ESP_LOGI(TAG, "encryption %s (status %d)",
                 event->enc_change.status == 0 ? "on" : "failed", event->enc_change.status);
        break;

    case BLE_GAP_EVENT_REPEAT_PAIRING: {
        /* The host lost its bond: forget ours and pair again. */
        struct ble_gap_conn_desc desc;
        if (ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc) == 0) {
            ble_store_util_delete_peer(&desc.peer_id_addr);
        }
        return BLE_GAP_REPEAT_PAIRING_RETRY;
    }

    case BLE_GAP_EVENT_MTU:
        ESP_LOGI(TAG, "MTU %d", event->mtu.value);
        break;

    default:
        break;
    }
    return 0;
}

static void on_reset(int reason)
{
    ESP_LOGE(TAG, "NimBLE reset, reason %d", reason);
}

/*
 * Rollback protection: an image installed by OTA boots as "pending verify".
 * Confirm it once the BLE stack is up (the minimum needed to receive the next
 * update); if it crashes or resets before this point, the bootloader goes back
 * to the previous image.
 */
static void confirm_running_image(void)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state;
    if (esp_ota_get_state_partition(running, &state) == ESP_OK &&
        state == ESP_OTA_IMG_PENDING_VERIFY) {
        esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
        ESP_LOGW(TAG, "new firmware %s confirmed (%s)", esp_app_get_description()->version,
                 esp_err_to_name(err));
    }
}

static void on_sync(void)
{
    confirm_running_image();

    int rc = ble_hs_util_ensure_addr(0);
    if (rc == 0) {
        rc = ble_hs_id_infer_auto(0, &s_own_addr_type);
    }
    if (rc != 0) {
        ESP_LOGE(TAG, "address setup failed: %d", rc);
        return;
    }
    advertise();
}

static void host_task(void *param)
{
    (void)param;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

/* ----------------------------------------------------------------- button */

static void button_task(void *arg)
{
    (void)arg;
    gpio_config_t io = {};
    io.pin_bit_mask = 1ULL << BUTTON_GPIO;
    io.mode = GPIO_MODE_INPUT;
    io.pull_up_en = GPIO_PULLUP_ENABLE;
    gpio_config(&io);

    bool pressed = false;
    bool long_done = false;
    int64_t t0 = 0;
    int same = 0;
    bool last_raw = false;

    for (;;) {
        bool raw = gpio_get_level(BUTTON_GPIO) == 0;   /* active low */
        same = (raw == last_raw) ? same + 1 : 0;
        last_raw = raw;
        int64_t now = esp_timer_get_time();

        if (same >= 3) {                               /* 30 ms debounce */
            if (raw && !pressed) {
                pressed = true;
                long_done = false;
                t0 = now;
            } else if (!raw && pressed) {
                pressed = false;
                if (!long_done && now - t0 < SHORT_PRESS_MAX_US) {
                    ESP_LOGI(TAG, "short press: sending 'A'");
                    hid_kbd_send_key(HID_MOD_LEFT_SHIFT, HID_KEY_A);
                }
            }
        }
        if (pressed && !long_done && now - t0 >= LONG_PRESS_US) {
            long_done = true;
            ESP_LOGW(TAG, "long press: unpairing");
            unpair_all();
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

/* -------------------------------------------------------- device identity */

/*
 * Written by "idf.py flash" from tools/ota_server/ota_server.py device (in a
 * product: at the factory). Kept outside the app image so that OTA images do
 * not carry a private key. Production devices should rather keep the key in
 * the Digital Signature peripheral or encrypted flash.
 */
static constexpr const char *FCTRY_PART = "fctry";

static struct {
    bool loaded;
    mbedtls_x509_crt cert;
    mbedtls_pk_context key;
    ble_tunnel_identity_t tunnel;
} s_id;

static esp_err_t read_blob(nvs_handle_t h, const char *name, uint8_t **out, size_t *len)
{
    size_t n = 0;
    esp_err_t err = nvs_get_blob(h, name, nullptr, &n);
    if (err != ESP_OK) {
        return err;
    }
    auto *p = static_cast<uint8_t *>(malloc(n));
    if (!p) {
        return ESP_ERR_NO_MEM;
    }
    err = nvs_get_blob(h, name, p, &n);
    if (err != ESP_OK) {
        free(p);
        return err;
    }
    *out = p;
    *len = n;
    return ESP_OK;
}

/* ble_tunnel_sign_fn: ECDSA P-256 / SHA-256, DER signature. */
static int sign_with_device_key(const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t sig_size,
                                size_t *sig_len, void *arg)
{
    auto *key = static_cast<mbedtls_pk_context *>(arg);
    uint8_t hash[32];
    size_t hash_len = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, msg, msg_len, hash, sizeof(hash), &hash_len) !=
        PSA_SUCCESS) {
        return -1;
    }
    return mbedtls_pk_sign(key, MBEDTLS_MD_SHA256, hash, hash_len, sig, sig_size, sig_len);
}

static void load_device_identity(void)
{
    esp_err_t err = nvs_flash_init_partition(FCTRY_PART);
    nvs_handle_t h = 0;
    if (err == ESP_OK) {
        err = nvs_open_from_partition(FCTRY_PART, "fctry", NVS_READONLY, &h);
    }
    uint8_t *cert_der = nullptr, *key_der = nullptr;
    size_t cert_len = 0, key_len = 0;
    if (err == ESP_OK) {
        err = read_blob(h, "dev_cert", &cert_der, &cert_len);
        if (err == ESP_OK) {
            err = read_blob(h, "dev_key", &key_der, &key_len);
        }
        nvs_close(h);
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "no device identity in the \"%s\" partition (%s): no device "
                 "authentication, no TLS client certificate", FCTRY_PART, esp_err_to_name(err));
        free(cert_der);
        return;
    }

    psa_crypto_init();   /* idempotent; needed by the key and psa_hash_compute */
    mbedtls_x509_crt_init(&s_id.cert);
    mbedtls_pk_init(&s_id.key);
    int ret = mbedtls_x509_crt_parse_der(&s_id.cert, cert_der, cert_len);   /* copies */
    if (ret == 0) {
        ret = mbedtls_pk_parse_key(&s_id.key, key_der, key_len, nullptr, 0);
    }
    free(cert_der);
    mbedtls_platform_zeroize(key_der, key_len);
    free(key_der);
    if (ret != 0) {
        ESP_LOGE(TAG, "device identity: parse failed -0x%04x", static_cast<unsigned>(-ret));
        mbedtls_x509_crt_free(&s_id.cert);
        mbedtls_pk_free(&s_id.key);
        return;
    }

    s_id.tunnel.device_cert_der = s_id.cert.raw.p;
    s_id.tunnel.device_cert_len = s_id.cert.raw.len;
    s_id.tunnel.intermediate_cert_der = nullptr;   /* issued directly by the test CA */
    s_id.tunnel.intermediate_cert_len = 0;
    s_id.tunnel.sign = sign_with_device_key;
    s_id.tunnel.sign_arg = &s_id.key;
    s_id.loaded = true;

    char subject[128];
    mbedtls_x509_dn_gets(subject, sizeof(subject), &s_id.cert.subject);
    ESP_LOGI(TAG, "device identity: %s", subject);
}

/* -------------------------------------------------------- TLS tunnel demo */

static void on_tunnel_ready(bool ready, void *arg)
{
    (void)arg;
    if (ready) {
        xSemaphoreGive(s_ready_sem);
    }
}

#if CONFIG_APP_TLS_DEMO && !CONFIG_APP_TLS_DEMO_RAW
/* esp_http_client over the ble_tls esp_transport adapter. */
static void https_get_demo(void)
{
    ESP_LOGI(TAG, "HTTPS demo (esp_http_client): GET https://%s%s (free heap %u)",
             CONFIG_APP_TLS_DEMO_HOST, CONFIG_APP_TLS_DEMO_PATH,
             (unsigned)esp_get_free_heap_size());

    /* TLS settings go to the transport, not to esp_http_client_config_t. */
    ble_tls_transport_config_t tcfg = {};
    tcfg.crt_bundle_attach = esp_crt_bundle_attach;
    tcfg.open_timeout_ms = 30000;
    esp_transport_handle_t tr = ble_tls_transport_create(&tcfg);
    if (!tr) {
        ESP_LOGE(TAG, "ble_tls_transport_create failed");
        return;
    }

    esp_http_client_config_t cfg = {};
    cfg.host = CONFIG_APP_TLS_DEMO_HOST;
    cfg.port = CONFIG_APP_TLS_DEMO_PORT;
    cfg.path = CONFIG_APP_TLS_DEMO_PATH;
    cfg.transport_type = HTTP_TRANSPORT_OVER_SSL;   /* scheme "https" */
    cfg.transport = tr;
    cfg.timeout_ms = 15000;                         /* per read */
    cfg.user_agent = "tls-over-ble-sample";
    cfg.method = HTTP_METHOD_GET;

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        ESP_LOGE(TAG, "esp_http_client_init failed");
        esp_transport_destroy(tr);
        return;
    }

    int64_t t0 = esp_timer_get_time();
    size_t total = 0;
    esp_err_t err = esp_http_client_open(client, 0);   /* tunnel + TLS handshake + request */
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_http_client_open failed: %s (tls error -0x%04x)",
                 esp_err_to_name(err), static_cast<unsigned>(-ble_tls_transport_last_error(tr)));
    } else {
        int64_t len = esp_http_client_fetch_headers(client);
        if (esp_http_client_is_chunked_response(client)) {
            ESP_LOGI(TAG, "status %d, chunked body (free heap %u)",
                     esp_http_client_get_status_code(client), (unsigned)esp_get_free_heap_size());
        } else {
            ESP_LOGI(TAG, "status %d, content-length %lld (free heap %u)",
                     esp_http_client_get_status_code(client), static_cast<long long>(len),
                     (unsigned)esp_get_free_heap_size());
        }

        static char buf[1025];
        bool first = true;
        for (;;) {
            int r = esp_http_client_read(client, buf, sizeof(buf) - 1);
            if (r > 0) {
                buf[r] = '\0';
                ESP_LOGI(TAG, "%s\n%s", first ? "body starts with:" : "body:", buf);
                first = false;
                total += static_cast<size_t>(r);
            } else if (r == 0) {
                break;                                  /* whole body received */
            } else if (r == -ESP_ERR_HTTP_EAGAIN) {
                ESP_LOGW(TAG, "read timed out");
                break;
            } else {
                ESP_LOGW(TAG, "read failed: %d", r);
                break;
            }
        }
        if (!esp_http_client_is_complete_data_received(client)) {
            ESP_LOGW(TAG, "body incomplete");
        }
    }
    int64_t ms = (esp_timer_get_time() - t0) / 1000;

    esp_http_client_cleanup(client);   /* closes the TLS session and the tunnel session */
    esp_transport_destroy(tr);         /* the custom transport is owned by the app */
    ESP_LOGI(TAG, "received %u bytes of body in %lld ms; session closed (free heap %u)",
             (unsigned)total, (long long)ms, (unsigned)esp_get_free_heap_size());
}

#elif CONFIG_APP_TLS_DEMO && CONFIG_APP_TLS_DEMO_RAW
/* Older demo: the HTTP/1.1 request is written by hand directly on ble_tls. */
static void https_get_demo(void)
{
    ESP_LOGI(TAG, "HTTPS demo (raw): GET https://%s%s (free heap %u)", CONFIG_APP_TLS_DEMO_HOST,
             CONFIG_APP_TLS_DEMO_PATH, (unsigned)esp_get_free_heap_size());

    ble_tls_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host = CONFIG_APP_TLS_DEMO_HOST;
    cfg.port = CONFIG_APP_TLS_DEMO_PORT;
    cfg.crt_bundle_attach = esp_crt_bundle_attach;
    cfg.timeout_ms = 30000;

    ble_tls_t *tls = nullptr;
    esp_err_t err = ble_tls_open(&cfg, &tls);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ble_tls_open failed: %s (open result 0x%02x)", esp_err_to_name(err),
                 ble_tunnel_last_open_result());
        return;
    }
    ESP_LOGI(TAG, "session open (free heap %u)", (unsigned)esp_get_free_heap_size());

    char req[256];
    int n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: tls-over-ble-sample\r\n"
                     "Connection: close\r\n\r\n",
                     CONFIG_APP_TLS_DEMO_PATH, CONFIG_APP_TLS_DEMO_HOST);
    if (ble_tls_write(tls, req, static_cast<size_t>(n)) < 0) {
        ESP_LOGE(TAG, "write failed");
        ble_tls_close(tls);
        return;
    }

    static char buf[1025];
    size_t total = 0;
    bool first = true;
    int64_t t0 = esp_timer_get_time();
    for (;;) {
        int r = ble_tls_read(tls, buf, sizeof(buf) - 1, 15000);
        if (r > 0) {
            buf[r < 1024 ? r : 1024] = '\0';
            if (first) {
                ESP_LOGI(TAG, "response starts with:\n%s", buf);
                first = false;
            }
            else {
                ESP_LOGI(TAG, "response:\n%s", buf);
            }
            total += static_cast<size_t>(r);
        } else if (r == 0) {
            break;                                      /* server closed */
        } else if (r == MBEDTLS_ERR_SSL_TIMEOUT) {
            ESP_LOGW(TAG, "read timed out");
            break;
        } else {
            ESP_LOGW(TAG, "read failed: -0x%04x", static_cast<unsigned>(-r));
            break;
        }
    }
    int64_t ms = (esp_timer_get_time() - t0) / 1000;
    ble_tls_close(tls);
    ESP_LOGI(TAG, "received %u bytes in %lld ms; session closed (free heap %u)",
             (unsigned)total, (long long)ms, (unsigned)esp_get_free_heap_size());
}
#endif

/* --------------------------------------------------------------- OTA demo */

#if CONFIG_APP_OTA_DEMO
#if CONFIG_APP_OTA_CA_EMBEDDED
extern const char ota_ca_pem_start[] asm("_binary_ota_ca_pem_start");
extern const char ota_ca_pem_end[] asm("_binary_ota_ca_pem_end");
#endif

/*
 * esp_https_ota over the ble_tls esp_transport adapter. Reads the image header
 * first and stops there if the version equals the running one, so a check
 * without an update costs only a few KB over BLE.
 */
static void ota_demo(void)
{
    const esp_app_desc_t *running = esp_app_get_description();
    const esp_partition_t *target = esp_ota_get_next_update_partition(nullptr);
    if (!target) {
        ESP_LOGE(TAG, "OTA: no OTA partition (check the partition table)");
        return;
    }
    ESP_LOGI(TAG, "OTA demo: running %s from %s, checking %s", running->version,
             esp_ota_get_running_partition()->label, CONFIG_APP_OTA_URL);

    /* TLS settings go to the transport. */
    ble_tls_transport_config_t tcfg = {};
#if CONFIG_APP_OTA_CA_EMBEDDED
    tcfg.ca_cert = reinterpret_cast<const uint8_t *>(ota_ca_pem_start);
    tcfg.ca_cert_len = static_cast<size_t>(ota_ca_pem_end - ota_ca_pem_start);  /* incl. NUL */
#else
    tcfg.crt_bundle_attach = esp_crt_bundle_attach;
#endif
    if (s_id.loaded) {
        /* Sent only when the server asks for it (mTLS). */
        tcfg.client_cert = &s_id.cert;
        tcfg.client_key = &s_id.key;
    }
    tcfg.open_timeout_ms = 30000;
    esp_transport_handle_t tr = ble_tls_transport_create(&tcfg);
    if (!tr) {
        ESP_LOGE(TAG, "OTA: ble_tls_transport_create failed");
        return;
    }

    esp_http_client_config_t http = {};
    http.url = CONFIG_APP_OTA_URL;
    http.transport = tr;
    http.timeout_ms = 20000;   /* per read */
    http.buffer_size = 4096;   /* fewer, larger reads */
    /* Not used by the custom transport, but esp_https_ota requires one of them. */
#if CONFIG_APP_OTA_CA_EMBEDDED
    http.cert_pem = ota_ca_pem_start;
#else
    http.crt_bundle_attach = esp_crt_bundle_attach;
#endif

    esp_https_ota_config_t ota = {};
    ota.http_config = &http;

    esp_https_ota_handle_t h = nullptr;
    esp_err_t err = esp_https_ota_begin(&ota, &h);   /* tunnel + TLS + GET */
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "OTA: begin failed: %s (tls error -0x%04x)", esp_err_to_name(err),
                 static_cast<unsigned>(-ble_tls_transport_last_error(tr)));
        esp_transport_destroy(tr);
        return;
    }

    esp_app_desc_t next = {};
    err = esp_https_ota_get_img_desc(h, &next);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "OTA: could not read the image header: %s", esp_err_to_name(err));
        esp_https_ota_abort(h);
        esp_transport_destroy(tr);
        return;
    }
    if (strncmp(next.version, running->version, sizeof(next.version)) == 0) {
        ESP_LOGI(TAG, "OTA: server has %s, same as running; nothing to do", next.version);
        esp_https_ota_abort(h);
        esp_transport_destroy(tr);
        return;
    }

    int size = esp_https_ota_get_image_size(h);
    ESP_LOGW(TAG, "OTA: updating %s -> %s (%d bytes) into %s", running->version, next.version,
             size, target->label);
    int64_t t0 = esp_timer_get_time();
    int next_report = 0;
    for (;;) {
        err = esp_https_ota_perform(h);
        if (err != ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
            break;
        }
        int done = esp_https_ota_get_image_len_read(h);
        if (size > 0 && done * 10 / size >= next_report) {
            int64_t ms = (esp_timer_get_time() - t0) / 1000;
            ESP_LOGI(TAG, "OTA: %3d%%  %7d bytes  %.1f KB/s", done * 100 / size, done,
                     ms > 0 ? done / 1.024 / static_cast<double>(ms) : 0.0);
            next_report = done * 10 / size + 1;
        }
    }

    int64_t ms = (esp_timer_get_time() - t0) / 1000;
    if (err == ESP_OK && esp_https_ota_is_complete_data_received(h)) {
        /* Verifies the image and sets it as the boot partition. */
        err = esp_https_ota_finish(h);
        esp_transport_destroy(tr);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "OTA: image rejected: %s", esp_err_to_name(err));
            return;
        }
        ESP_LOGW(TAG, "OTA: done in %lld ms; restarting into %s", static_cast<long long>(ms),
                 next.version);
        /* Close the BLE link cleanly so the PCs notice at once, then restart. */
        uint16_t conn = s_conn;
        if (conn != BLE_HS_CONN_HANDLE_NONE) {
            ble_gap_terminate(conn, BLE_ERR_REM_USER_CONN_TERM);
        }
        vTaskDelay(pdMS_TO_TICKS(500));
        esp_restart();
    }

    ESP_LOGE(TAG, "OTA: failed after %d bytes in %lld ms: %s", esp_https_ota_get_image_len_read(h),
             static_cast<long long>(ms), esp_err_to_name(err));
    esp_https_ota_abort(h);
    esp_transport_destroy(tr);
}
#endif

static void tls_demo_task(void *arg)
{
    (void)arg;
    for (;;) {
        xSemaphoreTake(s_ready_sem, portMAX_DELAY);
#if CONFIG_APP_TLS_DEMO || CONFIG_APP_OTA_DEMO
        vTaskDelay(pdMS_TO_TICKS(1500));   /* let the central send TIME / AUTH first */
#endif
#if CONFIG_APP_TLS_DEMO
        if (ble_tunnel_is_ready()) {
            https_get_demo();
        }
#endif
#if CONFIG_APP_OTA_DEMO
        if (ble_tunnel_is_ready()) {
            ota_demo();
        }
#endif
    }
}

/* ------------------------------------------------------------------- main */

extern "C" void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    load_device_identity();

    /*
     * Default event loop: esp_http_client also posts its events there and logs
     * "Failed to post http_client event" if it does not exist.
     */
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK(nimble_port_init());

    ble_hs_cfg.reset_cb = on_reset;
    ble_hs_cfg.sync_cb = on_sync;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

    /* Just Works (no display / keyboard on the device) with LE Secure Connections + bonding */
    ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_NO_IO;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;

    ble_svc_gap_init();
    ble_svc_gatt_init();
    ESP_ERROR_CHECK(ble_svc_gap_device_name_set(CONFIG_APP_DEVICE_NAME) == 0 ? ESP_OK : ESP_FAIL);
    ble_svc_gap_device_appearance_set(HID_KBD_APPEARANCE);

    /* Main role: HID keyboard. */
    ESP_ERROR_CHECK(ble_gatts_count_cfg(hid_kbd_gatt_svcs()) == 0 ? ESP_OK : ESP_FAIL);
    ESP_ERROR_CHECK(ble_gatts_add_svcs(hid_kbd_gatt_svcs()) == 0 ? ESP_OK : ESP_FAIL);

    /* Add-on: TLS over BLE tunnel. */
    s_ready_sem = xSemaphoreCreateBinary();
    ble_tunnel_config_t tcfg = {};
    tcfg.app_version = esp_app_get_description()->version;   /* from version.txt */
    tcfg.identity = s_id.loaded ? &s_id.tunnel : nullptr;   /* for the central's AUTH */
    tcfg.on_ready = on_tunnel_ready;
    ESP_ERROR_CHECK(ble_tunnel_init(&tcfg));
    ESP_ERROR_CHECK(ble_gatts_count_cfg(ble_tunnel_gatt_svcs()) == 0 ? ESP_OK : ESP_FAIL);
    ESP_ERROR_CHECK(ble_gatts_add_svcs(ble_tunnel_gatt_svcs()) == 0 ? ESP_OK : ESP_FAIL);

    /* Firmware-wide setting owned by the app (spec: 247 or more recommended). */
    ble_att_set_preferred_mtu(247);

    ble_store_config_init();

    xTaskCreate(button_task, "button", 3072, nullptr, 5, nullptr);
    /* TLS handshake + esp_http_client / esp_https_ota run on this stack */
    xTaskCreate(tls_demo_task, "tls_demo", 12288, nullptr, 4, nullptr);

    nimble_port_freertos_init(host_task);
}
