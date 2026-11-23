/*
 * TLS over BLE - tunnel layer (GATT service, control protocol, flow control)
 */
#include <stdlib.h>
#include <string.h>

#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/stream_buffer.h"
#include "freertos/task.h"
#include "host/ble_hs.h"
#include "os/os_mbuf.h"

#include "ble_tunnel.h"

static const char *TAG = "ble_tunnel";

/* ---- Protocol constants (values are the spec's proposals) ---- */
enum {
    OP_HELLO = 0x01,
    OP_AUTH_CHALLENGE = 0x02,
    OP_AUTH_RESPONSE = 0x03,
    OP_TIME = 0x04,
    OP_OPEN_REQ = 0x10,
    OP_OPEN_RSP = 0x11,
    OP_CREDIT = 0x12,
    OP_CLOSE = 0x13,
    OP_REMOTE_CLOSED = 0x14,
};

enum {
    TLV_PROTO_VERSION = 0x01,
    TLV_APP_VERSION = 0x02,
    TLV_RX_BUFFER_SIZE = 0x03,
    TLV_DEVICE_CERT = 0x10,
    TLV_INTERMEDIATE_CERT = 0x11,
    TLV_NONCE_D = 0x12,
    TLV_SIGNATURE = 0x13,
    TLV_HOST = 0x20,
    TLV_PORT = 0x21,
};

enum {
    CLOSE_NORMAL = 0x00,
    CLOSE_TIMEOUT = 0x01,
    CLOSE_PROTOCOL = 0x02,
    CLOSE_TLS = 0x03,
    CLOSE_VERSION = 0x04,
    CLOSE_NOMEM = 0x05,
    CLOSE_APP = 0x06,
};

#define CTRL_HDR_LEN    5
#define CTRL_FLAG_MORE  0x01
#define CTRL_RX_MAX     1024
#define ATT_BUF_MAX     528
#define NONCE_LEN       32
#define AUTH_CONTEXT    "TLS-over-BLE-device-auth-v1"
#define JOB_QUEUE_LEN   16

#define RX_BUF_SIZE     ((size_t)CONFIG_TLS_OVER_BLE_RX_BUFFER_SIZE)

#define EV_OPEN_RSP     BIT0
#define EV_SESSION_END  BIT1
#define EV_IND_DONE     BIT2

/* Connection parameters are restored only after RX has been quiet this long. */
#define RESTORE_QUIET_US     (300 * 1000)
#define RESTORE_MAX_WAIT_US  (3000 * 1000)

typedef enum { JOB_CTRL, JOB_AUTH, JOB_RESTORE } job_kind_t;

typedef struct {
    job_kind_t kind;
    uint8_t op;
    uint8_t session;
    uint16_t len;
    uint8_t *payload;   /* malloc'd, freed by the worker */
} job_t;

typedef enum { SESS_IDLE, SESS_OPENING, SESS_OPEN } sess_state_t;

static struct {
    bool initialized;
    ble_tunnel_config_t cfg;

    ble_uuid128_t svc_uuid, rx_uuid, tx_uuid, ctrl_uuid;
    uint16_t rx_handle, tx_handle, ctrl_handle;
    struct ble_gatt_chr_def chrs[4];
    struct ble_gatt_svc_def svcs[2];

    SemaphoreHandle_t lock;     /* protects connection and session state */
    SemaphoreHandle_t tx_lock;  /* serializes our notify/indicate calls */
    EventGroupHandle_t events;
    QueueHandle_t jobs;
    portMUX_TYPE credit_mux;

    /* connection */
    uint16_t conn;
    uint16_t mtu;
    bool tx_sub;
    bool ctrl_notify;
    bool ctrl_indicate;
    bool hello;
    bool ready;
    int ind_status;

    /* central time */
    bool has_time;
    int64_t time_unix;
    int64_t time_at_us;

    /* control message reassembly (host task only) */
    uint8_t ctrl_rx[CTRL_RX_MAX];
    size_t ctrl_rx_len;
    uint8_t ctrl_rx_op;
    bool ctrl_rx_active;

    /* session */
    sess_state_t state;
    uint8_t session_id;
    StreamBufferHandle_t rx_sb;
    int32_t credit_avail;   /* bytes the central may still send (credit_mux) */
    size_t consumed;        /* read but not yet returned as credit (credit_mux) */
    bool remote_closed;
    bool remote_error;
    bool aborted;
    ble_tunnel_open_result_t open_result;
    bool saved_params_valid;
    struct ble_gap_upd_params saved_params;
    int64_t last_rx_us;     /* last write to RX, of any session */
} s;

static uint8_t s_att_buf[ATT_BUF_MAX];   /* host task only (GATT access) */
static uint8_t s_tx_frame[ATT_BUF_MAX];  /* session writer only */

/* ---------------------------------------------------------------- helpers */

static void lock(void) { xSemaphoreTake(s.lock, portMAX_DELAY); }
static void unlock(void) { xSemaphoreGive(s.lock); }

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -> little-endian ble_uuid128_t */
static bool parse_uuid128(const char *str, ble_uuid128_t *out)
{
    uint8_t be[16] = { 0 };
    int n = 0;
    for (const char *p = str; *p; p++) {
        if (*p == '-') {
            continue;
        }
        int v = hexval(*p);
        if (v < 0 || n >= 32) {
            return false;
        }
        be[n / 2] |= (n % 2 == 0) ? (uint8_t)(v << 4) : (uint8_t)v;
        n++;
    }
    if (n != 32) {
        return false;
    }
    out->u.type = BLE_UUID_TYPE_128;
    for (int i = 0; i < 16; i++) {
        out->value[i] = be[15 - i];
    }
    return true;
}

static size_t tlv_put(uint8_t *buf, size_t off, uint8_t type, const void *val, uint16_t len)
{
    buf[off] = type;
    buf[off + 1] = (uint8_t)(len & 0xff);
    buf[off + 2] = (uint8_t)(len >> 8);
    if (len) {
        memcpy(buf + off + 3, val, len);
    }
    return off + 3 + len;
}

static const uint8_t *tlv_find(const uint8_t *p, size_t len, uint8_t type, uint16_t *out_len)
{
    size_t off = 0;
    while (off + 3 <= len) {
        uint8_t t = p[off];
        uint16_t l = (uint16_t)(p[off + 1] | (p[off + 2] << 8));
        if (off + 3 + l > len) {
            return NULL;
        }
        if (t == type) {
            *out_len = l;
            return p + off + 3;
        }
        off += 3 + (size_t)l;   /* unknown types are skipped */
    }
    return NULL;
}

static void put_u32le(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}

/* Queues a control message for the worker task (never blocks the host task). */
static bool queue_ctrl(uint8_t op, uint8_t session, const void *payload, uint16_t len,
                       TickType_t wait)
{
    job_t j = { .kind = JOB_CTRL, .op = op, .session = session, .len = len, .payload = NULL };
    if (len) {
        j.payload = malloc(len);
        if (!j.payload) {
            return false;
        }
        memcpy(j.payload, payload, len);
    }
    if (xQueueSend(s.jobs, &j, wait) != pdTRUE) {
        free(j.payload);
        ESP_LOGW(TAG, "control queue full, op 0x%02x dropped", op);
        return false;
    }
    return true;
}

static bool compute_ready_locked(void)
{
    return s.conn != BLE_HS_CONN_HANDLE_NONE && s.hello && s.tx_sub &&
           (s.ctrl_notify || s.ctrl_indicate);
}

static void report_ready(void)
{
    lock();
    bool r = compute_ready_locked();
    bool changed = (r != s.ready);
    s.ready = r;
    unlock();
    if (changed) {
        ESP_LOGI(TAG, "tunnel %s", r ? "ready" : "not ready");
        if (s.cfg.on_ready) {
            s.cfg.on_ready(r, s.cfg.cb_arg);
        }
    }
}

/* Marks the current session as aborted and wakes up waiting tasks. */
static void abort_session(uint8_t reason, bool send_close)
{
    bool do_close = false;
    uint8_t sid = 0;
    lock();
    if (s.state != SESS_IDLE && !s.aborted) {
        s.aborted = true;
        sid = s.session_id;
        do_close = send_close;
    }
    unlock();
    xEventGroupSetBits(s.events, EV_SESSION_END);
    if (do_close) {
        queue_ctrl(OP_CLOSE, sid, &reason, 1, 0);
    }
}

/* ----------------------------------------------------- GATT transmission */

/*
 * Sends one notification or indication. Keeps CONFIG_TLS_OVER_BLE_MSYS_RESERVE
 * mbuf blocks free so that other services (e.g. HID input reports) are never
 * starved; waits and retries while the host is out of buffers.
 */
static bool gatt_send(uint16_t conn, uint16_t handle, const uint8_t *data, size_t len,
                      bool indicate, uint32_t timeout_ms)
{
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    for (;;) {
        if (os_msys_num_free() > CONFIG_TLS_OVER_BLE_MSYS_RESERVE) {
            int rc;
            xSemaphoreTake(s.tx_lock, portMAX_DELAY);
            struct os_mbuf *om = ble_hs_mbuf_from_flat(data, (uint16_t)len);
            if (om == NULL) {
                rc = BLE_HS_ENOMEM;
            } else if (indicate) {
                xEventGroupClearBits(s.events, EV_IND_DONE);
                rc = ble_gatts_indicate_custom(conn, handle, om);
            } else {
                rc = ble_gatts_notify_custom(conn, handle, om);
            }
            xSemaphoreGive(s.tx_lock);

            if (rc == 0) {
                if (!indicate) {
                    return true;
                }
                EventBits_t b = xEventGroupWaitBits(s.events, EV_IND_DONE, pdTRUE, pdFALSE,
                                                    pdMS_TO_TICKS(timeout_ms));
                return (b & EV_IND_DONE) && s.ind_status == BLE_HS_EDONE;
            }
            if (rc != BLE_HS_ENOMEM && rc != BLE_HS_EALREADY && rc != BLE_HS_EBUSY) {
                ESP_LOGW(TAG, "%s failed: %d", indicate ? "indicate" : "notify", rc);
                return false;
            }
        }
        if (esp_timer_get_time() >= deadline) {
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}

/* Worker task only: sends a control message, fragmented to the ATT MTU. */
static void send_ctrl(uint8_t op, uint8_t session, const uint8_t *payload, uint16_t len)
{
    lock();
    uint16_t conn = s.conn;
    uint16_t mtu = s.mtu;
    bool ntf = s.ctrl_notify;
    bool ind = s.ctrl_indicate;
    unlock();

    if (conn == BLE_HS_CONN_HANDLE_NONE || (!ntf && !ind)) {
        ESP_LOGD(TAG, "op 0x%02x not sent: control not subscribed", op);
        return;
    }
    /* Indicate per spec; CREDIT uses Notify. Notify-only subscribers get Notify. */
    bool indicate = ind && !(op == OP_CREDIT && ntf);
    if (!ind) {
        indicate = false;
    }

    size_t max_chunk = (size_t)mtu - 3 - CTRL_HDR_LEN;
    uint8_t frame[ATT_BUF_MAX];
    size_t off = 0;
    do {
        size_t chunk = len - off;
        if (chunk > max_chunk) {
            chunk = max_chunk;
        }
        frame[0] = op;
        frame[1] = (off + chunk < len) ? CTRL_FLAG_MORE : 0;
        frame[2] = session;
        frame[3] = (uint8_t)(chunk & 0xff);
        frame[4] = (uint8_t)(chunk >> 8);
        if (chunk) {
            memcpy(frame + CTRL_HDR_LEN, payload + off, chunk);
        }
        if (!gatt_send(conn, s.ctrl_handle, frame, CTRL_HDR_LEN + chunk, indicate, 3000)) {
            ESP_LOGW(TAG, "control op 0x%02x send failed", op);
            return;
        }
        off += chunk;
    } while (off < len);
}

/* Worker task only: answers AUTH_CHALLENGE. */
static void handle_auth(const uint8_t *nonce_c)
{
    const ble_tunnel_identity_t *id = s.cfg.identity;
    if (!id || !id->sign || !id->device_cert_der || !id->device_cert_len) {
        ESP_LOGW(TAG, "AUTH_CHALLENGE received but no device identity is configured");
        send_ctrl(OP_AUTH_RESPONSE, 0, NULL, 0);
        return;
    }

    uint8_t nonce_d[NONCE_LEN];
    esp_fill_random(nonce_d, sizeof(nonce_d));

    const size_t ctx_len = sizeof(AUTH_CONTEXT) - 1;
    uint8_t msg[sizeof(AUTH_CONTEXT) - 1 + 2 * NONCE_LEN];
    memcpy(msg, AUTH_CONTEXT, ctx_len);
    memcpy(msg + ctx_len, nonce_c, NONCE_LEN);
    memcpy(msg + ctx_len + NONCE_LEN, nonce_d, NONCE_LEN);

    uint8_t sig[80];
    size_t sig_len = 0;
    if (id->sign(msg, sizeof(msg), sig, sizeof(sig), &sig_len, id->sign_arg) != 0 ||
        sig_len == 0 || sig_len > sizeof(sig)) {
        ESP_LOGE(TAG, "device signature failed");
        send_ctrl(OP_AUTH_RESPONSE, 0, NULL, 0);
        return;
    }

    size_t total = 4 * 3 + id->device_cert_len + id->intermediate_cert_len + NONCE_LEN + sig_len;
    if (total > 0xffff) {
        ESP_LOGE(TAG, "identity too large");
        send_ctrl(OP_AUTH_RESPONSE, 0, NULL, 0);
        return;
    }
    uint8_t *buf = malloc(total);
    if (!buf) {
        send_ctrl(OP_AUTH_RESPONSE, 0, NULL, 0);
        return;
    }
    size_t off = 0;
    off = tlv_put(buf, off, TLV_DEVICE_CERT, id->device_cert_der, (uint16_t)id->device_cert_len);
    off = tlv_put(buf, off, TLV_INTERMEDIATE_CERT, id->intermediate_cert_der,
                  (uint16_t)id->intermediate_cert_len);
    off = tlv_put(buf, off, TLV_NONCE_D, nonce_d, NONCE_LEN);
    off = tlv_put(buf, off, TLV_SIGNATURE, sig, (uint16_t)sig_len);
    send_ctrl(OP_AUTH_RESPONSE, 0, buf, (uint16_t)off);
    free(buf);
}

static void handle_restore(void);

static void worker_task(void *arg)
{
    (void)arg;
    job_t j;
    for (;;) {
        if (xQueueReceive(s.jobs, &j, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        if (j.kind == JOB_AUTH) {
            handle_auth(j.payload);
        } else if (j.kind == JOB_RESTORE) {
            handle_restore();
        } else {
            send_ctrl(j.op, j.session, j.payload, j.len);
        }
        free(j.payload);
    }
}

/* ------------------------------------------------- incoming (host task) */

static void send_hello(void)
{
    uint8_t buf[3 + 2 + 3 + 64 + 3 + 4];
    size_t off = 0;
    const uint8_t ver[2] = { BLE_TUNNEL_PROTO_VERSION_MAJOR, BLE_TUNNEL_PROTO_VERSION_MINOR };
    off = tlv_put(buf, off, TLV_PROTO_VERSION, ver, 2);
    if (s.cfg.app_version) {
        size_t l = strlen(s.cfg.app_version);
        if (l > 64) {
            l = 64;
        }
        off = tlv_put(buf, off, TLV_APP_VERSION, s.cfg.app_version, (uint16_t)l);
    }
    uint8_t sz[4];
    put_u32le(sz, (uint32_t)RX_BUF_SIZE);
    off = tlv_put(buf, off, TLV_RX_BUFFER_SIZE, sz, 4);
    queue_ctrl(OP_HELLO, 0, buf, (uint16_t)off, 0);
}

static void handle_ctrl(uint8_t op, uint8_t sid, const uint8_t *p, size_t len)
{
    switch (op) {
    case OP_HELLO: {
        uint16_t l = 0;
        const uint8_t *v = tlv_find(p, len, TLV_PROTO_VERSION, &l);
        if (!v || l < 2) {
            ESP_LOGW(TAG, "HELLO without protocol version");
            return;
        }
        if (v[0] != BLE_TUNNEL_PROTO_VERSION_MAJOR) {
            ESP_LOGW(TAG, "protocol major mismatch: central %u, device %u",
                     v[0], BLE_TUNNEL_PROTO_VERSION_MAJOR);
            uint8_t reason = CLOSE_VERSION;
            queue_ctrl(OP_CLOSE, 0, &reason, 1, 0);
            return;
        }
        ESP_LOGI(TAG, "HELLO from central (protocol %u.%u)", v[0], v[1]);
        lock();
        bool again = s.hello;
        unlock();
        if (again) {
            /* The relay app restarted while the BLE link stayed up (the OS keeps
             * a bonded device connected): drop the previous instance's session
             * and report not ready -> ready, so the app sees a fresh start. */
            ESP_LOGI(TAG, "HELLO again: relay app restarted");
            abort_session(CLOSE_APP, false);
            lock();
            s.hello = false;
            unlock();
            report_ready();
        }
        send_hello();
        lock();
        s.hello = true;
        unlock();
        report_ready();
        break;
    }
    case OP_AUTH_CHALLENGE: {
        if (len != NONCE_LEN) {
            ESP_LOGW(TAG, "bad AUTH_CHALLENGE length %u", (unsigned)len);
            return;
        }
        job_t j = { .kind = JOB_AUTH, .payload = malloc(NONCE_LEN) };
        if (!j.payload) {
            return;
        }
        memcpy(j.payload, p, NONCE_LEN);
        if (xQueueSend(s.jobs, &j, 0) != pdTRUE) {
            free(j.payload);
        }
        break;
    }
    case OP_TIME: {
        if (len != 8) {
            return;
        }
        uint64_t t = 0;
        for (int i = 7; i >= 0; i--) {
            t = (t << 8) | p[i];
        }
        lock();
        s.has_time = true;
        s.time_unix = (int64_t)t;
        s.time_at_us = esp_timer_get_time();
        unlock();
        ESP_LOGI(TAG, "time from central: %lld", (long long)t);
        break;
    }
    case OP_OPEN_RSP: {
        if (len < 1) {
            return;
        }
        bool hit = false;
        lock();
        if (s.state == SESS_OPENING && sid == s.session_id) {
            s.open_result = (ble_tunnel_open_result_t)p[0];
            hit = true;
        }
        unlock();
        if (hit) {
            xEventGroupSetBits(s.events, EV_OPEN_RSP);
        }
        break;
    }
    case OP_CLOSE:
    case OP_REMOTE_CLOSED: {
        uint8_t reason = len ? p[0] : 0;
        if (op == OP_CLOSE && sid == 0) {
            ESP_LOGW(TAG, "central closed the tunnel (reason 0x%02x)", reason);
            lock();
            s.hello = false;
            unlock();
            abort_session(CLOSE_NORMAL, false);
            report_ready();
            return;
        }
        bool hit = false;
        lock();
        if (s.state != SESS_IDLE && sid == s.session_id) {
            s.remote_closed = true;
            s.remote_error = (reason != 0);
            hit = true;
        }
        unlock();
        if (hit) {
            ESP_LOGI(TAG, "%s (reason 0x%02x)", op == OP_CLOSE ? "CLOSE" : "REMOTE_CLOSED", reason);
            xEventGroupSetBits(s.events, EV_SESSION_END);
        }
        break;
    }
    default:
        ESP_LOGW(TAG, "unknown control op 0x%02x", op);
        break;
    }
}

static void on_ctrl_write(const uint8_t *d, size_t len)
{
    if (len < CTRL_HDR_LEN) {
        return;
    }
    uint8_t op = d[0];
    uint8_t flags = d[1];
    uint8_t sid = d[2];
    size_t plen = (size_t)(d[3] | (d[4] << 8));
    if (plen != len - CTRL_HDR_LEN) {
        ESP_LOGW(TAG, "control length mismatch");
        return;
    }
    if (!s.ctrl_rx_active || s.ctrl_rx_op != op) {
        s.ctrl_rx_active = true;
        s.ctrl_rx_op = op;
        s.ctrl_rx_len = 0;
    }
    if (s.ctrl_rx_len + plen > CTRL_RX_MAX) {
        ESP_LOGW(TAG, "control message too large");
        s.ctrl_rx_active = false;
        return;
    }
    memcpy(s.ctrl_rx + s.ctrl_rx_len, d + CTRL_HDR_LEN, plen);
    s.ctrl_rx_len += plen;
    if (flags & CTRL_FLAG_MORE) {
        return;
    }
    s.ctrl_rx_active = false;
    handle_ctrl(op, sid, s.ctrl_rx, s.ctrl_rx_len);
}

static void on_rx_data(const uint8_t *d, size_t len)
{
    if (len < 1) {
        return;
    }
    bool proto_err = false;
    lock();
    s.last_rx_us = esp_timer_get_time();
    if (s.state == SESS_OPEN && !s.aborted && s.rx_sb && d[0] == s.session_id) {
        size_t n = len - 1;
        portENTER_CRITICAL(&s.credit_mux);
        if ((int32_t)n > s.credit_avail) {
            proto_err = true;
        } else {
            s.credit_avail -= (int32_t)n;
        }
        portEXIT_CRITICAL(&s.credit_mux);
        if (!proto_err && n) {
            if (xStreamBufferSend(s.rx_sb, d + 1, n, 0) != n) {
                proto_err = true;
            }
        }
    }
    /* data of another (older) session is dropped silently */
    unlock();
    if (proto_err) {
        ESP_LOGE(TAG, "central exceeded its credit");
        abort_session(CLOSE_PROTOCOL, true);
    }
}

static int chr_access(uint16_t conn_handle, uint16_t attr_handle,
                      struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)arg;
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        return 0;   /* TX is readable (empty) only so that it requires encryption */
    }
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    if (conn_handle != s.conn) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    uint16_t len = 0;
    if (OS_MBUF_PKTLEN(ctxt->om) > sizeof(s_att_buf) ||
        ble_hs_mbuf_to_flat(ctxt->om, s_att_buf, sizeof(s_att_buf), &len) != 0) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }
    if (attr_handle == s.rx_handle) {
        on_rx_data(s_att_buf, len);
    } else if (attr_handle == s.ctrl_handle) {
        on_ctrl_write(s_att_buf, len);
    }
    return 0;
}

/* ------------------------------------------------------------ GAP events */

void ble_tunnel_on_gap_event(struct ble_gap_event *ev)
{
    if (!s.initialized) {
        return;
    }
    switch (ev->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (ev->connect.status == 0) {
            lock();
            if (s.conn != BLE_HS_CONN_HANDLE_NONE) {
                /* One tunnel connection at a time; others keep the app's own
                 * services (e.g. HID) and get ATT errors on the tunnel. */
                uint16_t cur = s.conn;
                unlock();
                ESP_LOGW(TAG, "connection %u not used for the tunnel (serving %u)",
                         ev->connect.conn_handle, cur);
                break;
            }
            s.conn = ev->connect.conn_handle;
            s.mtu = ble_att_mtu(s.conn);
            if (s.mtu < BLE_ATT_MTU_DFLT) {
                s.mtu = BLE_ATT_MTU_DFLT;
            }
            s.tx_sub = s.ctrl_notify = s.ctrl_indicate = s.hello = false;
            s.ctrl_rx_active = false;
            unlock();
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        if (ev->disconnect.conn.conn_handle == s.conn) {
            abort_session(CLOSE_NORMAL, false);
            lock();
            s.conn = BLE_HS_CONN_HANDLE_NONE;
            s.mtu = BLE_ATT_MTU_DFLT;
            s.tx_sub = s.ctrl_notify = s.ctrl_indicate = s.hello = false;
            s.ctrl_rx_active = false;
            s.saved_params_valid = false;
            unlock();
            report_ready();
        }
        break;

    case BLE_GAP_EVENT_MTU:
        if (ev->mtu.conn_handle == s.conn) {
            lock();
            s.mtu = ev->mtu.value;
            unlock();
            ESP_LOGI(TAG, "ATT MTU %u", ev->mtu.value);
        }
        break;

    case BLE_GAP_EVENT_SUBSCRIBE: {
        if (ev->subscribe.conn_handle != s.conn) {
            break;
        }
        uint16_t h = ev->subscribe.attr_handle;
        if (h != s.tx_handle && h != s.ctrl_handle) {
            break;
        }
        bool lost;
        lock();
        if (h == s.tx_handle) {
            s.tx_sub = ev->subscribe.cur_notify;
        } else {
            s.ctrl_notify = ev->subscribe.cur_notify;
            s.ctrl_indicate = ev->subscribe.cur_indicate;
        }
        /* CCCDs of bonded peers are restored on reconnect, so subscription
         * alone does not mean the relay app is running: readiness needs HELLO. */
        lost = !s.tx_sub || !(s.ctrl_notify || s.ctrl_indicate);
        if (lost) {
            s.hello = false;
        }
        unlock();
        if (lost) {
            abort_session(CLOSE_APP, false);
        }
        report_ready();
        break;
    }

    case BLE_GAP_EVENT_NOTIFY_TX:
        if (ev->notify_tx.attr_handle == s.ctrl_handle && ev->notify_tx.indication &&
            ev->notify_tx.status != 0) {
            s.ind_status = ev->notify_tx.status;   /* BLE_HS_EDONE = acknowledged */
            xEventGroupSetBits(s.events, EV_IND_DONE);
        }
        break;

    default:
        break;
    }
}

/* -------------------------------------------------------- session (app) */

static void apply_fast_params(void)
{
#if CONFIG_TLS_OVER_BLE_FAST_CONN_PARAMS
    struct ble_gap_conn_desc d;
    lock();
    uint16_t conn = s.conn;
    bool pending_restore = s.saved_params_valid;   /* previous session not restored yet */
    unlock();
    if (conn == BLE_HS_CONN_HANDLE_NONE || ble_gap_conn_find(conn, &d) != 0) {
        return;
    }
    if (!pending_restore) {
        /* otherwise d holds the fast parameters; keep the original ones */
        lock();
        s.saved_params = (struct ble_gap_upd_params){
            .itvl_min = d.conn_itvl,
            .itvl_max = d.conn_itvl,
            .latency = d.conn_latency,
            .supervision_timeout = d.supervision_timeout,
            .min_ce_len = 0,
            .max_ce_len = 0,
        };
        s.saved_params_valid = true;
        unlock();
    }
    struct ble_gap_upd_params fast = {
        .itvl_min = 6,      /* 7.5 ms */
        .itvl_max = 12,     /* 15 ms */
        .latency = 0,
        .supervision_timeout = d.supervision_timeout < 100 ? 100 : d.supervision_timeout,
        .min_ce_len = 0,
        .max_ce_len = 0,
    };
    int rc = ble_gap_update_params(conn, &fast);
    if (rc != 0) {
        ESP_LOGD(TAG, "connection parameter update not started: %d", rc);
    }
    ble_gap_set_prefered_le_phy(conn, BLE_GAP_LE_PHY_2M_MASK, BLE_GAP_LE_PHY_2M_MASK,
                                BLE_GAP_LE_PHY_CODED_ANY);
#endif
}

/* ble_tunnel_close(): the worker restores the parameters once RX is quiet. */
static void schedule_restore(void)
{
#if CONFIG_TLS_OVER_BLE_FAST_CONN_PARAMS
    job_t j = { .kind = JOB_RESTORE };
    xQueueSend(s.jobs, &j, pdMS_TO_TICKS(100));
#endif
}

/*
 * Worker task only. ble_gap_update_params() holds the NimBLE host lock while it
 * waits for the controller's Command Status. If the central is still sending
 * data of the closed session (up to the credit window), the host cannot process
 * it meanwhile, the HCI ACL buffers run out and the controller's RX path stalls
 * in front of that Command Status ("ACL buf alloc failed ... MBUF alloc stuck")
 * until the data stops. So wait until RX has been quiet first.
 */
static void handle_restore(void)
{
#if CONFIG_TLS_OVER_BLE_FAST_CONN_PARAMS
    int64_t start = esp_timer_get_time();
    for (;;) {
        lock();
        bool idle = s.state == SESS_IDLE;
        int64_t last = s.last_rx_us;
        unlock();
        if (!idle) {
            return;   /* a new session started; its close restores the parameters */
        }
        int64_t now = esp_timer_get_time();
        if (now - last >= RESTORE_QUIET_US || now - start >= RESTORE_MAX_WAIT_US) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    lock();
    bool ok = s.saved_params_valid && s.state == SESS_IDLE && s.conn != BLE_HS_CONN_HANDLE_NONE;
    uint16_t conn = s.conn;
    struct ble_gap_upd_params p = s.saved_params;
    if (ok) {
        s.saved_params_valid = false;
    }
    unlock();
    if (ok) {
        ble_gap_update_params(conn, &p);
    }
#endif
}

static void free_session(void)
{
    lock();
    StreamBufferHandle_t sb = s.rx_sb;
    s.rx_sb = NULL;
    s.state = SESS_IDLE;
    unlock();
    if (sb) {
        vStreamBufferDelete(sb);
    }
}

static void return_credit(size_t n)
{
    uint32_t amount = 0;
    portENTER_CRITICAL(&s.credit_mux);
    s.consumed += n;
    if (s.consumed >= RX_BUF_SIZE / 4) {
        amount = (uint32_t)s.consumed;
        s.consumed = 0;
        s.credit_avail += (int32_t)amount;  /* before the central can see it */
    }
    portEXIT_CRITICAL(&s.credit_mux);
    if (amount) {
        uint8_t c[4];
        put_u32le(c, amount);
        queue_ctrl(OP_CREDIT, s.session_id, c, 4, pdMS_TO_TICKS(100));
    }
}

esp_err_t ble_tunnel_open(const char *host, uint16_t port, uint32_t timeout_ms)
{
    if (!s.initialized || !host) {
        return ESP_ERR_INVALID_STATE;
    }
    size_t hlen = strlen(host);
    if (hlen == 0 || hlen > 253) {
        return ESP_ERR_INVALID_ARG;
    }

    lock();
    if (!s.ready || s.state != SESS_IDLE) {
        unlock();
        return ESP_ERR_INVALID_STATE;
    }
    StreamBufferHandle_t sb = xStreamBufferCreate(RX_BUF_SIZE, 1);
    if (!sb) {
        unlock();
        return ESP_ERR_NO_MEM;
    }
    s.rx_sb = sb;
    s.state = SESS_OPENING;
    s.session_id = (uint8_t)((s.session_id % 255) + 1);   /* 1..255, 0 = no session */
    uint8_t sid = s.session_id;
    s.consumed = 0;
    s.credit_avail = 0;
    s.remote_closed = s.remote_error = s.aborted = false;
    s.open_result = BLE_TUNNEL_OPEN_NO_RESPONSE;
    xEventGroupClearBits(s.events, EV_OPEN_RSP | EV_SESSION_END);
    unlock();

    uint8_t req[3 + 253 + 3 + 2];
    size_t off = tlv_put(req, 0, TLV_HOST, host, (uint16_t)hlen);
    const uint8_t pb[2] = { (uint8_t)(port & 0xff), (uint8_t)(port >> 8) };
    off = tlv_put(req, off, TLV_PORT, pb, 2);
    if (!queue_ctrl(OP_OPEN_REQ, sid, req, (uint16_t)off, pdMS_TO_TICKS(100))) {
        free_session();
        return ESP_ERR_NO_MEM;
    }

    EventBits_t b = xEventGroupWaitBits(s.events, EV_OPEN_RSP | EV_SESSION_END, pdFALSE, pdFALSE,
                                        pdMS_TO_TICKS(timeout_ms));
    lock();
    bool ok = s.state == SESS_OPENING && !s.aborted && !s.remote_closed &&
              (b & EV_OPEN_RSP) && s.open_result == BLE_TUNNEL_OPEN_OK;
    bool no_rsp = !(b & (EV_OPEN_RSP | EV_SESSION_END));
    if (ok) {
        s.state = SESS_OPEN;
        portENTER_CRITICAL(&s.credit_mux);
        s.credit_avail = (int32_t)RX_BUF_SIZE;
        portEXIT_CRITICAL(&s.credit_mux);
    }
    ble_tunnel_open_result_t r = s.open_result;
    unlock();

    if (ok) {
        uint8_t c[4];
        put_u32le(c, (uint32_t)RX_BUF_SIZE);
        queue_ctrl(OP_CREDIT, sid, c, 4, pdMS_TO_TICKS(100));
        apply_fast_params();
        ESP_LOGI(TAG, "session %u open to %s:%u", sid, host, port);
        return ESP_OK;
    }

    if (no_rsp) {
        uint8_t reason = CLOSE_TIMEOUT;
        queue_ctrl(OP_CLOSE, sid, &reason, 1, pdMS_TO_TICKS(100));
    }
    free_session();
    ESP_LOGW(TAG, "open %s:%u failed (result 0x%02x)", host, port, r);
    return no_rsp ? ESP_ERR_TIMEOUT : ESP_FAIL;
}

ble_tunnel_open_result_t ble_tunnel_last_open_result(void)
{
    return s.open_result;
}

int ble_tunnel_send(const void *data, size_t len, uint32_t timeout_ms)
{
    lock();
    bool ok = s.state == SESS_OPEN && !s.aborted && !s.remote_closed;
    uint16_t conn = s.conn;
    uint16_t mtu = s.mtu;
    uint8_t sid = s.session_id;
    unlock();
    if (!ok) {
        return (s.state == SESS_OPEN) ? BLE_TUNNEL_ERR_CLOSED : BLE_TUNNEL_ERR_STATE;
    }

    const uint8_t *p = (const uint8_t *)data;
    size_t max_chunk = (size_t)mtu - 3 - 1;
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > max_chunk) {
            chunk = max_chunk;
        }
        s_tx_frame[0] = sid;
        memcpy(s_tx_frame + 1, p + off, chunk);
        int64_t left_ms = (deadline - esp_timer_get_time()) / 1000;
        if (left_ms < 1) {
            left_ms = 1;
        }
        if (!gatt_send(conn, s.tx_handle, s_tx_frame, chunk + 1, false, (uint32_t)left_ms)) {
            lock();
            bool dead = s.aborted || s.state != SESS_OPEN;
            unlock();
            if (dead) {
                return BLE_TUNNEL_ERR_CLOSED;
            }
            /* Report what already went out, so the caller does not resend it. */
            return off > 0 ? (int)off : BLE_TUNNEL_ERR_TIMEOUT;
        }
        off += chunk;
    }
    return (int)len;
}

int ble_tunnel_recv(void *buf, size_t len, uint32_t timeout_ms)
{
    lock();
    StreamBufferHandle_t sb = (s.state == SESS_OPEN) ? s.rx_sb : NULL;
    unlock();
    if (!sb) {
        return BLE_TUNNEL_ERR_STATE;
    }
    if (len == 0) {
        return 0;
    }

    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    for (;;) {
        size_t n = xStreamBufferReceive(sb, buf, len, 0);
        if (n > 0) {
            return_credit(n);
            return (int)n;
        }
        lock();
        bool aborted = s.aborted;
        bool closed = s.remote_closed;
        bool err = s.remote_error;
        unlock();
        if (aborted) {
            return BLE_TUNNEL_ERR_CLOSED;
        }
        if (closed) {
            n = xStreamBufferReceive(sb, buf, len, 0);   /* data that raced the close */
            if (n > 0) {
                return_credit(n);
                return (int)n;
            }
            return err ? BLE_TUNNEL_ERR_CLOSED : 0;
        }
        int64_t left_us = deadline - esp_timer_get_time();
        if (left_us <= 0) {
            return BLE_TUNNEL_ERR_TIMEOUT;
        }
        TickType_t wait = pdMS_TO_TICKS(left_us / 1000 > 50 ? 50 : left_us / 1000);
        if (wait == 0) {
            wait = 1;
        }
        n = xStreamBufferReceive(sb, buf, len, wait);
        if (n > 0) {
            return_credit(n);
            return (int)n;
        }
    }
}

void ble_tunnel_close(void)
{
    lock();
    bool active = s.state != SESS_IDLE;
    bool send_close = active && !s.aborted && s.conn != BLE_HS_CONN_HANDLE_NONE;
    uint8_t sid = s.session_id;
    unlock();
    if (!active) {
        return;
    }
    if (send_close) {
        uint8_t reason = CLOSE_NORMAL;
        queue_ctrl(OP_CLOSE, sid, &reason, 1, pdMS_TO_TICKS(100));
    }
    free_session();
    schedule_restore();
    ESP_LOGI(TAG, "session %u closed", sid);
}

/* ----------------------------------------------------------- public misc */

bool ble_tunnel_is_ready(void)
{
    if (!s.initialized) {
        return false;
    }
    lock();
    bool r = s.ready;
    unlock();
    return r;
}

bool ble_tunnel_get_central_time(int64_t *unix_time)
{
    if (!s.initialized) {
        return false;
    }
    lock();
    bool has = s.has_time;
    int64_t t = s.time_unix + (esp_timer_get_time() - s.time_at_us) / 1000000;
    unlock();
    if (has && unix_time) {
        *unix_time = t;
    }
    return has;
}

const struct ble_gatt_svc_def *ble_tunnel_gatt_svcs(void)
{
    return s.initialized ? s.svcs : NULL;
}

const ble_uuid128_t *ble_tunnel_service_uuid(void)
{
    return &s.svc_uuid;
}

esp_err_t ble_tunnel_init(const ble_tunnel_config_t *cfg)
{
    if (s.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (cfg) {
        s.cfg = *cfg;
    }
    if (!parse_uuid128(CONFIG_TLS_OVER_BLE_SVC_UUID, &s.svc_uuid) ||
        !parse_uuid128(CONFIG_TLS_OVER_BLE_RX_UUID, &s.rx_uuid) ||
        !parse_uuid128(CONFIG_TLS_OVER_BLE_TX_UUID, &s.tx_uuid) ||
        !parse_uuid128(CONFIG_TLS_OVER_BLE_CTRL_UUID, &s.ctrl_uuid)) {
        ESP_LOGE(TAG, "invalid UUID in Kconfig");
        return ESP_ERR_INVALID_ARG;
    }

    s.conn = BLE_HS_CONN_HANDLE_NONE;
    s.mtu = BLE_ATT_MTU_DFLT;
    portMUX_INITIALIZE(&s.credit_mux);
    s.lock = xSemaphoreCreateMutex();
    s.tx_lock = xSemaphoreCreateMutex();
    s.events = xEventGroupCreate();
    s.jobs = xQueueCreate(JOB_QUEUE_LEN, sizeof(job_t));
    if (!s.lock || !s.tx_lock || !s.events || !s.jobs) {
        return ESP_ERR_NO_MEM;
    }

    s.chrs[0] = (struct ble_gatt_chr_def){
        .uuid = &s.rx_uuid.u,
        .access_cb = chr_access,
        .flags = BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_WRITE_ENC,
        .val_handle = &s.rx_handle,
    };
    s.chrs[1] = (struct ble_gatt_chr_def){
        .uuid = &s.tx_uuid.u,
        .access_cb = chr_access,
        .flags = BLE_GATT_CHR_F_NOTIFY | BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
        .val_handle = &s.tx_handle,
    };
    s.chrs[2] = (struct ble_gatt_chr_def){
        .uuid = &s.ctrl_uuid.u,
        .access_cb = chr_access,
        .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC |
                 BLE_GATT_CHR_F_NOTIFY | BLE_GATT_CHR_F_INDICATE,
        .val_handle = &s.ctrl_handle,
    };
    memset(&s.chrs[3], 0, sizeof(s.chrs[3]));
    s.svcs[0] = (struct ble_gatt_svc_def){
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &s.svc_uuid.u,
        .characteristics = s.chrs,
    };
    memset(&s.svcs[1], 0, sizeof(s.svcs[1]));

    if (xTaskCreate(worker_task, "ble_tunnel", CONFIG_TLS_OVER_BLE_TASK_STACK_SIZE, NULL,
                    CONFIG_TLS_OVER_BLE_TASK_PRIORITY, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    s.initialized = true;
    ESP_LOGI(TAG, "initialized (rx buffer %u bytes)", (unsigned)RX_BUF_SIZE);
    return ESP_OK;
}
