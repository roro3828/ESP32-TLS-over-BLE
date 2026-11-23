/*
 * TLS over BLE - tunnel layer
 *
 * Carries an opaque byte stream between the ESP32 (GATT server / peripheral)
 * and a relay application on the BLE central, which forwards it to a TCP
 * server. The app keeps ownership of NimBLE init, advertising, pairing and
 * the GAP event handler; this component only adds its own GATT service.
 *
 * Usage:
 *   1. ble_tunnel_init() before the NimBLE host task starts.
 *   2. Register ble_tunnel_gatt_svcs() together with the app's services.
 *   3. Forward every GAP event to ble_tunnel_on_gap_event().
 *   4. When needed: ble_tunnel_open() / send() / recv() / close(),
 *      or use the TLS layer in ble_tls.h.
 *
 * Limits: NimBLE only. The tunnel serves one BLE connection (the first one
 * established while none is served) and one session at a time; further
 * connections can still use the app's other services.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_uuid.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_TUNNEL_PROTO_VERSION_MAJOR  1
#define BLE_TUNNEL_PROTO_VERSION_MINOR  0

/* Return values of ble_tunnel_send() / ble_tunnel_recv() (besides >= 0). */
#define BLE_TUNNEL_ERR_TIMEOUT  (-1)    /* nothing happened before the timeout */
#define BLE_TUNNEL_ERR_CLOSED   (-2)    /* session aborted or closed with an error */
#define BLE_TUNNEL_ERR_STATE    (-3)    /* no open session */

/* OPEN_RSP result codes (also returned by ble_tunnel_last_open_result()). */
typedef enum {
    BLE_TUNNEL_OPEN_OK = 0x00,
    BLE_TUNNEL_OPEN_NOT_AUTHENTICATED = 0x01,
    BLE_TUNNEL_OPEN_NOT_ALLOWED = 0x02,
    BLE_TUNNEL_OPEN_DNS_FAILED = 0x03,
    BLE_TUNNEL_OPEN_REFUSED = 0x04,
    BLE_TUNNEL_OPEN_TIMEOUT = 0x05,
    BLE_TUNNEL_OPEN_BUSY = 0x06,
    BLE_TUNNEL_OPEN_NO_RESPONSE = 0xFF, /* local: central did not answer */
} ble_tunnel_open_result_t;

/**
 * Signs msg with the device key: ECDSA P-256 over SHA-256(msg).
 * Writes a DER encoded signature to sig and its length to sig_len.
 * Returns 0 on success.
 */
typedef int (*ble_tunnel_sign_fn)(const uint8_t *msg, size_t msg_len,
                                  uint8_t *sig, size_t sig_size, size_t *sig_len,
                                  void *arg);

/** Device identity used when the central asks the device to prove it is genuine. */
typedef struct {
    const uint8_t *device_cert_der;        /* device certificate (ECDSA P-256) */
    size_t device_cert_len;
    const uint8_t *intermediate_cert_der;  /* sent as opaque bytes, never parsed */
    size_t intermediate_cert_len;
    ble_tunnel_sign_fn sign;
    void *sign_arg;
} ble_tunnel_identity_t;

/** Called from the NimBLE host task when the tunnel becomes usable or unusable. */
typedef void (*ble_tunnel_ready_cb_t)(bool ready, void *arg);

typedef struct {
    const char *app_version;                /* sent in HELLO; may be NULL */
    const ble_tunnel_identity_t *identity;  /* NULL: device authentication unsupported */
    ble_tunnel_ready_cb_t on_ready;         /* may be NULL */
    void *cb_arg;
} ble_tunnel_config_t;

/** Initializes the tunnel. Call before the GATT services are registered. */
esp_err_t ble_tunnel_init(const ble_tunnel_config_t *cfg);

/** GATT service definition (terminated array) for ble_gatts_count_cfg/add_svcs. */
const struct ble_gatt_svc_def *ble_tunnel_gatt_svcs(void);

/** UUID of the tunnel service (e.g. for the scan response). */
const ble_uuid128_t *ble_tunnel_service_uuid(void);

/** Forward every GAP event of the app's handler here. */
void ble_tunnel_on_gap_event(struct ble_gap_event *event);

/** True once the central relay app sent HELLO on the current connection. */
bool ble_tunnel_is_ready(void);

/** Unix time received from the central (TIME), advanced by the local clock. */
bool ble_tunnel_get_central_time(int64_t *unix_time);

/**
 * Asks the central to open a TCP connection and starts a session.
 * Allocates the receive buffer; it is freed by ble_tunnel_close().
 * Returns ESP_ERR_INVALID_STATE (not ready / busy), ESP_ERR_NO_MEM,
 * ESP_ERR_TIMEOUT or ESP_FAIL (see ble_tunnel_last_open_result()).
 */
esp_err_t ble_tunnel_open(const char *host, uint16_t port, uint32_t timeout_ms);

/** Result code of the last ble_tunnel_open(). */
ble_tunnel_open_result_t ble_tunnel_last_open_result(void);

/**
 * Sends up to len bytes. Returns the number of bytes sent (len, or fewer when
 * the timeout hit after a partial send), or a negative BLE_TUNNEL_ERR_* value.
 */
int ble_tunnel_send(const void *data, size_t len, uint32_t timeout_ms);

/**
 * Receives up to len bytes. Returns the number of bytes (> 0), 0 when the
 * server closed the connection normally, or a negative BLE_TUNNEL_ERR_* value.
 */
int ble_tunnel_recv(void *buf, size_t len, uint32_t timeout_ms);

/** Ends the session (sends CLOSE) and frees the session buffers. */
void ble_tunnel_close(void);

#ifdef __cplusplus
}
#endif
