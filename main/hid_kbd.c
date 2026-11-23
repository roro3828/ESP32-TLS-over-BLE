/*
 * Minimal BLE HID keyboard (HID over GATT) for the sample app.
 * Services: HID (0x1812), Device Information (0x180A), Battery (0x180F).
 */
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "host/ble_hs.h"

#include "hid_kbd.h"

static const char *TAG = "hid_kbd";

#define REPORT_ID_KBD   1
#define REPORT_LEN      8

/* Keyboard with report ID 1: modifiers, reserved, 5 LEDs (output), 6 keys. */
static const uint8_t s_report_map[] = {
    0x05, 0x01,        /* Usage Page (Generic Desktop) */
    0x09, 0x06,        /* Usage (Keyboard) */
    0xA1, 0x01,        /* Collection (Application) */
    0x85, REPORT_ID_KBD, /* Report ID */
    0x05, 0x07,        /*   Usage Page (Keyboard/Keypad) */
    0x19, 0xE0,        /*   Usage Minimum (Left Control) */
    0x29, 0xE7,        /*   Usage Maximum (Right GUI) */
    0x15, 0x00,        /*   Logical Minimum (0) */
    0x25, 0x01,        /*   Logical Maximum (1) */
    0x75, 0x01,        /*   Report Size (1) */
    0x95, 0x08,        /*   Report Count (8) */
    0x81, 0x02,        /*   Input (Data, Var, Abs) - modifiers */
    0x95, 0x01,        /*   Report Count (1) */
    0x75, 0x08,        /*   Report Size (8) */
    0x81, 0x01,        /*   Input (Const) - reserved */
    0x95, 0x05,        /*   Report Count (5) */
    0x75, 0x01,        /*   Report Size (1) */
    0x05, 0x08,        /*   Usage Page (LEDs) */
    0x19, 0x01,        /*   Usage Minimum (Num Lock) */
    0x29, 0x05,        /*   Usage Maximum (Kana) */
    0x91, 0x02,        /*   Output (Data, Var, Abs) - LEDs */
    0x95, 0x01,        /*   Report Count (1) */
    0x75, 0x03,        /*   Report Size (3) */
    0x91, 0x01,        /*   Output (Const) - padding */
    0x95, 0x06,        /*   Report Count (6) */
    0x75, 0x08,        /*   Report Size (8) */
    0x15, 0x00,        /*   Logical Minimum (0) */
    0x25, 0x65,        /*   Logical Maximum (101) */
    0x05, 0x07,        /*   Usage Page (Keyboard/Keypad) */
    0x19, 0x00,        /*   Usage Minimum (0) */
    0x29, 0x65,        /*   Usage Maximum (101) */
    0x81, 0x00,        /*   Input (Data, Array) - keys */
    0xC0,              /* End Collection */
};

static const uint8_t s_hid_info[4] = { 0x11, 0x01, 0x00, 0x02 };  /* HID 1.11, normally connectable */
static const uint8_t s_rr_input[2] = { REPORT_ID_KBD, 0x01 };
static const uint8_t s_rr_output[2] = { REPORT_ID_KBD, 0x02 };
/* PnP ID: vendor ID source = Bluetooth SIG, vendor 0x02E5 (Espressif), product 1, version 1.0 */
static const uint8_t s_pnp_id[7] = { 0x01, 0xE5, 0x02, 0x01, 0x00, 0x00, 0x01 };
static const char s_manufacturer[] = "TLS over BLE sample";
static const uint8_t s_battery = 100;

static uint8_t s_input_report[REPORT_LEN];
static uint8_t s_boot_input[REPORT_LEN];
static uint8_t s_leds;
static uint8_t s_protocol_mode = 1;   /* 0 = boot, 1 = report */

static uint16_t s_input_handle;
static uint16_t s_boot_input_handle;
static uint16_t s_output_handle;
static uint16_t s_boot_output_handle;
static uint16_t s_proto_handle;
static uint16_t s_battery_handle;

static uint16_t s_conn = BLE_HS_CONN_HANDLE_NONE;
static bool s_input_sub;
static bool s_boot_sub;

enum {
    A_HID_INFO = 1, A_REPORT_MAP, A_CTRL_POINT, A_PROTO_MODE, A_INPUT, A_OUTPUT,
    A_BOOT_INPUT, A_BOOT_OUTPUT, A_RR_INPUT, A_RR_OUTPUT, A_MANUFACTURER, A_PNP_ID, A_BATTERY,
};

#define ARG(x) ((void *)(uintptr_t)(x))
#define ENC_READ (BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC)
#define ENC_WRITE (BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_WRITE_ENC)

static int append(struct os_mbuf *om, const void *data, size_t len)
{
    return os_mbuf_append(om, data, len) == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
}

static int read_u8(struct ble_gatt_access_ctxt *ctxt, uint8_t *out)
{
    uint16_t len = 0;
    if (OS_MBUF_PKTLEN(ctxt->om) != 1 || ble_hs_mbuf_to_flat(ctxt->om, out, 1, &len) != 0) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }
    return 0;
}

static int access_cb(uint16_t conn_handle, uint16_t attr_handle,
                     struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle;
    (void)attr_handle;
    int which = (int)(uintptr_t)arg;
    uint8_t v = 0;
    int rc;

    switch (ctxt->op) {
    case BLE_GATT_ACCESS_OP_READ_CHR:
    case BLE_GATT_ACCESS_OP_READ_DSC:
        switch (which) {
        case A_HID_INFO:     return append(ctxt->om, s_hid_info, sizeof(s_hid_info));
        case A_REPORT_MAP:   return append(ctxt->om, s_report_map, sizeof(s_report_map));
        case A_PROTO_MODE:   return append(ctxt->om, &s_protocol_mode, 1);
        case A_INPUT:        return append(ctxt->om, s_input_report, REPORT_LEN);
        case A_BOOT_INPUT:   return append(ctxt->om, s_boot_input, REPORT_LEN);
        case A_OUTPUT:
        case A_BOOT_OUTPUT:  return append(ctxt->om, &s_leds, 1);
        case A_RR_INPUT:     return append(ctxt->om, s_rr_input, sizeof(s_rr_input));
        case A_RR_OUTPUT:    return append(ctxt->om, s_rr_output, sizeof(s_rr_output));
        case A_MANUFACTURER: return append(ctxt->om, s_manufacturer, strlen(s_manufacturer));
        case A_PNP_ID:       return append(ctxt->om, s_pnp_id, sizeof(s_pnp_id));
        case A_BATTERY:      return append(ctxt->om, &s_battery, 1);
        default:             return BLE_ATT_ERR_UNLIKELY;
        }

    case BLE_GATT_ACCESS_OP_WRITE_CHR:
        rc = read_u8(ctxt, &v);
        if (rc != 0) {
            return rc;
        }
        switch (which) {
        case A_CTRL_POINT:
            ESP_LOGI(TAG, "HID control point: %s", v == 0 ? "suspend" : "exit suspend");
            return 0;
        case A_PROTO_MODE:
            if (v > 1) {
                return BLE_ATT_ERR_UNLIKELY;
            }
            s_protocol_mode = v;
            ESP_LOGI(TAG, "protocol mode: %s", v ? "report" : "boot");
            return 0;
        case A_OUTPUT:
        case A_BOOT_OUTPUT:
            s_leds = v;
            ESP_LOGI(TAG, "LEDs from host: 0x%02x", v);
            return 0;
        default:
            return BLE_ATT_ERR_UNLIKELY;
        }

    default:
        return BLE_ATT_ERR_UNLIKELY;
    }
}

static const struct ble_gatt_svc_def s_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(HID_KBD_SVC_UUID16),
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4A),     /* HID Information */
                .access_cb = access_cb, .arg = ARG(A_HID_INFO), .flags = ENC_READ,
            },
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4B),     /* Report Map */
                .access_cb = access_cb, .arg = ARG(A_REPORT_MAP), .flags = ENC_READ,
            },
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4C),     /* HID Control Point */
                .access_cb = access_cb, .arg = ARG(A_CTRL_POINT),
                .flags = BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_WRITE_ENC,
            },
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4E),     /* Protocol Mode */
                .access_cb = access_cb, .arg = ARG(A_PROTO_MODE),
                .flags = ENC_READ | BLE_GATT_CHR_F_WRITE_NO_RSP | BLE_GATT_CHR_F_WRITE_ENC,
                .val_handle = &s_proto_handle,
            },
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4D),     /* Report: keyboard input */
                .access_cb = access_cb, .arg = ARG(A_INPUT),
                .flags = ENC_READ | BLE_GATT_CHR_F_NOTIFY,
                .val_handle = &s_input_handle,
                .descriptors = (struct ble_gatt_dsc_def[]) {
                    {
                        .uuid = BLE_UUID16_DECLARE(0x2908),   /* Report Reference */
                        .att_flags = BLE_ATT_F_READ | BLE_ATT_F_READ_ENC,
                        .access_cb = access_cb, .arg = ARG(A_RR_INPUT),
                    },
                    { 0 },
                },
            },
            {
                .uuid = BLE_UUID16_DECLARE(0x2A4D),     /* Report: LED output */
                .access_cb = access_cb, .arg = ARG(A_OUTPUT),
                .flags = ENC_READ | ENC_WRITE,
                .val_handle = &s_output_handle,
                .descriptors = (struct ble_gatt_dsc_def[]) {
                    {
                        .uuid = BLE_UUID16_DECLARE(0x2908),
                        .att_flags = BLE_ATT_F_READ | BLE_ATT_F_READ_ENC,
                        .access_cb = access_cb, .arg = ARG(A_RR_OUTPUT),
                    },
                    { 0 },
                },
            },
            {
                .uuid = BLE_UUID16_DECLARE(0x2A22),     /* Boot Keyboard Input */
                .access_cb = access_cb, .arg = ARG(A_BOOT_INPUT),
                .flags = ENC_READ | BLE_GATT_CHR_F_NOTIFY,
                .val_handle = &s_boot_input_handle,
            },
            {
                .uuid = BLE_UUID16_DECLARE(0x2A32),     /* Boot Keyboard Output */
                .access_cb = access_cb, .arg = ARG(A_BOOT_OUTPUT),
                .flags = ENC_READ | ENC_WRITE,
                .val_handle = &s_boot_output_handle,
            },
            { 0 },
        },
    },
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(0x180A),             /* Device Information */
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                .uuid = BLE_UUID16_DECLARE(0x2A29),     /* Manufacturer Name */
                .access_cb = access_cb, .arg = ARG(A_MANUFACTURER), .flags = BLE_GATT_CHR_F_READ,
            },
            {
                .uuid = BLE_UUID16_DECLARE(0x2A50),     /* PnP ID */
                .access_cb = access_cb, .arg = ARG(A_PNP_ID), .flags = BLE_GATT_CHR_F_READ,
            },
            { 0 },
        },
    },
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(0x180F),             /* Battery */
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                .uuid = BLE_UUID16_DECLARE(0x2A19),     /* Battery Level */
                .access_cb = access_cb, .arg = ARG(A_BATTERY),
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
                .val_handle = &s_battery_handle,
            },
            { 0 },
        },
    },
    { 0 },
};

const struct ble_gatt_svc_def *hid_kbd_gatt_svcs(void)
{
    return s_svcs;
}

void hid_kbd_on_gap_event(struct ble_gap_event *ev)
{
    switch (ev->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (ev->connect.status == 0) {
            s_conn = ev->connect.conn_handle;
            s_input_sub = s_boot_sub = false;
            s_protocol_mode = 1;
        }
        break;
    case BLE_GAP_EVENT_DISCONNECT:
        s_conn = BLE_HS_CONN_HANDLE_NONE;
        s_input_sub = s_boot_sub = false;
        break;
    case BLE_GAP_EVENT_SUBSCRIBE:
        if (ev->subscribe.attr_handle == s_input_handle) {
            s_input_sub = ev->subscribe.cur_notify;
        } else if (ev->subscribe.attr_handle == s_boot_input_handle) {
            s_boot_sub = ev->subscribe.cur_notify;
        }
        break;
    default:
        break;
    }
}

static int notify_report(const uint8_t *report)
{
    bool boot = (s_protocol_mode == 0);
    uint16_t handle = boot ? s_boot_input_handle : s_input_handle;
    bool subscribed = boot ? s_boot_sub : s_input_sub;
    if (s_conn == BLE_HS_CONN_HANDLE_NONE || !subscribed) {
        return BLE_HS_ENOTCONN;
    }
    memcpy(boot ? s_boot_input : s_input_report, report, REPORT_LEN);
    struct os_mbuf *om = ble_hs_mbuf_from_flat(report, REPORT_LEN);
    if (!om) {
        return BLE_HS_ENOMEM;
    }
    return ble_gatts_notify_custom(s_conn, handle, om);
}

int hid_kbd_send_key(uint8_t modifier, uint8_t keycode)
{
    uint8_t report[REPORT_LEN] = { modifier, 0, keycode, 0, 0, 0, 0, 0 };
    int rc = notify_report(report);
    if (rc != 0) {
        ESP_LOGW(TAG, "key not sent (rc=%d): host not connected or not subscribed", rc);
        return rc;
    }
    vTaskDelay(pdMS_TO_TICKS(20));
    memset(report, 0, sizeof(report));
    return notify_report(report);
}
