/*
 * Minimal BLE HID keyboard (HID over GATT) for the sample app.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "host/ble_gap.h"
#include "host/ble_gatt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HID_KBD_APPEARANCE      0x03C1  /* Keyboard */
#define HID_KBD_SVC_UUID16      0x1812

#define HID_MOD_LEFT_SHIFT      0x02
#define HID_KEY_A               0x04

/** HID, Device Information and Battery services (terminated array). */
const struct ble_gatt_svc_def *hid_kbd_gatt_svcs(void);

/** Forward every GAP event here. */
void hid_kbd_on_gap_event(struct ble_gap_event *event);

/** Sends a key press followed by a release. Returns 0 on success. */
int hid_kbd_send_key(uint8_t modifier, uint8_t keycode);

#ifdef __cplusplus
}
#endif
