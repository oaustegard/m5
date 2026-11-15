// SPDX-License-Identifier: MIT
// WiFi credentials: stored in NVS, entered through a setup access point.
#pragma once
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PROVISION_AP_SSID "Muninn-Core2"

// Loads saved credentials. Returns true if both were found.
bool provision_load(char *ssid, int ssid_len, char *pass, int pass_len);
void provision_clear(void);
// Starts the open access point and a web form at http://192.168.4.1 (with a
// captive-portal DNS so phones open it themselves), and listens on the USB
// serial port for "WIFI <ssid><TAB><password>". Either saves the credentials
// and restarts the device.
// Never returns.
void provision_run(void);

#ifdef __cplusplus
}
#endif
