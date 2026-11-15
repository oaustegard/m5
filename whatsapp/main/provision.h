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
// Starts the open access point and a web form at http://192.168.4.1. When the
// form is submitted the credentials are saved and the device restarts.
// Never returns.
void provision_run(void);

#ifdef __cplusplus
}
#endif
