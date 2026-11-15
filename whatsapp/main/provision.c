// SPDX-License-Identifier: MIT
#include "provision.h"

#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"

static const char *TAG = "provision";

bool provision_load(char *ssid, int ssid_len, char *pass, int pass_len) {
    nvs_handle_t h;
    if (nvs_open("wifi", NVS_READONLY, &h) != ESP_OK) return false;
    size_t a = ssid_len, b = pass_len;
    bool ok = nvs_get_str(h, "ssid", ssid, &a) == ESP_OK && nvs_get_str(h, "pass", pass, &b) == ESP_OK && ssid[0];
    nvs_close(h);
    return ok;
}

void provision_clear(void) {
    nvs_handle_t h;
    if (nvs_open("wifi", NVS_READWRITE, &h) != ESP_OK) return;
    nvs_erase_all(h);
    nvs_commit(h);
    nvs_close(h);
}

static const char FORM[] =
    "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Muninn Core2</title><style>body{font:16px system-ui;margin:2em;max-width:30em}"
    "input{display:block;width:100%;font-size:1.1em;margin:.3em 0 1em;padding:.4em}"
    "button{font-size:1.1em;padding:.5em 1.5em}</style>"
    "<h2>WiFi for the Core2</h2><form method=post action=/save>"
    "<label>Network name<input name=ssid autocapitalize=none required></label>"
    "<label>Password<input name=pass type=password></label>"
    "<button>Save and restart</button></form>";

static esp_err_t get_root(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, FORM, HTTPD_RESP_USE_STRLEN);
}

// Decodes application/x-www-form-urlencoded value in place.
static void url_decode(char *s) {
    char *o = s;
    for (; *s; s++) {
        if (*s == '+') {
            *o++ = ' ';
        } else if (*s == '%' && s[1] && s[2]) {
            char hex[3] = {s[1], s[2], 0};
            *o++ = (char)strtol(hex, NULL, 16);
            s += 2;
        } else {
            *o++ = *s;
        }
    }
    *o = 0;
}

static esp_err_t post_save(httpd_req_t *req) {
    char body[256] = {0};
    int len = req->content_len < (int)sizeof body - 1 ? req->content_len : (int)sizeof body - 1;
    int got = 0;
    while (got < len) {
        int r = httpd_req_recv(req, body + got, len - got);
        if (r <= 0) return ESP_FAIL;
        got += r;
    }
    char ssid[33] = {0}, pass[65] = {0};
    if (httpd_query_key_value(body, "ssid", ssid, sizeof ssid) != ESP_OK) {
        httpd_resp_send(req, "missing network name", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    httpd_query_key_value(body, "pass", pass, sizeof pass);
    url_decode(ssid);
    url_decode(pass);
    nvs_handle_t h;
    if (nvs_open("wifi", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, "ssid", ssid);
        nvs_set_str(h, "pass", pass);
        nvs_commit(h);
        nvs_close(h);
    }
    ESP_LOGI(TAG, "saved credentials for '%s', restarting", ssid);
    httpd_resp_send(req, "Saved. The Core2 is restarting and will join your network.", HTTPD_RESP_USE_STRLEN);
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
    return ESP_OK;
}

void provision_run(void) {
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    wifi_config_t ap = {0};
    strcpy((char *)ap.ap.ssid, PROVISION_AP_SSID);
    ap.ap.ssid_len = strlen(PROVISION_AP_SSID);
    ap.ap.authmode = WIFI_AUTH_OPEN;
    ap.ap.max_connection = 2;
    ap.ap.channel = 6;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap));
    ESP_ERROR_CHECK(esp_wifi_start());

    httpd_handle_t server = NULL;
    httpd_config_t hc = HTTPD_DEFAULT_CONFIG();
    ESP_ERROR_CHECK(httpd_start(&server, &hc));
    httpd_uri_t root = {.uri = "/", .method = HTTP_GET, .handler = get_root};
    httpd_uri_t save = {.uri = "/save", .method = HTTP_POST, .handler = post_save};
    httpd_register_uri_handler(server, &root);
    httpd_register_uri_handler(server, &save);
    ESP_LOGI(TAG, "setup access point '%s' up at http://192.168.4.1", PROVISION_AP_SSID);
    for (;;) vTaskDelay(portMAX_DELAY);
}
