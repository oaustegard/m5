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
#include "driver/uart.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
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

static void save_creds(const char *ssid, const char *pass) {
    nvs_handle_t h;
    if (nvs_open("wifi", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, "ssid", ssid);
        nvs_set_str(h, "pass", pass);
        nvs_commit(h);
        nvs_close(h);
    }
    ESP_LOGI(TAG, "saved credentials for '%s', restarting", ssid);
}

static const char FORM[] =
    "<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Muninn Core2</title><style>body{font:16px system-ui;margin:2em;max-width:30em}"
    "input{display:block;width:100%;font-size:1.1em;margin:.3em 0 1em;padding:.4em}"
    "button{font-size:1.1em;padding:.5em 1.5em}</style>"
    "<h2>WiFi for the Core2</h2><form method=post action=/save>"
    "<label>Network name<input name=ssid autocapitalize=none autocorrect=off spellcheck=false required></label>"
    "<label>Password<input name=pass type=password autocapitalize=none autocorrect=off spellcheck=false></label>"
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
    char body[512] = {0};
    int len = req->content_len < (int)sizeof body - 1 ? req->content_len : (int)sizeof body - 1;
    int got = 0;
    while (got < len) {
        int r = httpd_req_recv(req, body + got, len - got);
        if (r <= 0) return ESP_FAIL;
        got += r;
    }
    // The values arrive URL-encoded, up to three bytes per character, so the
    // buffers are sized for that; a truncated password must not be saved.
    char ssid[3 * 32 + 1] = {0}, pass[3 * 64 + 1] = {0};
    if (httpd_query_key_value(body, "ssid", ssid, sizeof ssid) != ESP_OK || !ssid[0]) {
        httpd_resp_send(req, "missing network name", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    esp_err_t pe = httpd_query_key_value(body, "pass", pass, sizeof pass);
    if (pe != ESP_OK && pe != ESP_ERR_NOT_FOUND) {
        httpd_resp_send(req, "password too long", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    url_decode(ssid);
    url_decode(pass);
    if (strlen(ssid) > 32 || strlen(pass) > 64) {
        httpd_resp_send(req, "network name or password too long", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }
    save_creds(ssid, pass);
    httpd_resp_send(req, "Saved. The Core2 is restarting and will join your network.", HTTPD_RESP_USE_STRLEN);
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
    return ESP_OK;
}

// Captive portal: any other URL redirects to the form, so a phone's
// connectivity check (captive.apple.com and friends) opens the setup sheet
// instead of dropping the network for having no internet.
static esp_err_t redirect_404(httpd_req_t *req, httpd_err_code_t err) {
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    return httpd_resp_send(req, NULL, 0);
}

// Answers every DNS query with 192.168.4.1.
static void dns_task(void *arg) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(53), .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0) {
        ESP_LOGE(TAG, "dns: cannot bind port 53");
        vTaskDelete(NULL);
    }
    uint8_t buf[512];
    for (;;) {
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        int n = recvfrom(s, buf, sizeof buf - 16, 0, (struct sockaddr *)&from, &fl);
        if (n < 12 || (buf[2] & 0x80)) continue;  // too short, or a response
        // Skip the question name to find where the answer goes.
        int q = 12;
        while (q < n && buf[q]) q += buf[q] + 1;
        q += 5;  // terminating zero, QTYPE, QCLASS
        if (q > n) continue;
        buf[2] = 0x84 | (buf[2] & 0x01);  // response, authoritative, keep RD
        buf[3] = 0x00;
        buf[6] = 0, buf[7] = 1;                        // one answer
        buf[8] = buf[9] = buf[10] = buf[11] = 0;       // no authority or additional records
        static const uint8_t ans[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 168, 4, 1};
        memcpy(buf + q, ans, sizeof ans);
        sendto(s, buf, q + sizeof ans, 0, (struct sockaddr *)&from, fl);
    }
}

// Serial provisioning: a line "WIFI <ssid><TAB><password>" on the USB serial
// port saves the credentials, for setting up from a computer the Core2 is
// plugged into.
static void serial_task(void *arg) {
    if (uart_driver_install(UART_NUM_0, 1024, 0, 0, NULL, 0) != ESP_OK) {
        ESP_LOGE(TAG, "serial: cannot install the UART driver");
        vTaskDelete(NULL);
    }
    char line[128];
    size_t len = 0;
    for (;;) {
        uint8_t c;
        if (uart_read_bytes(UART_NUM_0, &c, 1, portMAX_DELAY) != 1) continue;
        if (c != '\n' && c != '\r') {
            if (len < sizeof line - 1) line[len++] = (char)c;
            continue;
        }
        line[len] = 0;
        len = 0;
        if (strncmp(line, "WIFI ", 5) != 0) continue;
        char *ssid = line + 5, *tab = strchr(ssid, '\t');
        if (!tab || tab == ssid || strlen(ssid) > 32 || strlen(tab + 1) > 64) {
            ESP_LOGW(TAG, "serial: expected WIFI <ssid><TAB><password>");
            continue;
        }
        *tab = 0;
        save_creds(ssid, tab + 1);
        vTaskDelay(pdMS_TO_TICKS(500));
        esp_restart();
    }
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
    httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, redirect_404);
    xTaskCreate(dns_task, "dns", 3072, NULL, 5, NULL);
    xTaskCreate(serial_task, "serial", 3072, NULL, 5, NULL);
    ESP_LOGI(TAG, "setup access point '%s' up at http://192.168.4.1", PROVISION_AP_SSID);
    ESP_LOGI(TAG, "or send \"WIFI <ssid><TAB><password>\" over serial");
    for (;;) vTaskDelay(portMAX_DELAY);
}
