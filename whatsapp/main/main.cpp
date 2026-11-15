// SPDX-License-Identifier: MIT
// Core2 firmware: joins WiFi, connects to WhatsApp, shows the pairing QR code
// on screen, stays online as a linked device, and shows incoming messages.
//
// Threads: the WebSocket client delivers events on its own task; they go
// through a queue to the main loop, which is the only caller of the wa core.
//
// Buttons (the three touch circles under the screen):
//   hold A 3 s  forget WiFi and start the setup access point
//   hold C 5 s  unlink: forget the WhatsApp pairing and show a new QR code
#include <M5Unified.h>
#include <string.h>
#include <time.h>

#include "esp_crt_bundle.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_timer.h"
#include "esp_websocket_client.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "nvs.h"
#include "nvs_flash.h"

extern "C" {
#include "provision.h"
#include "wa.h"
}

static const char *TAG = "core2-wa";

// ---------------------------------------------------------------- screen

static void screen(const char *title, const char *line1 = nullptr, const char *line2 = nullptr,
                   uint16_t color = TFT_WHITE) {
    auto &d = M5.Display;
    d.startWrite();
    d.fillScreen(TFT_BLACK);
    d.setTextDatum(top_center);
    d.setTextColor(color, TFT_BLACK);
    d.setFont(&fonts::FreeSansBold12pt7b);
    d.drawString(title, d.width() / 2, 70);
    d.setFont(&fonts::FreeSans9pt7b);
    d.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    if (line1) d.drawString(line1, d.width() / 2, 120);
    if (line2) d.drawString(line2, d.width() / 2, 150);
    d.endWrite();
}

static void screen_qr(const char *payload, int seconds) {
    auto &d = M5.Display;
    d.startWrite();
    d.fillScreen(TFT_WHITE);
    // The payload is ~277 bytes; M5GFX picks the smallest QR version that fits.
    int size = d.height() - 10;
    d.qrcode(payload, (d.width() - size) / 2, 5, size, 1);
    d.endWrite();
    ESP_LOGI(TAG, "QR shown, valid %d s", seconds);
}

// ---------------------------------------------------------------- store

static wa_store store;

static bool store_load(void) {
    nvs_handle_t h;
    if (nvs_open("wa", NVS_READONLY, &h) != ESP_OK) return false;
    size_t len = sizeof store;
    bool ok = nvs_get_blob(h, "store", &store, &len) == ESP_OK && len == sizeof store &&
              store.version == WA_STORE_VERSION;
    nvs_close(h);
    return ok;
}

static void store_save(void *, const wa_store *s) {
    nvs_handle_t h;
    if (nvs_open("wa", NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_blob(h, "store", s, sizeof *s);
    nvs_commit(h);
    nvs_close(h);
    ESP_LOGI(TAG, "store saved (paired=%d)", s->paired);
}

// ---------------------------------------------------------------- key store

// Signal sessions, sender keys and prekeys, in their own NVS partition.
#define KEYS_PARTITION "wakeys"
static nvs_handle_t keys_nvs;
static bool keys_ok;

static void keys_open(void) {
    esp_err_t err = nvs_flash_init_partition(KEYS_PARTITION);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase_partition(KEYS_PARTITION);
        err = nvs_flash_init_partition(KEYS_PARTITION);
    }
    keys_ok = err == ESP_OK && nvs_open_from_partition(KEYS_PARTITION, "sig", NVS_READWRITE, &keys_nvs) == ESP_OK;
    if (!keys_ok) ESP_LOGE(TAG, "key store unavailable (%s); messages will not decrypt", esp_err_to_name(err));
}

static int kv_get(void *, const char *key, uint8_t *buf, size_t cap) {
    if (!keys_ok) return -1;
    size_t len = 0;
    esp_err_t err = nvs_get_blob(keys_nvs, key, NULL, &len);
    if (err == ESP_ERR_NVS_NOT_FOUND) return 0;
    if (err != ESP_OK) return -1;
    if (len > cap) return (int)len;  // the core treats a size mismatch as "no record"
    err = nvs_get_blob(keys_nvs, key, buf, &len);
    return err == ESP_OK ? (int)len : -1;
}

static int kv_set(void *, const char *key, const uint8_t *data, size_t len) {
    if (!keys_ok || nvs_set_blob(keys_nvs, key, data, len) != ESP_OK) return -1;
    return nvs_commit(keys_nvs) == ESP_OK ? 0 : -1;
}

static int kv_del(void *, const char *key) {
    if (!keys_ok) return -1;
    esp_err_t err = nvs_erase_key(keys_nvs, key);
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) return -1;
    return nvs_commit(keys_nvs) == ESP_OK ? 0 : -1;
}

// Sessions and prekeys belong to one device identity; drop them with it.
static void keys_wipe(void) {
    if (!keys_ok) return;
    nvs_erase_all(keys_nvs);
    nvs_commit(keys_nvs);
    ESP_LOGI(TAG, "key store cleared");
}

// ---------------------------------------------------------------- messages

// The newest messages, drawn newest at the bottom.
#define INBOX 8
struct inbox_line {
    char who[40];
    char text[160];
};
static inbox_line inbox[INBOX];
static int inbox_n;
static char status_line[64];

static void draw_inbox(void) {
    auto &d = M5.Display;
    d.startWrite();
    d.fillScreen(TFT_BLACK);
    d.setTextDatum(top_left);
    d.setFont(&fonts::efontJA_14);  // UTF-8 with Latin, Greek, Cyrillic and CJK glyphs
    d.setTextColor(TFT_GREEN, TFT_BLACK);
    d.drawString(status_line, 4, 2);
    d.drawFastHLine(0, 20, d.width(), TFT_DARKGREY);
    if (inbox_n == 0) {
        d.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
        d.drawString("No messages yet", 4, 30);
    }
    // Lay out from the newest message up until the screen is full.
    int bottom = d.height() - 2, lh = d.fontHeight();
    d.setTextWrap(true, false);
    for (int i = inbox_n - 1; i >= 0 && bottom > 24; i--) {
        const inbox_line &m = inbox[i];
        // Two lines of text at most per message keeps a few on screen.
        int h = lh * (1 + (d.textWidth(m.text) > d.width() - 8 ? 2 : 1));
        int top = bottom - h;
        if (top < 24) break;
        d.setClipRect(0, top, d.width(), h);
        d.setTextColor(TFT_CYAN, TFT_BLACK);
        d.setCursor(4, top);
        d.print(m.who);
        d.setTextColor(TFT_WHITE, TFT_BLACK);
        d.setCursor(4, top + lh);
        d.print(m.text);
        d.clearClipRect();
        bottom = top - 4;
    }
    d.endWrite();
}

static void inbox_add(const wa_message *msg) {
    if (inbox_n == INBOX) {
        memmove(&inbox[0], &inbox[1], sizeof inbox[0] * (INBOX - 1));
        inbox_n--;
    }
    inbox_line &m = inbox[inbox_n++];
    const char *name = msg->from_me ? "me" : msg->push_name;
    char user[32];
    if (!name || !*name) {
        // "15551234567:3@s.whatsapp.net" -> "+15551234567"
        snprintf(user, sizeof user, "+%.*s", (int)strcspn(msg->sender, ":@"), msg->sender);
        name = user;
    }
    snprintf(m.who, sizeof m.who, "%s%s", name, msg->is_group ? " (group)" : "");
    snprintf(m.text, sizeof m.text, "%s", msg->text ? msg->text : "");
    draw_inbox();
}

// ---------------------------------------------------------------- websocket

enum { EV_OPEN, EV_DATA, EV_CLOSE };
struct ws_event {
    int type;
    uint8_t *data;
    size_t len;
};
static QueueHandle_t ws_queue;
static esp_websocket_client_handle_t ws;

static void ws_handler(void *, esp_event_base_t, int32_t id, void *event_data) {
    auto *e = (esp_websocket_event_data_t *)event_data;
    ws_event ev = {};
    switch (id) {
        case WEBSOCKET_EVENT_CONNECTED:
            ev.type = EV_OPEN;
            break;
        case WEBSOCKET_EVENT_DATA:
            // Binary frames and their continuations. The core reassembles
            // WhatsApp frames from the byte stream, so chunks pass straight on.
            if ((e->op_code != 0x2 && e->op_code != 0x0) || e->data_len <= 0) return;
            ev.type = EV_DATA;
            ev.len = e->data_len;
            ev.data = (uint8_t *)malloc(ev.len);
            if (!ev.data) return;
            memcpy(ev.data, e->data_ptr, ev.len);
            break;
        case WEBSOCKET_EVENT_DISCONNECTED:
        case WEBSOCKET_EVENT_CLOSED:
        case WEBSOCKET_EVENT_ERROR:
            ev.type = EV_CLOSE;
            break;
        default:
            return;
    }
    if (xQueueSend(ws_queue, &ev, pdMS_TO_TICKS(1000)) != pdTRUE) free(ev.data);
}

static int ws_send(void *, const uint8_t *data, size_t len) {
    if (!ws || !esp_websocket_client_is_connected(ws)) return -1;
    int w = esp_websocket_client_send_bin(ws, (const char *)data, len, pdMS_TO_TICKS(10000));
    return w == (int)len ? 0 : -1;
}

static void ws_start(void) {
    if (!ws) {
        esp_websocket_client_config_t cfg = {};
        cfg.uri = WA_URL;
        cfg.headers = "Origin: " WA_ORIGIN "\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n";
        cfg.crt_bundle_attach = esp_crt_bundle_attach;
        cfg.buffer_size = 8192;
        cfg.task_stack = 8192;
        cfg.network_timeout_ms = 20000;
        cfg.disable_auto_reconnect = true;  // the main loop decides when to reconnect
        cfg.disable_pingpong_discon = true; // WhatsApp does not answer WebSocket pings
        ws = esp_websocket_client_init(&cfg);
        esp_websocket_register_events(ws, WEBSOCKET_EVENT_ANY, ws_handler, NULL);
    }
    esp_websocket_client_start(ws);
}

static void ws_stop(void) {
    if (ws && esp_websocket_client_is_connected(ws)) esp_websocket_client_close(ws, pdMS_TO_TICKS(2000));
    if (ws) esp_websocket_client_stop(ws);
    // Drop anything still queued from the old connection.
    ws_event ev;
    while (xQueueReceive(ws_queue, &ev, 0) == pdTRUE) free(ev.data);
}

// ---------------------------------------------------------------- wa core

static wa_client client;
static bool want_reconnect;
static int64_t reconnect_at_us;

static void schedule_reconnect(int delay_ms) {
    want_reconnect = true;
    reconnect_at_us = esp_timer_get_time() + (int64_t)delay_ms * 1000;
}

static uint64_t now_ms(void *) { return (uint64_t)(esp_timer_get_time() / 1000); }

static int64_t unix_time(void *) {
    time_t t = time(NULL);
    return t > 1700000000 ? (int64_t)t : 0;  // 0 until SNTP has set the clock
}

static void log_cb(void *, const char *msg) { ESP_LOGI("wa", "%s", msg); }

static void on_event(void *, const wa_event *ev) {
    switch (ev->type) {
        case WA_EV_QR:
            screen_qr(ev->text, ev->seconds);
            break;
        case WA_EV_QR_EXHAUSTED:
            screen("QR expired", "Fetching a new code...");
            schedule_reconnect(500);
            break;
        case WA_EV_PAIRED:
            screen("Linked!", "Finishing login...", nullptr, TFT_GREEN);
            break;
        case WA_EV_PAIR_ERROR:
            screen("Pairing failed", ev->text, nullptr, TFT_RED);
            schedule_reconnect(5000);
            break;
        case WA_EV_LOGGED_IN:
            snprintf(status_line, sizeof status_line, "Online: +%s (device %u)", store.user, store.device);
            draw_inbox();
            break;
        case WA_EV_LOGGED_OUT:
            keys_wipe();
            inbox_n = 0;
            screen("Unlinked", ev->text, "Getting a new QR code...", TFT_ORANGE);
            schedule_reconnect(2000);
            break;
        case WA_EV_MESSAGE:
            if (ev->msg->text) inbox_add(ev->msg);
            break;
        case WA_EV_UNDECRYPTABLE:
            ESP_LOGW(TAG, "undecryptable message from %s: %s", ev->msg->sender, ev->text);
            break;
        case WA_EV_PREKEYS:
            ESP_LOGI(TAG, "uploaded %d prekeys", ev->seconds);
            break;
        case WA_EV_RECONNECT:
            schedule_reconnect(200);
            break;
        case WA_EV_ERROR:
            screen("Connection problem", ev->text, "Retrying...", TFT_ORANGE);
            schedule_reconnect(5000);
            break;
        case WA_EV_NODE:
            break;
    }
}

// ---------------------------------------------------------------- wifi

static EventGroupHandle_t net_events;
#define NET_UP BIT0

static void wifi_handler(void *, esp_event_base_t base, int32_t id, void *) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        xEventGroupClearBits(net_events, NET_UP);
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(net_events, NET_UP);
    }
}

static void wifi_join(const char *ssid, const char *pass) {
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_handler, NULL);
    wifi_config_t wc = {};
    strncpy((char *)wc.sta.ssid, ssid, sizeof wc.sta.ssid);
    strncpy((char *)wc.sta.password, pass, sizeof wc.sta.password);
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_connect();
}

static void start_setup_ap(void) {
    auto &d = M5.Display;
    d.fillScreen(TFT_WHITE);
    // Scanning this joins the open setup network on most phones.
    d.qrcode("WIFI:T:nopass;S:" PROVISION_AP_SSID ";;", 10, 10, 140, 1);
    d.setTextColor(TFT_BLACK, TFT_WHITE);
    d.setTextDatum(top_left);
    d.setFont(&fonts::FreeSans9pt7b);
    d.drawString("WiFi setup", 160, 20);
    d.drawString("1. Join network", 160, 60);
    d.drawString(PROVISION_AP_SSID, 160, 80);
    d.drawString("2. Open", 160, 115);
    d.drawString("192.168.4.1", 160, 135);
    d.drawString("3. Enter your WiFi", 160, 170);
    provision_run();  // never returns
}

// ---------------------------------------------------------------- main

extern "C" void app_main(void) {
    auto cfg = M5.config();
    M5.begin(cfg);  // the Core2's default rotation (0) is landscape
    screen("Muninn Core2", "Starting...");

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    net_events = xEventGroupCreate();

    char ssid[33] = {0}, pass[65] = {0};
    if (!provision_load(ssid, sizeof ssid, pass, sizeof pass)) start_setup_ap();

    screen("Joining WiFi", ssid);
    wifi_join(ssid, pass);
    int64_t deadline = esp_timer_get_time() + 30 * 1000000LL;
    while (!(xEventGroupGetBits(net_events) & NET_UP)) {
        M5.update();
        if (M5.BtnA.pressedFor(3000)) {
            provision_clear();
            esp_restart();
        }
        if (esp_timer_get_time() > deadline) {
            screen("Can't join WiFi", ssid, "hold A 3 s to change network", TFT_ORANGE);
            deadline = INT64_MAX;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    esp_sntp_config_t sntp = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    esp_netif_sntp_init(&sntp);

    // Keys come from the hardware RNG, which is truly random now WiFi is up.
    keys_open();
    if (!store_load()) {
        wa_store_init(&store);
        store_save(NULL, &store);
    }
    if (!store.paired) keys_wipe();  // a new identity starts with no sessions or prekeys

    ws_queue = xQueueCreate(32, sizeof(ws_event));
    wa_callbacks cb = {ws_send, on_event, store_save, now_ms, unix_time, log_cb, NULL, {kv_get, kv_set, kv_del, NULL}};
    wa_client_init(&client, &store, &cb);

    screen("Connecting", "web.whatsapp.com");
    ws_start();

    for (;;) {
        ws_event ev;
        if (xQueueReceive(ws_queue, &ev, pdMS_TO_TICKS(50)) == pdTRUE) {
            switch (ev.type) {
                case EV_OPEN:
                    ESP_LOGI(TAG, "websocket open");
                    wa_client_on_open(&client);
                    break;
                case EV_DATA:
                    wa_client_on_data(&client, ev.data, ev.len);
                    break;
                case EV_CLOSE:
                    ESP_LOGW(TAG, "websocket closed");
                    wa_client_on_close(&client);
                    if (!want_reconnect) schedule_reconnect(3000);
                    break;
            }
            free(ev.data);
        }
        wa_client_tick(&client);

        if (want_reconnect && esp_timer_get_time() >= reconnect_at_us) {
            want_reconnect = false;
            ws_stop();
            wa_client_on_close(&client);
            if (xEventGroupGetBits(net_events) & NET_UP) {
                screen("Connecting", "web.whatsapp.com");
                ws_start();
            } else {
                schedule_reconnect(2000);
            }
        }

        M5.update();
        if (M5.BtnA.pressedFor(3000)) {
            provision_clear();
            esp_restart();
        }
        if (M5.BtnC.pressedFor(5000)) {
            screen("Unlinking...");
            wa_store_init(&store);
            store_save(NULL, &store);
            keys_wipe();
            vTaskDelay(pdMS_TO_TICKS(500));
            esp_restart();
        }
    }
}
