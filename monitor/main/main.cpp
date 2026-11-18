// SPDX-License-Identifier: MIT
// The Core2 as a tiny external monitor. A Mac-side streamer (../mac) sends
// screen rectangles over WiFi (TCP port 5320) or the USB serial port; this
// draws them and sends touches and button presses back.
//
// Wire format, both directions, little-endian:
//   magic(2) type(1) flags(1) length(4) payload(length)
// Host to device uses magic 5A A5, device to host A5 5A. Console log text is
// ASCII, so on the serial port neither side mistakes a log line for a message.
//
// Host to device:
//   'H' hello              -> 'I' info text
//   'R' rect: x y w h (u16) enc (u8) last (u8) seq (u16) data
//        enc 0 raw RGB565 big-endian, 1 the same raw-deflated, 2 JPEG.
//        last=1 ends a frame                                  -> 'A' seq (u16)
//   'S' serial baud (u32)  -> 'S' echo, then the port switches speed
//   'W' WiFi "ssid\tpassword": saved to NVS, then restart
//   'K' keepalive (no reply)
// Device to host:
//   'T' touch: kind (u8: 0 down, 1 move, 2 up) x y (u16)
//   'B' button: index (u8: 0 A, 1 B, 2 C)
#include <M5Unified.h>

#include <string.h>

#include "driver/uart.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "mdns.h"
#include "miniz.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "monitor";

#define W 320
#define H 240
#define PORT 5320
#define MAX_PAYLOAD (W * H * 2 + 64)
#define SERIAL_BAUD 115200

// ---------------------------------------------------------------- links

// A source of host messages: the TCP client or the USB serial port.
struct Link {
    const char *name;
    // Reads exactly n bytes; false on disconnect or timeout.
    bool (*read)(Link *, uint8_t *, size_t, int timeout_ms);
    void (*write)(Link *, const uint8_t *, size_t);
    int sock;
    uint8_t *buf;  // payload buffer, MAX_PAYLOAD bytes
    SemaphoreHandle_t tx_lock;
};

static SemaphoreHandle_t draw_lock;
static Link *volatile active;    // link that most recently sent a frame
static volatile int64_t last_frame_us;
static uint16_t *decode_buf;     // W*H pixels
static char ip_text[32] = "";
static volatile bool splash_dirty = true;

static void send_msg(Link *l, char type, const void *payload, uint32_t len) {
    if (!l) return;
    uint8_t hdr[8] = {0xA5, 0x5A, (uint8_t)type, 0, (uint8_t)len, (uint8_t)(len >> 8), (uint8_t)(len >> 16),
                      (uint8_t)(len >> 24)};
    xSemaphoreTake(l->tx_lock, portMAX_DELAY);
    l->write(l, hdr, 8);
    if (len) l->write(l, (const uint8_t *)payload, len);
    xSemaphoreGive(l->tx_lock);
}

static inline uint16_t u16(const uint8_t *p) { return p[0] | (p[1] << 8); }

static void save_wifi(const char *ssid, const char *pass) {
    nvs_handle_t h;
    if (nvs_open("wifi", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_str(h, "ssid", ssid);
        nvs_set_str(h, "pass", pass);
        nvs_commit(h);
        nvs_close(h);
    }
}

static void draw_rect(const uint8_t *p, uint32_t len) {
    int x = u16(p), y = u16(p + 2), w = u16(p + 4), h = u16(p + 6), enc = p[8];
    const uint8_t *data = p + 12;
    uint32_t dlen = len - 12;
    if (w <= 0 || h <= 0 || x + w > W || y + h > H) return;
    xSemaphoreTake(draw_lock, portMAX_DELAY);
    auto &d = M5.Display;
    if (enc == 0 && dlen >= (uint32_t)w * h * 2) {
        d.pushImage(x, y, w, h, (const lgfx::swap565_t *)data);
    } else if (enc == 1) {
        size_t out = tinfl_decompress_mem_to_mem(decode_buf, (size_t)W * H * 2, data, dlen, 0);
        if (out == (size_t)w * h * 2)
            d.pushImage(x, y, w, h, (const lgfx::swap565_t *)decode_buf);
        else
            ESP_LOGW(TAG, "inflate gave %d bytes, wanted %d", (int)out, w * h * 2);
    } else if (enc == 2) {
        d.drawJpg(data, dlen, x, y, w, h);
    }
    xSemaphoreGive(draw_lock);
}

// Parses messages from one link until it fails. Returns when the link drops.
static void serve(Link *l, int idle_timeout_ms) {
    uint8_t hdr[8];
    for (;;) {
        // Resynchronise on the magic: skip bytes until 5A A5.
        if (!l->read(l, hdr, 1, idle_timeout_ms)) return;
        if (hdr[0] != 0x5A) continue;
        if (!l->read(l, hdr + 1, 1, 200)) return;
        if (hdr[1] != 0xA5) continue;
        if (!l->read(l, hdr + 2, 6, 200)) return;
        uint32_t len = hdr[4] | (hdr[5] << 8) | (hdr[6] << 16) | ((uint32_t)hdr[7] << 24);
        if (len > MAX_PAYLOAD) continue;
        if (len && !l->read(l, l->buf, len, 2000)) return;
        if (active == l) last_frame_us = esp_timer_get_time();  // keepalives count
        switch (hdr[2]) {
            case 'H': {
                char info[96];
                int n = snprintf(info, sizeof info, "m5mon 1 %dx%d ip=%s", W, H, ip_text[0] ? ip_text : "-");
                send_msg(l, 'I', info, n);
                break;
            }
            case 'R':
                if (len < 12) break;
                if (active != l) {
                    active = l;
                    ESP_LOGI(TAG, "streaming from %s", l->name);
                }
                last_frame_us = esp_timer_get_time();
                draw_rect(l->buf, len);
                if (l->buf[9]) send_msg(l, 'A', l->buf + 10, 2);
                break;
            case 'W': {
                l->buf[len] = 0;
                char *tab = strchr((char *)l->buf, '\t');
                if (!tab || tab == (char *)l->buf || tab - (char *)l->buf > 32 || strlen(tab + 1) > 64) break;
                *tab = 0;
                save_wifi((char *)l->buf, tab + 1);
                send_msg(l, 'W', NULL, 0);
                vTaskDelay(pdMS_TO_TICKS(300));
                esp_restart();
                break;
            }
            case 'S':
                if (len == 4 && l->sock < 0) {
                    uint32_t baud = u16(l->buf) | ((uint32_t)u16(l->buf + 2) << 16);
                    send_msg(l, 'S', l->buf, 4);
                    uart_wait_tx_done(UART_NUM_0, pdMS_TO_TICKS(100));
                    // Log text in the middle of a frame would break it.
                    esp_log_level_set("*", ESP_LOG_NONE);
                    uart_set_baudrate(UART_NUM_0, baud);
                }
                break;
            default:
                break;
        }
    }
}

// ---------------------------------------------------------------- serial

static bool uart_rd(Link *, uint8_t *p, size_t n, int timeout_ms) {
    while (n) {
        int r = uart_read_bytes(UART_NUM_0, p, n, pdMS_TO_TICKS(timeout_ms));
        if (r <= 0) return false;
        p += r, n -= r;
    }
    return true;
}
static void uart_wr(Link *, const uint8_t *p, size_t n) { uart_write_bytes(UART_NUM_0, p, n); }

static void serial_task(void *arg) {
    Link *l = (Link *)arg;
    uart_driver_install(UART_NUM_0, 32768, 4096, 0, NULL, 0);
    for (;;) {
        serve(l, 3000);
        // Nothing for 3 s: drop back to the boot speed so a newly started
        // host (or idf.py monitor) can talk to us again.
        uint32_t baud = 0;
        uart_get_baudrate(UART_NUM_0, &baud);
        if (baud > SERIAL_BAUD * 11 / 10) {  // the driver reports 115200 as 115201 or so
            uart_set_baudrate(UART_NUM_0, SERIAL_BAUD);
            esp_log_level_set("*", ESP_LOG_INFO);
            ESP_LOGI(TAG, "serial idle, back to %d baud", SERIAL_BAUD);
        }
        if (active == l) { active = NULL; splash_dirty = true; }
    }
}

// ---------------------------------------------------------------- tcp

static bool tcp_rd(Link *l, uint8_t *p, size_t n, int timeout_ms) {
    struct timeval tv = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
    setsockopt(l->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    while (n) {
        int r = recv(l->sock, p, n, 0);
        if (r <= 0) return false;
        p += r, n -= r;
    }
    return true;
}
static void tcp_wr(Link *l, const uint8_t *p, size_t n) {
    while (n) {
        int r = send(l->sock, p, n, 0);
        if (r <= 0) return;
        p += r, n -= r;
    }
}

static void tcp_task(void *arg) {
    Link *l = (Link *)arg;
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT);
    bind(srv, (struct sockaddr *)&a, sizeof a);
    listen(srv, 1);
    for (;;) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) continue;
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        ESP_LOGI(TAG, "tcp client connected");
        l->sock = c;
        serve(l, 10000);
        l->sock = -1;
        close(c);
        ESP_LOGI(TAG, "tcp client gone");
        if (active == l) { active = NULL; splash_dirty = true; }
    }
}

// ---------------------------------------------------------------- wifi

static void wifi_handler(void *, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (ip_text[0]) { ip_text[0] = 0; splash_dirty = true; }
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        auto *e = (ip_event_got_ip_t *)data;
        snprintf(ip_text, sizeof ip_text, IPSTR, IP2STR(&e->ip_info.ip));
        ESP_LOGI(TAG, "ip %s", ip_text);
        splash_dirty = true;
    }
}

static bool wifi_start(void) {
    char ssid[33] = {0}, pass[65] = {0};
    nvs_handle_t h;
    if (nvs_open("wifi", NVS_READONLY, &h) != ESP_OK) return false;
    size_t a = sizeof ssid, b = sizeof pass;
    bool ok = nvs_get_str(h, "ssid", ssid, &a) == ESP_OK && nvs_get_str(h, "pass", pass, &b) == ESP_OK && ssid[0];
    nvs_close(h);
    if (!ok) return false;

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
    esp_wifi_set_ps(WIFI_PS_NONE);  // power save adds ~100 ms latency per frame
    esp_wifi_connect();

    mdns_init();
    mdns_hostname_set("m5mon");
    mdns_instance_name_set("Core2 monitor");
    mdns_service_add(NULL, "_m5mon", "_tcp", PORT, NULL, 0);
    return true;
}

// ---------------------------------------------------------------- screen

static bool have_wifi;

static void draw_splash(void) {
    xSemaphoreTake(draw_lock, portMAX_DELAY);
    auto &d = M5.Display;
    d.fillScreen(TFT_BLACK);
    // A little monitor: bezel, screen, stand.
    d.fillRoundRect(110, 22, 100, 70, 6, 0x4208);
    d.fillRect(117, 29, 86, 54, 0x2B5F);
    d.fillRect(150, 92, 20, 12, 0x4208);
    d.fillRoundRect(135, 102, 50, 6, 3, 0x4208);
    d.setTextColor(TFT_WHITE, TFT_BLACK);
    d.setTextDatum(top_center);
    d.setFont(&fonts::FreeSansBold12pt7b);
    d.drawString("m5mon", W / 2, 120);
    d.setFont(&fonts::FreeSans9pt7b);
    d.setTextColor(0xBDF7, TFT_BLACK);
    d.drawString("320 x 240, waiting for the Mac", W / 2, 152);
    char line[64];
    if (ip_text[0])
        snprintf(line, sizeof line, "WiFi: m5mon.local  %s", ip_text);
    else
        snprintf(line, sizeof line, have_wifi ? "WiFi: joining..." : "WiFi: not set up");
    d.drawString(line, W / 2, 180);
    d.drawString("USB: plugged-in serial works too", W / 2, 202);
    xSemaphoreGive(draw_lock);
}

// ---------------------------------------------------------------- main

static Link *make_link(const char *name, bool (*rd)(Link *, uint8_t *, size_t, int),
                       void (*wr)(Link *, const uint8_t *, size_t)) {
    Link *l = (Link *)calloc(1, sizeof(Link));
    l->name = name;
    l->read = rd;
    l->write = wr;
    l->sock = -1;
    l->buf = (uint8_t *)heap_caps_malloc(MAX_PAYLOAD + 1, MALLOC_CAP_SPIRAM);
    l->tx_lock = xSemaphoreCreateMutex();
    return l;
}

extern "C" void app_main(void) {
    auto cfg = M5.config();
    M5.begin(cfg);  // the Core2's default rotation is landscape
    M5.Display.setBrightness(160);
    draw_lock = xSemaphoreCreateMutex();
    decode_buf = (uint16_t *)heap_caps_malloc(W * H * 2, MALLOC_CAP_SPIRAM);

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    have_wifi = wifi_start();

    // inflate keeps an ~11 KB decompressor on the stack.
    xTaskCreatePinnedToCore(serial_task, "serial", 20480, make_link("usb", uart_rd, uart_wr), 5, NULL, 1);
    if (have_wifi)
        xTaskCreatePinnedToCore(tcp_task, "tcp", 20480, make_link("wifi", tcp_rd, tcp_wr), 5, NULL, 1);

    bool down = false;
    int lx = -1, ly = -1;
    int64_t last_move = 0;
    for (;;) {
        M5.update();
        Link *l = active;
        if (!l && splash_dirty) {
            splash_dirty = false;
            draw_splash();
        }
        if (l && esp_timer_get_time() - last_frame_us > 15 * 1000000LL) {
            active = NULL;  // host went quiet without disconnecting
            splash_dirty = true;
        }
        // The panel's touch area runs below the screen (y >= 240), where the
        // three circles are buttons A, B and C; M5Unified reports those as
        // BtnA..C, so only touches on the screen itself become pointer events.
        auto t = M5.Touch.getDetail();
        bool on_screen = t.isPressed() && t.y >= 0 && t.y < H;
        if (l) {
            uint8_t p[5];
            int64_t now = esp_timer_get_time();
            if (on_screen && !down) {
                down = true;
                lx = t.x, ly = t.y;
                p[0] = 0, p[1] = lx, p[2] = lx >> 8, p[3] = ly, p[4] = ly >> 8;
                send_msg(l, 'T', p, 5);
            } else if (on_screen && down && (t.x != lx || t.y != ly) && now - last_move > 25000) {
                lx = t.x, ly = t.y, last_move = now;
                p[0] = 1, p[1] = lx, p[2] = lx >> 8, p[3] = ly, p[4] = ly >> 8;
                send_msg(l, 'T', p, 5);
            } else if (!on_screen && down) {
                down = false;
                p[0] = 2, p[1] = lx, p[2] = lx >> 8, p[3] = ly, p[4] = ly >> 8;
                send_msg(l, 'T', p, 5);
            }
            uint8_t b;
            if (M5.BtnA.wasPressed()) b = 0, send_msg(l, 'B', &b, 1);
            if (M5.BtnB.wasPressed()) b = 1, send_msg(l, 'B', &b, 1);
            if (M5.BtnC.wasPressed()) b = 2, send_msg(l, 'B', &b, 1);
        } else {
            down = false;
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}
