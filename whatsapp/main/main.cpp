// SPDX-License-Identifier: MIT
// Core2 firmware: joins WiFi, connects to WhatsApp, shows the pairing QR code
// on screen, stays online as a linked device, and shows incoming messages.
// It is also Claude's WhatsApp connection: what Oskar writes in one bound
// chat goes to the muninn-pager worker, and the worker's replies are posted
// back in that chat (see "bot" below).
//
// Threads: the WebSocket clients deliver events on their own tasks; they go
// through queues to the main loop, which is the only caller of the wa core.
//
// Buttons (the three touch circles under the screen):
//   hold A 3 s  forget WiFi and start the setup access point
//   hold C 5 s  unlink: forget the WhatsApp pairing and show a new QR code
#include <M5Unified.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "esp_crt_bundle.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_timer.h"
#include "esp_websocket_client.h"
#include "esp_wifi.h"
#include "cJSON.h"
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

static wa_client client;

// Bot state shown on the status line (the bot section is further down).
static char bot_chat[48];  // the bound chat, "" when unbound
static bool bot_up;        // connected to the worker
static bool bot_enabled;   // built with a device key

// The newest messages, drawn newest at the bottom.
#define INBOX 8
struct inbox_line {
    char who[40];
    char text[160];
    char chat[48];     // where a reply goes
    int top, bottom;   // where it was last drawn, for taps; -1 when off screen
};
static inbox_line inbox[INBOX];
static int inbox_n;
static char status_line[64];
static char note[64];  // a passing notice in place of the status line
static int64_t note_until_us;

static void set_note(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void set_note(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(note, sizeof note, fmt, ap);
    va_end(ap);
    note_until_us = esp_timer_get_time() + 6 * 1000000LL;
}

static void draw_inbox(void) {
    auto &d = M5.Display;
    d.startWrite();
    d.fillScreen(TFT_BLACK);
    d.setTextDatum(top_left);
    d.setFont(&fonts::efontJA_14);  // UTF-8 with Latin, Greek, Cyrillic and CJK glyphs
    bool noting = note[0] && esp_timer_get_time() < note_until_us;
    d.setTextColor(noting ? TFT_ORANGE : TFT_GREEN, TFT_BLACK);
    d.drawString(noting ? note : status_line, 4, 2);
    if (!noting) {
        const char *b = !bot_enabled ? "Claude: no key" : !bot_chat[0] ? "Claude: unbound" : bot_up ? "Claude: on" : "Claude: offline";
        d.setTextDatum(top_right);
        d.setTextColor(bot_up && bot_chat[0] ? TFT_CYAN : TFT_DARKGREY, TFT_BLACK);
        d.drawString(b, d.width() - 4, 2);
        d.setTextDatum(top_left);
    }
    d.drawFastHLine(0, 20, d.width(), TFT_DARKGREY);
    if (inbox_n == 0) {
        d.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
        d.drawString("No messages yet", 4, 30);
    }
    // Lay out from the newest message up until the screen is full.
    int bottom = d.height() - 2, lh = d.fontHeight();
    d.setTextWrap(true, false);
    for (int i = 0; i < inbox_n; i++) inbox[i].top = inbox[i].bottom = -1;
    for (int i = inbox_n - 1; i >= 0 && bottom > 24; i--) {
        inbox_line &m = inbox[i];
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
        m.top = top;
        m.bottom = bottom;
        bottom = top - 4;
    }
    d.endWrite();
}

static inbox_line *inbox_push(void) {
    if (inbox_n == INBOX) {
        memmove(&inbox[0], &inbox[1], sizeof inbox[0] * (INBOX - 1));
        inbox_n--;
    }
    inbox_line *m = &inbox[inbox_n++];
    memset(m, 0, sizeof *m);
    return m;
}

// The name to show for a chat we only know by JID: "+15551234567", or the LID.
static void chat_name(const char *jid, char *out, size_t n) {
    bool pn = strstr(jid, "@s.whatsapp.net") != NULL;
    snprintf(out, n, "%s%.*s", pn ? "+" : "", (int)strcspn(jid, ":@"), jid);
}

static void inbox_add(const wa_message *msg) {
    inbox_line &m = *inbox_push();
    const char *name = msg->from_me ? "me" : msg->push_name;
    char user[32];
    if (!name || !*name) {
        chat_name(msg->sender, user, sizeof user);
        name = user;
    }
    snprintf(m.who, sizeof m.who, "%s%s", name, msg->is_group ? " (group)" : "");
    snprintf(m.text, sizeof m.text, "%s", msg->text ? msg->text : "");
    snprintf(m.chat, sizeof m.chat, "%s", msg->chat);
    draw_inbox();
}

// ---------------------------------------------------------------- replies

// Tap a message (or press B for the newest one from someone else) to reply
// with one of three canned answers on buttons A, B and C.
static const char *const REPLIES[3] = {"OK", "Thanks!", "On my way"};
static bool replying;
static int64_t reply_until_us;
static char reply_chat[48], reply_who[40], reply_quote[160];
static char sending_text[40], sending_who[40];  // the reply in flight
static bool sending;
static bool sending_for_bot;  // the send in flight is the bot's, not a canned reply
static void bot_on_sent(void);
static void bot_on_send_failed(const char *why);

static void draw_reply(void) {
    auto &d = M5.Display;
    d.startWrite();
    d.fillScreen(TFT_BLACK);
    d.setFont(&fonts::efontJA_14);
    d.setTextDatum(top_left);
    d.setTextColor(TFT_GREEN, TFT_BLACK);
    d.drawString("Reply to", 4, 4);
    d.setTextColor(TFT_CYAN, TFT_BLACK);
    d.drawString(reply_who, 4 + d.textWidth("Reply to "), 4);
    d.setTextColor(TFT_LIGHTGREY, TFT_BLACK);
    d.setTextWrap(true, false);
    d.setClipRect(0, 26, d.width(), 120);
    d.setCursor(4, 30);
    d.print(reply_quote);
    d.clearClipRect();
    // Labels over the Core2's three touch buttons (centred at x = 1/6, 1/2, 5/6).
    d.setTextDatum(bottom_center);
    for (int i = 0; i < 3; i++) {
        int x = d.width() * (2 * i + 1) / 6;
        d.fillRoundRect(x - 50, d.height() - 44, 100, 38, 6, TFT_DARKGREEN);
        d.setTextColor(TFT_WHITE, TFT_DARKGREEN);
        d.drawString(REPLIES[i], x, d.height() - 16);
    }
    d.endWrite();
}

static void reply_open(const inbox_line &m) {
    if (strstr(m.chat, "@broadcast")) {
        set_note("Can't reply to broadcasts");
        draw_inbox();
        return;
    }
    snprintf(reply_chat, sizeof reply_chat, "%s", m.chat);
    if (strcmp(m.who, "me") == 0)
        chat_name(m.chat, reply_who, sizeof reply_who);
    else
        snprintf(reply_who, sizeof reply_who, "%s", m.who);
    snprintf(reply_quote, sizeof reply_quote, "%s", m.text);
    replying = true;
    reply_until_us = esp_timer_get_time() + 15 * 1000000LL;
    draw_reply();
}

static void reply_close(void) {
    replying = false;
    draw_inbox();
}

static void reply_send(int choice) {
    replying = false;
    if (sending) {
        set_note("Still sending the last reply");
    } else if (!wa_client_send_text(&client, reply_chat, REPLIES[choice])) {
        set_note("Not connected; reply not sent");
    } else {
        sending = true;
        sending_for_bot = false;
        snprintf(sending_text, sizeof sending_text, "%s", REPLIES[choice]);
        snprintf(sending_who, sizeof sending_who, "%s", reply_who);
        set_note("Sending \"%s\"...", REPLIES[choice]);
    }
    draw_inbox();
}

static void on_sent(void) {
    sending = false;
    if (sending_for_bot) return bot_on_sent();
    inbox_line &m = *inbox_push();
    snprintf(m.who, sizeof m.who, "me to %.33s", sending_who);  // who[40]: "me to " + 33
    snprintf(m.text, sizeof m.text, "%s", sending_text);
    snprintf(m.chat, sizeof m.chat, "%s", reply_chat);
    note[0] = 0;
    draw_inbox();
}

static void on_send_failed(const char *why) {
    sending = false;
    if (sending_for_bot) return bot_on_send_failed(why);
    set_note("Not sent: %s", why);
    draw_inbox();
}

// Buttons and taps while the inbox is up. Returns after at most one action.
static void reply_input(void) {
    if (replying) {
        if (M5.BtnA.wasClicked()) return reply_send(0);
        if (M5.BtnB.wasClicked()) return reply_send(1);
        if (M5.BtnC.wasClicked()) return reply_send(2);
        auto t = M5.Touch.getDetail();
        if ((t.wasClicked() && t.y < M5.Display.height()) || esp_timer_get_time() > reply_until_us)
            return reply_close();
        return;
    }
    if (!client.logged_in) return;
    if (M5.BtnB.wasClicked()) {
        for (int i = inbox_n - 1; i >= 0; i--)
            if (strcmp(inbox[i].who, "me") != 0 && strncmp(inbox[i].who, "me to ", 6) != 0)
                return reply_open(inbox[i]);
        if (inbox_n) return reply_open(inbox[inbox_n - 1]);
        set_note("No message to reply to");
        return draw_inbox();
    }
    auto t = M5.Touch.getDetail();
    if (t.wasClicked() && t.y < M5.Display.height()) {
        for (int i = 0; i < inbox_n; i++)
            if (inbox[i].top >= 0 && t.y >= inbox[i].top && t.y <= inbox[i].bottom) return reply_open(inbox[i]);
    }
    if (note[0] && esp_timer_get_time() >= note_until_us) {
        note[0] = 0;
        draw_inbox();
    }
}

// ---------------------------------------------------------------- bot

// The Core2 as Claude's WhatsApp connection. The account is Oskar's own, so
// the bot acts in one chat only: the one where Oskar sent "@claude bind" from
// his own phone. In that chat, every text he writes goes to the muninn-pager
// worker as {type: "wa_message"}, and the worker fires the bot's Claude Code
// task. Replies come back as {type: "wa_send"} and are posted in that same
// chat, prefixed with a robot, and confirmed with {type: "wa_sent"}. Nothing
// the worker sends can reach any other chat. Messages from anyone else, and
// messages older than BOT_MAX_AGE_S (a backlog after the Core2 was off), are
// shown but not forwarded.
//
// The worker's device key is compiled in from main/bot_key.txt (gitignored);
// without that file the bot stays off.
#define BOT_URL "wss://muninn-pager.austegard.workers.dev/ws"
#define BOT_PREFIX "\xF0\x9F\xA4\x96 "  // U+1F916 robot face and a space
#define BOT_MAX_AGE_S (30 * 60)
#define BOT_OUTQ 8
#define BOT_INQ 4

static int64_t unix_time(void *);

#ifdef HAVE_BOT_KEY
extern const char bot_key_txt[] asm("_binary_bot_key_txt_start");
#endif

enum { BOT_OPEN, BOT_TEXT, BOT_CLOSE };
struct bot_event {
    int type;
    char *text;
};
static QueueHandle_t bot_queue;
static esp_websocket_client_handle_t bot_ws;
static char bot_headers[128];

// To post in the bound chat: replies from the worker (id set) and the bot's
// own notices (id empty).
struct bot_out {
    char id[16];
    char chat[48];
    char *text;
};
static bot_out bot_outq[BOT_OUTQ];
static int bot_outq_n;
static char bot_sent_ids[8][16];  // recently posted, in case the worker sends one again
static int bot_sent_next;
static int64_t bot_retry_at_us;

// Messages for the worker while it is unreachable.
struct bot_in {
    char id[32];
    char *text;
};
static bot_in bot_inq[BOT_INQ];
static int bot_inq_n;

static void bot_ws_handler(void *, esp_event_base_t, int32_t id, void *event_data) {
    auto *e = (esp_websocket_event_data_t *)event_data;
    static char *buf;  // a text frame larger than the client's buffer arrives in pieces
    bot_event ev = {};
    switch (id) {
        case WEBSOCKET_EVENT_CONNECTED:
            ev.type = BOT_OPEN;
            break;
        case WEBSOCKET_EVENT_DATA:
            if (e->op_code != 0x1 || e->payload_len <= 0 || e->payload_len > 16384) return;
            if (e->payload_offset == 0) {
                free(buf);
                buf = (char *)malloc(e->payload_len + 1);
            }
            if (!buf || e->payload_offset + e->data_len > e->payload_len) return;
            memcpy(buf + e->payload_offset, e->data_ptr, e->data_len);
            if (e->payload_offset + e->data_len < e->payload_len) return;
            buf[e->payload_len] = 0;
            ev.type = BOT_TEXT;
            ev.text = buf;
            buf = NULL;
            break;
        case WEBSOCKET_EVENT_DISCONNECTED:
        case WEBSOCKET_EVENT_CLOSED:
        case WEBSOCKET_EVENT_ERROR:
            ev.type = BOT_CLOSE;
            break;
        default:
            return;
    }
    if (xQueueSend(bot_queue, &ev, pdMS_TO_TICKS(100)) != pdTRUE) free(ev.text);
}

static void bot_load(void) {
    nvs_handle_t h;
    if (nvs_open("bot", NVS_READONLY, &h) != ESP_OK) return;
    size_t len = sizeof bot_chat;
    if (nvs_get_str(h, "chat", bot_chat, &len) != ESP_OK) bot_chat[0] = 0;
    nvs_close(h);
}

static void bot_save(void) {
    nvs_handle_t h;
    if (nvs_open("bot", NVS_READWRITE, &h) != ESP_OK) return;
    if (bot_chat[0])
        nvs_set_str(h, "chat", bot_chat);
    else
        nvs_erase_key(h, "chat");
    nvs_commit(h);
    nvs_close(h);
}

static void bot_start(void) {
#ifdef HAVE_BOT_KEY
    char key[96];
    snprintf(key, sizeof key, "%s", bot_key_txt);
    key[strcspn(key, " \r\n\t")] = 0;
    bot_enabled = key[0] != 0;
    if (!bot_enabled) return;
    snprintf(bot_headers, sizeof bot_headers, "Authorization: Bearer %s\r\n", key);
    memset(key, 0, sizeof key);
    bot_queue = xQueueCreate(16, sizeof(bot_event));
    esp_websocket_client_config_t cfg = {};
    cfg.uri = BOT_URL;
    cfg.headers = bot_headers;
    cfg.crt_bundle_attach = esp_crt_bundle_attach;
    cfg.buffer_size = 4096;
    cfg.task_stack = 6144;
    cfg.network_timeout_ms = 20000;
    cfg.reconnect_timeout_ms = 10000;
    cfg.ping_interval_sec = 30;
    bot_ws = esp_websocket_client_init(&cfg);
    esp_websocket_register_events(bot_ws, WEBSOCKET_EVENT_ANY, bot_ws_handler, NULL);
    esp_websocket_client_start(bot_ws);
#endif
}

static bool bot_send_json(cJSON *o) {
    bool ok = false;
    char *s = cJSON_PrintUnformatted(o);
    if (s && bot_ws && esp_websocket_client_is_connected(bot_ws))
        ok = esp_websocket_client_send_text(bot_ws, s, strlen(s), pdMS_TO_TICKS(5000)) >= 0;
    free(s);
    cJSON_Delete(o);
    return ok;
}

static void bot_report(const char *type, const char *id, const char *error) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "type", type);
    cJSON_AddStringToObject(o, "id", id);
    if (error) cJSON_AddStringToObject(o, "error", error);
    bot_send_json(o);
}

static bool bot_forward(const char *id, const char *text) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "type", "wa_message");
    cJSON_AddStringToObject(o, "id", id);
    cJSON_AddStringToObject(o, "text", text);
    return bot_send_json(o);
}

// Queue text for chat (a reply when id is set, else a notice).
static void bot_post(const char *id, const char *chat, const char *text) {
    if (!chat[0]) return;
    for (int i = 0; id[0] && i < bot_outq_n; i++)
        if (strcmp(bot_outq[i].id, id) == 0) return;  // already queued
    for (int i = 0; id[0] && i < 8; i++)
        if (strcmp(bot_sent_ids[i], id) == 0) return bot_report("wa_sent", id, NULL);  // posted; our ack was lost
    if (bot_outq_n == BOT_OUTQ) {
        if (id[0]) bot_report("wa_failed", id, "Core2 queue full");
        return;
    }
    char *t = (char *)malloc(strlen(BOT_PREFIX) + strlen(text) + 1);
    if (!t) return;
    strcpy(t, BOT_PREFIX);
    strcat(t, text);
    bot_out &o = bot_outq[bot_outq_n++];
    snprintf(o.id, sizeof o.id, "%s", id);
    snprintf(o.chat, sizeof o.chat, "%s", chat);
    o.text = t;
}

static void bot_pop(void) {
    free(bot_outq[0].text);
    memmove(&bot_outq[0], &bot_outq[1], sizeof bot_outq[0] * (BOT_OUTQ - 1));
    bot_outq_n--;
}

static void bot_on_sent(void) {
    if (!bot_outq_n) return;
    bot_out &o = bot_outq[0];
    if (o.id[0]) {
        bot_report("wa_sent", o.id, NULL);
        snprintf(bot_sent_ids[bot_sent_next++ % 8], sizeof bot_sent_ids[0], "%s", o.id);
    }
    inbox_line &m = *inbox_push();
    snprintf(m.who, sizeof m.who, "Claude");
    snprintf(m.text, sizeof m.text, "%s", o.text + strlen(BOT_PREFIX));
    snprintf(m.chat, sizeof m.chat, "%s", o.chat);
    bot_pop();
    if (!replying) draw_inbox();
}

static void bot_on_send_failed(const char *why) {
    if (!bot_outq_n) return;
    if (bot_outq[0].id[0]) bot_report("wa_failed", bot_outq[0].id, why);
    set_note("Claude's reply not sent: %s", why);
    bot_pop();
    if (!replying) draw_inbox();
}

static bool bot_cmd(const char *text, const char *cmd) {
    while (*text == ' ' || *text == '\n') text++;
    size_t n = strlen(cmd);
    if (strncasecmp(text, cmd, n) != 0) return false;
    for (text += n; *text; text++)
        if (*text != ' ' && *text != '\n') return false;
    return true;
}

// Every message the wa core decrypts passes through here.
static void bot_on_message(const wa_message *msg) {
    if (!bot_enabled || !msg->from_me || !msg->text || !msg->kind || strcmp(msg->kind, "text") != 0) return;
    if (bot_cmd(msg->text, "@claude bind")) {
        snprintf(bot_chat, sizeof bot_chat, "%s", msg->chat);
        bot_save();
        bot_post("", bot_chat, "Bound. What you write in this chat now goes to Claude. Send @claude unbind to stop.");
        set_note("Claude bound to this chat");
        return;
    }
    if (!bot_chat[0] || strcmp(msg->chat, bot_chat) != 0) return;
    if (bot_cmd(msg->text, "@claude unbind")) {
        bot_post("", bot_chat, "Unbound. Claude no longer reads this chat.");
        bot_chat[0] = 0;
        bot_save();
        set_note("Claude unbound");
        return;
    }
    if (strncmp(msg->text, BOT_PREFIX, strlen(BOT_PREFIX)) == 0) return;  // one of ours
    int64_t now = unix_time(NULL);
    if (now && msg->timestamp && now - msg->timestamp > BOT_MAX_AGE_S) {
        ESP_LOGI(TAG, "bot: not forwarding %s, %lld s old", msg->id, (long long)(now - msg->timestamp));
        return;
    }
    if (bot_up && bot_forward(msg->id, msg->text)) return;
    if (bot_inq_n == BOT_INQ) {
        bot_post("", bot_chat, "The Core2 can't reach Claude right now; this message was not delivered.");
        return;
    }
    bot_in &q = bot_inq[bot_inq_n];
    q.text = strdup(msg->text);
    if (!q.text) return;
    snprintf(q.id, sizeof q.id, "%s", msg->id);
    bot_inq_n++;
}

static void bot_on_text(const char *text) {
    cJSON *o = cJSON_Parse(text);
    if (!o) return;  // e.g. "pong"
    const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(o, "type"));
    const char *id = cJSON_GetStringValue(cJSON_GetObjectItem(o, "id"));
    const char *t = cJSON_GetStringValue(cJSON_GetObjectItem(o, "text"));
    if (!type) {
    } else if (strcmp(type, "wa_send") == 0 && id && t) {
        if (bot_chat[0])
            bot_post(id, bot_chat, t);
        else
            bot_report("wa_failed", id, "no chat is bound on the Core2");
    } else if (strcmp(type, "state") == 0) {
        const char *st = cJSON_GetStringValue(cJSON_GetObjectItem(o, "state"));
        if (st && strcmp(st, "idle") != 0 && t && t[0]) {
            set_note("Claude %s: %.40s", st, t);
            if (!replying) draw_inbox();
        }
    } else if (strcmp(type, "ack") == 0) {
        cJSON *fired = cJSON_GetObjectItem(o, "fired");
        const char *reason = cJSON_GetStringValue(cJSON_GetObjectItem(o, "reason"));
        if (fired && cJSON_IsFalse(fired) && reason && strcmp(reason, "duplicate") != 0) {
            set_note("Claude not reached: %s", reason);
            if (!replying) draw_inbox();
        }
    }
    cJSON_Delete(o);
}

// From the main loop: worker events, the waiting queue, the next post.
static void bot_poll(void) {
    if (!bot_queue) return;
    bot_event ev;
    while (xQueueReceive(bot_queue, &ev, 0) == pdTRUE) {
        switch (ev.type) {
            case BOT_OPEN:
                ESP_LOGI(TAG, "bot: connected to the worker");
                bot_up = true;
                if (!replying) draw_inbox();
                break;
            case BOT_CLOSE:
                if (bot_up) {
                    ESP_LOGW(TAG, "bot: disconnected from the worker");
                    bot_up = false;
                    if (!replying) draw_inbox();
                }
                break;
            case BOT_TEXT:
                bot_on_text(ev.text);
                break;
        }
        free(ev.text);
    }
    while (bot_up && bot_inq_n && bot_forward(bot_inq[0].id, bot_inq[0].text)) {
        free(bot_inq[0].text);
        memmove(&bot_inq[0], &bot_inq[1], sizeof bot_inq[0] * (BOT_INQ - 1));
        bot_inq_n--;
    }
    if (sending || !bot_outq_n || !client.logged_in || esp_timer_get_time() < bot_retry_at_us) return;
    if (wa_client_send_text(&client, bot_outq[0].chat, bot_outq[0].text)) {
        sending = true;
        sending_for_bot = true;
    } else {
        bot_retry_at_us = esp_timer_get_time() + 2000000;  // not connected or the chat is not sendable
    }
}

// ---------------------------------------------------------------- websocket

enum { EV_OPEN, EV_DATA, EV_CLOSE };
struct ws_event {
    int type;
    uint8_t *data;
    size_t len;
};
static QueueHandle_t ws_queue;
static volatile bool ws_stopping;  // ws_stop() is draining: don't block the WebSocket task
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
    // Never drop a data chunk: a missing chunk desyncs the WhatsApp frame stream for
    // the rest of the connection. Block the WebSocket task until app_main catches up.
    if (xQueueSend(ws_queue, &ev, ev.type == EV_DATA && !ws_stopping ? portMAX_DELAY : pdMS_TO_TICKS(100)) != pdTRUE) free(ev.data);
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
        // No WebSocket-level pings: the server's PONG reaches WEBSOCKET_EVENT_DATA as
        // raw frame bytes (8a 00) tagged op_code 2, which desyncs the WhatsApp frame
        // stream. The core's own <iq xmlns="w:p"> keepalive holds the connection open.
        cfg.ping_interval_sec = 7 * 24 * 3600;
        ws = esp_websocket_client_init(&cfg);
        esp_websocket_register_events(ws, WEBSOCKET_EVENT_ANY, ws_handler, NULL);
    }
    esp_websocket_client_start(ws);
}

static void ws_stop(void) {
    ws_stopping = true;
    ws_event ev;
    while (xQueueReceive(ws_queue, &ev, 0) == pdTRUE) free(ev.data);  // unblock the WebSocket task
    if (ws && esp_websocket_client_is_connected(ws)) esp_websocket_client_close(ws, pdMS_TO_TICKS(2000));
    if (ws) esp_websocket_client_stop(ws);
    // Drop anything still queued from the old connection.
    while (xQueueReceive(ws_queue, &ev, 0) == pdTRUE) free(ev.data);
    ws_stopping = false;
}

// ---------------------------------------------------------------- wa core

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
            snprintf(status_line, sizeof status_line, "Online +%s", store.user);  // the right side shows the bot
            draw_inbox();
            break;
        case WA_EV_LOGGED_OUT:
            keys_wipe();
            inbox_n = 0;
            screen("Unlinked", ev->text, "Getting a new QR code...", TFT_ORANGE);
            schedule_reconnect(2000);
            break;
        case WA_EV_MESSAGE:
            if (ev->msg->text) {
                inbox_add(ev->msg);
                if (replying) draw_reply();  // keep the reply screen up
            }
            bot_on_message(ev->msg);
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
        case WA_EV_SENT:
            on_sent();
            break;
        case WA_EV_SEND_FAILED:
            on_send_failed(ev->text);
            break;
        case WA_EV_NODE:
            break;
    }
}

// ---------------------------------------------------------------- wifi

static EventGroupHandle_t net_events;
#define NET_UP BIT0

static volatile int wifi_reason;  // last disconnect reason, 0 if none yet

// What a disconnect reason means for the person holding the device.
static const char *wifi_reason_text(int r) {
    switch (r) {
        case WIFI_REASON_NO_AP_FOUND:
            return "network not found (2.4 GHz only)";
        case WIFI_REASON_AUTH_FAIL:
        case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
        case WIFI_REASON_HANDSHAKE_TIMEOUT:
        case WIFI_REASON_MIC_FAILURE:
        case WIFI_REASON_CONNECTION_FAIL:
            return "wrong password?";
        case WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY:
        case WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD:
            return "unsupported security mode";
        case WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD:
            return "signal too weak";
        default:
            return nullptr;
    }
}

static void wifi_handler(void *, esp_event_base_t base, int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        auto *e = (wifi_event_sta_disconnected_t *)data;
        if (e->reason != wifi_reason) ESP_LOGW(TAG, "wifi disconnected, reason %d", e->reason);
        wifi_reason = e->reason;
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
            char why[48];
            const char *t = wifi_reason_text(wifi_reason);
            if (t) {
                snprintf(why, sizeof why, "%s: %s", ssid, t);
            } else {
                snprintf(why, sizeof why, "%s (reason %d)", ssid, wifi_reason);
            }
            screen("Can't join WiFi", why, "hold A 3 s to change network", TFT_ORANGE);
            deadline = esp_timer_get_time() + 10 * 1000000LL;  // refresh as the reason changes
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
    // Paired, but the key partition has no prekeys: it was erased (another
    // firmware's data partition overlaps "wakeys"). The server still holds
    // prekeys whose private halves are gone, so start over with a new link.
    uint8_t probe[4];
    if (store.paired && keys_ok && kv_get(NULL, "pk", probe, sizeof probe) == 0) {
        ESP_LOGW(TAG, "paired but the Signal key store is empty; unlinking");
        wa_store_init(&store);
        store_save(NULL, &store);
        keys_wipe();
        screen("Keys lost", "Link the Core2 again", "WhatsApp > Linked devices", TFT_ORANGE);
        vTaskDelay(pdMS_TO_TICKS(3000));
    }

    ws_queue = xQueueCreate(128, sizeof(ws_event));
    wa_callbacks cb = {ws_send, on_event, store_save, now_ms, unix_time, log_cb, NULL, {kv_get, kv_set, kv_del, NULL}};
    wa_client_init(&client, &store, &cb);

    bot_load();
    bot_start();

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
        bot_poll();

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
        reply_input();
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
