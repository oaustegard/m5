// SPDX-License-Identifier: MPL-2.0
// A WhatsApp multi-device companion client core, ported from whatsmeow
// (https://github.com/tulir/whatsmeow, MPL-2.0) to C for the M5Stack Core2.
//
// The core is transport-agnostic and single-threaded: the platform opens a
// WebSocket to WA_URL with Origin WA_ORIGIN, then feeds it events.
//
//   wa_client_init(&c, &store, &callbacks);
//   on socket open:     wa_client_on_open(&c);
//   on binary message:  wa_client_on_data(&c, data, len);
//   every ~100 ms:      wa_client_tick(&c);
//   on socket close:    wa_client_on_close(&c);
//
// The core sends through callbacks.send and reports through callbacks.event.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../wa_binary.h"

#define WA_URL "wss://web.whatsapp.com/ws/chat"
#define WA_ORIGIN "https://web.whatsapp.com"

// Everything that must persist across reboots. Save it whenever
// callbacks.store_changed fires; a store with paired == false re-pairs.
typedef struct {
    uint32_t version;  // WA_STORE_VERSION
    uint8_t noise_priv[32], noise_pub[32];
    uint8_t ident_priv[32], ident_pub[32];
    uint32_t spk_id;
    uint8_t spk_priv[32], spk_pub[32], spk_sig[64];
    uint32_t reg_id;
    uint8_t adv_secret[32];
    bool paired;
    char user[32];   // phone number of the account this device is linked to
    uint16_t device; // this companion's device id
    char lid_user[32];
    char platform[32];
    char push_name[64];
    uint16_t account_len;
    uint8_t account[512];  // ADVSignedDeviceIdentity incl. accountSignatureKey
} wa_store;
#define WA_STORE_VERSION 1

// Generate fresh keys for an unpaired device. Returns 0 or -1.
int wa_store_init(wa_store *s);

typedef enum {
    WA_EV_QR,           // text: QR payload to render; seconds: how long it is valid
    WA_EV_QR_EXHAUSTED, // every QR expired unscanned; reconnect to get new ones
    WA_EV_PAIRED,       // text: our JID; the server will close the socket, reconnect
    WA_EV_PAIR_ERROR,   // text: reason
    WA_EV_LOGGED_IN,    // <success> received
    WA_EV_LOGGED_OUT,   // text: reason; the store has been reset, re-pair
    WA_EV_RECONNECT,    // server asked us to reconnect (stream error 515)
    WA_EV_ERROR,        // text: what failed; the platform should close and retry
    WA_EV_NODE,         // node: a decoded node nobody handled (for debugging/apps)
} wa_event_type;

typedef struct {
    wa_event_type type;
    const char *text;
    int seconds;
    const wa_node *node;
} wa_event;

typedef struct {
    // Send one binary WebSocket message. Return 0 on success.
    int (*send)(void *ctx, const uint8_t *data, size_t len);
    void (*event)(void *ctx, const wa_event *ev);
    void (*store_changed)(void *ctx, const wa_store *s);
    // Monotonic milliseconds, for timers.
    uint64_t (*now_ms)(void *ctx);
    // Unix seconds, or 0 if the clock is not set yet (then certificate
    // validity windows are not checked; signatures always are).
    int64_t (*unix_time)(void *ctx);
    // Optional log sink.
    void (*log)(void *ctx, const char *msg);
    void *ctx;
} wa_callbacks;

typedef enum { WA_S_IDLE, WA_S_HELLO_SENT, WA_S_OPEN, WA_S_CLOSED } wa_state;

typedef struct {
    wa_store *store;
    wa_callbacks cb;
    wa_state state;

    // Frame reassembly (3-byte big-endian length prefix).
    bool header_sent;
    uint8_t *in;
    size_t in_len, in_cap;

    // Noise handshake.
    uint8_t hash[32], salt[32], key[32];
    uint32_t counter;
    uint8_t eph_priv[32], eph_pub[32];

    // Transport.
    uint8_t wkey[32], rkey[32];
    uint32_t wctr, rctr;

    char id_prefix[16];
    uint32_t id_counter;

    char qr[6][256];
    int qr_count, qr_index;
    uint64_t qr_deadline_ms;
    uint64_t next_ping_ms;
    bool logged_in;
} wa_client;

void wa_client_init(wa_client *c, wa_store *s, const wa_callbacks *cb);
int wa_client_on_open(wa_client *c);
int wa_client_on_data(wa_client *c, const uint8_t *data, size_t len);
void wa_client_tick(wa_client *c);
void wa_client_on_close(wa_client *c);
void wa_client_free(wa_client *c);

// Encrypt and send a node. Only valid once the handshake is done.
int wa_client_send_node(wa_client *c, const wa_node *n);
// A fresh request id ("<prefix><counter>"), valid until the next call.
const char *wa_client_next_id(wa_client *c);
