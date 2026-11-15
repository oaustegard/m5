// SPDX-License-Identifier: MPL-2.0
// The Signal protocol as WhatsApp uses it: X3DH (both sides), the
// double ratchet for 1:1 messages, and sender keys for groups. Written from
// the public specifications and tested against go.mau.fi/libsignal (the
// library whatsmeow uses) through host/sigpeer; see wa_signal.c.
//
// Sessions, sender keys and one-time prekeys live in the platform's key-value
// store (wa_kv). Keys are at most 14 characters, so they fit ESP-IDF NVS.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "wa.h"

typedef enum {
    WA_SIG_OK = 0,
    WA_SIG_DUPLICATE = 1,           // counter already used: a redelivery, ignore it
    WA_SIG_ERR_INVALID = -1,        // malformed message
    WA_SIG_ERR_NO_SESSION = -2,     // no session (or no state that decrypts it)
    WA_SIG_ERR_NO_PREKEY = -3,      // the prekey message names a prekey we do not have
    WA_SIG_ERR_BAD_MAC = -4,        // MAC or signature mismatch
    WA_SIG_ERR_NO_SENDER_KEY = -5,  // no sender key for this group sender
    WA_SIG_ERR_FUTURE = -6,         // more than 2000 messages ahead of the chain
    WA_SIG_ERR_STORE = -7,          // the key-value store failed
    WA_SIG_ERR_NOMEM = -8,
} wa_sig_result;

const char *wa_sig_strerror(int rc);

typedef struct {
    wa_store *store;  // our identity key, signed prekey and registration id
    wa_kv kv;
} wa_sig;

// Decrypt a 1:1 message: an <enc type="pkmsg"> (prekey = true) or
// type="msg". addr names the sender device (any stable string; the client
// uses the device JID). On WA_SIG_OK, *out is a malloc'd plaintext the caller
// frees. It still carries WhatsApp's random padding; see wa_unpad.
int wa_sig_decrypt(wa_sig *s, const char *addr, bool prekey, const uint8_t *in, size_t len, uint8_t **out,
                   size_t *outlen);

// Encrypt to a device we have a session with (wa_sig_has_session). *out is a
// malloc'd ciphertext. Until the other side has answered a session we started
// (wa_sig_process_bundle), it is a PreKeySignalMessage, the content of
// <enc type="pkmsg">, and *prekey is set; otherwise a SignalMessage for
// <enc type="msg">. The caller pads the plaintext (whatsmeow padMessage).
int wa_sig_encrypt(wa_sig *s, const char *addr, const uint8_t *in, size_t len, uint8_t **out, size_t *outlen,
                   bool *prekey);

// 1 if we have a session with addr, 0 if not, or a negative wa_sig_result.
int wa_sig_has_session(wa_sig *s, const char *addr);

// The keys a device publishes for others to start a session with it
// (<iq xmlns="encrypt" type="get"><key>...).
typedef struct {
    uint32_t reg_id;
    uint8_t ident[32];
    uint32_t spk_id;
    uint8_t spk[32], spk_sig[64];
    bool has_opk;
    uint32_t opk_id;
    uint8_t opk[32];
} wa_prekey_bundle;
// Start a session with addr from its bundle (X3DH as the initiator), replacing
// any current one. WA_SIG_ERR_BAD_MAC if the signed prekey's signature is bad.
int wa_sig_process_bundle(wa_sig *s, const char *addr, const wa_prekey_bundle *b);

// Store the sender key from a SenderKeyDistributionMessage (the
// axolotlSenderKeyDistributionMessage bytes) for sender addr in group.
int wa_sig_group_process(wa_sig *s, const char *group, const char *addr, const uint8_t *in, size_t len);
// Decrypt an <enc type="skmsg">. Same output contract as wa_sig_decrypt.
// Our own sender key for group (made on first use): the
// SenderKeyDistributionMessage that lets others decrypt what we send, and
// a SenderKeyMessage (<enc type="skmsg">) of the padded plaintext. addr names
// our own device, as the receivers see it.
int wa_sig_group_skdm(wa_sig *s, const char *group, const char *addr, uint8_t **out, size_t *outlen);
int wa_sig_group_encrypt(wa_sig *s, const char *group, const char *addr, const uint8_t *in, size_t len,
                         uint8_t **out, size_t *outlen);
int wa_sig_group_decrypt(wa_sig *s, const char *group, const char *addr, const uint8_t *in, size_t len,
                         uint8_t **out, size_t *outlen);

// One-time prekeys.
#define WA_PREKEY_MAX 150    // how many private keys the store keeps
#define WA_PREKEY_UPLOAD 50  // whatsmeow's WantedPreKeyCount
#define WA_PREKEY_MIN 5      // whatsmeow's MinPreKeyCount
typedef struct {
    uint32_t id;  // 24 bits on the wire
    uint8_t pub[32];
} wa_prekey_pub;
// Number of unused one-time prekeys we hold, or -1 if the store failed.
int wa_sig_prekey_count(wa_sig *s);
// Generate n (<= WA_PREKEY_MAX) new prekeys, store their private halves, and
// return the public halves in out for upload. The oldest are dropped past
// WA_PREKEY_MAX. Returns n, or a negative wa_sig_result.
int wa_sig_prekeys_generate(wa_sig *s, int n, wa_prekey_pub *out);

// Strip WhatsApp's v2 plaintext padding (message.go unpadMessage): the last
// byte n says the last n bytes all equal n. Returns the unpadded length, or
// -1 if the padding is wrong (or the input is empty).
long wa_unpad(const uint8_t *data, size_t len);
