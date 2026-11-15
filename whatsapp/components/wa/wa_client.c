// SPDX-License-Identifier: MPL-2.0
// Ported from whatsmeow (https://github.com/tulir/whatsmeow): handshake.go,
// socket/noisehandshake.go, socket/noisesocket.go, socket/framesocket.go,
// pair.go, store/clientpayload.go, connectionevents.go, keepalive.go.
// Copyright (c) 2021-2025 Tulir Asokan; C port for the Core2.
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa.h"
#include "wa_crypto.h"
#include "wa_internal.h"
#include "wa_pb.h"

#define FRAME_MAX (1u << 24)

// WhatsApp Web version this port speaks (whatsmeow store/clientpayload.go @ecc3917).
static const uint32_t WA_VERSION[3] = {2, 3000, 1052556849};

static const uint8_t NOISE_PATTERN[32] = "Noise_XX_25519_AESGCM_SHA256\0\0\0";

// WhatsApp's noise certificate root (handshake.go WACertPubKey).
static const uint8_t WA_CERT_PUB[32] = {0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7,
                                        0x1e, 0xbe, 0x51, 0x64, 0x37, 0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69,
                                        0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b};

static void wa_log(wa_client *c, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void wa_log(wa_client *c, const char *fmt, ...) {
    if (!c->cb.log) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    c->cb.log(c->cb.ctx, buf);
}

void wa__log(wa_client *c, const char *fmt, ...) {
    if (!c->cb.log) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    c->cb.log(c->cb.ctx, buf);
}

void wa__emit(wa_client *c, const wa_event *ev) {
    if (c->cb.event) c->cb.event(c->cb.ctx, ev);
}

static void emit(wa_client *c, wa_event_type t, const char *text, int seconds, const wa_node *node) {
    wa_event ev = {t, text, seconds, node, NULL};
    wa__emit(c, &ev);
}

static void fail(wa_client *c, const char *why) {
    wa_log(c, "error: %s", why);
    c->state = WA_S_CLOSED;
    emit(c, WA_EV_ERROR, why, 0, NULL);
}

static void save(wa_client *c) {
    if (c->cb.store_changed) c->cb.store_changed(c->cb.ctx, c->store);
}

// ---------------------------------------------------------------- store

int wa_store_init(wa_store *s) {
    memset(s, 0, sizeof *s);
    s->version = WA_STORE_VERSION;
    if (wa_x25519_keypair(s->noise_priv, s->noise_pub)) return -1;
    if (wa_x25519_keypair(s->ident_priv, s->ident_pub)) return -1;
    if (wa_x25519_keypair(s->spk_priv, s->spk_pub)) return -1;
    s->spk_id = 1;
    uint8_t signed_pub[33] = {0x05};
    memcpy(signed_pub + 1, s->spk_pub, 32);
    if (wa_curve_sign(s->spk_sig, s->ident_priv, signed_pub, sizeof signed_pub)) return -1;
    if (wa_random((uint8_t *)&s->reg_id, sizeof s->reg_id)) return -1;
    if (wa_random(s->adv_secret, 32)) return -1;
    return 0;
}

// ---------------------------------------------------------------- noise

static void iv_for(uint32_t counter, uint8_t iv[12]) {
    memset(iv, 0, 12);
    iv[8] = counter >> 24;
    iv[9] = counter >> 16;
    iv[10] = counter >> 8;
    iv[11] = counter;
}

static void nh_authenticate(wa_client *c, const uint8_t *data, size_t len) {
    wa_sha256_2(c->hash, 32, data, len, c->hash);
}

// HKDF(salt, data) -> write || read; salt := write, key := read (MixIntoKey).
static void nh_mix_into_key(wa_client *c, const uint8_t *data, size_t len) {
    uint8_t out[64];
    wa_hkdf_sha256(c->salt, 32, data, len, NULL, 0, out, 64);
    memcpy(c->salt, out, 32);
    memcpy(c->key, out + 32, 32);
    c->counter = 0;
}

static int nh_mix_dh(wa_client *c, const uint8_t priv[32], const uint8_t pub[32]) {
    uint8_t secret[32];
    if (wa_x25519(secret, priv, pub)) return -1;
    nh_mix_into_key(c, secret, 32);
    return 0;
}

// out must hold len + 16.
static void nh_encrypt(wa_client *c, const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t iv[12];
    iv_for(c->counter++, iv);
    wa_aes_gcm_encrypt(c->key, iv, c->hash, 32, in, len, out);
    nh_authenticate(c, out, len + 16);
}

// out must hold len - 16.
static int nh_decrypt(wa_client *c, const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t iv[12];
    iv_for(c->counter++, iv);
    if (wa_aes_gcm_decrypt(c->key, iv, c->hash, 32, in, len, out)) return -1;
    nh_authenticate(c, in, len);
    return 0;
}

// ---------------------------------------------------------------- frames

static int send_frame(wa_client *c, const uint8_t *data, size_t len) {
    if (len >= FRAME_MAX) return -1;
    wa_buf b = {0};
    if (!c->header_sent) {
        uint8_t hdr[4] = {'W', 'A', 6, WA_DICT_VERSION};
        wa_buf_put(&b, hdr, 4);
        c->header_sent = true;
    }
    uint8_t l[3] = {len >> 16, len >> 8, len};
    wa_buf_put(&b, l, 3);
    wa_buf_put(&b, data, len);
    int rc = b.oom ? -1 : c->cb.send(c->cb.ctx, b.data, b.len);
    wa_buf_free(&b);
    return rc;
}

// ---------------------------------------------------------------- ids

const char *wa_client_next_id(wa_client *c) {
    static char id[32];
    snprintf(id, sizeof id, "%s%u", c->id_prefix, (unsigned)++c->id_counter);
    return id;
}

// ---------------------------------------------------------------- payloads

static void put_app_version(wa_buf *b, uint32_t field, const uint32_t v[3]) {
    wa_buf sub = {0};
    wa_pb_varint(&sub, 1, v[0]);
    wa_pb_varint(&sub, 2, v[1]);
    wa_pb_varint(&sub, 3, v[2]);
    wa_pb_msg(b, field, &sub);
}

static void put_user_agent(wa_buf *b) {
    wa_buf ua = {0};
    wa_pb_varint(&ua, 1, 14);  // Platform WEB
    put_app_version(&ua, 2, WA_VERSION);
    wa_pb_str(&ua, 3, "000");
    wa_pb_str(&ua, 4, "000");
    wa_pb_str(&ua, 5, "0.1");
    wa_pb_str(&ua, 6, "");
    wa_pb_str(&ua, 7, "Desktop");
    wa_pb_str(&ua, 8, "0.1");
    wa_pb_varint(&ua, 10, 0);  // ReleaseChannel RELEASE
    wa_pb_str(&ua, 11, "en");
    wa_pb_str(&ua, 12, "US");
    wa_pb_msg(b, 5, &ua);
    wa_buf web = {0};
    wa_pb_varint(&web, 4, 0);  // WebSubPlatform WEB_BROWSER
    wa_pb_msg(b, 6, &web);
}

static void put_device_props(wa_buf *b) {
    static const uint32_t ver[3] = {0, 1, 0};
    wa_pb_str(b, 1, "Muninn Core2");
    put_app_version(b, 2, ver);
    wa_pb_varint(b, 3, 0);  // PlatformType UNKNOWN
    wa_pb_varint(b, 4, 0);  // requireFullSync false
    wa_buf h = {0};
    wa_pb_varint(&h, 3, 10240);  // storageQuotaMb
    wa_pb_varint(&h, 4, 1);      // inlineInitialPayloadInE2EeMsg
    wa_pb_varint(&h, 6, 1);      // supportCallLogHistory
    wa_pb_varint(&h, 7, 1);
    wa_pb_varint(&h, 8, 1);
    wa_pb_varint(&h, 9, 1);
    wa_pb_varint(&h, 10, 1);
    wa_pb_varint(&h, 11, 1);
    wa_pb_varint(&h, 12, 1);
    wa_pb_varint(&h, 14, 1);
    wa_pb_varint(&h, 15, 1);
    wa_pb_varint(&h, 19, 60);  // thumbnailSyncDaysLimit
    wa_pb_varint(&h, 21, 1);
    wa_pb_varint(&h, 22, 1);
    wa_pb_msg(b, 5, &h);
}

static void client_payload(wa_client *c, wa_buf *b) {
    wa_store *s = c->store;
    if (s->paired) {
        wa_pb_varint(b, 1, strtoull(s->user, NULL, 10));  // username
        wa_pb_varint(b, 3, 1);                            // passive
        put_user_agent(b);
        wa_pb_varint(b, 12, 1);  // ConnectType WIFI_UNKNOWN
        wa_pb_varint(b, 13, 1);  // ConnectReason USER_ACTIVATED
        wa_pb_varint(b, 18, s->device);
        wa_pb_varint(b, 24, 1);  // lc
        wa_pb_varint(b, 33, 1);  // pull
        wa_pb_varint(b, 41, 1);  // lidDbMigrated
        return;
    }
    char vs[40];
    uint8_t build_hash[16];
    snprintf(vs, sizeof vs, "%u.%u.%u", (unsigned)WA_VERSION[0], (unsigned)WA_VERSION[1], (unsigned)WA_VERSION[2]);
    wa_md5((const uint8_t *)vs, strlen(vs), build_hash);
    uint8_t regid[4] = {s->reg_id >> 24, s->reg_id >> 16, s->reg_id >> 8, s->reg_id};
    uint8_t skid[3] = {s->spk_id >> 16, s->spk_id >> 8, s->spk_id};
    uint8_t keytype = 0x05;

    wa_pb_varint(b, 3, 0);  // passive
    put_user_agent(b);
    wa_pb_varint(b, 12, 1);
    wa_pb_varint(b, 13, 1);
    wa_buf reg = {0}, props = {0};
    wa_pb_bytes(&reg, 1, regid, 4);
    wa_pb_bytes(&reg, 2, &keytype, 1);
    wa_pb_bytes(&reg, 3, s->ident_pub, 32);
    wa_pb_bytes(&reg, 4, skid, 3);
    wa_pb_bytes(&reg, 5, s->spk_pub, 32);
    wa_pb_bytes(&reg, 6, s->spk_sig, 64);
    wa_pb_bytes(&reg, 7, build_hash, 16);
    put_device_props(&props);
    wa_pb_msg(&reg, 8, &props);
    wa_pb_msg(b, 19, &reg);
    wa_pb_varint(b, 33, 0);  // pull
}

// ---------------------------------------------------------------- handshake

int wa_client_on_open(wa_client *c) {
    c->state = WA_S_IDLE;
    c->header_sent = false;
    c->in_len = 0;
    c->logged_in = false;
    c->qr_count = c->qr_index = 0;

    memcpy(c->hash, NOISE_PATTERN, 32);  // a 32-byte pattern is used as the hash directly
    memcpy(c->salt, c->hash, 32);
    memcpy(c->key, c->hash, 32);
    c->counter = 0;
    uint8_t hdr[4] = {'W', 'A', 6, WA_DICT_VERSION};
    nh_authenticate(c, hdr, 4);

    if (wa_x25519_keypair(c->eph_priv, c->eph_pub)) return fail(c, "random failed"), -1;
    nh_authenticate(c, c->eph_pub, 32);

    wa_buf hello = {0}, msg = {0};
    wa_pb_bytes(&hello, 1, c->eph_pub, 32);
    wa_pb_msg(&msg, 2, &hello);
    int rc = msg.oom ? -1 : send_frame(c, msg.data, msg.len);
    wa_buf_free(&msg);
    if (rc) return fail(c, "failed to send client hello"), -1;
    c->state = WA_S_HELLO_SENT;
    wa_log(c, "client hello sent");
    return 0;
}

static int verify_cert_details(wa_client *c, const uint8_t *d, size_t dl, uint64_t want_issuer, uint64_t *serial,
                               const uint8_t **key, size_t *keylen) {
    uint64_t issuer = 0, nb = 0, na = 0;
    *serial = 0;
    wa_pb_get_varint(d, dl, 1, serial);
    wa_pb_get_varint(d, dl, 2, &issuer);
    if (issuer != want_issuer) return -1;
    if (!wa_pb_get_bytes(d, dl, 3, key, keylen)) return -1;
    int64_t now = c->cb.unix_time ? c->cb.unix_time(c->cb.ctx) : 0;
    if (now > 0 && wa_pb_get_varint(d, dl, 4, &nb) && wa_pb_get_varint(d, dl, 5, &na)) {
        if ((uint64_t)now < nb || (uint64_t)now > na) return -1;
    }
    return 0;
}

static int verify_server_cert(wa_client *c, const uint8_t *cert, size_t certlen, const uint8_t *server_static) {
    const uint8_t *leaf, *inter, *ld, *ls, *id, *is, *ikey, *lkey;
    size_t leafl, interl, ldl, lsl, idl, isl, ikeyl, lkeyl;
    uint64_t iserial, lserial;
    if (!wa_pb_get_bytes(cert, certlen, 1, &leaf, &leafl) || !wa_pb_get_bytes(cert, certlen, 2, &inter, &interl))
        return -1;
    if (!wa_pb_get_bytes(inter, interl, 1, &id, &idl) || !wa_pb_get_bytes(inter, interl, 2, &is, &isl) || isl != 64)
        return -1;
    if (!wa_pb_get_bytes(leaf, leafl, 1, &ld, &ldl) || !wa_pb_get_bytes(leaf, leafl, 2, &ls, &lsl) || lsl != 64)
        return -1;
    if (!wa_curve_verify(WA_CERT_PUB, id, idl, is)) return wa_log(c, "intermediate cert signature invalid"), -1;
    if (verify_cert_details(c, id, idl, 0, &iserial, &ikey, &ikeyl) || ikeyl != 32)
        return wa_log(c, "intermediate cert details invalid"), -1;
    if (!wa_curve_verify(ikey, ld, ldl, ls)) return wa_log(c, "leaf cert signature invalid"), -1;
    if (verify_cert_details(c, ld, ldl, iserial, &lserial, &lkey, &lkeyl) || lkeyl != 32)
        return wa_log(c, "leaf cert details invalid"), -1;
    if (!wa_ct_equal(lkey, server_static, 32)) return wa_log(c, "leaf cert key != server static"), -1;
    return 0;
}

static int handle_server_hello(wa_client *c, const uint8_t *frame, size_t len) {
    const uint8_t *sh, *eph, *stat, *payload;
    size_t shl, ephl, statl, payl;
    if (!wa_pb_get_bytes(frame, len, 3, &sh, &shl)) return fail(c, "no server hello"), -1;
    if (!wa_pb_get_bytes(sh, shl, 1, &eph, &ephl) || ephl != 32 || !wa_pb_get_bytes(sh, shl, 2, &stat, &statl) ||
        statl < 16 || !wa_pb_get_bytes(sh, shl, 3, &payload, &payl) || payl < 16)
        return fail(c, "missing parts of server hello"), -1;

    nh_authenticate(c, eph, 32);
    if (nh_mix_dh(c, c->eph_priv, eph)) return fail(c, "bad server ephemeral"), -1;

    uint8_t server_static[48];
    if (statl - 16 != 32 || nh_decrypt(c, stat, statl, server_static))
        return fail(c, "failed to decrypt server static"), -1;
    if (nh_mix_dh(c, c->eph_priv, server_static)) return fail(c, "bad server static"), -1;

    uint8_t *cert = malloc(payl);
    if (!cert) return fail(c, "out of memory"), -1;
    if (nh_decrypt(c, payload, payl, cert)) {
        free(cert);
        return fail(c, "failed to decrypt server certificate"), -1;
    }
    int bad = verify_server_cert(c, cert, payl - 16, server_static);
    free(cert);
    if (bad) return fail(c, "server certificate verification failed"), -1;
    wa_log(c, "server certificate chain verified");

    uint8_t enc_static[48];
    nh_encrypt(c, c->store->noise_pub, 32, enc_static);
    if (nh_mix_dh(c, c->store->noise_priv, eph)) return fail(c, "noise key mix failed"), -1;

    wa_buf pl = {0};
    client_payload(c, &pl);
    uint8_t *enc_pl = pl.oom ? NULL : malloc(pl.len + 16);
    if (!enc_pl) {
        wa_buf_free(&pl);
        return fail(c, "out of memory"), -1;
    }
    nh_encrypt(c, pl.data, pl.len, enc_pl);
    wa_buf fin = {0}, msg = {0};
    wa_pb_bytes(&fin, 1, enc_static, 48);
    wa_pb_bytes(&fin, 2, enc_pl, pl.len + 16);
    free(enc_pl);
    wa_buf_free(&pl);
    wa_pb_msg(&msg, 4, &fin);
    int rc = msg.oom ? -1 : send_frame(c, msg.data, msg.len);
    wa_buf_free(&msg);
    if (rc) return fail(c, "failed to send client finish"), -1;

    // Split into transport keys (Finish: extractAndExpand(salt, nil)).
    uint8_t keys[64];
    wa_hkdf_sha256(c->salt, 32, NULL, 0, NULL, 0, keys, 64);
    memcpy(c->wkey, keys, 32);
    memcpy(c->rkey, keys + 32, 32);
    c->wctr = c->rctr = 0;
    c->state = WA_S_OPEN;
    c->next_ping_ms = c->cb.now_ms(c->cb.ctx) + 20000;
    wa_log(c, "noise handshake complete (%s)", c->store->paired ? "login" : "registration");
    return 0;
}

// ---------------------------------------------------------------- nodes

int wa_client_send_node(wa_client *c, const wa_node *n) {
    if (c->state != WA_S_OPEN) return -1;
    wa_buf plain = {0};
    if (wa_node_encode(n, &plain)) {
        wa_buf_free(&plain);
        return -1;
    }
    uint8_t *ct = malloc(plain.len + 16);
    if (!ct) {
        wa_buf_free(&plain);
        return -1;
    }
    uint8_t iv[12];
    iv_for(c->wctr++, iv);
    wa_aes_gcm_encrypt(c->wkey, iv, NULL, 0, plain.data, plain.len, ct);
    int rc = send_frame(c, ct, plain.len + 16);
    free(ct);
    if (c->cb.log) {
        char dbg[400];
        wa_node_print(n, dbg, sizeof dbg);
        wa_log(c, "--> %s", dbg);
    }
    wa_buf_free(&plain);
    return rc;
}

static void send_iq_result(wa_client *c, const char *id, const wa_node *content) {
    wa_attr attrs[] = {{"to", wa_vjid(WA_SERVER_JID)}, {"type", wa_vstr("result")}, {"id", wa_vstr(id)}};
    wa_node n = {"iq", attrs, 3, content ? wa_vlist((wa_node *)content, 1) : (wa_value){0}};
    wa_client_send_node(c, &n);
}

static void send_pair_error(wa_client *c, const char *id, const char *code, const char *text) {
    wa_attr eattrs[] = {{"code", wa_vstr(code)}, {"text", wa_vstr(text)}};
    wa_node err = {"error", eattrs, 2, {0}};
    wa_attr attrs[] = {{"to", wa_vjid(WA_SERVER_JID)}, {"type", wa_vstr("error")}, {"id", wa_vstr(id)}};
    wa_node n = {"iq", attrs, 3, wa_vlist(&err, 1)};
    wa_client_send_node(c, &n);
}

static void show_qr(wa_client *c) {
    int secs = c->qr_index == 0 ? 60 : 20;
    c->qr_deadline_ms = c->cb.now_ms(c->cb.ctx) + (uint64_t)secs * 1000;
    emit(c, WA_EV_QR, c->qr[c->qr_index], secs, NULL);
}

static void handle_pair_device(wa_client *c, const wa_node *iq, const wa_node *pd) {
    const char *id = wa_attr_str(iq, "id");
    send_iq_result(c, id ? id : "", NULL);

    char noise[48], ident[48], adv[48];
    wa_base64(c->store->noise_pub, 32, noise);
    wa_base64(c->store->ident_pub, 32, ident);
    wa_base64(c->store->adv_secret, 32, adv);
    const wa_node *refs;
    size_t n = wa_children(pd, &refs);
    c->qr_count = 0;
    for (size_t i = 0; i < n && c->qr_count < 6; i++) {
        if (strcmp(refs[i].tag, "ref") != 0 || refs[i].content.type != WA_V_BYTES) continue;
        // "9" = PairClientOtherWebClient: DeviceProps UNKNOWN + UserAgent WEB.
        int w = snprintf(c->qr[c->qr_count], sizeof c->qr[0], "https://wa.me/settings/linked_devices#%.*s,%s,%s,%s,9",
                         (int)refs[i].content.bytes.len, (const char *)refs[i].content.bytes.data, noise, ident, adv);
        if (w < 0 || (size_t)w >= sizeof c->qr[0]) {
            wa_log(c, "QR payload too long (%d bytes), skipping ref", w);
            continue;
        }
        c->qr_count++;
    }
    wa_log(c, "pair-device: %d QR refs", c->qr_count);
    c->qr_index = 0;
    if (c->qr_count) show_qr(c);
}

static void handle_pair_success(wa_client *c, const wa_node *iq, const wa_node *ps) {
    wa_store *s = c->store;
    const char *req_id = wa_attr_str(iq, "id");
    if (!req_id) req_id = "";
    const wa_node *di = wa_child(ps, "device-identity");
    const wa_node *dev = wa_child(ps, "device");
    const wa_node *plat = wa_child(ps, "platform");
    const wa_jid *jid = dev ? wa_attr_jid(dev, "jid") : NULL;
    const wa_jid *lid = dev ? wa_attr_jid(dev, "lid") : NULL;
    if (!di || di->content.type != WA_V_BYTES || !jid) {
        send_pair_error(c, req_id, "500", "internal-error");
        emit(c, WA_EV_PAIR_ERROR, "pair-success missing device identity or jid", 0, NULL);
        return;
    }
    const uint8_t *container = di->content.bytes.data;
    size_t container_len = di->content.bytes.len;

    // ADVSignedDeviceIdentityHMAC { details=1, HMAC=2, accountType=3 }
    const uint8_t *details, *mac;
    size_t details_len, mac_len;
    uint64_t account_type = 0;
    if (!wa_pb_get_bytes(container, container_len, 1, &details, &details_len) ||
        !wa_pb_get_bytes(container, container_len, 2, &mac, &mac_len) || mac_len != 32) {
        send_pair_error(c, req_id, "500", "internal-error");
        emit(c, WA_EV_PAIR_ERROR, "malformed device identity container", 0, NULL);
        return;
    }
    wa_pb_get_varint(container, container_len, 3, &account_type);
    static const uint8_t hosted_acct_prefix[2] = {6, 5};
    uint8_t expect[32];
    wa_slice hparts[] = {{hosted_acct_prefix, 2}, {details, details_len}};
    if (account_type == 1)
        wa_hmac_sha256(s->adv_secret, 32, hparts, 2, expect);
    else
        wa_hmac_sha256(s->adv_secret, 32, hparts + 1, 1, expect);
    if (!wa_ct_equal(expect, mac, 32)) {
        send_pair_error(c, req_id, "401", "hmac-mismatch");
        emit(c, WA_EV_PAIR_ERROR, "device identity HMAC mismatch", 0, NULL);
        return;
    }

    // ADVSignedDeviceIdentity { details=1, accountSignatureKey=2, accountSignature=3, deviceSignature=4 }
    const uint8_t *id_details, *acct_key, *acct_sig;
    size_t id_details_len, acct_key_len, acct_sig_len;
    if (!wa_pb_get_bytes(details, details_len, 1, &id_details, &id_details_len) ||
        !wa_pb_get_bytes(details, details_len, 2, &acct_key, &acct_key_len) || acct_key_len != 32 ||
        !wa_pb_get_bytes(details, details_len, 3, &acct_sig, &acct_sig_len) || acct_sig_len != 64) {
        send_pair_error(c, req_id, "500", "internal-error");
        emit(c, WA_EV_PAIR_ERROR, "malformed signed device identity", 0, NULL);
        return;
    }
    // ADVDeviceIdentity { rawID=1, timestamp=2, keyIndex=3, accountType=4, deviceType=5 }
    uint64_t key_index = 0, device_type = 0;
    wa_pb_get_varint(id_details, id_details_len, 3, &key_index);
    wa_pb_get_varint(id_details, id_details_len, 5, &device_type);

    // Account signature over prefix || details || our identity pub.
    uint8_t acct_prefix[2] = {6, device_type == 1 ? 5 : 0};
    wa_buf m = {0};
    wa_buf_put(&m, acct_prefix, 2);
    wa_buf_put(&m, id_details, id_details_len);
    wa_buf_put(&m, s->ident_pub, 32);
    int ok = !m.oom && wa_curve_verify(acct_key, m.data, m.len, acct_sig);
    wa_buf_free(&m);
    if (!ok) {
        send_pair_error(c, req_id, "401", "signature-mismatch");
        emit(c, WA_EV_PAIR_ERROR, "account signature mismatch", 0, NULL);
        return;
    }

    // Device signature over {6,1} || details || our identity pub || account key.
    static const uint8_t dev_prefix[2] = {6, 1};
    uint8_t dev_sig[64];
    wa_buf_put(&m, dev_prefix, 2);
    wa_buf_put(&m, id_details, id_details_len);
    wa_buf_put(&m, s->ident_pub, 32);
    wa_buf_put(&m, acct_key, 32);
    int sign_rc = m.oom ? -1 : wa_curve_sign(dev_sig, s->ident_priv, m.data, m.len);
    wa_buf_free(&m);
    if (sign_rc) {
        send_pair_error(c, req_id, "500", "internal-error");
        emit(c, WA_EV_PAIR_ERROR, "failed to sign device identity", 0, NULL);
        return;
    }

    // Keep the full identity (with account key) for later message sending.
    wa_buf acct = {0};
    wa_pb_bytes(&acct, 1, id_details, id_details_len);
    wa_pb_bytes(&acct, 2, acct_key, 32);
    wa_pb_bytes(&acct, 3, acct_sig, 64);
    wa_pb_bytes(&acct, 4, dev_sig, 64);
    // The one we send back omits accountSignatureKey.
    wa_buf self = {0};
    wa_pb_bytes(&self, 1, id_details, id_details_len);
    wa_pb_bytes(&self, 3, acct_sig, 64);
    wa_pb_bytes(&self, 4, dev_sig, 64);
    if (acct.oom || self.oom || acct.len > sizeof s->account) {
        wa_buf_free(&acct);
        wa_buf_free(&self);
        send_pair_error(c, req_id, "500", "internal-error");
        emit(c, WA_EV_PAIR_ERROR, "device identity too large", 0, NULL);
        return;
    }
    memcpy(s->account, acct.data, acct.len);
    s->account_len = (uint16_t)acct.len;
    wa_buf_free(&acct);

    snprintf(s->user, sizeof s->user, "%s", jid->user);
    s->device = jid->device;
    if (lid) snprintf(s->lid_user, sizeof s->lid_user, "%s", lid->user);
    const char *pname = plat ? wa_attr_str(plat, "name") : NULL;
    snprintf(s->platform, sizeof s->platform, "%s", pname ? pname : "");
    s->paired = true;
    save(c);

    char kidx[12];
    snprintf(kidx, sizeof kidx, "%u", (unsigned)key_index);
    wa_attr dattrs[] = {{"key-index", wa_vstr(kidx)}};
    wa_node didn = {"device-identity", dattrs, 1, wa_vbytes(self.data, self.len)};
    wa_node sign = {"pair-device-sign", NULL, 0, wa_vlist(&didn, 1)};
    send_iq_result(c, req_id, &sign);
    wa_buf_free(&self);

    char jb[96];
    c->qr_count = 0;
    emit(c, WA_EV_PAIRED, wa_jid_str(jid, jb, sizeof jb), 0, NULL);
}

static void handle_node(wa_client *c, const wa_node *n) {
    if (c->cb.log) {
        char dbg[600];
        wa_node_print(n, dbg, sizeof dbg);
        wa_log(c, "<-- %s", dbg);
    }
    if (strcmp(n->tag, "iq") == 0) {
        const wa_jid *from = wa_attr_jid(n, "from");
        const wa_node *kids;
        size_t nk = wa_children(n, &kids);
        wa_jid server = WA_SERVER_JID;
        const char *type = wa_attr_str(n, "type");
        const char *xmlns = wa_attr_str(n, "xmlns");
        if (from && wa_jid_eq(from, &server) && nk == 1) {
            if (strcmp(kids[0].tag, "pair-device") == 0) return handle_pair_device(c, n, &kids[0]);
            if (strcmp(kids[0].tag, "pair-success") == 0) return handle_pair_success(c, n, &kids[0]);
        }
        // request.go handleIQ: answer the server's pings.
        if (type && xmlns && strcmp(type, "get") == 0 && strcmp(xmlns, "urn:xmpp:ping") == 0) {
            const char *id = wa_attr_str(n, "id");
            return send_iq_result(c, id ? id : "", NULL);
        }
        if (type && (strcmp(type, "result") == 0 || strcmp(type, "error") == 0) && wa__handle_iq_response(c, n))
            return;
    } else if (strcmp(n->tag, "message") == 0) {
        if (wa__handle_message(c, n)) return;
    } else if (strcmp(n->tag, "notification") == 0) {
        emit(c, WA_EV_NODE, NULL, 0, n);  // apps may want the content; the ack follows
        wa__handle_notification(c, n);
        return;
    } else if (strcmp(n->tag, "receipt") == 0 || strcmp(n->tag, "call") == 0) {
        emit(c, WA_EV_NODE, NULL, 0, n);
        wa__send_ack(c, n, 0);
        return;
    } else if (strcmp(n->tag, "success") == 0) {
        c->logged_in = true;
        const wa_jid *lid = wa_attr_jid(n, "lid");
        if (lid && !c->store->lid_user[0]) {
            snprintf(c->store->lid_user, sizeof c->store->lid_user, "%s", lid->user);
            save(c);
        }
        // SetPassive(false): <iq xmlns="passive" type="set" to=server><active/></iq>
        wa_node active = {"active", NULL, 0, {0}};
        wa_attr attrs[] = {{"id", wa_vstr(wa_client_next_id(c))},
                           {"xmlns", wa_vstr("passive")},
                           {"type", wa_vstr("set")},
                           {"to", wa_vjid(WA_SERVER_JID)}};
        wa_node iq = {"iq", attrs, 4, wa_vlist(&active, 1)};
        wa_client_send_node(c, &iq);
        wa__on_success(c);
        emit(c, WA_EV_LOGGED_IN, NULL, 0, n);
        return;
    } else if (strcmp(n->tag, "failure") == 0) {
        const char *reason = wa_attr_str(n, "reason");
        if (reason && strcmp(reason, "401") == 0) {
            wa_store_init(c->store);
            save(c);
            emit(c, WA_EV_LOGGED_OUT, "logged out (failure 401)", 0, n);
        } else {
            emit(c, WA_EV_ERROR, reason ? reason : "connect failure", 0, n);
        }
        c->state = WA_S_CLOSED;
        return;
    } else if (strcmp(n->tag, "stream:error") == 0) {
        const char *code = wa_attr_str(n, "code");
        const wa_node *conflict = wa_child(n, "conflict");
        const char *ctype = conflict ? wa_attr_str(conflict, "type") : NULL;
        c->state = WA_S_CLOSED;
        if (code && strcmp(code, "515") == 0) {
            emit(c, WA_EV_RECONNECT, "515", 0, n);
        } else if (code && strcmp(code, "401") == 0 && ctype && strcmp(ctype, "device_removed") == 0) {
            wa_store_init(c->store);
            save(c);
            emit(c, WA_EV_LOGGED_OUT, "device removed", 0, n);
        } else {
            emit(c, WA_EV_ERROR, ctype ? ctype : (code ? code : "stream error"), 0, n);
        }
        return;
    }
    emit(c, WA_EV_NODE, NULL, 0, n);
}

static int handle_frame(wa_client *c, const uint8_t *frame, size_t len) {
    if (c->state == WA_S_HELLO_SENT) return handle_server_hello(c, frame, len);
    if (c->state != WA_S_OPEN || len < 16) return -1;
    uint8_t *plain = malloc(len - 16);
    if (!plain) return fail(c, "out of memory"), -1;
    uint8_t iv[12];
    iv_for(c->rctr++, iv);
    if (wa_aes_gcm_decrypt(c->rkey, iv, NULL, 0, frame, len, plain)) {
        free(plain);
        return fail(c, "failed to decrypt frame"), -1;
    }
    const uint8_t *payload;
    size_t plen;
    uint8_t *owned;
    if (wa_unpack(plain, len - 16, &payload, &plen, &owned)) {
        free(plain);
        wa_log(c, "failed to unpack frame");
        return 0;
    }
    wa_arena a = {0};
    wa_node *n = wa_node_decode(&a, payload, plen);
    if (n)
        handle_node(c, n);
    else
        wa_log(c, "failed to decode node (%zu bytes)", plen);
    wa_arena_free(&a);
    free(owned);
    free(plain);
    return 0;
}

int wa_client_on_data(wa_client *c, const uint8_t *data, size_t len) {
    if (c->state == WA_S_CLOSED) return -1;
    if (c->in_len + len > c->in_cap) {
        size_t cap = c->in_cap ? c->in_cap : 4096;
        while (cap < c->in_len + len) cap *= 2;
        uint8_t *n = realloc(c->in, cap);
        if (!n) return fail(c, "out of memory"), -1;
        c->in = n;
        c->in_cap = cap;
    }
    memcpy(c->in + c->in_len, data, len);
    c->in_len += len;
    size_t off = 0;
    while (c->in_len - off >= 3) {
        size_t flen = ((size_t)c->in[off] << 16) | ((size_t)c->in[off + 1] << 8) | c->in[off + 2];
        if (c->in_len - off - 3 < flen) break;
        if (handle_frame(c, c->in + off + 3, flen)) return -1;
        off += 3 + flen;
        if (c->state == WA_S_CLOSED) break;
    }
    memmove(c->in, c->in + off, c->in_len - off);
    c->in_len -= off;
    return c->state == WA_S_CLOSED ? -1 : 0;
}

void wa_client_tick(wa_client *c) {
    if (c->state != WA_S_OPEN) return;
    uint64_t now = c->cb.now_ms(c->cb.ctx);
    if (c->qr_count && now >= c->qr_deadline_ms) {
        if (++c->qr_index < c->qr_count) {
            show_qr(c);
        } else {
            c->qr_count = 0;
            emit(c, WA_EV_QR_EXHAUSTED, NULL, 0, NULL);
        }
    }
    // whatsmeow starts its keepalive loop on connect, not on login; the server
    // drops a silent connection after about 40 seconds, even while pairing.
    if (now >= c->next_ping_ms) {
        wa_attr attrs[] = {{"id", wa_vstr(wa_client_next_id(c))},
                           {"xmlns", wa_vstr("w:p")},
                           {"type", wa_vstr("get")},
                           {"to", wa_vjid(WA_SERVER_JID)}};
        wa_node iq = {"iq", attrs, 4, {0}};
        wa_client_send_node(c, &iq);
        c->next_ping_ms = now + 20000 + (now % 10000);
    }
}

void wa_client_init(wa_client *c, wa_store *s, const wa_callbacks *cb) {
    memset(c, 0, sizeof *c);
    c->store = s;
    c->cb = *cb;
    uint8_t r[2] = {0};
    wa_random(r, 2);
    snprintf(c->id_prefix, sizeof c->id_prefix, "%u.%u-", r[0], r[1]);
}

void wa_client_on_close(wa_client *c) {
    c->state = WA_S_CLOSED;
    c->in_len = 0;
}

void wa_client_free(wa_client *c) {
    free(c->in);
    c->in = NULL;
    c->in_cap = c->in_len = 0;
}
