// SPDX-License-Identifier: MPL-2.0
// Receiving messages: prekey upload, <message> decryption, receipts and acks.
// Ported from whatsmeow (https://github.com/tulir/whatsmeow): prekeys.go,
// message.go, receipt.go, retry.go, notification.go, connectionevents.go.
// Copyright (c) 2021-2025 Tulir Asokan; C port for the Core2.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_crypto.h"
#include "wa_internal.h"
#include "wa_pb.h"
#include "wa_signal.h"

// receipt.go Nack codes.
#define NACK_UNRECOGNIZED_STANZA 488
#define NACK_INVALID_PROTOBUF 491

static wa_sig sig_of(wa_client *c) {
    wa_sig s = {c->store, c->cb.kv};
    return s;
}

static bool have_kv(wa_client *c) { return c->cb.kv.get && c->cb.kv.set; }

static void copy_attr(wa_attr *attrs, size_t *n, const wa_node *src, const char *key) {
    const wa_value *v = wa_attr_get(src, key);
    if (v) attrs[(*n)++] = (wa_attr){key, *v};
}

void wa__send_ack(wa_client *c, const wa_node *n, int error) {
    wa_attr attrs[7];
    size_t na = 0;
    char err[12];
    attrs[na++] = (wa_attr){"class", wa_vstr(n->tag)};
    copy_attr(attrs, &na, n, "id");
    const wa_value *from = wa_attr_get(n, "from");
    if (from) attrs[na++] = (wa_attr){"to", *from};
    copy_attr(attrs, &na, n, "participant");
    copy_attr(attrs, &na, n, "recipient");
    if (strcmp(n->tag, "message") != 0) copy_attr(attrs, &na, n, "type");
    if (error) {
        snprintf(err, sizeof err, "%d", error);
        attrs[na++] = (wa_attr){"error", wa_vstr(err)};
    }
    wa_node ack = {"ack", attrs, na, {0}};
    wa_client_send_node(c, &ack);
}

// ---------------------------------------------------------------- prekeys

static void send_prekey_count_query(wa_client *c) {
    snprintf(c->prekey_count_id, sizeof c->prekey_count_id, "%s", wa_client_next_id(c));
    wa_node count = {"count", NULL, 0, {0}};
    wa_attr attrs[] = {{"id", wa_vstr(c->prekey_count_id)},
                       {"xmlns", wa_vstr("encrypt")},
                       {"type", wa_vstr("get")},
                       {"to", wa_vjid(WA_SERVER_JID)}};
    wa_node iq = {"iq", attrs, 4, wa_vlist(&count, 1)};
    wa_client_send_node(c, &iq);
}

static void be24(uint32_t v, uint8_t out[3]) {
    out[0] = (uint8_t)(v >> 16);
    out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)v;
}

// prekeys.go uploadPreKeys.
static void upload_prekeys(wa_client *c) {
    if (c->prekey_upload_id[0]) return;  // one in flight
    wa_sig s = sig_of(c);
    const int n = WA_PREKEY_UPLOAD;
    wa_prekey_pub *pubs = malloc(sizeof *pubs * n);
    wa_node *keys = malloc(sizeof *keys * n);
    wa_node *kids = malloc(sizeof *kids * n * 2);
    uint8_t(*ids)[3] = malloc(3 * (size_t)n);
    if (!pubs || !keys || !kids || !ids) {
        wa__log(c, "prekey upload: out of memory");
        goto done;
    }
    int rc = wa_sig_prekeys_generate(&s, n, pubs);
    if (rc != n) {
        wa__log(c, "prekey upload: %s", wa_sig_strerror(rc));
        goto done;
    }
    for (int i = 0; i < n; i++) {
        be24(pubs[i].id, ids[i]);
        kids[2 * i] = (wa_node){"id", NULL, 0, wa_vbytes(ids[i], 3)};
        kids[2 * i + 1] = (wa_node){"value", NULL, 0, wa_vbytes(pubs[i].pub, 32)};
        keys[i] = (wa_node){"key", NULL, 0, wa_vlist(&kids[2 * i], 2)};
    }
    wa_store *st = c->store;
    uint8_t reg[4] = {st->reg_id >> 24, st->reg_id >> 16, st->reg_id >> 8, st->reg_id};
    uint8_t type = 0x05, skid[3];
    be24(st->spk_id, skid);
    wa_node skey_kids[] = {{"id", NULL, 0, wa_vbytes(skid, 3)},
                           {"value", NULL, 0, wa_vbytes(st->spk_pub, 32)},
                           {"signature", NULL, 0, wa_vbytes(st->spk_sig, 64)}};
    wa_node content[] = {{"registration", NULL, 0, wa_vbytes(reg, 4)},
                         {"type", NULL, 0, wa_vbytes(&type, 1)},
                         {"identity", NULL, 0, wa_vbytes(st->ident_pub, 32)},
                         {"list", NULL, 0, wa_vlist(keys, (size_t)n)},
                         {"skey", NULL, 0, wa_vlist(skey_kids, 3)}};
    snprintf(c->prekey_upload_id, sizeof c->prekey_upload_id, "%s", wa_client_next_id(c));
    wa_attr attrs[] = {{"id", wa_vstr(c->prekey_upload_id)},
                       {"xmlns", wa_vstr("encrypt")},
                       {"type", wa_vstr("set")},
                       {"to", wa_vjid(WA_SERVER_JID)}};
    wa_node iq = {"iq", attrs, 4, wa_vlist(content, 5)};
    wa__log(c, "uploading %d prekeys (ids %u-%u)", n, (unsigned)pubs[0].id, (unsigned)pubs[n - 1].id);
    if (wa_client_send_node(c, &iq)) c->prekey_upload_id[0] = 0;
done:
    free(pubs);
    free(keys);
    free(kids);
    free(ids);
}

void wa__on_success(wa_client *c) {
    c->prekey_count_id[0] = c->prekey_upload_id[0] = 0;
    if (!have_kv(c)) {
        wa__log(c, "no key store: not uploading prekeys; messages will not decrypt");
        return;
    }
    send_prekey_count_query(c);
}

static int count_value(const wa_node *n) {
    const wa_node *count = wa_child(n, "count");
    const char *v = count ? wa_attr_str(count, "value") : NULL;
    return v ? atoi(v) : -1;
}

bool wa__handle_iq_response(wa_client *c, const wa_node *n) {
    const char *id = wa_attr_str(n, "id");
    const char *type = wa_attr_str(n, "type");
    if (!id || !type) return false;
    if (c->prekey_count_id[0] && strcmp(id, c->prekey_count_id) == 0) {
        c->prekey_count_id[0] = 0;
        int server = strcmp(type, "result") == 0 ? count_value(n) : -1;
        wa_sig s = sig_of(c);
        int local = wa_sig_prekey_count(&s);
        wa__log(c, "prekeys: server has %d, we hold %d", server, local);
        // connectionevents.go: upload when either side runs low.
        if (server < 0)
            wa__log(c, "prekey count query failed");
        else if (server < WA_PREKEY_MIN || (local >= 0 && local < WA_PREKEY_MIN))
            upload_prekeys(c);
        return true;
    }
    if (c->prekey_upload_id[0] && strcmp(id, c->prekey_upload_id) == 0) {
        c->prekey_upload_id[0] = 0;
        if (strcmp(type, "result") == 0) {
            wa__log(c, "prekeys uploaded");
            wa_event ev = {WA_EV_PREKEYS, NULL, WA_PREKEY_UPLOAD, n, NULL};
            wa__emit(c, &ev);
        } else {
            wa__log(c, "prekey upload rejected");
        }
        return true;
    }
    return false;
}

// notification.go: <notification type="encrypt"> carries the server's
// remaining prekey count. Every notification is acked.
bool wa__handle_notification(wa_client *c, const wa_node *n) {
    const char *type = wa_attr_str(n, "type");
    const wa_jid *from = wa_attr_jid(n, "from");
    wa_jid server = WA_SERVER_JID;
    if (type && strcmp(type, "encrypt") == 0 && from && wa_jid_eq(from, &server) && have_kv(c)) {
        int left = count_value(n);
        wa__log(c, "server has %d prekeys left", left);
        if (left >= 0 && left < WA_PREKEY_MIN) upload_prekeys(c);
    }
    wa__send_ack(c, n, 0);
    return true;
}

// ---------------------------------------------------------------- rendering

static char *dupn(const uint8_t *s, size_t n) {
    char *d = malloc(n + 1);
    if (!d) return NULL;
    memcpy(d, s, n);
    d[n] = 0;
    return d;
}

static char *label(const char *tag, const uint8_t *s, size_t n) {
    size_t tl = strlen(tag);
    char *d = malloc(tl + (n ? n + 1 : 0) + 1);
    if (!d) return NULL;
    memcpy(d, tag, tl);
    if (n) {
        d[tl] = ' ';
        memcpy(d + tl + 1, s, n);
        tl += n + 1;
    }
    d[tl] = 0;
    return d;
}

// The string field f of sub-message field sub, or NULL/0.
static size_t sub_str(const uint8_t *m, size_t ml, uint32_t sub, uint32_t f, const uint8_t **out) {
    const uint8_t *d;
    size_t dl, sl = 0;
    *out = NULL;
    if (wa_pb_get_bytes(m, ml, sub, &d, &dl) && wa_pb_get_bytes(d, dl, f, out, &sl)) return sl;
    return 0;
}

// What a waE2E.Message shows: a kind and display text (malloc'd, may be NULL).
static void render(const uint8_t *m, size_t ml, const char **kind, char **text) {
    const uint8_t *d, *s;
    size_t dl, sl;
    // Unwrap DeviceSentMessage (31 -> 2) and FutureProofMessage wrappers
    // (ephemeral 40, viewOnce 37/55/59, documentWithCaption 53, edited 58).
    static const uint32_t wrappers[] = {40, 37, 55, 59, 53, 58};
    for (int depth = 0; depth < 4; depth++) {
        if (wa_pb_get_bytes(m, ml, 31, &d, &dl) && wa_pb_get_bytes(d, dl, 2, &d, &dl)) {
            m = d, ml = dl;
            continue;
        }
        bool unwrapped = false;
        for (size_t i = 0; i < sizeof wrappers / sizeof *wrappers; i++)
            if (wa_pb_get_bytes(m, ml, wrappers[i], &d, &dl) && wa_pb_get_bytes(d, dl, 1, &d, &dl)) {
                m = d, ml = dl;
                unwrapped = true;
                break;
            }
        if (!unwrapped) break;
    }
    *text = NULL;
    if (wa_pb_get_bytes(m, ml, 1, &s, &sl)) {
        *kind = "text";
        *text = dupn(s, sl);
    } else if ((sl = sub_str(m, ml, 6, 1, &s)) || wa_pb_get_bytes(m, ml, 6, &d, &dl)) {
        *kind = "text";
        *text = dupn(s ? s : (const uint8_t *)"", sl);
    } else if (wa_pb_get_bytes(m, ml, 3, &d, &dl)) {
        *kind = "image";
        sl = sub_str(m, ml, 3, 3, &s);
        *text = label("[photo]", s, sl);
    } else if (wa_pb_get_bytes(m, ml, 9, &d, &dl)) {
        *kind = "video";
        sl = sub_str(m, ml, 9, 7, &s);
        *text = label("[video]", s, sl);
    } else if (wa_pb_get_bytes(m, ml, 66, &d, &dl)) {
        *kind = "video";
        *text = label("[video note]", NULL, 0);
    } else if (wa_pb_get_bytes(m, ml, 8, &d, &dl)) {
        uint64_t ptt = 0;
        wa_pb_get_varint(d, dl, 6, &ptt);
        *kind = "audio";
        *text = label(ptt ? "[voice message]" : "[audio]", NULL, 0);
    } else if (wa_pb_get_bytes(m, ml, 26, &d, &dl)) {
        *kind = "sticker";
        *text = label("[sticker]", NULL, 0);
    } else if (wa_pb_get_bytes(m, ml, 7, &d, &dl)) {
        *kind = "document";
        if (!(sl = sub_str(m, ml, 7, 8, &s))) sl = sub_str(m, ml, 7, 3, &s);
        *text = label("[document]", s, sl);
    } else if (wa_pb_get_bytes(m, ml, 5, &d, &dl)) {
        *kind = "location";
        sl = sub_str(m, ml, 5, 3, &s);
        *text = label("[location]", s, sl);
    } else if (wa_pb_get_bytes(m, ml, 18, &d, &dl)) {
        *kind = "location";
        *text = label("[live location]", NULL, 0);
    } else if (wa_pb_get_bytes(m, ml, 4, &d, &dl)) {
        *kind = "contact";
        sl = sub_str(m, ml, 4, 1, &s);
        *text = label("[contact]", s, sl);
    } else if (wa_pb_get_bytes(m, ml, 13, &d, &dl)) {
        *kind = "contact";
        *text = label("[contacts]", NULL, 0);
    } else if (wa_pb_get_bytes(m, ml, 46, &d, &dl)) {
        *kind = "reaction";
        sl = sub_str(m, ml, 46, 2, &s);
        *text = sl ? label("reacted", s, sl) : label("removed a reaction", NULL, 0);
    } else if (wa_pb_get_bytes(m, ml, 49, &d, &dl) || wa_pb_get_bytes(m, ml, 60, &d, &dl) ||
               wa_pb_get_bytes(m, ml, 64, &d, &dl)) {
        *kind = "poll";
        if (!wa_pb_get_bytes(d, dl, 2, &s, &sl)) s = NULL, sl = 0;
        *text = label("[poll]", s, sl);
    } else {
        // Only protocol parts (sender keys 2, protocolMessage 12, context 35)?
        wa_pb_reader r = {m, m + ml};
        wa_pb_field f;
        bool other = false;
        int rc;
        while ((rc = wa_pb_next(&r, &f)) == 1)
            if (f.field != 2 && f.field != 12 && f.field != 15 && f.field != 35) other = true;
        *kind = other ? "other" : "protocol";
        if (other) *text = label("[unsupported message]", NULL, 0);
    }
}

// ---------------------------------------------------------------- receiving

typedef struct {
    bool is_group, from_me;
    const wa_jid *chat_jid, *sender_jid;
    wa_jid chat_nonad, enc;
    char chat[96], sender[96], enc_addr[96];
} msg_source;

static wa_jid non_ad(const wa_jid *j) {
    wa_jid r = *j;
    r.agent = 0;
    r.device = 0;
    return r;
}

static bool is_own(wa_client *c, const wa_jid *j) {
    return j->user && j->user[0] &&
           (strcmp(j->user, c->store->user) == 0 || (c->store->lid_user[0] && strcmp(j->user, c->store->lid_user) == 0));
}

// message.go parseMessageSource, then decryptMessages' choice of the
// encryption identity: a phone-number sender with a known LID decrypts as the LID.
static int parse_source(wa_client *c, const wa_node *n, msg_source *src) {
    memset(src, 0, sizeof *src);
    const wa_jid *from = wa_attr_jid(n, "from");
    if (!from) return -1;
    const char *mode = wa_attr_str(n, "addressing_mode");
    const wa_jid *alt = NULL;
    if (strcmp(from->server, "g.us") == 0 || strcmp(from->server, "broadcast") == 0) {
        src->is_group = true;
        src->chat_jid = from;
        src->sender_jid = wa_attr_jid(n, "participant");
        if (!src->sender_jid) return -1;
        alt = wa_attr_jid(n, "participant_pn");
        if (!alt && !(mode && strcmp(mode, "lid") == 0)) alt = wa_attr_jid(n, "participant_lid");
        src->from_me = is_own(c, src->sender_jid);
    } else if (is_own(c, from)) {
        src->from_me = true;
        src->sender_jid = from;
        src->chat_jid = wa_attr_jid(n, "recipient");
        if (!src->chat_jid) {
            src->chat_nonad = non_ad(from);
            src->chat_jid = &src->chat_nonad;
        }
    } else {
        src->sender_jid = from;
        src->chat_nonad = non_ad(from);
        src->chat_jid = &src->chat_nonad;
        if (strcmp(from->server, "lid") != 0) alt = wa_attr_jid(n, "sender_lid");
    }
    src->enc = *src->sender_jid;
    if (strcmp(src->sender_jid->server, "s.whatsapp.net") == 0 && alt && strcmp(alt->server, "lid") == 0) {
        src->enc = *alt;
        if (!src->enc.device) src->enc.device = src->sender_jid->device;
    }
    wa_jid_str(src->chat_jid, src->chat, sizeof src->chat);
    wa_jid_str(src->sender_jid, src->sender, sizeof src->sender);
    wa_jid_str(&src->enc, src->enc_addr, sizeof src->enc_addr);
    return 0;
}

static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    for (; *s; s++) h = (h ^ (uint8_t)*s) * 16777619u;
    return h;
}

// retry.go sendRetryReceipt: ask the sender to re-encrypt. From the second
// try on, include our keys so the sender can start a fresh session.
static void send_retry_receipt(wa_client *c, const wa_node *n, const msg_source *src) {
    const char *id = wa_attr_str(n, "id");
    if (!id) return;
    uint32_t h = fnv1a(id);
    int slot = -1;
    for (int i = 0; i < 16; i++)
        if (c->retries[i].count && c->retries[i].id_hash == h) slot = i;
    if (slot < 0) {
        slot = c->retry_next++ % 16;
        c->retries[slot].id_hash = h;
        c->retries[slot].count = 0;
        const wa_node *enc = wa_child(n, "enc");
        const char *cnt = enc ? wa_attr_str(enc, "count") : NULL;
        if (cnt) c->retries[slot].count = (uint8_t)atoi(cnt);  // a retry of a retry after a restart
    }
    int count = ++c->retries[slot].count;
    if (count >= 5) {
        wa__log(c, "not sending more retry receipts for %s", id);
        return;
    }
    wa_store *st = c->store;
    char cs[8];
    snprintf(cs, sizeof cs, "%d", count);
    uint8_t reg[4] = {st->reg_id >> 24, st->reg_id >> 16, st->reg_id >> 8, st->reg_id};
    wa_attr rattrs[4];
    size_t nr = 0;
    rattrs[nr++] = (wa_attr){"count", wa_vstr(cs)};
    rattrs[nr++] = (wa_attr){"id", wa_vstr(id)};
    copy_attr(rattrs, &nr, n, "t");
    rattrs[nr++] = (wa_attr){"v", wa_vstr("1")};
    wa_node content[3];
    size_t nc = 0;
    content[nc++] = (wa_node){"retry", rattrs, nr, {0}};
    content[nc++] = (wa_node){"registration", NULL, 0, wa_vbytes(reg, 4)};

    wa_prekey_pub pk;
    uint8_t type = 0x05, pkid[3], skid[3];
    wa_node pk_kids[2], sk_kids[3], keys[5];
    wa_sig s = sig_of(c);
    if (count > 1 && have_kv(c) && wa_sig_prekeys_generate(&s, 1, &pk) == 1) {
        be24(pk.id, pkid);
        be24(st->spk_id, skid);
        pk_kids[0] = (wa_node){"id", NULL, 0, wa_vbytes(pkid, 3)};
        pk_kids[1] = (wa_node){"value", NULL, 0, wa_vbytes(pk.pub, 32)};
        sk_kids[0] = (wa_node){"id", NULL, 0, wa_vbytes(skid, 3)};
        sk_kids[1] = (wa_node){"value", NULL, 0, wa_vbytes(st->spk_pub, 32)};
        sk_kids[2] = (wa_node){"signature", NULL, 0, wa_vbytes(st->spk_sig, 64)};
        keys[0] = (wa_node){"type", NULL, 0, wa_vbytes(&type, 1)};
        keys[1] = (wa_node){"identity", NULL, 0, wa_vbytes(st->ident_pub, 32)};
        keys[2] = (wa_node){"key", NULL, 0, wa_vlist(pk_kids, 2)};
        keys[3] = (wa_node){"skey", NULL, 0, wa_vlist(sk_kids, 3)};
        keys[4] = (wa_node){"device-identity", NULL, 0, wa_vbytes(st->account, st->account_len)};
        content[nc++] = (wa_node){"keys", NULL, 0, wa_vlist(keys, 5)};
    }

    wa_attr attrs[6];
    size_t na = 0;
    attrs[na++] = (wa_attr){"id", wa_vstr(id)};
    const wa_value *from = wa_attr_get(n, "from");
    if (from) attrs[na++] = (wa_attr){"to", *from};
    copy_attr(attrs, &na, n, "recipient");
    copy_attr(attrs, &na, n, "participant");
    attrs[na++] = (wa_attr){"type", wa_vstr("retry")};
    const char *mtype = wa_attr_str(n, "type");
    if (src->from_me && mtype && strcmp(mtype, "peer_msg") == 0) attrs[na++] = (wa_attr){"category", wa_vstr("peer")};
    wa_node receipt = {"receipt", attrs, na, wa_vlist(content, nc)};
    wa_client_send_node(c, &receipt);
}

// receipt.go sendMessageReceipt: "inactive" delivery receipts (we never send
// read receipts), "sender" for our own messages from other devices.
static void send_message_receipt(wa_client *c, const wa_node *n, const msg_source *src) {
    wa_attr attrs[5];
    size_t na = 0;
    copy_attr(attrs, &na, n, "id");
    const wa_value *from = wa_attr_get(n, "from");
    if (from) attrs[na++] = (wa_attr){"to", *from};
    copy_attr(attrs, &na, n, "recipient");
    copy_attr(attrs, &na, n, "participant");
    const char *mtype = wa_attr_str(n, "type");
    if (src->from_me)
        attrs[na++] = (wa_attr){"type", wa_vstr(mtype && strcmp(mtype, "peer_msg") == 0 ? "peer_msg" : "sender")};
    else
        attrs[na++] = (wa_attr){"type", wa_vstr("inactive")};
    wa_node receipt = {"receipt", attrs, na, {0}};
    wa_client_send_node(c, &receipt);
}

// receipt.go sendProtocolMessageReceipt: the phone waits for a "hist_sync"
// receipt for each history sync notification before it finishes linking (its
// "Logging in" spinner) and sends the next chunk. We don't download the
// history itself, only acknowledge it.
static void send_hist_sync_receipt(wa_client *c, const wa_node *n) {
    const char *id = wa_attr_str(n, "id");
    if (!id || !c->store->user[0]) return;
    wa_jid to = {.user = c->store->user, .server = "c.us"};
    wa_attr attrs[] = {{"id", wa_vstr(id)}, {"type", wa_vstr("hist_sync")}, {"to", wa_vjid(to)}};
    wa_node receipt = {"receipt", attrs, 3, {0}};
    wa_client_send_node(c, &receipt);
}

static void fill_msg(wa_message *m, const wa_node *n, const msg_source *src) {
    memset(m, 0, sizeof *m);
    m->id = wa_attr_str(n, "id");
    m->chat = src->chat;
    m->sender = src->sender;
    m->push_name = wa_attr_str(n, "notify");
    const char *t = wa_attr_str(n, "t");
    m->timestamp = t ? strtoll(t, NULL, 10) : 0;
    m->from_me = src->from_me;
    m->is_group = src->is_group;
}

// Handle one decrypted, unpadded waE2E.Message. Returns false if it is not a
// valid protobuf.
static bool handle_plaintext(wa_client *c, const wa_node *n, const msg_source *src, const uint8_t *pt, size_t len) {
    wa_pb_reader r = {pt, pt + len};
    wa_pb_field f;
    int rc;
    do rc = wa_pb_next(&r, &f);
    while (rc == 1);
    if (rc < 0) return false;

    // processProtocolParts: sender keys, possibly inside a DeviceSentMessage.
    const uint8_t *m = pt, *d, *skdm, *axo;
    size_t ml = len, dl, skdml, axol;
    if (wa_pb_get_bytes(m, ml, 31, &d, &dl) && wa_pb_get_bytes(d, dl, 2, &d, &dl)) m = d, ml = dl;
    if (wa_pb_get_bytes(m, ml, 2, &skdm, &skdml) && wa_pb_get_bytes(skdm, skdml, 2, &axo, &axol)) {
        if (!src->is_group) {
            wa__log(c, "sender key distribution outside a group from %s, ignored", src->sender);
        } else {
            wa_sig s = sig_of(c);
            int src_rc = wa_sig_group_process(&s, src->chat, src->enc_addr, axo, axol);
            wa__log(c, "sender key from %s in %s: %s", src->enc_addr, src->chat, wa_sig_strerror(src_rc));
        }
    }

    // protocolMessage (12) carrying a historySyncNotification (6) from our phone.
    const uint8_t *proto, *hsn;
    size_t protol, hsnl;
    if (src->from_me && wa_pb_get_bytes(pt, len, 12, &proto, &protol) && wa_pb_get_bytes(proto, protol, 6, &hsn, &hsnl)) {
        wa__log(c, "history sync notification %s, acknowledging", wa_attr_str(n, "id"));
        send_hist_sync_receipt(c, n);
    }

    const char *kind = NULL;
    char *text = NULL;
    render(pt, len, &kind, &text);
    if (strcmp(kind, "protocol") != 0) {
        wa_message msg;
        fill_msg(&msg, n, src);
        msg.kind = kind;
        msg.text = text;
        wa_event ev = {WA_EV_MESSAGE, text, 0, n, &msg};
        wa__emit(c, &ev);
    }
    free(text);
    return true;
}

// message.go handleEncryptedMessage + decryptMessages.
bool wa__handle_message(wa_client *c, const wa_node *n) {
    msg_source src;
    if (parse_source(c, n, &src)) {
        wa__log(c, "message without a usable sender");
        wa__send_ack(c, n, 487);  // NackParsingError
        return true;
    }
    if (!have_kv(c)) {
        wa__send_ack(c, n, 0);
        return true;
    }
    const wa_node *kids;
    size_t nk = wa_children(n, &kids);
    bool recognized = false, proto_failed = false;
    wa_sig s = sig_of(c);
    for (size_t i = 0; i < nk; i++) {
        const wa_node *enc = &kids[i];
        if (strcmp(enc->tag, "enc") != 0) continue;
        recognized = true;
        const char *type = wa_attr_str(enc, "type");
        if (!type || enc->content.type != WA_V_BYTES) continue;
        const uint8_t *ct = enc->content.bytes.data;
        size_t ctl = enc->content.bytes.len;
        uint8_t *pt = NULL;
        size_t ptl = 0;
        int rc;
        if (strcmp(type, "pkmsg") == 0 || strcmp(type, "msg") == 0) {
            rc = wa_sig_decrypt(&s, src.enc_addr, type[0] == 'p', ct, ctl, &pt, &ptl);
        } else if (strcmp(type, "skmsg") == 0 && src.is_group) {
            rc = wa_sig_group_decrypt(&s, src.chat, src.enc_addr, ct, ctl, &pt, &ptl);
        } else {
            wa__log(c, "unhandled <enc type=%s> from %s", type, src.sender);
            continue;
        }
        if (rc == WA_SIG_DUPLICATE) {
            wa__log(c, "ignoring already-decrypted %s from %s", type, src.enc_addr);
            continue;
        }
        if (rc != WA_SIG_OK) {
            const char *id = wa_attr_str(n, "id");
            wa__log(c, "cannot decrypt %s %s from %s: %s", type, id ? id : "?", src.enc_addr, wa_sig_strerror(rc));
            wa_message msg;
            fill_msg(&msg, n, &src);
            wa_event ev = {WA_EV_UNDECRYPTABLE, wa_sig_strerror(rc), 0, n, &msg};
            wa__emit(c, &ev);
            send_retry_receipt(c, n, &src);
            wa__send_ack(c, n, 0);
            return true;
        }
        const char *v = wa_attr_str(enc, "v");
        if (v && strcmp(v, "3") == 0) {
            wa__log(c, "skipping a v3 (armadillo) message from %s", src.sender);
        } else {
            long ul = wa_unpad(pt, ptl);
            if (ul < 0 || !handle_plaintext(c, n, &src, pt, (size_t)ul)) {
                wa__log(c, "bad plaintext in %s from %s", type, src.sender);
                proto_failed = true;
            } else {
                proto_failed = false;
            }
        }
        free(pt);
    }
    if (!recognized)
        wa__send_ack(c, n, NACK_UNRECOGNIZED_STANZA);
    else if (proto_failed)
        wa__send_ack(c, n, NACK_INVALID_PROTOBUF);
    else
        send_message_receipt(c, n, &src);
    return true;
}
