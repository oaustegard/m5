// SPDX-License-Identifier: MPL-2.0
// Sending text messages to people and groups. Ported from whatsmeow
// (https://github.com/tulir/whatsmeow): send.go SendMessage, sendDM,
// sendGroup, prepareMessageNode, marshalMessage, participantListHashV2 and
// encryptMessageForDevices; group.go getGroupInfo and parseParticipant;
// user.go usync, GetUserInfo and GetUserDevices; prekeys.go fetchPreKeys and
// nodeToPreKeyBundle. Copyright (c) 2021-2026 Tulir Asokan; C port for the Core2.
//
// whatsmeow blocks on each request; this core is event driven, so a send is a
// small state machine on c->out, advanced by the iq responses and the server's
// <ack>. One send runs at a time:
//
//   phone number -> LID   usync (only when the LID is not cached)
//   group members         <iq xmlns=w:g2 type=get> (groups only)
//   device lists          usync for the recipient (or the members) and ourselves
//   prekey bundles        <iq xmlns=encrypt type=get> for devices without a session
//   <message>             one <enc> per device; then wait for the server's <ack>
//
// Like current whatsmeow, a message to a phone number is addressed to the
// recipient's LID, with peer_recipient_pn naming the number.
//
// A group message is encrypted once with our sender key (<enc type=skmsg>);
// every member device, our own included, gets the sender key distribution
// message through its 1:1 session. Like whatsmeow, every send carries it.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_crypto.h"
#include "wa_internal.h"
#include "wa_pb.h"
#include "wa_signal.h"

enum { OUT_IDLE, OUT_LID, OUT_GROUP, OUT_DEVICES, OUT_PREKEYS, OUT_ACK };

#define STAGE_TIMEOUT_MS 20000

static wa_sig sig_of(wa_client *c) {
    wa_sig s = {c->store, c->cb.kv};
    return s;
}

static void out_reset(wa_client *c) {
    free(c->out.text);
    memset(&c->out, 0, sizeof c->out);
}

static void out_fail(wa_client *c, const char *why) {
    if (c->out.stage == OUT_IDLE) return;
    wa__log(c, "send %s failed: %s", c->out.id, why);
    out_reset(c);
    wa_event ev = {WA_EV_SEND_FAILED, why, 0, NULL, NULL};
    wa__emit(c, &ev);
}

void wa__send_abort(wa_client *c, const char *why) { out_fail(c, why); }

void wa__send_tick(wa_client *c, uint64_t now) {
    if (c->out.stage != OUT_IDLE && now >= c->out.deadline_ms) out_fail(c, "timed out");
}

static void stage(wa_client *c, int s) {
    c->out.stage = (uint8_t)s;
    c->out.deadline_ms = c->cb.now_ms(c->cb.ctx) + STAGE_TIMEOUT_MS;
}

// ---------------------------------------------------------------- LID cache

void wa__lid_learn(wa_client *c, const char *pn, const char *lid) {
    if (!pn || !lid || !pn[0] || !lid[0] || strlen(pn) >= sizeof c->lids[0].pn || strlen(lid) >= sizeof c->lids[0].lid)
        return;
    for (int i = 0; i < WA_LID_CACHE; i++)
        if (strcmp(c->lids[i].pn, pn) == 0) {
            snprintf(c->lids[i].lid, sizeof c->lids[i].lid, "%s", lid);
            return;
        }
    int i = c->lid_next++ % WA_LID_CACHE;
    snprintf(c->lids[i].pn, sizeof c->lids[i].pn, "%s", pn);
    snprintf(c->lids[i].lid, sizeof c->lids[i].lid, "%s", lid);
}

static const char *lid_for(wa_client *c, const char *pn) {
    if (strcmp(pn, c->store->user) == 0 && c->store->lid_user[0]) return c->store->lid_user;
    for (int i = 0; i < WA_LID_CACHE; i++)
        if (c->lids[i].pn[0] && strcmp(c->lids[i].pn, pn) == 0) return c->lids[i].lid;
    return NULL;
}

// ---------------------------------------------------------------- requests

static wa_jid lid_jid(const char *user, uint16_t device) {
    wa_jid j = {.user = user, .server = "lid", .device = device};
    return j;
}

// user.go usync: <iq xmlns=usync type=get><usync sid mode last index context>
// <query>...</query><list><user jid/>...</list></usync></iq>
static int send_usync(wa_client *c, const char *mode, const char *context, wa_node *query, size_t nq,
                      wa_node *users, size_t nu) {
    snprintf(c->out.iq_id, sizeof c->out.iq_id, "%s", wa_client_next_id(c));
    char sid[24];
    snprintf(sid, sizeof sid, "%s", wa_client_next_id(c));
    wa_attr uattrs[] = {{"sid", wa_vstr(sid)},
                        {"mode", wa_vstr(mode)},
                        {"last", wa_vstr("true")},
                        {"index", wa_vstr("0")},
                        {"context", wa_vstr(context)}};
    wa_node parts[] = {{"query", NULL, 0, wa_vlist(query, nq)}, {"list", NULL, 0, wa_vlist(users, nu)}};
    wa_node usync = {"usync", uattrs, 5, wa_vlist(parts, 2)};
    wa_attr attrs[] = {{"id", wa_vstr(c->out.iq_id)},
                       {"xmlns", wa_vstr("usync")},
                       {"type", wa_vstr("get")},
                       {"to", wa_vjid(WA_SERVER_JID)}};
    wa_node iq = {"iq", attrs, 4, wa_vlist(&usync, 1)};
    return wa_client_send_node(c, &iq);
}

// GetUserInfo, for its <lid val=...>.
static void query_lid(wa_client *c) {
    wa_node verified = {"verified_name", NULL, 0, {0}};
    wa_attr dattrs[] = {{"version", wa_vstr("2")}};
    wa_node query[] = {{"business", NULL, 0, wa_vlist(&verified, 1)},
                       {"status", NULL, 0, {0}},
                       {"picture", NULL, 0, {0}},
                       {"devices", dattrs, 1, {0}},
                       {"lid", NULL, 0, {0}}};
    wa_jid pn = {.user = c->out.pn, .server = "s.whatsapp.net"};
    wa_attr uattrs[] = {{"jid", wa_vjid(pn)}};
    wa_node user = {"user", uattrs, 1, {0}};
    stage(c, OUT_LID);
    if (send_usync(c, "full", "background", query, 5, &user, 1)) out_fail(c, "could not send the LID query");
}

// GetUserDevices for the recipient (or the group's members) and our own account.
static void query_devices(wa_client *c) {
    wa_attr dattrs[] = {{"version", wa_vstr("2")}};
    wa_node query = {"devices", dattrs, 1, {0}};
    wa_attr uattrs[WA_GROUP_MAX_MEMBERS + 1][1];
    wa_node users[WA_GROUP_MAX_MEMBERS + 1];
    size_t n = 0;
    if (c->out.group[0]) {
        for (int i = 0; i < c->out.nmembers; i++) {
            uattrs[n][0] = (wa_attr){"jid", wa_vjid(lid_jid(c->out.members[i], 0))};
            users[n] = (wa_node){"user", uattrs[n], 1, {0}};
            n++;
        }
    } else {
        uattrs[n][0] = (wa_attr){"jid", wa_vjid(lid_jid(c->out.to_lid, 0))};
        users[n] = (wa_node){"user", uattrs[n], 1, {0}};
        n++;
        if (strcmp(c->out.to_lid, c->store->lid_user) != 0) {
            uattrs[n][0] = (wa_attr){"jid", wa_vjid(lid_jid(c->store->lid_user, 0))};
            users[n] = (wa_node){"user", uattrs[n], 1, {0}};
            n++;
        }
    }
    stage(c, OUT_DEVICES);
    if (send_usync(c, "query", "message", &query, 1, users, n)) out_fail(c, "could not send the device query");
}

// group.go getGroupInfo: <iq xmlns=w:g2 type=get to=<group>><query request=interactive/></iq>
static void query_group(wa_client *c) {
    snprintf(c->out.iq_id, sizeof c->out.iq_id, "%s", wa_client_next_id(c));
    const char *at = strchr(c->out.group, '@');
    char user[48];
    snprintf(user, sizeof user, "%.*s", (int)(at - c->out.group), c->out.group);
    wa_jid g = {.user = user, .server = "g.us"};
    wa_attr qattrs[] = {{"request", wa_vstr("interactive")}};
    wa_node query = {"query", qattrs, 1, {0}};
    wa_attr attrs[] = {{"id", wa_vstr(c->out.iq_id)},
                       {"xmlns", wa_vstr("w:g2")},
                       {"type", wa_vstr("get")},
                       {"to", wa_vjid(g)}};
    wa_node iq = {"iq", attrs, 4, wa_vlist(&query, 1)};
    stage(c, OUT_GROUP);
    if (wa_client_send_node(c, &iq)) out_fail(c, "could not send the group query");
}

static const char *dev_addr(wa_client *c, int i, char *buf, size_t n) {
    wa_jid j = lid_jid(c->out.dev[i].user, c->out.dev[i].device);
    return wa_jid_str(&j, buf, n);
}

static void encrypt_and_send(wa_client *c);

// prekeys.go fetchPreKeys for the devices we have no session with.
static void fetch_prekeys(wa_client *c) {
    wa_sig s = sig_of(c);
    wa_attr attrs[WA_SEND_MAX_DEVICES][2];
    wa_node users[WA_SEND_MAX_DEVICES];
    size_t n = 0;
    for (int i = 0; i < c->out.ndev; i++) {
        char addr[64];
        int rc = wa_sig_has_session(&s, dev_addr(c, i, addr, sizeof addr));
        if (rc < 0) return out_fail(c, wa_sig_strerror(rc));
        if (rc) continue;
        attrs[n][0] = (wa_attr){"jid", wa_vjid(lid_jid(c->out.dev[i].user, c->out.dev[i].device))};
        attrs[n][1] = (wa_attr){"reason", wa_vstr("identity")};
        users[n] = (wa_node){"user", attrs[n], 2, {0}};
        n++;
    }
    if (!n) return encrypt_and_send(c);
    wa__log(c, "send %s: fetching prekeys for %zu device(s)", c->out.id, n);
    snprintf(c->out.iq_id, sizeof c->out.iq_id, "%s", wa_client_next_id(c));
    wa_node key = {"key", NULL, 0, wa_vlist(users, n)};
    wa_attr iattrs[] = {{"id", wa_vstr(c->out.iq_id)},
                        {"xmlns", wa_vstr("encrypt")},
                        {"type", wa_vstr("get")},
                        {"to", wa_vjid(WA_SERVER_JID)}};
    wa_node iq = {"iq", iattrs, 4, wa_vlist(&key, 1)};
    stage(c, OUT_PREKEYS);
    if (wa_client_send_node(c, &iq)) out_fail(c, "could not send the prekey request");
}

// ---------------------------------------------------------------- responses

static const wa_node *usync_list(const wa_node *iq) {
    const wa_node *u = wa_child(iq, "usync");
    return u ? wa_child(u, "list") : NULL;
}

static void on_lid(wa_client *c, const wa_node *iq) {
    const wa_node *list = usync_list(iq), *users;
    size_t nu = list ? wa_children(list, &users) : 0;
    for (size_t i = 0; i < nu; i++) {
        const wa_jid *jid = wa_attr_jid(&users[i], "jid");
        const wa_node *lid = wa_child(&users[i], "lid");
        const wa_jid *val = lid ? wa_attr_jid(lid, "val") : NULL;
        if (strcmp(users[i].tag, "user") || !jid || !val || strcmp(val->server, "lid")) continue;
        wa__lid_learn(c, jid->user, val->user);
        if (strcmp(jid->user, c->out.pn) == 0) {
            snprintf(c->out.to_lid, sizeof c->out.to_lid, "%s", val->user);
            return query_devices(c);
        }
    }
    out_fail(c, "not on WhatsApp (no LID)");
}

// group.go parseGroupNode and parseParticipant: the members' LIDs.
static void on_group(wa_client *c, const wa_node *iq) {
    const wa_node *g = wa_child(iq, "group"), *kids;
    if (!g) return out_fail(c, "no group in the answer");
    const char *mode = wa_attr_str(g, "addressing_mode");
    if (!mode || strcmp(mode, "lid") != 0) return out_fail(c, "group uses phone-number addressing (unsupported)");
    size_t nk = wa_children(g, &kids);
    c->out.nmembers = 0;
    bool self = false;
    for (size_t i = 0; i < nk; i++) {
        const wa_jid *jid = wa_attr_jid(&kids[i], "jid");
        if (strcmp(kids[i].tag, "participant") || !jid || strcmp(jid->server, "lid") ||
            strlen(jid->user) >= sizeof c->out.members[0])
            continue;
        if (c->out.nmembers == WA_GROUP_MAX_MEMBERS) return out_fail(c, "group has too many members");
        snprintf(c->out.members[c->out.nmembers++], sizeof c->out.members[0], "%s", jid->user);
        self |= strcmp(jid->user, c->store->lid_user) == 0;
    }
    if (!self) {
        if (c->out.nmembers == WA_GROUP_MAX_MEMBERS) return out_fail(c, "group has too many members");
        snprintf(c->out.members[c->out.nmembers++], sizeof c->out.members[0], "%s", c->store->lid_user);
    }
    wa__log(c, "send %s: group has %d member(s)", c->out.id, c->out.nmembers);
    query_devices(c);
}

// user.go parseDeviceList, keeping everything but ourselves and hosted devices.
static void on_devices(wa_client *c, const wa_node *iq) {
    const wa_node *list = usync_list(iq), *users;
    size_t nu = list ? wa_children(list, &users) : 0;
    c->out.ndev = 0;
    for (size_t i = 0; i < nu; i++) {
        const wa_jid *jid = wa_attr_jid(&users[i], "jid");
        const wa_node *devs = wa_child(&users[i], "devices");
        const wa_node *dl = devs ? wa_child(devs, "device-list") : NULL, *items;
        if (strcmp(users[i].tag, "user") || !jid || !dl) continue;
        bool own = strcmp(jid->user, c->store->lid_user) == 0;
        size_t nd = wa_children(dl, &items);
        for (size_t k = 0; k < nd; k++) {
            const char *id = wa_attr_str(&items[k], "id");
            const char *hosted = wa_attr_str(&items[k], "is_hosted");
            if (strcmp(items[k].tag, "device") || !id) continue;
            long d = strtol(id, NULL, 10);
            if (d < 0 || d > 255) continue;
            if (own && d == c->store->device) continue;
            if (hosted && strcmp(hosted, "true") == 0) {
                wa__log(c, "send %s: skipping hosted device %s:%ld", c->out.id, jid->user, d);
                continue;
            }
            if (c->out.ndev == WA_SEND_MAX_DEVICES) {
                wa__log(c, "send %s: more than %d devices, skipping the rest", c->out.id, WA_SEND_MAX_DEVICES);
                break;
            }
            snprintf(c->out.dev[c->out.ndev].user, sizeof c->out.dev[0].user, "%s", jid->user);
            c->out.dev[c->out.ndev].device = (uint16_t)d;
            c->out.ndev++;
        }
    }
    wa__log(c, "send %s: %d device(s)", c->out.id, c->out.ndev);
    if (!c->out.ndev) return out_fail(c, "no devices to send to");
    fetch_prekeys(c);
}

static const uint8_t *child_bytes(const wa_node *n, const char *tag, size_t want) {
    const wa_node *k = n ? wa_child(n, tag) : NULL;
    if (!k || k->content.type != WA_V_BYTES || k->content.bytes.len != want) return NULL;
    return k->content.bytes.data;
}

static uint32_t be(const uint8_t *p, int n) {
    uint32_t v = 0;
    for (int i = 0; i < n; i++) v = v << 8 | p[i];
    return v;
}

// prekeys.go nodeToPreKeyBundle.
static int parse_bundle(const wa_node *user, wa_prekey_bundle *b) {
    memset(b, 0, sizeof *b);
    if (wa_child(user, "error")) return -1;
    const uint8_t *reg = child_bytes(user, "registration", 4);
    const wa_node *keys = wa_child(user, "keys");
    if (!keys) keys = user;
    const uint8_t *ident = child_bytes(keys, "identity", 32);
    const wa_node *skey = wa_child(keys, "skey");
    const uint8_t *sid = child_bytes(skey, "id", 3), *spk = child_bytes(skey, "value", 32),
                  *sig = child_bytes(skey, "signature", 64);
    if (!reg || !ident || !sid || !spk || !sig) return -1;
    b->reg_id = be(reg, 4);
    memcpy(b->ident, ident, 32);
    b->spk_id = be(sid, 3);
    memcpy(b->spk, spk, 32);
    memcpy(b->spk_sig, sig, 64);
    const wa_node *key = wa_child(keys, "key");
    if (key) {
        const uint8_t *oid = child_bytes(key, "id", 3), *opk = child_bytes(key, "value", 32);
        if (!oid || !opk) return -1;
        b->has_opk = true;
        b->opk_id = be(oid, 3);
        memcpy(b->opk, opk, 32);
    }
    return 0;
}

static void on_prekeys(wa_client *c, const wa_node *iq) {
    wa_sig s = sig_of(c);
    const wa_node *list = wa_child(iq, "list"), *users;
    size_t nu = list ? wa_children(list, &users) : 0;
    for (size_t i = 0; i < nu; i++) {
        const wa_jid *jid = wa_attr_jid(&users[i], "jid");
        if (strcmp(users[i].tag, "user") || !jid) continue;
        char addr[64];
        wa_jid_str(jid, addr, sizeof addr);
        wa_prekey_bundle b;
        if (parse_bundle(&users[i], &b)) {
            wa__log(c, "send %s: no usable prekeys for %s", c->out.id, addr);
            continue;
        }
        int rc = wa_sig_process_bundle(&s, addr, &b);
        if (rc) wa__log(c, "send %s: prekey bundle for %s: %s", c->out.id, addr, wa_sig_strerror(rc));
    }
    encrypt_and_send(c);
}

bool wa__send_handle_iq(wa_client *c, const wa_node *n) {
    const char *id = wa_attr_str(n, "id");
    if (c->out.stage == OUT_IDLE || c->out.stage == OUT_ACK || !id || strcmp(id, c->out.iq_id) != 0) return false;
    c->out.iq_id[0] = 0;
    const char *type = wa_attr_str(n, "type");
    if (!type || strcmp(type, "result") != 0) {
        const wa_node *err = wa_child(n, "error");
        const char *code = err ? wa_attr_str(err, "code") : NULL;
        char why[48];
        snprintf(why, sizeof why, "server refused the %s query (%s)",
                 c->out.stage == OUT_PREKEYS ? "prekey" : c->out.stage == OUT_GROUP ? "group" : "user",
                 code ? code : "error");
        out_fail(c, why);
        return true;
    }
    switch (c->out.stage) {
        case OUT_LID: on_lid(c, n); break;
        case OUT_GROUP: on_group(c, n); break;
        case OUT_DEVICES: on_devices(c, n); break;
        case OUT_PREKEYS: on_prekeys(c, n); break;
    }
    return true;
}

// ---------------------------------------------------------------- the message

// message.go padMessage: 1-15 bytes, each equal to the count.
static void pad(wa_buf *b) {
    uint8_t n;
    wa_random(&n, 1);
    n &= 0xf;
    if (!n) n = 0xf;
    for (int i = 0; i < n; i++) wa_buf_byte(b, n);
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

// send.go participantListHashV2: "2:" + base64(SHA-256(sorted AD strings))[:6 bytes].
static void phash(wa_client *c, char out[16]) {
    char ad[WA_SEND_MAX_DEVICES + 1][48];
    char *p[WA_SEND_MAX_DEVICES + 1];
    int n = 0;
    for (int i = 0; i < c->out.ndev; i++, n++) {
        snprintf(ad[n], sizeof ad[n], "%s.0:%u@lid", c->out.dev[i].user, (unsigned)c->out.dev[i].device);
        p[n] = ad[n];
    }
    snprintf(ad[n], sizeof ad[n], "%s.0:%u@lid", c->store->lid_user, (unsigned)c->store->device);
    p[n] = ad[n];
    n++;
    qsort(p, (size_t)n, sizeof p[0], cmp_str);
    wa_buf all = {0};
    for (int i = 0; i < n; i++) wa_buf_put(&all, p[i], strlen(p[i]));
    uint8_t h[32];
    wa_sha256(all.data, all.len, h);
    wa_buf_free(&all);
    memcpy(out, "2:", 2);
    wa_base64(h, 6, out + 2);
}

static void encrypt_and_send(wa_client *c) {
    wa_sig s = sig_of(c);
    bool group = c->out.group[0] != 0;
    // marshalMessage: Message { conversation=1 } for the recipient, and
    // Message { deviceSentMessage=31 { destinationJid=1, message=2 } } for
    // our own other devices. A group gets the message once, encrypted with
    // our sender key, and every device gets
    // Message { senderKeyDistributionMessage=2 { groupId=1, axolotlSenderKeyDistributionMessage=2 } }.
    wa_buf msg = {0}, dsm = {0}, inner = {0}, plain = {0};
    uint8_t *skmsg = NULL, *skdm = NULL;
    size_t skmsg_len = 0, skdm_len = 0;
    char own_addr[64];
    const char *err = NULL;
    int n = c->out.ndev;
    uint8_t *cts[WA_SEND_MAX_DEVICES] = {0};
    wa_attr to_attrs[WA_SEND_MAX_DEVICES][1], enc_attrs[WA_SEND_MAX_DEVICES][2];
    wa_node encs[WA_SEND_MAX_DEVICES], tos[WA_SEND_MAX_DEVICES];
    size_t nt = 0;
    bool any_prekey = false;
    wa_pb_str(&plain, 1, c->out.text);
    if (group) {
        wa_jid me = lid_jid(c->store->lid_user, c->store->device);
        wa_jid_str(&me, own_addr, sizeof own_addr);
        // The distribution message first: it carries the iteration the
        // encryption below uses.
        int rc = wa_sig_group_skdm(&s, c->out.group, own_addr, &skdm, &skdm_len);
        if (rc) {
            err = wa_sig_strerror(rc);
            goto done;
        }
        wa_buf body = {0};
        wa_buf_put(&body, plain.data, plain.len);
        pad(&body);
        rc = body.oom ? WA_SIG_ERR_NOMEM
                      : wa_sig_group_encrypt(&s, c->out.group, own_addr, body.data, body.len, &skmsg, &skmsg_len);
        wa_buf_free(&body);
        if (rc) {
            err = wa_sig_strerror(rc);
            goto done;
        }
        wa_pb_str(&inner, 1, c->out.group);
        wa_pb_bytes(&inner, 2, skdm, skdm_len);
        wa_pb_msg(&msg, 2, &inner);
        pad(&msg);
    } else {
        wa_buf_put(&msg, plain.data, plain.len);
        pad(&msg);
        char dest[48];
        snprintf(dest, sizeof dest, "%s@lid", c->out.to_lid);
        wa_pb_str(&inner, 1, dest);
        wa_pb_bytes(&inner, 2, plain.data, plain.len);
        wa_pb_msg(&dsm, 31, &inner);
        pad(&dsm);
    }
    if (msg.oom || dsm.oom || plain.oom) {
        err = "out of memory";
        goto done;
    }
    for (int i = 0; i < n; i++) {
        char addr[64];
        dev_addr(c, i, addr, sizeof addr);
        int rc = wa_sig_has_session(&s, addr);
        if (rc <= 0) {
            wa__log(c, "send %s: no session with %s, skipping it", c->out.id, addr);
            continue;
        }
        bool own = strcmp(c->out.dev[i].user, c->store->lid_user) == 0;
        const wa_buf *pt = own && !group ? &dsm : &msg;
        size_t ctl;
        bool prekey;
        rc = wa_sig_encrypt(&s, addr, pt->data, pt->len, &cts[nt], &ctl, &prekey);
        if (rc) {
            wa__log(c, "send %s: encrypting for %s: %s", c->out.id, addr, wa_sig_strerror(rc));
            continue;
        }
        any_prekey |= prekey;
        enc_attrs[nt][0] = (wa_attr){"v", wa_vstr("2")};
        enc_attrs[nt][1] = (wa_attr){"type", wa_vstr(prekey ? "pkmsg" : "msg")};
        encs[nt] = (wa_node){"enc", enc_attrs[nt], 2, wa_vbytes(cts[nt], ctl)};
        to_attrs[nt][0] = (wa_attr){"jid", wa_vjid(lid_jid(c->out.dev[i].user, c->out.dev[i].device))};
        tos[nt] = (wa_node){"to", to_attrs[nt], 1, wa_vlist(&encs[nt], 1)};
        nt++;
    }
    if (!nt) {
        err = "could not encrypt for any device";
        goto done;
    }
    wa_node content[3];
    size_t nc = 0;
    content[nc++] = (wa_node){"participants", NULL, 0, wa_vlist(tos, nt)};
    if (any_prekey)
        content[nc++] = (wa_node){"device-identity", NULL, 0, wa_vbytes(c->store->account, c->store->account_len)};
    wa_attr sk_attrs[] = {{"v", wa_vstr("2")}, {"type", wa_vstr("skmsg")}};
    if (group) content[nc++] = (wa_node){"enc", sk_attrs, 2, wa_vbytes(skmsg, skmsg_len)};
    wa_attr attrs[5];
    size_t na = 0;
    char guser[48], ph[16];
    attrs[na++] = (wa_attr){"id", wa_vstr(c->out.id)};
    attrs[na++] = (wa_attr){"type", wa_vstr("text")};
    if (group) {
        snprintf(guser, sizeof guser, "%.*s", (int)strcspn(c->out.group, "@"), c->out.group);
        wa_jid g = {.user = guser, .server = "g.us"};
        attrs[na++] = (wa_attr){"to", wa_vjid(g)};
        attrs[na++] = (wa_attr){"addressing_mode", wa_vstr("lid")};
        phash(c, ph);
        attrs[na++] = (wa_attr){"phash", wa_vstr(ph)};
    } else {
        attrs[na++] = (wa_attr){"to", wa_vjid(lid_jid(c->out.to_lid, 0))};
        if (c->out.pn[0]) {
            wa_jid pn = {.user = c->out.pn, .server = "s.whatsapp.net"};
            attrs[na++] = (wa_attr){"peer_recipient_pn", wa_vjid(pn)};
        }
    }
    wa_node m = {"message", attrs, na, wa_vlist(content, nc)};
    wa__log(c, "send %s: encrypted for %zu of %d device(s)", c->out.id, nt, n);
    stage(c, OUT_ACK);
    if (wa_client_send_node(c, &m)) err = "could not send the message";
done:
    for (size_t i = 0; i < nt; i++) free(cts[i]);
    free(skmsg);
    free(skdm);
    wa_buf_free(&plain);
    wa_buf_free(&inner);
    wa_buf_free(&msg);
    wa_buf_free(&dsm);
    if (err) out_fail(c, err);
}

// The server's <ack class="message" id=...> for what we sent (SendMessage's
// respNode): an error attribute means it was refused.
bool wa__handle_ack(wa_client *c, const wa_node *n) {
    const char *cls = wa_attr_str(n, "class"), *id = wa_attr_str(n, "id");
    if (c->out.stage != OUT_ACK || !cls || !id || strcmp(cls, "message") || strcmp(id, c->out.id)) return false;
    const char *error = wa_attr_str(n, "error");
    if (error && strcmp(error, "0") != 0) {
        char why[40];
        snprintf(why, sizeof why, "server error %s", error);
        out_fail(c, why);
        return true;
    }
    char sent[sizeof c->out.id];
    snprintf(sent, sizeof sent, "%s", c->out.id);
    wa__log(c, "send %s: delivered to the server", sent);
    out_reset(c);
    wa_event ev = {WA_EV_SENT, sent, 0, n, NULL};
    wa__emit(c, &ev);
    return true;
}

// ---------------------------------------------------------------- public

const char *wa_client_send_text(wa_client *c, const char *to, const char *text) {
    if (!c->logged_in || c->state != WA_S_OPEN || c->out.stage != OUT_IDLE || !c->store->lid_user[0] || !text ||
        !c->cb.kv.get)
        return NULL;
    // A user JID without a device ("<number>@s.whatsapp.net" or "<lid>@lid"),
    // or a group ("<id>@g.us").
    const char *at = strchr(to, '@');
    if (!at || at == to || memchr(to, ':', (size_t)(at - to)) || memchr(to, '.', (size_t)(at - to))) return NULL;
    bool grp = strcmp(at + 1, "g.us") == 0;
    if ((size_t)(at - to) >= (grp ? sizeof c->out.group - 5 : sizeof c->out.to_lid)) return NULL;
    char user[48];
    snprintf(user, sizeof user, "%.*s", (int)(at - to), to);
    bool pn = strcmp(at + 1, "s.whatsapp.net") == 0;
    if (!pn && !grp && strcmp(at + 1, "lid") != 0) return NULL;
    out_reset(c);
    if (!(c->out.text = strdup(text))) return NULL;
    // whatsmeow GenerateMessageID: "3EB0" and 18 upper-case hex digits.
    uint8_t r[9];
    wa_random(r, sizeof r);
    static const char hex[] = "0123456789ABCDEF";
    memcpy(c->out.id, "3EB0", 4);
    for (int i = 0; i < 9; i++) {
        c->out.id[4 + 2 * i] = hex[r[i] >> 4];
        c->out.id[5 + 2 * i] = hex[r[i] & 15];
    }
    c->out.id[22] = 0;
    if (grp) {
        snprintf(c->out.group, sizeof c->out.group, "%.42s@g.us", user);
        query_group(c);
    } else if (pn) {
        snprintf(c->out.pn, sizeof c->out.pn, "%.31s", user);
        const char *lid = lid_for(c, user);
        if (lid) {
            snprintf(c->out.to_lid, sizeof c->out.to_lid, "%s", lid);
            query_devices(c);
        } else {
            query_lid(c);
        }
    } else {
        snprintf(c->out.to_lid, sizeof c->out.to_lid, "%.31s", user);
        query_devices(c);
    }
    wa__log(c, "send %s to %s started", c->out.id, to);
    // A failure while starting has already emitted WA_EV_SEND_FAILED.
    return c->out.stage == OUT_IDLE ? NULL : c->out.id;
}
