// SPDX-License-Identifier: MPL-2.0
// Written from the public X3DH and Double Ratchet specifications
// (signal.org/docs). WhatsApp's wire details (version bytes, KDF info
// strings, MAC layout, sender keys) were checked against go.mau.fi/libsignal,
// the library whatsmeow uses, and host/sigpeer tests this file against it;
// that library is GPL-3.0 and none of its code is copied here. Comments name
// the libsignal function each step corresponds to, for cross-reading.
// The records are fixed-size C structs rather than libsignal's protobufs:
// they only ever round-trip through this file.
#include "wa_signal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_crypto.h"
#include "wa_pb.h"

#define VERSION_BYTE 0x33  // (3 << 4) | 3; libsignal writes strconv.Itoa(3), the same byte
#define MAC_LEN 8
#define SIG_LEN 64
#define MAX_FUTURE 2000  // maxFutureMessages

#define RCHAINS 5   // libsignal maxReceiverChains
#define SKIPPED 12  // skipped message keys kept per session state (libsignal: 2000 per chain)
#define PREV_STATES 2
#define SK_STATES 5  // libsignal groups maxStates
#define SK_SKIPPED 8

#define REC_MAGIC 0x57615332u  // "WaS2" (WaS1 had no pending prekey fields)
#define SK_MAGIC 0x57614731u   // "WaG1"
#define PK_MAGIC 0x57615031u   // "WaP1"

const char *wa_sig_strerror(int rc) {
    switch (rc) {
        case WA_SIG_OK: return "ok";
        case WA_SIG_DUPLICATE: return "duplicate (old counter)";
        case WA_SIG_ERR_INVALID: return "malformed message";
        case WA_SIG_ERR_NO_SESSION: return "no valid session";
        case WA_SIG_ERR_NO_PREKEY: return "unknown prekey";
        case WA_SIG_ERR_BAD_MAC: return "bad MAC or signature";
        case WA_SIG_ERR_NO_SENDER_KEY: return "no sender key";
        case WA_SIG_ERR_FUTURE: return "message too far into the future";
        case WA_SIG_ERR_STORE: return "key store failure";
        case WA_SIG_ERR_NOMEM: return "out of memory";
    }
    return "unknown error";
}

// ---------------------------------------------------------------- records

typedef struct {
    uint8_t ratchet[32];  // their ratchet public key
    uint8_t ck[32];
    uint32_t idx;
} sig_chain;

typedef struct {
    uint8_t ratchet[32];
    uint32_t counter;
    uint8_t seed[32];  // HMAC(chain key, 0x01), the input to the message key HKDF
} sig_mkey;

typedef struct {
    uint8_t used;
    uint8_t nchains, nkeys;
    uint8_t remote_ident[32];
    uint8_t root[32];
    uint8_t send_priv[32], send_pub[32], send_ck[32];
    uint32_t send_idx;
    uint32_t prev_counter;
    uint8_t base_key[32];  // the X3DH base key: theirs if they started the session, ours if we did
    uint32_t remote_reg;
    // We started this session (wa_sig_process_bundle) and have not heard back:
    // every message we send is wrapped in a PreKeySignalMessage until then.
    uint8_t pending, pending_has_opk;
    uint32_t pending_opk_id, pending_spk_id;
    sig_chain chains[RCHAINS];  // newest last, as libsignal appends
    sig_mkey keys[SKIPPED];     // oldest first
} sig_state;

typedef struct {
    uint32_t magic;
    uint8_t addr_hash[32];
    sig_state cur;
    sig_state prev[PREV_STATES];  // newest first
} sig_record;

typedef struct {
    uint32_t iter;
    uint8_t seed[32];
} sk_mkey;

typedef struct {
    uint8_t used, nkeys;
    uint32_t key_id;
    uint32_t iter;
    uint8_t ck[32];
    uint8_t sign_pub[32];
    sk_mkey keys[SK_SKIPPED];  // oldest first
} sk_state;

typedef struct {
    uint32_t magic;
    uint8_t name_hash[32];
    sk_state st[SK_STATES];  // newest first
} sk_record;

typedef struct {
    uint32_t id;
    uint8_t priv[32];
} pk_entry;

typedef struct {
    uint32_t magic;
    uint32_t next_id;
    uint32_t n;
    pk_entry e[WA_PREKEY_MAX];
} pk_record;

// Key "<prefix><12 hex chars of SHA-256(name)>"; the full hash is kept in
// the record so a (2^-48) collision reads as "no record", not as garbage.
static void kv_key(char prefix, const char *a, const char *b, char key[16], uint8_t hash[32]) {
    if (b) {
        size_t al = strlen(a), bl = strlen(b);
        char *t = malloc(al + bl + 2);
        if (t) {
            memcpy(t, a, al);
            t[al] = '\n';
            memcpy(t + al + 1, b, bl + 1);
            wa_sha256((const uint8_t *)t, al + bl + 1, hash);
            free(t);
        } else {
            wa_sha256_2((const uint8_t *)a, al, (const uint8_t *)b, bl, hash);
        }
    } else {
        wa_sha256((const uint8_t *)a, strlen(a), hash);
    }
    static const char hex[] = "0123456789abcdef";
    key[0] = prefix;
    for (int i = 0; i < 6; i++) {
        key[1 + 2 * i] = hex[hash[i] >> 4];
        key[2 + 2 * i] = hex[hash[i] & 15];
    }
    key[13] = 0;
}

// 1 = loaded, 0 = absent (rec zeroed), negative = error.
static int kv_load(wa_sig *s, const char *key, void *rec, size_t size, uint32_t magic, const uint8_t *hash) {
    memset(rec, 0, size);
    if (!s->kv.get) return WA_SIG_ERR_STORE;
    int n = s->kv.get(s->kv.ctx, key, rec, size);
    if (n < 0) return WA_SIG_ERR_STORE;
    if (n == 0) return 0;
    if ((size_t)n != size || *(uint32_t *)rec != magic || (hash && memcmp((uint8_t *)rec + 4, hash, 32) != 0)) {
        memset(rec, 0, size);  // another layout or a collision: start over
        return 0;
    }
    return 1;
}

static int kv_save(wa_sig *s, const char *key, const void *rec, size_t size) {
    if (!s->kv.set || s->kv.set(s->kv.ctx, key, rec, size) != 0) return WA_SIG_ERR_STORE;
    return WA_SIG_OK;
}

// ---------------------------------------------------------------- kdf

static void hmac1(const uint8_t key[32], uint8_t b, uint8_t out[32]) {
    wa_slice p = {&b, 1};
    wa_hmac_sha256(key, 32, &p, 1, out);
}

// keys/chain ChainKey.MessageKeys: HKDF(seed, info="WhisperMessageKeys") -> cipher | mac | iv.
static void message_keys(const uint8_t seed[32], uint8_t cipher[32], uint8_t mac[32], uint8_t iv[16]) {
    static const uint8_t info[] = "WhisperMessageKeys";
    uint8_t out[80];
    wa_hkdf_sha256(NULL, 0, seed, 32, info, sizeof info - 1, out, 80);
    memcpy(cipher, out, 32);
    memcpy(mac, out + 32, 32);
    memcpy(iv, out + 64, 16);
}

// keys/root RootKey.CreateChain: HKDF(DH(ours, theirs), salt=root, info="WhisperRatchet").
static int create_chain(const uint8_t root[32], const uint8_t our_priv[32], const uint8_t their_pub[32],
                        uint8_t new_root[32], uint8_t ck[32]) {
    static const uint8_t info[] = "WhisperRatchet";
    uint8_t dh[32], out[64];
    if (wa_x25519(dh, our_priv, their_pub)) return -1;
    wa_hkdf_sha256(root, 32, dh, 32, info, sizeof info - 1, out, 64);
    memcpy(new_root, out, 32);
    memcpy(ck, out + 32, 32);
    return 0;
}

// A serialized curve25519 public key: 0x05 || 32 bytes.
static int djb_key(const uint8_t *d, size_t len, uint8_t out[32]) {
    if (len != 33 || d[0] != 0x05) return -1;
    memcpy(out, d + 1, 32);
    return 0;
}

static void serialize_key(const uint8_t pub[32], uint8_t out[33]) {
    out[0] = 0x05;
    memcpy(out + 1, pub, 32);
}

// ---------------------------------------------------------------- messages

typedef struct {
    const uint8_t *body;  // version byte + protobuf, the MAC input
    size_t body_len;
    const uint8_t *mac;
    uint8_t ratchet[32];
    uint32_t counter, prev_counter;
    const uint8_t *ct;
    size_t ct_len;
} signal_msg;

static int parse_signal_msg(const uint8_t *in, size_t len, signal_msg *m) {
    if (len < 1 + MAC_LEN || (in[0] >> 4) != 3) return WA_SIG_ERR_INVALID;
    m->body = in;
    m->body_len = len - MAC_LEN;
    m->mac = in + len - MAC_LEN;
    const uint8_t *pb = in + 1, *rk = NULL;
    size_t pbl = len - 1 - MAC_LEN, rkl = 0;
    uint64_t v;
    if (!wa_pb_get_bytes(pb, pbl, 1, &rk, &rkl) || djb_key(rk, rkl, m->ratchet)) return WA_SIG_ERR_INVALID;
    if (!wa_pb_get_varint(pb, pbl, 2, &v)) return WA_SIG_ERR_INVALID;
    m->counter = (uint32_t)v;
    m->prev_counter = wa_pb_get_varint(pb, pbl, 3, &v) ? (uint32_t)v : 0;
    if (!wa_pb_get_bytes(pb, pbl, 4, &m->ct, &m->ct_len)) return WA_SIG_ERR_INVALID;
    return WA_SIG_OK;
}

// protocol/SignalMessage.go getMac: HMAC(macKey, sender identity || receiver identity || body)[:8].
static void signal_mac(const uint8_t mac_key[32], const uint8_t sender[32], const uint8_t receiver[32],
                       const uint8_t *body, size_t body_len, uint8_t out[32]) {
    uint8_t si[33], ri[33];
    serialize_key(sender, si);
    serialize_key(receiver, ri);
    wa_slice parts[] = {{si, 33}, {ri, 33}, {body, body_len}};
    wa_hmac_sha256(mac_key, 32, parts, 3, out);
}

// ---------------------------------------------------------------- session decrypt

static void add_skipped(sig_state *st, const uint8_t ratchet[32], uint32_t counter, const uint8_t seed[32]) {
    if (st->nkeys == SKIPPED) {
        memmove(&st->keys[0], &st->keys[1], sizeof st->keys[0] * (SKIPPED - 1));
        st->nkeys--;
    }
    sig_mkey *k = &st->keys[st->nkeys++];
    memcpy(k->ratchet, ratchet, 32);
    k->counter = counter;
    memcpy(k->seed, seed, 32);
}

static int take_skipped(sig_state *st, const uint8_t ratchet[32], uint32_t counter, uint8_t seed[32]) {
    for (int i = 0; i < st->nkeys; i++) {
        if (st->keys[i].counter == counter && memcmp(st->keys[i].ratchet, ratchet, 32) == 0) {
            memcpy(seed, st->keys[i].seed, 32);
            memmove(&st->keys[i], &st->keys[i + 1], sizeof st->keys[0] * (size_t)(st->nkeys - i - 1));
            st->nkeys--;
            return 1;
        }
    }
    return 0;
}

// SessionCipher.getOrCreateChainKey: a new ratchet key from them means two
// root steps, one for their new sending chain and one for ours.
static sig_chain *get_or_create_chain(sig_state *st, const uint8_t their[32]) {
    for (int i = 0; i < st->nchains; i++)
        if (memcmp(st->chains[i].ratchet, their, 32) == 0) return &st->chains[i];
    uint8_t root1[32], rck[32], root2[32], sck[32], npriv[32], npub[32];
    if (create_chain(st->root, st->send_priv, their, root1, rck)) return NULL;
    if (wa_x25519_keypair(npriv, npub)) return NULL;
    if (create_chain(root1, npriv, their, root2, sck)) return NULL;
    memcpy(st->root, root2, 32);
    if (st->nchains == RCHAINS) {
        memmove(&st->chains[0], &st->chains[1], sizeof st->chains[0] * (RCHAINS - 1));
        st->nchains--;
    }
    sig_chain *c = &st->chains[st->nchains++];
    memcpy(c->ratchet, their, 32);
    memcpy(c->ck, rck, 32);
    c->idx = 0;
    // Go's max(index-1, 0) on a uint32 wraps at 0; libsignal-java gives 0.
    st->prev_counter = st->send_idx > 0 ? st->send_idx - 1 : 0;
    memcpy(st->send_priv, npriv, 32);
    memcpy(st->send_pub, npub, 32);
    memcpy(st->send_ck, sck, 32);
    st->send_idx = 0;
    return c;
}

// SessionCipher.DecryptWithState, on a copy the caller commits on success.
static int state_decrypt(const wa_sig *s, sig_state *st, const signal_msg *m, uint8_t *out, size_t *outlen) {
    if (!st->used) return WA_SIG_ERR_NO_SESSION;
    sig_chain *c = get_or_create_chain(st, m->ratchet);
    if (!c) return WA_SIG_ERR_INVALID;
    uint8_t seed[32];
    if (c->idx > m->counter) {
        if (!take_skipped(st, m->ratchet, m->counter, seed)) return WA_SIG_DUPLICATE;
    } else {
        if (m->counter - c->idx > MAX_FUTURE) return WA_SIG_ERR_FUTURE;
        while (c->idx < m->counter) {
            hmac1(c->ck, 1, seed);
            add_skipped(st, m->ratchet, c->idx, seed);
            hmac1(c->ck, 2, c->ck);
            c->idx++;
        }
        hmac1(c->ck, 1, seed);
        hmac1(c->ck, 2, c->ck);
        c->idx++;
    }
    uint8_t ckey[32], mkey[32], iv[16], mac[32];
    message_keys(seed, ckey, mkey, iv);
    signal_mac(mkey, st->remote_ident, s->store->ident_pub, m->body, m->body_len, mac);
    if (!wa_ct_equal(mac, m->mac, MAC_LEN)) return WA_SIG_ERR_BAD_MAC;
    if (wa_aes_cbc_decrypt(ckey, iv, m->ct, m->ct_len, out, outlen)) return WA_SIG_ERR_BAD_MAC;
    st->pending = 0;  // ClearUnackPreKeyMessage: they have the session now
    return WA_SIG_OK;
}

// SessionCipher.DecryptWithRecord: the current state, then the archived ones;
// a state that works is promoted to current.
static int record_decrypt(const wa_sig *s, sig_record *r, const signal_msg *m, uint8_t *out, size_t *outlen) {
    sig_state *t = malloc(sizeof *t);
    if (!t) return WA_SIG_ERR_NOMEM;
    *t = r->cur;
    int rc = state_decrypt(s, t, m, out, outlen);
    if (rc == WA_SIG_OK) r->cur = *t;
    if (rc == WA_SIG_OK || rc == WA_SIG_DUPLICATE) {
        free(t);
        return rc;
    }
    int first = rc;
    for (int i = 0; i < PREV_STATES; i++) {
        *t = r->prev[i];
        rc = state_decrypt(s, t, m, out, outlen);
        if (rc == WA_SIG_DUPLICATE) {
            free(t);
            return rc;
        }
        if (rc != WA_SIG_OK) continue;
        // PromoteState: the working state becomes current, the old current is
        // archived. prev[i] is already copied into t, so shifting over it is safe.
        memmove(&r->prev[1], &r->prev[0], sizeof r->prev[0] * (size_t)i);
        r->prev[0] = r->cur;
        r->cur = *t;
        free(t);
        return WA_SIG_OK;
    }
    free(t);
    return first == WA_SIG_ERR_NO_SESSION ? WA_SIG_ERR_NO_SESSION : first;
}

static int pk_find(wa_sig *s, uint32_t id, uint8_t priv[32]) {
    pk_record *pk = malloc(sizeof *pk);
    if (!pk) return WA_SIG_ERR_NOMEM;
    int rc = kv_load(s, "pk", pk, sizeof *pk, PK_MAGIC, NULL);
    int found = 0;
    if (rc > 0)
        for (uint32_t i = 0; i < pk->n && i < WA_PREKEY_MAX; i++)
            if (pk->e[i].id == id) {
                memcpy(priv, pk->e[i].priv, 32);
                found = 1;
                break;
            }
    free(pk);
    return rc < 0 ? rc : found;
}

static int pk_remove(wa_sig *s, uint32_t id) {
    pk_record *pk = malloc(sizeof *pk);
    if (!pk) return WA_SIG_ERR_NOMEM;
    int rc = kv_load(s, "pk", pk, sizeof *pk, PK_MAGIC, NULL);
    if (rc > 0) {
        for (uint32_t i = 0; i < pk->n && i < WA_PREKEY_MAX; i++)
            if (pk->e[i].id == id) {
                memmove(&pk->e[i], &pk->e[i + 1], sizeof pk->e[0] * (pk->n - i - 1));
                pk->n--;
                rc = kv_save(s, "pk", pk, sizeof *pk);
                break;
            }
    }
    free(pk);
    return rc < 0 ? rc : WA_SIG_OK;
}

// Session.processV3 + Ratchet.CalculateReceiverSession: X3DH from the
// receiving side. Fills a new current state; archives the old one.
static int process_prekey(wa_sig *s, sig_record *r, uint32_t spk_id, bool has_opk, uint32_t opk_id,
                          const uint8_t base[32], const uint8_t ident[32], uint32_t reg, bool *used_opk) {
    *used_opk = false;
    if (r->cur.used && memcmp(r->cur.base_key, base, 32) == 0) return WA_SIG_OK;
    for (int i = 0; i < PREV_STATES; i++)
        if (r->prev[i].used && memcmp(r->prev[i].base_key, base, 32) == 0) return WA_SIG_OK;
    wa_store *st = s->store;
    if (spk_id != st->spk_id) return WA_SIG_ERR_NO_PREKEY;
    uint8_t opk[32];
    if (has_opk) {
        int rc = pk_find(s, opk_id, opk);
        if (rc < 0) return rc;
        if (rc == 0) return WA_SIG_ERR_NO_PREKEY;
    }
    uint8_t master[32 * 5];
    memset(master, 0xFF, 32);
    if (wa_x25519(master + 32, st->spk_priv, ident) || wa_x25519(master + 64, st->ident_priv, base) ||
        wa_x25519(master + 96, st->spk_priv, base) || (has_opk && wa_x25519(master + 128, opk, base)))
        return WA_SIG_ERR_INVALID;
    static const uint8_t info[] = "WhisperText";
    uint8_t derived[64];
    wa_hkdf_sha256(NULL, 0, master, has_opk ? 160 : 128, info, sizeof info - 1, derived, 64);

    if (r->cur.used) {
        memmove(&r->prev[1], &r->prev[0], sizeof r->prev[0] * (PREV_STATES - 1));
        r->prev[0] = r->cur;
    }
    sig_state *n = &r->cur;
    memset(n, 0, sizeof *n);
    n->used = 1;
    memcpy(n->remote_ident, ident, 32);
    memcpy(n->root, derived, 32);
    memcpy(n->send_priv, st->spk_priv, 32);  // our ratchet key starts as the signed prekey
    memcpy(n->send_pub, st->spk_pub, 32);
    memcpy(n->send_ck, derived + 32, 32);
    memcpy(n->base_key, base, 32);
    n->remote_reg = reg;
    *used_opk = has_opk && opk_id != 0xFFFFFF;
    return WA_SIG_OK;
}

int wa_sig_decrypt(wa_sig *s, const char *addr, bool prekey, const uint8_t *in, size_t len, uint8_t **out,
                   size_t *outlen) {
    *out = NULL;
    *outlen = 0;
    const uint8_t *inner = in;
    size_t inner_len = len;
    uint32_t spk_id = 0, opk_id = 0, reg = 0;
    bool has_opk = false;
    uint8_t base[32], ident[32];
    if (prekey) {
        // PreKeySignalMessage { preKeyId=1, baseKey=2, identityKey=3, message=4, registrationId=5, signedPreKeyId=6 }
        if (len < 2 || (in[0] >> 4) != 3) return WA_SIG_ERR_INVALID;
        const uint8_t *pb = in + 1, *b, *id;
        size_t pbl = len - 1, bl, idl;
        uint64_t v;
        if (wa_pb_get_varint(pb, pbl, 1, &v)) {
            has_opk = true;
            opk_id = (uint32_t)v;
        }
        if (!wa_pb_get_varint(pb, pbl, 6, &v)) return WA_SIG_ERR_INVALID;
        spk_id = (uint32_t)v;
        reg = wa_pb_get_varint(pb, pbl, 5, &v) ? (uint32_t)v : 0;
        if (!wa_pb_get_bytes(pb, pbl, 2, &b, &bl) || djb_key(b, bl, base)) return WA_SIG_ERR_INVALID;
        if (!wa_pb_get_bytes(pb, pbl, 3, &id, &idl) || djb_key(id, idl, ident)) return WA_SIG_ERR_INVALID;
        if (!wa_pb_get_bytes(pb, pbl, 4, &inner, &inner_len)) return WA_SIG_ERR_INVALID;
    }
    signal_msg m;
    int rc = parse_signal_msg(inner, inner_len, &m);
    if (rc) return rc;

    char key[16];
    uint8_t hash[32];
    kv_key('s', addr, NULL, key, hash);
    sig_record *r = malloc(sizeof *r);
    uint8_t *pt = malloc(m.ct_len ? m.ct_len : 1);
    if (!r || !pt) {
        free(r);
        free(pt);
        return WA_SIG_ERR_NOMEM;
    }
    rc = kv_load(s, key, r, sizeof *r, REC_MAGIC, hash);
    if (rc < 0) goto done;
    if (!prekey && rc == 0) {
        rc = WA_SIG_ERR_NO_SESSION;
        goto done;
    }
    r->magic = REC_MAGIC;
    memcpy(r->addr_hash, hash, 32);
    bool used_opk = false;
    if (prekey) {
        rc = process_prekey(s, r, spk_id, has_opk, opk_id, base, ident, reg, &used_opk);
        if (rc) goto done;
    }
    rc = record_decrypt(s, r, &m, pt, outlen);
    if (rc) goto done;
    rc = kv_save(s, key, r, sizeof *r);
    if (rc) goto done;
    if (used_opk) pk_remove(s, opk_id);  // a failure here only leaves a spent key around
    *out = pt;
    pt = NULL;
done:
    if (rc) *outlen = 0;
    free(pt);
    free(r);
    return rc;
}

// ---------------------------------------------------------------- session encrypt

int wa_sig_has_session(wa_sig *s, const char *addr) {
    char key[16];
    uint8_t hash[32];
    kv_key('s', addr, NULL, key, hash);
    sig_record *r = malloc(sizeof *r);
    if (!r) return WA_SIG_ERR_NOMEM;
    int rc = kv_load(s, key, r, sizeof *r, REC_MAGIC, hash);
    if (rc > 0) rc = r->cur.used ? 1 : 0;
    free(r);
    return rc;
}

// SessionBuilder.ProcessBundle + Ratchet.CalculateSenderSession: X3DH from
// the sending side. The new state becomes current; the old one is archived.
int wa_sig_process_bundle(wa_sig *s, const char *addr, const wa_prekey_bundle *b) {
    uint8_t spk_ser[33];
    serialize_key(b->spk, spk_ser);
    if (!wa_curve_verify(b->ident, spk_ser, 33, b->spk_sig)) return WA_SIG_ERR_BAD_MAC;
    wa_store *st = s->store;
    uint8_t base_priv[32], base_pub[32], rat_priv[32], rat_pub[32];
    if (wa_x25519_keypair(base_priv, base_pub) || wa_x25519_keypair(rat_priv, rat_pub)) return WA_SIG_ERR_INVALID;
    // The mirror of process_prekey: DH(our identity, their signed prekey),
    // DH(our base, their identity), DH(our base, their signed prekey),
    // [DH(our base, their one-time prekey)].
    uint8_t master[32 * 5];
    memset(master, 0xFF, 32);
    if (wa_x25519(master + 32, st->ident_priv, b->spk) || wa_x25519(master + 64, base_priv, b->ident) ||
        wa_x25519(master + 96, base_priv, b->spk) || (b->has_opk && wa_x25519(master + 128, base_priv, b->opk)))
        return WA_SIG_ERR_INVALID;
    static const uint8_t info[] = "WhisperText";
    uint8_t derived[64], root[32], send_ck[32];
    wa_hkdf_sha256(NULL, 0, master, b->has_opk ? 160 : 128, info, sizeof info - 1, derived, 64);
    // Their first sending chain is keyed by their signed prekey; ours starts
    // with a fresh ratchet key one root step on.
    if (create_chain(derived, rat_priv, b->spk, root, send_ck)) return WA_SIG_ERR_INVALID;

    char key[16];
    uint8_t hash[32];
    kv_key('s', addr, NULL, key, hash);
    sig_record *r = malloc(sizeof *r);
    if (!r) return WA_SIG_ERR_NOMEM;
    int rc = kv_load(s, key, r, sizeof *r, REC_MAGIC, hash);
    if (rc < 0) {
        free(r);
        return rc;
    }
    r->magic = REC_MAGIC;
    memcpy(r->addr_hash, hash, 32);
    if (r->cur.used) {
        memmove(&r->prev[1], &r->prev[0], sizeof r->prev[0] * (PREV_STATES - 1));
        r->prev[0] = r->cur;
    }
    sig_state *n = &r->cur;
    memset(n, 0, sizeof *n);
    n->used = 1;
    memcpy(n->remote_ident, b->ident, 32);
    memcpy(n->root, root, 32);
    memcpy(n->send_priv, rat_priv, 32);
    memcpy(n->send_pub, rat_pub, 32);
    memcpy(n->send_ck, send_ck, 32);
    n->nchains = 1;
    memcpy(n->chains[0].ratchet, b->spk, 32);
    memcpy(n->chains[0].ck, derived + 32, 32);
    memcpy(n->base_key, base_pub, 32);
    n->remote_reg = b->reg_id;
    n->pending = 1;
    n->pending_has_opk = b->has_opk;
    n->pending_opk_id = b->opk_id;
    n->pending_spk_id = b->spk_id;
    rc = kv_save(s, key, r, sizeof *r);
    free(r);
    return rc;
}

int wa_sig_encrypt(wa_sig *s, const char *addr, const uint8_t *in, size_t len, uint8_t **out, size_t *outlen,
                   bool *prekey) {
    *out = NULL;
    *outlen = 0;
    if (prekey) *prekey = false;
    char key[16];
    uint8_t hash[32];
    kv_key('s', addr, NULL, key, hash);
    sig_record *r = malloc(sizeof *r);
    uint8_t *ct = malloc(len + 16);
    wa_buf pb = {0}, pk = {0};
    if (!r || !ct) {
        free(r);
        free(ct);
        return WA_SIG_ERR_NOMEM;
    }
    int rc = kv_load(s, key, r, sizeof *r, REC_MAGIC, hash);
    if (rc <= 0 || !r->cur.used) {
        rc = rc < 0 ? rc : WA_SIG_ERR_NO_SESSION;
        goto done;
    }
    sig_state *st = &r->cur;
    uint8_t seed[32], ckey[32], mkey[32], iv[16], mac[32], rk[33];
    hmac1(st->send_ck, 1, seed);
    message_keys(seed, ckey, mkey, iv);
    size_t ctl;
    if (wa_aes_cbc_encrypt(ckey, iv, in, len, ct, &ctl)) {
        rc = WA_SIG_ERR_INVALID;
        goto done;
    }
    serialize_key(st->send_pub, rk);
    wa_buf_byte(&pb, VERSION_BYTE);
    wa_pb_bytes(&pb, 1, rk, 33);
    wa_pb_varint(&pb, 2, st->send_idx);
    wa_pb_varint(&pb, 3, st->prev_counter);
    wa_pb_bytes(&pb, 4, ct, ctl);
    if (pb.oom) {
        rc = WA_SIG_ERR_NOMEM;
        goto done;
    }
    signal_mac(mkey, s->store->ident_pub, st->remote_ident, pb.data, pb.len, mac);
    wa_buf_put(&pb, mac, MAC_LEN);
    if (pb.oom) {
        rc = WA_SIG_ERR_NOMEM;
        goto done;
    }
    if (st->pending) {
        // PreKeySignalMessage { preKeyId=1, baseKey=2, identityKey=3, message=4, registrationId=5, signedPreKeyId=6 }
        uint8_t bk[33], ik[33];
        serialize_key(st->base_key, bk);
        serialize_key(s->store->ident_pub, ik);
        wa_buf_byte(&pk, VERSION_BYTE);
        if (st->pending_has_opk) wa_pb_varint(&pk, 1, st->pending_opk_id);
        wa_pb_bytes(&pk, 2, bk, 33);
        wa_pb_bytes(&pk, 3, ik, 33);
        wa_pb_bytes(&pk, 4, pb.data, pb.len);
        wa_pb_varint(&pk, 5, s->store->reg_id);
        wa_pb_varint(&pk, 6, st->pending_spk_id);
        if (pk.oom) {
            rc = WA_SIG_ERR_NOMEM;
            goto done;
        }
    }
    hmac1(st->send_ck, 2, st->send_ck);
    st->send_idx++;
    rc = kv_save(s, key, r, sizeof *r);
    if (rc) goto done;
    if (st->pending) {
        *out = pk.data;
        *outlen = pk.len;
        pk.data = NULL;
        if (prekey) *prekey = true;
    } else {
        *out = pb.data;
        *outlen = pb.len;
        pb.data = NULL;
    }
done:
    wa_buf_free(&pb);
    wa_buf_free(&pk);
    free(ct);
    free(r);
    return rc;
}

// ---------------------------------------------------------------- groups

int wa_sig_group_process(wa_sig *s, const char *group, const char *addr, const uint8_t *in, size_t len) {
    // SenderKeyDistributionMessage { id=1, iteration=2, chainKey=3, signingKey=4 }
    if (len < 2 || (in[0] >> 4) != 3) return WA_SIG_ERR_INVALID;
    const uint8_t *pb = in + 1, *ck, *sk;
    size_t pbl = len - 1, ckl, skl;
    uint64_t id, iter;
    uint8_t sign_pub[32];
    if (!wa_pb_get_varint(pb, pbl, 1, &id) || !wa_pb_get_varint(pb, pbl, 2, &iter) ||
        !wa_pb_get_bytes(pb, pbl, 3, &ck, &ckl) || ckl != 32 || !wa_pb_get_bytes(pb, pbl, 4, &sk, &skl) ||
        djb_key(sk, skl, sign_pub))
        return WA_SIG_ERR_INVALID;
    char key[16];
    uint8_t hash[32];
    kv_key('g', group, addr, key, hash);
    sk_record *r = malloc(sizeof *r);
    if (!r) return WA_SIG_ERR_NOMEM;
    int rc = kv_load(s, key, r, sizeof *r, SK_MAGIC, hash);
    if (rc >= 0) {
        // SenderKeyRecord.AddSenderKeyState: newest first, at most maxStates.
        r->magic = SK_MAGIC;
        memcpy(r->name_hash, hash, 32);
        memmove(&r->st[1], &r->st[0], sizeof r->st[0] * (SK_STATES - 1));
        sk_state *n = &r->st[0];
        memset(n, 0, sizeof *n);
        n->used = 1;
        n->key_id = (uint32_t)id;
        n->iter = (uint32_t)iter;
        memcpy(n->ck, ck, 32);
        memcpy(n->sign_pub, sign_pub, 32);
        rc = kv_save(s, key, r, sizeof *r);
    }
    free(r);
    return rc;
}

int wa_sig_group_decrypt(wa_sig *s, const char *group, const char *addr, const uint8_t *in, size_t len,
                         uint8_t **out, size_t *outlen) {
    *out = NULL;
    *outlen = 0;
    // SenderKeyMessage: version || { id=1, iteration=2, ciphertext=3 } || signature
    if (len < 1 + SIG_LEN || (in[0] >> 4) != 3) return WA_SIG_ERR_INVALID;
    const uint8_t *pb = in + 1, *ct, *sig = in + len - SIG_LEN;
    size_t pbl = len - 1 - SIG_LEN, ctl;
    uint64_t id, iter;
    if (!wa_pb_get_varint(pb, pbl, 1, &id) || !wa_pb_get_varint(pb, pbl, 2, &iter) ||
        !wa_pb_get_bytes(pb, pbl, 3, &ct, &ctl))
        return WA_SIG_ERR_INVALID;
    char key[16];
    uint8_t hash[32];
    kv_key('g', group, addr, key, hash);
    sk_record *r = malloc(sizeof *r);
    uint8_t *pt = malloc(ctl ? ctl : 1);
    if (!r || !pt) {
        free(r);
        free(pt);
        return WA_SIG_ERR_NOMEM;
    }
    int rc = kv_load(s, key, r, sizeof *r, SK_MAGIC, hash);
    if (rc <= 0) {
        rc = rc < 0 ? rc : WA_SIG_ERR_NO_SENDER_KEY;
        goto done;
    }
    sk_state *st = NULL;
    for (int i = 0; i < SK_STATES; i++)
        if (r->st[i].used && r->st[i].key_id == (uint32_t)id) {
            st = &r->st[i];
            break;
        }
    if (!st) {
        rc = WA_SIG_ERR_NO_SENDER_KEY;
        goto done;
    }
    if (!wa_curve_verify(st->sign_pub, in, len - SIG_LEN, sig)) {
        rc = WA_SIG_ERR_BAD_MAC;
        goto done;
    }
    // GroupCipher.getSenderKey
    uint8_t seed[32];
    uint32_t want = (uint32_t)iter;
    if (st->iter > want) {
        int found = 0;
        for (int i = 0; i < st->nkeys; i++)
            if (st->keys[i].iter == want) {
                memcpy(seed, st->keys[i].seed, 32);
                memmove(&st->keys[i], &st->keys[i + 1], sizeof st->keys[0] * (size_t)(st->nkeys - i - 1));
                st->nkeys--;
                found = 1;
                break;
            }
        if (!found) {
            rc = WA_SIG_DUPLICATE;
            goto done;
        }
    } else {
        if (want - st->iter > MAX_FUTURE) {
            rc = WA_SIG_ERR_FUTURE;
            goto done;
        }
        while (st->iter < want) {
            if (st->nkeys == SK_SKIPPED) {
                memmove(&st->keys[0], &st->keys[1], sizeof st->keys[0] * (SK_SKIPPED - 1));
                st->nkeys--;
            }
            st->keys[st->nkeys].iter = st->iter;
            hmac1(st->ck, 1, st->keys[st->nkeys].seed);
            st->nkeys++;
            hmac1(st->ck, 2, st->ck);
            st->iter++;
        }
        hmac1(st->ck, 1, seed);
        hmac1(st->ck, 2, st->ck);
        st->iter++;
    }
    // SenderMessageKey: HKDF(seed, info="WhisperGroup", 48) -> iv | cipher key.
    static const uint8_t info[] = "WhisperGroup";
    uint8_t d[48];
    wa_hkdf_sha256(NULL, 0, seed, 32, info, sizeof info - 1, d, 48);
    if (wa_aes_cbc_decrypt(d + 16, d, ct, ctl, pt, outlen)) {
        rc = WA_SIG_ERR_BAD_MAC;
        goto done;
    }
    rc = kv_save(s, key, r, sizeof *r);
    if (rc) goto done;
    *out = pt;
    pt = NULL;
done:
    if (rc) *outlen = 0;
    free(pt);
    free(r);
    return rc;
}

// ---------------------------------------------------------------- prekeys

int wa_sig_prekey_count(wa_sig *s) {
    pk_record *pk = malloc(sizeof *pk);
    if (!pk) return -1;
    int rc = kv_load(s, "pk", pk, sizeof *pk, PK_MAGIC, NULL);
    int n = rc < 0 ? -1 : (int)(pk->n > WA_PREKEY_MAX ? WA_PREKEY_MAX : pk->n);
    free(pk);
    return n;
}

int wa_sig_prekeys_generate(wa_sig *s, int n, wa_prekey_pub *out) {
    if (n <= 0 || n > WA_PREKEY_MAX) return WA_SIG_ERR_INVALID;
    pk_record *pk = malloc(sizeof *pk);
    if (!pk) return WA_SIG_ERR_NOMEM;
    int rc = kv_load(s, "pk", pk, sizeof *pk, PK_MAGIC, NULL);
    if (rc < 0) goto done;
    if (rc == 0) {
        pk->magic = PK_MAGIC;
        pk->next_id = 1;
    }
    if (pk->n > WA_PREKEY_MAX) pk->n = WA_PREKEY_MAX;
    if (pk->n + (uint32_t)n > WA_PREKEY_MAX) {
        uint32_t drop = pk->n + (uint32_t)n - WA_PREKEY_MAX;
        memmove(&pk->e[0], &pk->e[drop], sizeof pk->e[0] * (pk->n - drop));
        pk->n -= drop;
    }
    for (int i = 0; i < n; i++) {
        if (pk->next_id == 0 || pk->next_id >= 0xFFFFFF) pk->next_id = 1;  // 24-bit ids; 0xFFFFFF means "none"
        pk_entry *e = &pk->e[pk->n];
        if (wa_x25519_keypair(e->priv, out[i].pub)) {
            rc = WA_SIG_ERR_INVALID;
            goto done;
        }
        e->id = out[i].id = pk->next_id++;
        pk->n++;
    }
    rc = kv_save(s, "pk", pk, sizeof *pk);
    if (rc == WA_SIG_OK) rc = n;
done:
    memset(pk, 0, sizeof *pk);
    free(pk);
    return rc;
}

long wa_unpad(const uint8_t *data, size_t len) {
    if (len == 0) return -1;
    uint8_t n = data[len - 1];  // n == 0 is an empty suffix, which whatsmeow accepts
    if (n > len) return -1;
    for (size_t i = len - n; i < len; i++)
        if (data[i] != n) return -1;
    return (long)(len - n);
}
