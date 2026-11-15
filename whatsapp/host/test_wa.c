// SPDX-License-Identifier: MPL-2.0
// Offline tests for the wa core: crypto vectors, signature round trips,
// protobuf and binary-node round trips. The live handshake (bridge.py) is the
// test against WhatsApp's own signatures.
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <unistd.h>

#include "wa.h"
#include "wa_crypto.h"
#include "wa_pb.h"
#include "wa_signal.h"

int wa_random(uint8_t *out, size_t n) { return getrandom(out, n, 0) == (ssize_t)n ? 0 : -1; }
int wa_inflate(const uint8_t *in, size_t len, uint8_t **out, size_t *outlen) { return -1; }

static int failures = 0, passes = 0;
#define CHECK(cond, name)                                  \
    do {                                                   \
        if (cond) {                                        \
            passes++;                                      \
        } else {                                           \
            failures++;                                    \
            fprintf(stderr, "FAIL %s (line %d)\n", name, __LINE__); \
        }                                                  \
    } while (0)

static void unhex(const char *h, uint8_t *out) {
    for (size_t i = 0; h[2 * i]; i++) sscanf(h + 2 * i, "%2hhx", &out[i]);
}

static void test_hkdf(void) {
    uint8_t ikm[22], salt[13], info[10], okm[42], want[42];
    memset(ikm, 0x0b, sizeof ikm);
    for (int i = 0; i < 13; i++) salt[i] = (uint8_t)i;
    for (int i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);
    unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", want);
    wa_hkdf_sha256(salt, 13, ikm, 22, info, 10, okm, 42);
    CHECK(memcmp(okm, want, 42) == 0, "hkdf rfc5869 case 1");
}

static void test_x25519(void) {
    // RFC 7748 section 6.1
    uint8_t a_priv[32], b_pub[32], want[32], got[32], a_pub[32], want_a_pub[32];
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a_priv);
    unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", b_pub);
    unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", want);
    unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", want_a_pub);
    CHECK(wa_x25519(got, a_priv, b_pub) == 0 && memcmp(got, want, 32) == 0, "x25519 rfc7748 shared");
    wa_x25519_pub(a_priv, a_pub);
    CHECK(memcmp(a_pub, want_a_pub, 32) == 0, "x25519 rfc7748 public");
}

static void test_curve_sigs(void) {
    for (int round = 0; round < 50; round++) {
        uint8_t priv[32], pub[32], sig[64], msg[100];
        wa_x25519_keypair(priv, pub);
        wa_random(msg, sizeof msg);
        size_t len = (size_t)(round * 2);
        CHECK(wa_curve_sign(sig, priv, msg, len) == 0, "curve sign");
        CHECK(wa_curve_verify(pub, msg, len, sig) == 1, "curve verify round trip");
        sig[5] ^= 1;
        CHECK(wa_curve_verify(pub, msg, len, sig) == 0, "curve verify rejects tampered sig");
        sig[5] ^= 1;
        if (len) {
            msg[0] ^= 1;
            CHECK(wa_curve_verify(pub, msg, len, sig) == 0, "curve verify rejects tampered msg");
        }
    }
}

static void test_gcm(void) {
    uint8_t key[32], iv[12] = {0}, pt[37], ct[53], back[37];
    wa_random(key, 32);
    wa_random(pt, sizeof pt);
    const uint8_t aad[] = "header";
    CHECK(wa_aes_gcm_encrypt(key, iv, aad, 6, pt, sizeof pt, ct) == 0, "gcm encrypt");
    CHECK(wa_aes_gcm_decrypt(key, iv, aad, 6, ct, sizeof ct, back) == 0 && memcmp(back, pt, sizeof pt) == 0,
          "gcm round trip");
    ct[3] ^= 1;
    CHECK(wa_aes_gcm_decrypt(key, iv, aad, 6, ct, sizeof ct, back) == -1, "gcm rejects tampering");
    // NIST GCM test case 13 (256-bit zero key, zero IV, empty plaintext): tag only.
    uint8_t zk[32] = {0}, tag[16], want[16];
    unhex("530f8afbc74536b9a963b4f1c4cb738b", want);
    wa_aes_gcm_encrypt(zk, iv, NULL, 0, NULL, 0, tag);
    CHECK(memcmp(tag, want, 16) == 0, "gcm nist case 13");
}

static void test_pb(void) {
    wa_buf b = {0}, sub = {0};
    wa_pb_varint(&b, 1, 300);
    wa_pb_bytes(&sub, 1, "abc", 3);
    wa_pb_msg(&b, 2, &sub);
    wa_pb_varint(&b, 41, 1);
    wa_pb_sfixed32(&b, 9, -5);
    uint64_t v;
    const uint8_t *d, *dd;
    size_t dl, ddl;
    CHECK(wa_pb_get_varint(b.data, b.len, 1, &v) && v == 300, "pb varint");
    CHECK(wa_pb_get_varint(b.data, b.len, 41, &v) && v == 1, "pb high field number");
    CHECK(wa_pb_get_bytes(b.data, b.len, 2, &d, &dl) && wa_pb_get_bytes(d, dl, 1, &dd, &ddl) && ddl == 3 &&
              memcmp(dd, "abc", 3) == 0,
          "pb nested bytes");
    CHECK(!wa_pb_get_bytes(b.data, b.len - 1, 2, &d, &dl) || 1, "pb truncated input does not crash");
    wa_buf_free(&b);
}

static void test_binary(void) {
    uint8_t blob[300];
    for (size_t i = 0; i < sizeof blob; i++) blob[i] = (uint8_t)i;
    wa_jid server = WA_SERVER_JID;
    wa_jid user = {.user = "15551234567", .server = "s.whatsapp.net"};
    wa_jid dev = {.user = "15551234567", .server = "s.whatsapp.net", .device = 12};
    wa_jid lid = {.user = "123456789012345", .server = "lid", .device = 3};
    wa_node grand = {"ref", NULL, 0, wa_vbytes((const uint8_t *)"2@abcDEF+/=", 11)};
    wa_attr cattrs[] = {{"key-index", wa_vstr("7")}, {"name", wa_vstr("not a token, has spaces")}};
    wa_node kids[] = {{"pair-device", cattrs, 2, wa_vlist(&grand, 1)}, {"big", NULL, 0, wa_vbytes(blob, sizeof blob)}};
    wa_attr attrs[] = {{"id", wa_vstr("123.45-6")},      {"to", wa_vjid(server)},  {"from", wa_vjid(user)},
                       {"participant", wa_vjid(dev)},    {"recipient", wa_vjid(lid)}, {"type", wa_vstr("result")},
                       {"hash", wa_vstr("DEADBEEF01")}, {"empty", wa_vstr("")}};
    wa_node root = {"iq", attrs, 8, wa_vlist(kids, 2)};
    wa_buf b = {0};
    CHECK(wa_node_encode(&root, &b) == 0 && b.data[0] == 0, "binary encode");
    wa_arena a = {0};
    wa_node *n = wa_node_decode(&a, b.data + 1, b.len - 1);
    CHECK(n != NULL, "binary decode");
    if (n) {
        CHECK(strcmp(n->tag, "iq") == 0 && n->nattrs == 7, "decode tag and attr count (empty attr dropped)");
        CHECK(wa_attr_str(n, "id") && strcmp(wa_attr_str(n, "id"), "123.45-6") == 0, "nibble-packed id");
        CHECK(wa_attr_str(n, "hash") && strcmp(wa_attr_str(n, "hash"), "DEADBEEF01") == 0, "hex-packed string");
        CHECK(wa_attr_str(n, "type") && strcmp(wa_attr_str(n, "type"), "result") == 0, "single-byte token");
        const wa_jid *j;
        CHECK((j = wa_attr_jid(n, "to")) && wa_jid_eq(j, &server), "server jid");
        CHECK((j = wa_attr_jid(n, "from")) && wa_jid_eq(j, &user), "user jid");
        CHECK((j = wa_attr_jid(n, "participant")) && wa_jid_eq(j, &dev), "ad jid");
        CHECK((j = wa_attr_jid(n, "recipient")) && wa_jid_eq(j, &lid), "lid ad jid");
        const wa_node *pd = wa_child(n, "pair-device");
        CHECK(pd && strcmp(wa_attr_str(pd, "name"), "not a token, has spaces") == 0, "raw string attr");
        CHECK(pd && strcmp(wa_attr_str(pd, "key-index"), "7") == 0, "token digit attr");
        const wa_node *ref = pd ? wa_child(pd, "ref") : NULL;
        CHECK(ref && ref->content.type == WA_V_BYTES && ref->content.bytes.len == 11, "nested bytes content");
        const wa_node *big = wa_child(n, "big");
        CHECK(big && big->content.type == WA_V_BYTES && big->content.bytes.len == 300 &&
                  memcmp(big->content.bytes.data, blob, 300) == 0,
              "binary20 content");
        char dbg[512];
        wa_node_print(n, dbg, sizeof dbg);
        printf("%s\n", dbg);
    }
    CHECK(wa_node_decode(&a, b.data + 1, b.len - 2) == NULL, "truncated node rejected");
    wa_arena_free(&a);
    wa_buf_free(&b);
}

static void test_store(void) {
    wa_store s;
    CHECK(wa_store_init(&s) == 0, "store init");
    uint8_t signed_pub[33] = {0x05};
    memcpy(signed_pub + 1, s.spk_pub, 32);
    CHECK(wa_curve_verify(s.ident_pub, signed_pub, 33, s.spk_sig) == 1, "signed prekey verifies with identity key");
}

static void test_cbc(void) {
    // NIST SP 800-38A F.2.5 (CBC-AES256.Encrypt), first two blocks, plus the
    // PKCS#7 block a 32-byte input gets.
    uint8_t key[32], iv[16], pt[32], want[32], out[48], back[48];
    size_t ol, bl;
    unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key);
    unhex("000102030405060708090a0b0c0d0e0f", iv);
    unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", pt);
    unhex("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d", want);
    CHECK(wa_aes_cbc_encrypt(key, iv, pt, 32, out, &ol) == 0 && ol == 48 && memcmp(out, want, 32) == 0,
          "cbc nist F.2.5 + padding block");
    CHECK(wa_aes_cbc_decrypt(key, iv, out, ol, back, &bl) == 0 && bl == 32 && memcmp(back, pt, 32) == 0,
          "cbc round trip");
    out[47] ^= 1;
    CHECK(wa_aes_cbc_decrypt(key, iv, out, ol, back, &bl) == -1, "cbc rejects bad padding");
    CHECK(wa_aes_cbc_decrypt(key, iv, out, 47, back, &bl) == -1, "cbc rejects partial block");
    uint8_t padded[] = {'h', 'i', 3, 3, 3}, bad[] = {'h', 'i', 2, 3};
    CHECK(wa_unpad(padded, 5) == 2, "unpad");
    CHECK(wa_unpad(bad, 4) == -1, "unpad rejects bad padding");
}

// ---------------------------------------------------------------- in-memory kv

typedef struct {
    char key[16];
    uint8_t *val;
    size_t len;
} kv_entry;
typedef struct {
    kv_entry e[64];
    int n;
    int sets;
} mem_kv;

static int kv_get(void *ctx, const char *key, uint8_t *buf, size_t cap) {
    mem_kv *m = ctx;
    for (int i = 0; i < m->n; i++)
        if (strcmp(m->e[i].key, key) == 0) {
            memcpy(buf, m->e[i].val, m->e[i].len < cap ? m->e[i].len : cap);
            return (int)m->e[i].len;
        }
    return 0;
}
static int kv_set(void *ctx, const char *key, const uint8_t *data, size_t len) {
    mem_kv *m = ctx;
    m->sets++;
    for (int i = 0; i < m->n; i++)
        if (strcmp(m->e[i].key, key) == 0) {
            free(m->e[i].val);
            m->e[i].val = malloc(len);
            memcpy(m->e[i].val, data, len);
            m->e[i].len = len;
            return 0;
        }
    if (m->n == 64 || strlen(key) > 14) return -1;
    snprintf(m->e[m->n].key, sizeof m->e[0].key, "%s", key);
    m->e[m->n].val = malloc(len);
    memcpy(m->e[m->n].val, data, len);
    m->e[m->n].len = len;
    m->n++;
    return 0;
}
static int kv_del(void *ctx, const char *key) {
    mem_kv *m = ctx;
    for (int i = 0; i < m->n; i++)
        if (strcmp(m->e[i].key, key) == 0) {
            free(m->e[i].val);
            m->e[i] = m->e[--m->n];
        }
    return 0;
}
static void kv_clear(mem_kv *m) {
    for (int i = 0; i < m->n; i++) free(m->e[i].val);
    m->n = 0;
}

// ---------------------------------------------------------------- the Go peer

// WA_SIGPEER is a shell command that runs host/sigpeer (go.mau.fi/libsignal).
typedef struct {
    pid_t pid;
    FILE *in, *out;
    char line[1 << 16];
} peer;

static int peer_start(peer *p) {
    const char *cmd = getenv("WA_SIGPEER");
    if (!cmd || !*cmd) return -1;
    int to[2], from[2];
    if (pipe(to) || pipe(from)) return -1;
    p->pid = fork();
    if (p->pid < 0) return -1;
    if (p->pid == 0) {
        dup2(to[0], 0);
        dup2(from[1], 1);
        close(to[1]);
        close(from[0]);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    close(to[0]);
    close(from[1]);
    p->in = fdopen(to[1], "w");
    p->out = fdopen(from[0], "r");
    return 0;
}

static void peer_stop(peer *p) {
    fclose(p->in);
    fclose(p->out);
    waitpid(p->pid, NULL, 0);
}

// Send one command line, return the reply line (without the newline).
static const char *peer_cmd(peer *p, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(p->in, fmt, ap);
    va_end(ap);
    fputc('\n', p->in);
    fflush(p->in);
    if (!fgets(p->line, sizeof p->line, p->out)) return "err peer died";
    p->line[strcspn(p->line, "\n")] = 0;
    return p->line;
}

static void hexs(const uint8_t *d, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", d[i]);
    out[2 * n] = 0;
}

// Parse "<word> <hex>" into a malloc'd buffer.
static uint8_t *reply_bytes(const char *line, const char *word, size_t *len) {
    size_t wl = strlen(word);
    if (strncmp(line, word, wl) != 0 || line[wl] != ' ') {
        fprintf(stderr, "  peer said: %.200s\n", line);
        return NULL;
    }
    const char *h = line + wl + 1;
    *len = strlen(h) / 2;
    uint8_t *b = malloc(*len + 1);
    for (size_t i = 0; i < *len; i++) sscanf(h + 2 * i, "%2hhx", &b[i]);
    return b;
}

// Alice (peer) encrypts text; returns the ciphertext and its type in *type.
static uint8_t *alice_enc(peer *p, const char *text, size_t *len, char type[8]) {
    char h[512];
    hexs((const uint8_t *)text, strlen(text), h);
    const char *r = peer_cmd(p, "enc %s", h);
    snprintf(type, 8, "%s", strncmp(r, "msg ", 4) == 0 ? "msg" : "pkmsg");
    return reply_bytes(r, type, len);
}

static int bob_dec(wa_sig *s, const char *addr, const char *type, const uint8_t *ct, size_t len, char *out, size_t cap) {
    uint8_t *pt;
    size_t ptl;
    int rc = wa_sig_decrypt(s, addr, strcmp(type, "pkmsg") == 0, ct, len, &pt, &ptl);
    if (rc == WA_SIG_OK) {
        snprintf(out, cap, "%.*s", (int)ptl, (const char *)pt);
        free(pt);
    } else {
        out[0] = 0;
    }
    return rc;
}

// Send "text" from Alice and check that Bob reads it.
static int alice_says(peer *p, wa_sig *s, const char *addr, const char *text, const char *want_type) {
    char type[8], got[256];
    size_t len;
    uint8_t *ct = alice_enc(p, text, &len, type);
    if (!ct) return -1;
    int rc = bob_dec(s, addr, type, ct, len, got, sizeof got);
    free(ct);
    if (want_type && strcmp(type, want_type) != 0) return -2;
    return rc == WA_SIG_OK && strcmp(got, text) == 0 ? 0 : rc ? rc : -3;
}

// Bob replies; check that Alice reads it.
static int bob_says(peer *p, wa_sig *s, const char *addr, const char *text) {
    uint8_t *ct;
    size_t len;
    int rc = wa_sig_encrypt(s, addr, (const uint8_t *)text, strlen(text), &ct, &len, NULL);
    if (rc) return rc;
    char *h = malloc(2 * len + 1);
    hexs(ct, len, h);
    free(ct);
    const char *r = peer_cmd(p, "dec %s", h);
    free(h);
    size_t pl;
    uint8_t *pt = reply_bytes(r, "pt", &pl);
    int ok = pt && pl == strlen(text) && memcmp(pt, text, pl) == 0;
    free(pt);
    return ok ? 0 : -3;
}

static void send_bundle(peer *p, const wa_store *st, const wa_prekey_pub *opk) {
    char ik[65], spk[65], sig[129], opkh[65];
    hexs(st->ident_pub, 32, ik);
    hexs(st->spk_pub, 32, spk);
    hexs(st->spk_sig, 64, sig);
    if (opk) hexs(opk->pub, 32, opkh);
    char idbuf[16];
    snprintf(idbuf, sizeof idbuf, "%u", opk ? (unsigned)opk->id : 0);
    const char *r = peer_cmd(p, "bundle %u %s %u %s %s %s %s", (unsigned)st->reg_id, ik, (unsigned)st->spk_id, spk, sig,
                             opk ? idbuf : "-", opk ? opkh : "-");
    CHECK(strcmp(r, "ok") == 0, "peer accepted our prekey bundle");
}

static void test_signal_interop(void) {
    peer p;
    if (peer_start(&p)) {
        printf("signal interop: skipped (set WA_SIGPEER to run host/sigpeer)\n");
        return;
    }
    wa_store st;
    wa_store_init(&st);
    mem_kv kv = {0};
    wa_sig s = {&st, {kv_get, kv_set, kv_del, &kv}};
    const char *A = "alice:1@s.whatsapp.net";

    wa_prekey_pub pks[3];
    CHECK(wa_sig_prekeys_generate(&s, 3, pks) == 3 && pks[0].id == 1 && pks[2].id == 3, "generate prekeys");
    CHECK(wa_sig_prekey_count(&s) == 3, "prekey count");
    send_bundle(&p, &st, &pks[1]);

    // X3DH with a one-time prekey; Alice keeps sending pkmsg until Bob answers.
    char type[8], got[256];
    size_t len;
    uint8_t *m1 = alice_enc(&p, "hello bob", &len, type);
    CHECK(m1 && strcmp(type, "pkmsg") == 0, "peer sends a prekey message first");
    if (!m1) goto out;
    CHECK(bob_dec(&s, A, type, m1, len, got, sizeof got) == WA_SIG_OK && strcmp(got, "hello bob") == 0,
          "decrypt prekey message from libsignal");
    CHECK(wa_sig_prekey_count(&s) == 2, "used one-time prekey removed");
    CHECK(bob_dec(&s, A, type, m1, len, got, sizeof got) == WA_SIG_DUPLICATE, "redelivered prekey message is a duplicate");
    free(m1);

    size_t l2, l3, l4;
    char t2[8], t3[8], t4[8];
    uint8_t *m2 = alice_enc(&p, "two", &l2, t2), *m3 = alice_enc(&p, "three", &l3, t3), *m4 = alice_enc(&p, "four", &l4, t4);
    CHECK(m2 && m3 && m4 && strcmp(t4, "pkmsg") == 0, "unacknowledged session keeps sending pkmsg");
    if (!m2 || !m3 || !m4) goto out;
    CHECK(bob_dec(&s, A, t4, m4, l4, got, sizeof got) == WA_SIG_OK && strcmp(got, "four") == 0, "out of order: 4th first");
    // A pkmsg ends with registrationId and signedPreKeyId; the inner
    // SignalMessage's MAC is the last 8 bytes of field 4, just before them.
    const uint8_t *inner;
    size_t inner_len;
    int rc2 = -99, rc3 = -99;
    if (wa_pb_get_bytes(m2 + 1, l2 - 1, 4, &inner, &inner_len)) {
        uint8_t *mac_byte = (uint8_t *)inner + inner_len - 1;
        *mac_byte ^= 1;
        rc2 = bob_dec(&s, A, t2, m2, l2, got, sizeof got);
        *mac_byte ^= 1;
    }
    CHECK(rc2 == WA_SIG_ERR_BAD_MAC, "tampered message rejected");
    rc3 = bob_dec(&s, A, t2, m2, l2, got, sizeof got);
    CHECK(rc3 == WA_SIG_OK && strcmp(got, "two") == 0, "skipped key survives a failed attempt");
    if (rc2 != WA_SIG_ERR_BAD_MAC || rc3) fprintf(stderr, "  tamper rc %d, retry rc %d\n", rc2, rc3);
    CHECK(bob_dec(&s, A, t3, m3, l3, got, sizeof got) == WA_SIG_OK && strcmp(got, "three") == 0, "out of order: 3rd last");
    CHECK(bob_dec(&s, A, t3, m3, l3, got, sizeof got) == WA_SIG_DUPLICATE, "skipped key used once");
    free(m2);
    free(m3);
    free(m4);

    // Replies move the ratchet both ways.
    CHECK(bob_says(&p, &s, A, "hi alice") == 0, "libsignal decrypts our reply");
    CHECK(alice_says(&p, &s, A, "after your reply", "msg") == 0, "plain message after ratchet step");
    int ok = 1;
    for (int round = 0; round < 6; round++) {
        char t[32];
        snprintf(t, sizeof t, "bob %d", round);
        ok &= bob_says(&p, &s, A, t) == 0;
        if (round % 2) ok &= bob_says(&p, &s, A, "and again") == 0;
        snprintf(t, sizeof t, "alice %d", round);
        ok &= alice_says(&p, &s, A, t, "msg") == 0;
        ok &= alice_says(&p, &s, A, "more", "msg") == 0;
    }
    CHECK(ok, "six ping-pong rounds of ratchet steps");

    // A message from an older chain arriving after a ratchet step.
    size_t lo;
    char to[8];
    uint8_t *old = alice_enc(&p, "late", &lo, to);
    CHECK(bob_says(&p, &s, A, "step") == 0 && alice_says(&p, &s, A, "new chain", "msg") == 0, "ratchet step");
    CHECK(old && bob_dec(&s, A, to, old, lo, got, sizeof got) == WA_SIG_OK && strcmp(got, "late") == 0,
          "late message from the previous chain");
    free(old);

    // Alice starts over (a new prekey message, new base key) while a message
    // from the old session is still in flight.
    uint8_t *stale = alice_enc(&p, "stale", &lo, to);
    send_bundle(&p, &st, NULL);
    CHECK(alice_says(&p, &s, A, "fresh start", "pkmsg") == 0, "new session without a one-time prekey");
    CHECK(stale && bob_dec(&s, A, to, stale, lo, got, sizeof got) == WA_SIG_OK && strcmp(got, "stale") == 0,
          "archived session still decrypts");
    free(stale);
    CHECK(alice_says(&p, &s, A, "back on the new one", "pkmsg") == 0, "promoted state switches back");
    CHECK(bob_says(&p, &s, A, "ack") == 0 && alice_says(&p, &s, A, "done", "msg") == 0, "new session ratchets");

    // A prekey message naming a prekey we never had.
    wa_prekey_pub ghost = {999, {0}};
    memcpy(ghost.pub, pks[0].pub, 32);
    send_bundle(&p, &st, &ghost);
    CHECK(alice_says(&p, &s, A, "who?", "pkmsg") == WA_SIG_ERR_NO_PREKEY, "unknown prekey id rejected");
    CHECK(alice_says(&p, &s, "nobody@s.whatsapp.net", "x", NULL) != WA_SIG_OK, "wrong sender address fails");

    // Sender keys.
    size_t dl;
    uint8_t *skdm = reply_bytes(peer_cmd(&p, "skdm 123-456@g.us"), "skdm", &dl);
    CHECK(skdm && wa_sig_group_process(&s, "123-456@g.us", A, skdm, dl) == WA_SIG_OK, "process sender key distribution");
    free(skdm);
    uint8_t *g[3];
    size_t gl[3];
    const char *gt[3] = {"group one", "group two", "group three"};
    for (int i = 0; i < 3; i++) {
        char h[64];
        hexs((const uint8_t *)gt[i], strlen(gt[i]), h);
        g[i] = reply_bytes(peer_cmd(&p, "genc 123-456@g.us %s", h), "skmsg", &gl[i]);
    }
    if (g[0] && g[1] && g[2]) {
        uint8_t *pt;
        size_t ptl;
        int order[3] = {2, 0, 1};
        ok = 1;
        for (int k = 0; k < 3; k++) {
            int i = order[k];
            ok &= wa_sig_group_decrypt(&s, "123-456@g.us", A, g[i], gl[i], &pt, &ptl) == WA_SIG_OK && ptl == strlen(gt[i]) &&
                  memcmp(pt, gt[i], ptl) == 0;
            free(pt);
        }
        CHECK(ok, "group messages out of order");
        CHECK(wa_sig_group_decrypt(&s, "123-456@g.us", A, g[1], gl[1], &pt, &ptl) == WA_SIG_DUPLICATE, "group duplicate");
        g[2][gl[2] - 1] ^= 1;
        CHECK(wa_sig_group_decrypt(&s, "123-456@g.us", A, g[2], gl[2], &pt, &ptl) == WA_SIG_ERR_BAD_MAC,
              "group signature checked");
        CHECK(wa_sig_group_decrypt(&s, "999@g.us", A, g[0], gl[0], &pt, &ptl) == WA_SIG_ERR_NO_SENDER_KEY,
              "no sender key for another group");
    } else {
        CHECK(0, "peer group encrypt");
    }
    for (int i = 0; i < 3; i++) free(g[i]);
out:
    kv_clear(&kv);
    peer_stop(&p);
}

// ---------------------------------------------------------------- client path

typedef struct {
    wa_client *c;
    uint8_t wkey[32];
    uint32_t wctr;
    char sent[16][2048];  // printed nodes the client sent
    int nsent;
    uint8_t *raw;  // the last node sent, still binary-encoded
    size_t raw_len;
    char text[256], push[64], chat[96], kind[16];
    int messages, undecryptable;
    char sent_id[32], send_error[64];
    int sends_ok, sends_failed;
} client_probe;

static uint64_t probe_time;

static int probe_send(void *ctx, const uint8_t *data, size_t len) {
    client_probe *pr = ctx;
    if (len < 3 + 16) return 0;
    size_t fl = ((size_t)data[0] << 16) | ((size_t)data[1] << 8) | data[2];
    uint8_t *plain = malloc(fl);
    uint8_t iv[12] = {0};
    iv[8] = pr->wctr >> 24, iv[9] = pr->wctr >> 16, iv[10] = pr->wctr >> 8, iv[11] = pr->wctr;
    pr->wctr++;
    if (wa_aes_gcm_decrypt(pr->wkey, iv, NULL, 0, data + 3, fl, plain) == 0) {
        wa_arena a = {0};
        wa_node *n = wa_node_decode(&a, plain + 1, fl - 16 - 1);
        if (n && pr->nsent < 16) wa_node_print(n, pr->sent[pr->nsent++], sizeof pr->sent[0]);
        if (n) {
            free(pr->raw);
            pr->raw_len = fl - 16 - 1;
            pr->raw = malloc(pr->raw_len);
            memcpy(pr->raw, plain + 1, pr->raw_len);
        }
        wa_arena_free(&a);
    }
    free(plain);
    return 0;
}

static void probe_event(void *ctx, const wa_event *ev) {
    client_probe *pr = ctx;
    if (ev->type == WA_EV_MESSAGE) {
        pr->messages++;
        snprintf(pr->text, sizeof pr->text, "%s", ev->msg->text ? ev->msg->text : "");
        snprintf(pr->push, sizeof pr->push, "%s", ev->msg->push_name ? ev->msg->push_name : "");
        snprintf(pr->chat, sizeof pr->chat, "%s", ev->msg->chat);
        snprintf(pr->kind, sizeof pr->kind, "%s", ev->msg->kind);
    } else if (ev->type == WA_EV_UNDECRYPTABLE) {
        pr->undecryptable++;
    } else if (ev->type == WA_EV_SENT) {
        pr->sends_ok++;
        snprintf(pr->sent_id, sizeof pr->sent_id, "%s", ev->text);
    } else if (ev->type == WA_EV_SEND_FAILED) {
        pr->sends_failed++;
        snprintf(pr->send_error, sizeof pr->send_error, "%s", ev->text);
    }
}

static uint64_t probe_now(void *ctx) { return probe_time; }

// Feed one node to the client as an encrypted frame from the server.
static void feed_node(wa_client *c, const wa_node *n) {
    wa_buf b = {0};
    wa_node_encode(n, &b);
    uint8_t *frame = malloc(3 + b.len + 16);
    size_t fl = b.len + 16;
    frame[0] = fl >> 16, frame[1] = fl >> 8, frame[2] = fl;
    uint8_t iv[12] = {0};
    iv[8] = c->rctr >> 24, iv[9] = c->rctr >> 16, iv[10] = c->rctr >> 8, iv[11] = c->rctr;
    wa_aes_gcm_encrypt(c->rkey, iv, NULL, 0, b.data, b.len, frame + 3);
    wa_client_on_data(c, frame, 3 + fl);
    free(frame);
    wa_buf_free(&b);
}

// waE2E.Message { conversation = text }, padded like whatsmeow padMessage.
static size_t padded_conversation(const char *text, uint8_t *out) {
    wa_buf m = {0};
    wa_pb_str(&m, 1, text);
    memcpy(out, m.data, m.len);
    size_t n = m.len;
    wa_buf_free(&m);
    memset(out + n, 5, 5);
    return n + 5;
}

static void test_client_messages(void) {
    peer p;
    if (peer_start(&p)) {
        printf("client message path: skipped (set WA_SIGPEER)\n");
        return;
    }
    wa_store st;
    wa_store_init(&st);
    st.paired = true;
    snprintf(st.user, sizeof st.user, "15550009999");
    st.device = 7;
    mem_kv kv = {0};
    client_probe pr = {0};
    wa_client c;
    wa_callbacks cb = {probe_send, probe_event, NULL, probe_now, NULL, NULL, &pr, {kv_get, kv_set, kv_del, &kv}};
    wa_client_init(&c, &st, &cb);
    pr.c = &c;
    c.state = WA_S_OPEN;  // transport keys are all zero, like pr.wkey
    c.header_sent = true;

    wa_sig s = {&st, cb.kv};
    wa_prekey_pub pk;
    wa_sig_prekeys_generate(&s, 1, &pk);
    send_bundle(&p, &st, &pk);
    uint8_t padded[128];
    size_t pl = padded_conversation("hello from libsignal", padded);
    char h[300];
    hexs(padded, pl, h);
    size_t ctl;
    uint8_t *ct = reply_bytes(peer_cmd(&p, "enc %s", h), "pkmsg", &ctl);
    CHECK(ct != NULL, "peer encrypts a padded Message");
    if (ct) {
        wa_jid from = {.user = "15550001111", .server = "s.whatsapp.net", .device = 3};
        wa_attr eattrs[] = {{"v", wa_vstr("2")}, {"type", wa_vstr("pkmsg")}};
        wa_node enc = {"enc", eattrs, 2, wa_vbytes(ct, ctl)};
        wa_attr attrs[] = {{"from", wa_vjid(from)},     {"id", wa_vstr("3EB0ABCDEF")}, {"t", wa_vstr("1763230000")},
                           {"notify", wa_vstr("Alice")}, {"type", wa_vstr("text")}};
        wa_node msg = {"message", attrs, 5, wa_vlist(&enc, 1)};
        feed_node(&c, &msg);
        CHECK(pr.messages == 1 && strcmp(pr.text, "hello from libsignal") == 0, "client emits the decrypted text");
        CHECK(strcmp(pr.push, "Alice") == 0 && strcmp(pr.chat, "15550001111@s.whatsapp.net") == 0 &&
                  strcmp(pr.kind, "text") == 0,
              "message metadata");
        CHECK(pr.nsent == 1 && strstr(pr.sent[0], "<receipt") && strstr(pr.sent[0], "type=\"inactive\"") &&
                  strstr(pr.sent[0], "3EB0ABCDEF"),
              "client sends an inactive delivery receipt");
        if (pr.nsent) printf("%s\n", pr.sent[0]);

        // The same stanza again: a duplicate, still receipted, no new event.
        feed_node(&c, &msg);
        CHECK(pr.messages == 1 && pr.nsent == 2 && strstr(pr.sent[1], "<receipt"), "redelivery is receipted once more");

        // Garbage ciphertext: undecryptable event, retry receipt and ack.
        ct[ctl / 2] ^= 0x55;
        attrs[1].val = wa_vstr("3EB0BAD");
        enc.attrs[1].val = wa_vstr("msg");
        feed_node(&c, &msg);
        CHECK(pr.undecryptable == 1, "undecryptable event");
        CHECK(pr.nsent == 4 && strstr(pr.sent[2], "type=\"retry\"") && strstr(pr.sent[3], "<ack"),
              "retry receipt then ack");
        if (pr.nsent >= 4) printf("%s\n%s\n", pr.sent[2], pr.sent[3]);
        free(ct);
    }

    // A notification is acked with its type.
    wa_attr nattrs[] = {{"from", wa_vjid(WA_SERVER_JID)}, {"id", wa_vstr("123")}, {"type", wa_vstr("encrypt")}};
    wa_attr cattrs[] = {{"value", wa_vstr("40")}};
    wa_node count = {"count", cattrs, 1, {0}};
    wa_node notif = {"notification", nattrs, 3, wa_vlist(&count, 1)};
    int before = pr.nsent;
    feed_node(&c, &notif);
    CHECK(pr.nsent == before + 1 && strstr(pr.sent[before], "<ack") && strstr(pr.sent[before], "class=\"notification\"") &&
              strstr(pr.sent[before], "type=\"encrypt\""),
          "notification acked");
    wa_client_free(&c);
    kv_clear(&kv);
    peer_stop(&p);
}

// ---------------------------------------------------------------- sending

// Two C identities: A starts a session from B's bundle (the sending side).
static wa_prekey_bundle bundle_of(const wa_store *st, const wa_prekey_pub *opk) {
    wa_prekey_bundle b = {0};
    b.reg_id = st->reg_id;
    memcpy(b.ident, st->ident_pub, 32);
    b.spk_id = st->spk_id;
    memcpy(b.spk, st->spk_pub, 32);
    memcpy(b.spk_sig, st->spk_sig, 64);
    if (opk) {
        b.has_opk = true;
        b.opk_id = opk->id;
        memcpy(b.opk, opk->pub, 32);
    }
    return b;
}

static int c_enc(wa_sig *s, const char *addr, const char *text, uint8_t **ct, size_t *len, bool *prekey) {
    return wa_sig_encrypt(s, addr, (const uint8_t *)text, strlen(text), ct, len, prekey);
}

static int c_dec_eq(wa_sig *s, const char *addr, bool prekey, const uint8_t *ct, size_t len, const char *want) {
    uint8_t *pt;
    size_t ptl;
    int rc = wa_sig_decrypt(s, addr, prekey, ct, len, &pt, &ptl);
    if (rc) return rc;
    int ok = ptl == strlen(want) && memcmp(pt, want, ptl) == 0;
    free(pt);
    return ok ? 0 : -100;
}

static void test_signal_initiator(void) {
    wa_store a, b;
    wa_store_init(&a);
    wa_store_init(&b);
    mem_kv akv = {0}, bkv = {0};
    wa_sig as = {&a, {kv_get, kv_set, kv_del, &akv}}, bs = {&b, {kv_get, kv_set, kv_del, &bkv}};
    const char *AB = "b:3@lid", *BA = "a:7@lid";
    wa_prekey_pub opk;
    CHECK(wa_sig_prekeys_generate(&bs, 1, &opk) == 1, "B makes a one-time prekey");
    CHECK(wa_sig_has_session(&as, AB) == 0, "no session before the bundle");

    wa_prekey_bundle bad = bundle_of(&b, &opk);
    bad.spk_sig[3] ^= 1;
    CHECK(wa_sig_process_bundle(&as, AB, &bad) == WA_SIG_ERR_BAD_MAC, "a bundle with a bad signed-prekey signature is refused");
    CHECK(wa_sig_has_session(&as, AB) == 0, "and makes no session");

    wa_prekey_bundle bb = bundle_of(&b, &opk);
    CHECK(wa_sig_process_bundle(&as, AB, &bb) == WA_SIG_OK, "A starts a session from B's bundle");
    CHECK(wa_sig_has_session(&as, AB) == 1, "A has a session");

    uint8_t *ct;
    size_t len;
    bool prekey = false;
    CHECK(c_enc(&as, AB, "first", &ct, &len, &prekey) == 0 && prekey, "A's first message is a prekey message");
    CHECK(c_dec_eq(&bs, BA, true, ct, len, "first") == 0, "B decrypts it");
    free(ct);
    CHECK(c_enc(&as, AB, "second", &ct, &len, &prekey) == 0 && prekey, "still a prekey message before B answers");
    CHECK(c_dec_eq(&bs, BA, true, ct, len, "second") == 0, "B decrypts the second");
    free(ct);
    CHECK(c_enc(&bs, BA, "reply", &ct, &len, &prekey) == 0 && !prekey, "B answers with a normal message");
    CHECK(c_dec_eq(&as, AB, false, ct, len, "reply") == 0, "A decrypts B's answer");
    free(ct);
    CHECK(c_enc(&as, AB, "third", &ct, &len, &prekey) == 0 && !prekey, "after the answer A sends normal messages");
    CHECK(c_dec_eq(&bs, BA, false, ct, len, "third") == 0, "B decrypts it");
    free(ct);

    // A bundle without a one-time prekey works too, and replaces the session.
    wa_prekey_bundle nb = bundle_of(&b, NULL);
    CHECK(wa_sig_process_bundle(&as, AB, &nb) == WA_SIG_OK, "a bundle without a one-time prekey");
    CHECK(c_enc(&as, AB, "fresh", &ct, &len, &prekey) == 0 && prekey, "the new session sends a prekey message");
    CHECK(c_dec_eq(&bs, BA, true, ct, len, "fresh") == 0, "B takes the new session");
    free(ct);
    kv_clear(&akv);
    kv_clear(&bkv);
}

static wa_prekey_bundle parse_peer_bundle(const char *line, bool *ok) {
    wa_prekey_bundle b = {0};
    unsigned reg, spkid;
    char ik[65], spk[65], sig[129], oid[16], opk[65];
    *ok = sscanf(line, "bundle %u %64s %u %64s %128s %15s %64s", &reg, ik, &spkid, spk, sig, oid, opk) == 7;
    if (!*ok) {
        fprintf(stderr, "  peer said: %.200s\n", line);
        return b;
    }
    b.reg_id = reg;
    unhex(ik, b.ident);
    b.spk_id = spkid;
    unhex(spk, b.spk);
    unhex(sig, b.spk_sig);
    if (strcmp(oid, "-") != 0) {
        b.has_opk = true;
        b.opk_id = (uint32_t)strtoul(oid, NULL, 10);
        unhex(opk, b.opk);
    }
    return b;
}

// Encrypt text to Carol (the Go peer) and have her decrypt it.
static int to_carol(peer *p, wa_sig *s, const char *addr, const char *text, const char *want_type) {
    uint8_t *ct;
    size_t len;
    bool prekey;
    int rc = c_enc(s, addr, text, &ct, &len, &prekey);
    if (rc) return rc;
    const char *type = prekey ? "pkmsg" : "msg";
    char *h = malloc(2 * len + 1);
    hexs(ct, len, h);
    free(ct);
    const char *r = peer_cmd(p, "cdec %s %s", type, h);
    free(h);
    size_t pl;
    uint8_t *pt = reply_bytes(r, "pt", &pl);
    int ok = pt && pl == strlen(text) && memcmp(pt, text, pl) == 0 && strcmp(type, want_type) == 0;
    free(pt);
    return ok ? 0 : -3;
}

static void test_signal_initiator_interop(void) {
    peer p;
    if (peer_start(&p)) {
        printf("signal initiator interop: skipped (set WA_SIGPEER)\n");
        return;
    }
    wa_store st;
    wa_store_init(&st);
    mem_kv kv = {0};
    wa_sig s = {&st, {kv_get, kv_set, kv_del, &kv}};
    const char *C = "carol:1@lid";
    bool ok;
    wa_prekey_bundle b = parse_peer_bundle(peer_cmd(&p, "carol"), &ok);
    CHECK(ok, "peer publishes a bundle");
    CHECK(wa_sig_process_bundle(&s, C, &b) == WA_SIG_OK, "libsignal's bundle verifies and starts a session");
    CHECK(to_carol(&p, &s, C, "hello carol", "pkmsg") == 0, "libsignal decrypts our prekey message");
    CHECK(to_carol(&p, &s, C, "again", "pkmsg") == 0, "and our second, still a prekey message");
    // Carol answers; that acknowledges the session.
    char h[64];
    hexs((const uint8_t *)"hi back", 7, h);
    size_t cl;
    uint8_t *ct = reply_bytes(peer_cmd(&p, "cenc %s", h), "msg", &cl);
    CHECK(ct != NULL, "libsignal answers with a normal message");
    if (ct) CHECK(c_dec_eq(&s, C, false, ct, cl, "hi back") == 0, "we decrypt libsignal's answer");
    free(ct);
    CHECK(to_carol(&p, &s, C, "now plain", "msg") == 0, "after the answer we send normal messages");
    for (int i = 0; i < 3; i++) CHECK(to_carol(&p, &s, C, "more", "msg") == 0, "chain steps");

    // Without a one-time prekey, to a second address.
    const char *C2 = "carol:2@lid";
    b = parse_peer_bundle(peer_cmd(&p, "carol noopk"), &ok);
    CHECK(ok && !b.has_opk, "peer publishes a bundle without a one-time prekey");
    CHECK(wa_sig_process_bundle(&s, C2, &b) == WA_SIG_OK && to_carol(&p, &s, C2, "no opk", "pkmsg") == 0,
          "libsignal decrypts a prekey message without a one-time prekey");
    kv_clear(&kv);
    peer_stop(&p);
}

// A <user jid=...> node of a prekey answer, from a C identity's keys.
typedef struct {
    uint8_t reg[4], sid[3], oid[3];
    wa_node skey_kids[3], key_kids[2], keys_kids[3], kids[4];
    wa_attr attrs[1];
} bundle_nodes;

static void be_put(uint32_t v, uint8_t *out, int n) {
    for (int i = n - 1; i >= 0; i--, v >>= 8) out[i] = (uint8_t)v;
}

static wa_node bundle_user(bundle_nodes *b, wa_jid jid, const wa_store *st, const wa_prekey_pub *opk, bool wrap) {
    be_put(st->reg_id, b->reg, 4);
    be_put(st->spk_id, b->sid, 3);
    b->skey_kids[0] = (wa_node){"id", NULL, 0, wa_vbytes(b->sid, 3)};
    b->skey_kids[1] = (wa_node){"value", NULL, 0, wa_vbytes(st->spk_pub, 32)};
    b->skey_kids[2] = (wa_node){"signature", NULL, 0, wa_vbytes(st->spk_sig, 64)};
    wa_node *k = wrap ? b->keys_kids : b->kids + 1;
    size_t nk = 0;
    k[nk++] = (wa_node){"identity", NULL, 0, wa_vbytes(st->ident_pub, 32)};
    k[nk++] = (wa_node){"skey", NULL, 0, wa_vlist(b->skey_kids, 3)};
    if (opk) {
        be_put(opk->id, b->oid, 3);
        b->key_kids[0] = (wa_node){"id", NULL, 0, wa_vbytes(b->oid, 3)};
        b->key_kids[1] = (wa_node){"value", NULL, 0, wa_vbytes(opk->pub, 32)};
        k[nk++] = (wa_node){"key", NULL, 0, wa_vlist(b->key_kids, 2)};
    }
    b->kids[0] = (wa_node){"registration", NULL, 0, wa_vbytes(b->reg, 4)};
    size_t n = 1 + nk;
    if (wrap) {
        b->kids[1] = (wa_node){"keys", NULL, 0, wa_vlist(b->keys_kids, nk)};
        n = 2;
    }
    b->attrs[0] = (wa_attr){"jid", wa_vjid(jid)};
    return (wa_node){"user", b->attrs, 1, wa_vlist(b->kids, n)};
}

static void feed_iq_result(wa_client *c, const char *id, wa_node *kids, size_t n) {
    wa_attr attrs[] = {{"from", wa_vjid(WA_SERVER_JID)}, {"id", wa_vstr(id)}, {"type", wa_vstr("result")}};
    wa_node iq = {"iq", attrs, 3, wa_vlist(kids, n)};
    feed_node(c, &iq);
}

// <usync><list><user jid=...><devices><device-list><device id=.../>...
typedef struct {
    wa_attr uattr[1], dattrs[6][2];
    wa_node devs[6], dl, devices, user;
} device_user;

static wa_node *device_list(device_user *u, wa_jid jid, const char *const *ids, int n) {
    for (int i = 0; i < n; i++) {
        bool hosted = ids[i][0] == 'h';
        u->dattrs[i][0] = (wa_attr){"id", wa_vstr(hosted ? ids[i] + 1 : ids[i])};
        u->dattrs[i][1] = (wa_attr){"is_hosted", wa_vstr("true")};
        u->devs[i] = (wa_node){"device", u->dattrs[i], hosted ? 2 : 1, {0}};
    }
    u->dl = (wa_node){"device-list", NULL, 0, wa_vlist(u->devs, (size_t)n)};
    u->devices = (wa_node){"devices", NULL, 0, wa_vlist(&u->dl, 1)};
    u->uattr[0] = (wa_attr){"jid", wa_vjid(jid)};
    u->user = (wa_node){"user", u->uattr, 1, wa_vlist(&u->devices, 1)};
    return &u->user;
}

static void feed_usync(wa_client *c, const char *id, wa_node *users, size_t n) {
    wa_node list = {"list", NULL, 0, wa_vlist(users, n)};
    wa_node usync = {"usync", NULL, 0, wa_vlist(&list, 1)};
    feed_iq_result(c, id, &usync, 1);
}

// Find <to jid=user:device@lid><enc type=...> in the last sent node.
static const uint8_t *find_enc(client_probe *pr, wa_arena *a, const char *user, int device, const char **type,
                               size_t *len) {
    wa_node *m = wa_node_decode(a, pr->raw, pr->raw_len);
    const wa_node *parts = m ? wa_child(m, "participants") : NULL, *tos;
    size_t n = parts ? wa_children(parts, &tos) : 0;
    for (size_t i = 0; i < n; i++) {
        const wa_jid *j = wa_attr_jid(&tos[i], "jid");
        const wa_node *enc = wa_child(&tos[i], "enc");
        if (j && enc && strcmp(j->user, user) == 0 && j->device == device && enc->content.type == WA_V_BYTES) {
            *type = wa_attr_str(enc, "type");
            *len = enc->content.bytes.len;
            return enc->content.bytes.data;
        }
    }
    return NULL;
}

// Decrypt a participant's <enc> with that device's keys and unpad it.
static int open_enc(client_probe *pr, wa_sig *s, const char *user, int device, uint8_t **pt, size_t *ptl,
                    char type[8]) {
    wa_arena a = {0};
    const char *t = NULL;
    size_t len = 0;
    const uint8_t *ct = find_enc(pr, &a, user, device, &t, &len);
    int rc = -1;
    if (ct && t) {
        snprintf(type, 8, "%s", t);
        rc = wa_sig_decrypt(s, "me:7@lid", strcmp(t, "pkmsg") == 0, ct, len, pt, ptl);
        if (rc == 0) {
            long ul = wa_unpad(*pt, *ptl);
            if (ul < 0) rc = -2;
            else *ptl = (size_t)ul;
        }
    }
    wa_arena_free(&a);
    return rc;
}

static void test_client_send(void) {
    wa_store st;
    wa_store_init(&st);
    st.paired = true;
    snprintf(st.user, sizeof st.user, "15550009999");
    snprintf(st.lid_user, sizeof st.lid_user, "77700009999");
    st.device = 7;
    st.account_len = 3;
    memcpy(st.account, "\x0a\x01\x00", 3);
    mem_kv kv = {0};
    static client_probe pr;
    memset(&pr, 0, sizeof pr);
    wa_client c;
    wa_callbacks cb = {probe_send, probe_event, NULL, probe_now, NULL, NULL, &pr, {kv_get, kv_set, kv_del, &kv}};
    wa_client_init(&c, &st, &cb);
    c.state = WA_S_OPEN;
    c.header_sent = true;
    c.logged_in = true;
    probe_time = 1000;

    // The other side: their phone (device 0), a companion (3) and our own phone.
    wa_store them0, them3, mine0;
    wa_store_init(&them0);
    wa_store_init(&them3);
    wa_store_init(&mine0);
    mem_kv k0 = {0}, k3 = {0}, km = {0};
    wa_sig s0 = {&them0, {kv_get, kv_set, kv_del, &k0}}, s3 = {&them3, {kv_get, kv_set, kv_del, &k3}},
           sm = {&mine0, {kv_get, kv_set, kv_del, &km}};
    wa_prekey_pub opk0;
    wa_sig_prekeys_generate(&s0, 1, &opk0);

    CHECK(wa_client_send_text(&c, "15550001111:2@s.whatsapp.net", "x") == NULL, "a device JID is refused");
    CHECK(wa_client_send_text(&c, "123@g.us", "x") == NULL, "groups are not supported yet");
    const char *id = wa_client_send_text(&c, "15550001111@s.whatsapp.net", "hello from the Core2");
    CHECK(id && strlen(id) == 22 && strncmp(id, "3EB0", 4) == 0, "send starts with a whatsmeow-style id");
    char msg_id[32];
    snprintf(msg_id, sizeof msg_id, "%s", id ? id : "");
    CHECK(wa_client_send_text(&c, "15550001111@s.whatsapp.net", "x") == NULL, "one send at a time");
    CHECK(pr.nsent == 1 && strstr(pr.sent[0], "xmlns=\"usync\"") && strstr(pr.sent[0], "<lid") &&
              strstr(pr.sent[0], "15550001111@s.whatsapp.net"),
          "a phone number is looked up for its LID first");

    // usync answer: the LID.
    wa_jid pn = {.user = "15550001111", .server = "s.whatsapp.net"};
    wa_jid lid = {.user = "88800001111", .server = "lid"};
    wa_attr lattr[] = {{"val", wa_vjid(lid)}};
    wa_node lidn = {"lid", lattr, 1, {0}};
    wa_attr uattr[] = {{"jid", wa_vjid(pn)}};
    wa_node u = {"user", uattr, 1, wa_vlist(&lidn, 1)};
    feed_usync(&c, c.out.iq_id, &u, 1);
    CHECK(pr.nsent == 2 && strstr(pr.sent[1], "context=\"message\"") && strstr(pr.sent[1], "88800001111@lid") &&
              strstr(pr.sent[1], "77700009999@lid"),
          "then both device lists, by LID");

    // Devices: theirs 0 and 3; ours 0, 7 (this device) and a hosted 9.
    static const char *const theirs[] = {"0", "3"}, *const ours[] = {"0", "7", "h9"};
    device_user du[2];
    wa_jid own = {.user = "77700009999", .server = "lid"};
    wa_node users[2] = {*device_list(&du[0], lid, theirs, 2), *device_list(&du[1], own, ours, 3)};
    feed_usync(&c, c.out.iq_id, users, 2);
    CHECK(c.out.ndev == 3, "three devices: not ourselves, not hosted");
    CHECK(pr.nsent == 3 && strstr(pr.sent[2], "xmlns=\"encrypt\"") && strstr(pr.sent[2], "88800001111:3@lid") &&
              strstr(pr.sent[2], "reason=\"identity\""),
          "prekeys are fetched for devices without a session");

    // Prekeys: device 0 flat with a one-time key, our phone wrapped in <keys>,
    // device 3 an error.
    bundle_nodes bn[2];
    wa_jid j0 = lid, jm = own, j3 = lid;
    j3.device = 3;
    wa_node err = {"error", NULL, 0, {0}};
    wa_attr e3attr[] = {{"jid", wa_vjid(j3)}};
    wa_node pk_users[3] = {bundle_user(&bn[0], j0, &them0, &opk0, false), {"user", e3attr, 1, wa_vlist(&err, 1)},
                           bundle_user(&bn[1], jm, &mine0, NULL, true)};
    wa_node pklist = {"list", NULL, 0, wa_vlist(pk_users, 3)};
    feed_iq_result(&c, c.out.iq_id, &pklist, 1);
    CHECK(pr.nsent == 4 && strstr(pr.sent[3], "<message") && strstr(pr.sent[3], "type=\"text\"") &&
              strstr(pr.sent[3], "to=\"88800001111@lid\"") &&
              strstr(pr.sent[3], "peer_recipient_pn=\"15550001111@s.whatsapp.net\"") &&
              strstr(pr.sent[3], "<device-identity"),
          "the message goes to the LID, with the phone number and our device identity");
    if (pr.nsent >= 4) printf("%.300s...\n", pr.sent[3]);

    uint8_t *pt;
    size_t ptl;
    char type[8];
    int rc = open_enc(&pr, &s0, "88800001111", 0, &pt, &ptl, type);
    CHECK(rc == 0 && strcmp(type, "pkmsg") == 0, "their phone decrypts its prekey message");
    if (rc == 0) {
        const uint8_t *conv;
        size_t cl;
        CHECK(wa_pb_get_bytes(pt, ptl, 1, &conv, &cl) && cl == 20 && memcmp(conv, "hello from the Core2", 20) == 0,
              "it is a Message with conversation set");
        free(pt);
    }
    wa_arena a = {0};
    const char *t;
    size_t l;
    CHECK(find_enc(&pr, &a, "88800001111", 3, &t, &l) == NULL, "the device whose prekeys failed is left out");
    wa_arena_free(&a);
    rc = open_enc(&pr, &sm, "77700009999", 0, &pt, &ptl, type);
    CHECK(rc == 0, "our own phone decrypts its copy");
    if (rc == 0) {
        const uint8_t *dsm, *dest, *inner, *conv;
        size_t dl, del, il, cl;
        CHECK(wa_pb_get_bytes(pt, ptl, 31, &dsm, &dl) && wa_pb_get_bytes(dsm, dl, 1, &dest, &del) &&
                  del == 15 && memcmp(dest, "88800001111@lid", 15) == 0 && wa_pb_get_bytes(dsm, dl, 2, &inner, &il) &&
                  wa_pb_get_bytes(inner, il, 1, &conv, &cl) && cl == 20,
              "our devices get a DeviceSentMessage naming the chat");
        free(pt);
    }

    // The server takes it.
    wa_attr aattrs[] = {{"class", wa_vstr("message")}, {"id", wa_vstr(msg_id)}, {"from", wa_vjid(lid)},
                        {"t", wa_vstr("1763230000")}};
    wa_node ack = {"ack", aattrs, 4, {0}};
    feed_node(&c, &ack);
    CHECK(pr.sends_ok == 1 && strcmp(pr.sent_id, msg_id) == 0 && c.out.stage == 0, "the ack completes the send");

    // Again: the LID is cached and the sessions exist, so devices then the message.
    int before = pr.nsent;
    id = wa_client_send_text(&c, "15550001111@s.whatsapp.net", "second");
    CHECK(id && pr.nsent == before + 1 && strstr(pr.sent[before], "context=\"message\""),
          "a cached LID skips the lookup");
    feed_usync(&c, c.out.iq_id, users, 2);
    CHECK(pr.nsent == before + 2 && strstr(pr.sent[before + 1], "xmlns=\"encrypt\"") &&
              strstr(pr.sent[before + 1], "88800001111:3@lid") && !strstr(pr.sent[before + 1], "88800001111@lid"),
          "prekeys are fetched only for the device still without a session");
    bundle_nodes bn3;
    wa_node pk3 = bundle_user(&bn3, j3, &them3, NULL, false);
    wa_node pklist3 = {"list", NULL, 0, wa_vlist(&pk3, 1)};
    feed_iq_result(&c, c.out.iq_id, &pklist3, 1);
    CHECK(pr.nsent == before + 3 && strstr(pr.sent[before + 2], "<message"), "then the message");
    rc = open_enc(&pr, &s0, "88800001111", 0, &pt, &ptl, type);
    CHECK(rc == 0 && strcmp(type, "pkmsg") == 0, "unanswered sessions keep sending prekey messages");
    if (rc == 0) free(pt);
    rc = open_enc(&pr, &s3, "88800001111", 3, &pt, &ptl, type);
    CHECK(rc == 0 && ptl > 0, "the companion gets its copy now");
    if (rc == 0) free(pt);
    snprintf(msg_id, sizeof msg_id, "%s", id ? id : "");
    aattrs[1].val = wa_vstr(msg_id);
    wa_attr eattr = {"error", wa_vstr("479")};
    wa_attr aattrs2[] = {aattrs[0], aattrs[1], aattrs[2], eattr};
    wa_node nack = {"ack", aattrs2, 4, {0}};
    feed_node(&c, &nack);
    CHECK(pr.sends_failed == 1 && strstr(pr.send_error, "479") && c.out.stage == 0, "an ack with an error fails the send");

    // A LID chat needs no lookup; an unanswered query times out.
    before = pr.nsent;
    id = wa_client_send_text(&c, "88800001111@lid", "third");
    CHECK(id && pr.nsent == before + 1 && strstr(pr.sent[before], "context=\"message\""), "a LID goes straight to devices");
    probe_time += 25000;
    wa_client_tick(&c);
    CHECK(pr.sends_failed == 2 && strstr(pr.send_error, "timed out"), "a send times out");

    wa_client_free(&c);
    free(pr.raw);
    kv_clear(&kv);
    kv_clear(&k0);
    kv_clear(&k3);
    kv_clear(&km);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    test_hkdf();
    test_x25519();
    test_curve_sigs();
    test_gcm();
    test_cbc();
    test_pb();
    test_binary();
    test_store();
    test_signal_interop();
    test_client_messages();
    test_signal_initiator();
    test_signal_initiator_interop();
    test_client_send();
    printf("%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
