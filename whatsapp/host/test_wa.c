// SPDX-License-Identifier: MPL-2.0
// Offline tests for the wa core: crypto vectors, signature round trips,
// protobuf and binary-node round trips. The live handshake (bridge.py) is the
// test against WhatsApp's own signatures.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "wa.h"
#include "wa_crypto.h"
#include "wa_pb.h"

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

int main(void) {
    test_hkdf();
    test_x25519();
    test_curve_sigs();
    test_gcm();
    test_pb();
    test_binary();
    test_store();
    printf("%d passed, %d failed\n", passes, failures);
    return failures ? 1 : 0;
}
