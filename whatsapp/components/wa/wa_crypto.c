// SPDX-License-Identifier: MPL-2.0
// Signature scheme ported from go.mau.fi/libsignal ecc/SignCurve25519.go
// (GPL-3.0 project; the algorithm is libsignal's public curve25519 signature
// scheme, re-implemented here from its description, not copied).
#include "wa_crypto.h"

#include <string.h>

#include "mbedtls/aes.h"
#include "mbedtls/bignum.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "third_party/monocypher-ed25519.h"
#include "third_party/monocypher.h"

int wa_x25519_keypair(uint8_t priv[32], uint8_t pub[32]) {
    if (wa_random(priv, 32) != 0) return -1;
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    crypto_x25519_public_key(pub, priv);
    return 0;
}

void wa_x25519_pub(const uint8_t priv[32], uint8_t pub[32]) { crypto_x25519_public_key(pub, priv); }

int wa_x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32]) {
    crypto_x25519(out, priv, pub);
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= out[i];
    return acc ? 0 : -1;
}

static void sha512_parts(const wa_slice *parts, size_t n, uint8_t out[64]) {
    mbedtls_sha512_context c;
    mbedtls_sha512_init(&c);
    mbedtls_sha512_starts(&c, 0);
    for (size_t i = 0; i < n; i++) mbedtls_sha512_update(&c, parts[i].data, parts[i].len);
    mbedtls_sha512_finish(&c, out);
    mbedtls_sha512_free(&c);
}

int wa_curve_sign(uint8_t sig[64], const uint8_t priv[32], const uint8_t *msg, size_t len) {
    static const uint8_t diversifier[32] = {
        0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t a[32], A[32], rnd[64], r[64], rr[32], R[32], h[64], hr[32];
    if (wa_random(rnd, sizeof rnd) != 0) return -1;

    crypto_eddsa_trim_scalar(a, priv);  // clamping, as SetBytesWithClamping does
    crypto_eddsa_scalarbase(A, a);

    wa_slice p1[] = {{diversifier, 32}, {priv, 32}, {msg, len}, {rnd, 64}};
    sha512_parts(p1, 4, r);
    crypto_eddsa_reduce(rr, r);
    crypto_eddsa_scalarbase(R, rr);

    wa_slice p2[] = {{R, 32}, {A, 32}, {msg, len}};
    sha512_parts(p2, 3, h);
    crypto_eddsa_reduce(hr, h);

    memcpy(sig, R, 32);
    crypto_eddsa_mul_add(sig + 32, hr, a, rr);  // s = h*a + r mod L
    sig[63] |= A[31] & 0x80;

    crypto_wipe(a, sizeof a);
    crypto_wipe(r, sizeof r);
    crypto_wipe(rr, sizeof rr);
    return 0;
}

// Montgomery u -> Edwards y = (u - 1) / (u + 1) mod p. If u + 1 == 0 the
// result is 0, matching a field inversion by exponentiation.
static int mont_to_edwards(const uint8_t u_bytes[32], uint8_t y_out[32]) {
    mbedtls_mpi p, u, num, den, inv, y;
    int ret = -1;
    mbedtls_mpi_init(&p);
    mbedtls_mpi_init(&u);
    mbedtls_mpi_init(&num);
    mbedtls_mpi_init(&den);
    mbedtls_mpi_init(&inv);
    mbedtls_mpi_init(&y);
    // p = 2^255 - 19
    if (mbedtls_mpi_lset(&p, 1) || mbedtls_mpi_shift_l(&p, 255) || mbedtls_mpi_sub_int(&p, &p, 19)) goto out;
    if (mbedtls_mpi_read_binary_le(&u, u_bytes, 32) || mbedtls_mpi_mod_mpi(&u, &u, &p)) goto out;
    if (mbedtls_mpi_sub_int(&num, &u, 1) || mbedtls_mpi_mod_mpi(&num, &num, &p)) goto out;
    if (mbedtls_mpi_add_int(&den, &u, 1) || mbedtls_mpi_mod_mpi(&den, &den, &p)) goto out;
    if (mbedtls_mpi_cmp_int(&den, 0) == 0) {
        mbedtls_mpi_lset(&y, 0);
    } else {
        if (mbedtls_mpi_inv_mod(&inv, &den, &p)) goto out;
        if (mbedtls_mpi_mul_mpi(&y, &num, &inv) || mbedtls_mpi_mod_mpi(&y, &y, &p)) goto out;
    }
    if (mbedtls_mpi_write_binary_le(&y, y_out, 32)) goto out;
    ret = 0;
out:
    mbedtls_mpi_free(&p);
    mbedtls_mpi_free(&u);
    mbedtls_mpi_free(&num);
    mbedtls_mpi_free(&den);
    mbedtls_mpi_free(&inv);
    mbedtls_mpi_free(&y);
    return ret;
}

int wa_curve_verify(const uint8_t pub[32], const uint8_t *msg, size_t len, const uint8_t sig_in[64]) {
    uint8_t u[32], A_ed[32], sig[64];
    memcpy(u, pub, 32);
    u[31] &= 0x7F;
    if (mont_to_edwards(u, A_ed) != 0) return 0;
    memcpy(sig, sig_in, 64);
    A_ed[31] |= sig[63] & 0x80;
    sig[63] &= 0x7F;
    return crypto_ed25519_check(sig, A_ed, msg, len) == 0;
}

void wa_sha256(const uint8_t *data, size_t len, uint8_t out[32]) { mbedtls_sha256(data, len, out, 0); }

void wa_sha256_2(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen, uint8_t out[32]) {
    mbedtls_sha256_context c;
    mbedtls_sha256_init(&c);
    mbedtls_sha256_starts(&c, 0);
    mbedtls_sha256_update(&c, a, alen);
    mbedtls_sha256_update(&c, b, blen);
    mbedtls_sha256_finish(&c, out);
    mbedtls_sha256_free(&c);
}

void wa_md5(const uint8_t *data, size_t len, uint8_t out[16]) { mbedtls_md5(data, len, out); }

void wa_hmac_sha256(const uint8_t *key, size_t keylen, const wa_slice *parts, size_t n, uint8_t out[32]) {
    mbedtls_md_context_t c;
    mbedtls_md_init(&c);
    mbedtls_md_setup(&c, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&c, key, keylen);
    for (size_t i = 0; i < n; i++) mbedtls_md_hmac_update(&c, parts[i].data, parts[i].len);
    mbedtls_md_hmac_finish(&c, out);
    mbedtls_md_free(&c);
}

void wa_hkdf_sha256(const uint8_t *salt, size_t saltlen, const uint8_t *ikm, size_t ikmlen,
                    const uint8_t *info, size_t infolen, uint8_t *out, size_t outlen) {
    static const uint8_t zero[32] = {0};
    uint8_t prk[32], t[32];
    if (!salt || saltlen == 0) {
        salt = zero;
        saltlen = 32;
    }
    wa_slice ex[] = {{ikm, ikmlen}};
    wa_hmac_sha256(salt, saltlen, ex, ikm ? 1 : 0, prk);
    size_t tlen = 0, done = 0;
    for (uint8_t i = 1; done < outlen; i++) {
        wa_slice parts[] = {{t, tlen}, {info, infolen}, {&i, 1}};
        wa_hmac_sha256(prk, 32, parts, 3, t);
        tlen = 32;
        size_t take = outlen - done < 32 ? outlen - done : 32;
        memcpy(out + done, t, take);
        done += take;
    }
}

int wa_aes_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aadlen,
                       const uint8_t *in, size_t len, uint8_t *out) {
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    int ret = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (!ret) ret = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, len, iv, 12, aad, aadlen, in, out, 16, out + len);
    mbedtls_gcm_free(&g);
    return ret ? -1 : 0;
}

int wa_aes_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aadlen,
                       const uint8_t *in, size_t len, uint8_t *out) {
    if (len < 16) return -1;
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    int ret = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (!ret) ret = mbedtls_gcm_auth_decrypt(&g, len - 16, iv, 12, aad, aadlen, in + len - 16, 16, in, out);
    mbedtls_gcm_free(&g);
    return ret ? -1 : 0;
}

void wa_pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen, uint32_t iterations,
                      uint8_t *out, size_t outlen) {
    mbedtls_md_context_t c;
    mbedtls_md_init(&c);
    mbedtls_md_setup(&c, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&c, pw, pwlen);
    uint8_t u[32], t[32];
    for (uint32_t block = 1, done = 0; done < outlen; block++) {
        uint8_t be[4] = {block >> 24, block >> 16, block >> 8, block};
        mbedtls_md_hmac_reset(&c);
        mbedtls_md_hmac_update(&c, salt, saltlen);
        mbedtls_md_hmac_update(&c, be, 4);
        mbedtls_md_hmac_finish(&c, u);
        memcpy(t, u, 32);
        for (uint32_t i = 1; i < iterations; i++) {
            mbedtls_md_hmac_reset(&c);
            mbedtls_md_hmac_update(&c, u, 32);
            mbedtls_md_hmac_finish(&c, u);
            for (int k = 0; k < 32; k++) t[k] ^= u[k];
        }
        size_t take = outlen - done < 32 ? outlen - done : 32;
        memcpy(out + done, t, take);
        done += (uint32_t)take;
    }
    mbedtls_md_free(&c);
}

int wa_aes_ctr(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out) {
    mbedtls_aes_context a;
    uint8_t nonce[16], stream[16];
    size_t off = 0;
    memcpy(nonce, iv, 16);
    mbedtls_aes_init(&a);
    int ret = mbedtls_aes_setkey_enc(&a, key, 256);
    if (!ret) ret = mbedtls_aes_crypt_ctr(&a, len, &off, nonce, stream, in, out);
    mbedtls_aes_free(&a);
    return ret ? -1 : 0;
}

// PKCS#7-padded AES-256-CBC (libsignal cipher/Cipher.go EncryptCbc/DecryptCbc).
int wa_aes_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out,
                       size_t *outlen) {
    size_t pad = 16 - len % 16, total = len + pad;
    memmove(out, in, len);
    memset(out + len, (int)pad, pad);
    uint8_t ivc[16];
    memcpy(ivc, iv, 16);
    mbedtls_aes_context a;
    mbedtls_aes_init(&a);
    int ret = mbedtls_aes_setkey_enc(&a, key, 256);
    if (!ret) ret = mbedtls_aes_crypt_cbc(&a, MBEDTLS_AES_ENCRYPT, total, ivc, out, out);
    mbedtls_aes_free(&a);
    if (ret) return -1;
    *outlen = total;
    return 0;
}

int wa_aes_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out,
                       size_t *outlen) {
    if (len == 0 || len % 16) return -1;
    uint8_t ivc[16];
    memcpy(ivc, iv, 16);
    mbedtls_aes_context a;
    mbedtls_aes_init(&a);
    int ret = mbedtls_aes_setkey_dec(&a, key, 256);
    if (!ret) ret = mbedtls_aes_crypt_cbc(&a, MBEDTLS_AES_DECRYPT, len, ivc, in, out);
    mbedtls_aes_free(&a);
    if (ret) return -1;
    uint8_t pad = out[len - 1];
    if (pad == 0 || pad > 16) return -1;
    for (size_t i = len - pad; i < len; i++)
        if (out[i] != pad) return -1;
    *outlen = len - pad;
    return 0;
}

int wa_ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

void wa_base64(const uint8_t *in, size_t len, char *out) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        out[o++] = tbl[(v >> 18) & 63];
        out[o++] = tbl[(v >> 12) & 63];
        out[o++] = i + 1 < len ? tbl[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < len ? tbl[v & 63] : '=';
    }
    out[o] = 0;
}
