// SPDX-License-Identifier: MPL-2.0
// Crypto primitives the WhatsApp multi-device protocol needs, over mbedTLS
// (SHA, HMAC, AES-GCM, bignum) and Monocypher (Curve25519 / Ed25519 math).
#pragma once
#include <stddef.h>
#include <stdint.h>

// Fill out with cryptographically secure random bytes. Provided by the
// platform layer (host: getrandom; ESP32: esp_fill_random). Returns 0 on success.
int wa_random(uint8_t *out, size_t n);

// X25519 key pair with a clamped random private key.
int wa_x25519_keypair(uint8_t priv[32], uint8_t pub[32]);
void wa_x25519_pub(const uint8_t priv[32], uint8_t pub[32]);
// Shared secret; returns -1 for an all-zero (low-order) result.
int wa_x25519(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32]);

// libsignal "curve25519 signatures": Ed25519 arithmetic over a Montgomery
// key pair, with the Edwards sign bit carried in the signature's top bit.
int wa_curve_sign(uint8_t sig[64], const uint8_t priv[32], const uint8_t *msg, size_t len);
// Returns 1 if valid, 0 if not.
int wa_curve_verify(const uint8_t pub[32], const uint8_t *msg, size_t len, const uint8_t sig[64]);

void wa_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
// SHA-256 over the concatenation a || b.
void wa_sha256_2(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen, uint8_t out[32]);
void wa_md5(const uint8_t *data, size_t len, uint8_t out[16]);

typedef struct {
    const uint8_t *data;
    size_t len;
} wa_slice;
// HMAC-SHA256 over the concatenation of n parts.
void wa_hmac_sha256(const uint8_t *key, size_t keylen, const wa_slice *parts, size_t n, uint8_t out[32]);
// HKDF-SHA256 (RFC 5869). salt/ikm/info may be NULL with length 0.
void wa_hkdf_sha256(const uint8_t *salt, size_t saltlen, const uint8_t *ikm, size_t ikmlen,
                    const uint8_t *info, size_t infolen, uint8_t *out, size_t outlen);

// AES-256-GCM with a 12-byte IV and 16-byte tag appended to the ciphertext.
// out must hold len + 16 bytes for encrypt, len - 16 for decrypt.
int wa_aes_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aadlen,
                       const uint8_t *in, size_t len, uint8_t *out);
// Returns 0 on success, -1 on authentication failure.
int wa_aes_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aadlen,
                       const uint8_t *in, size_t len, uint8_t *out);

// PBKDF2-HMAC-SHA256.
void wa_pbkdf2_sha256(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t saltlen, uint32_t iterations,
                      uint8_t *out, size_t outlen);
// AES-256-CTR with a 16-byte initial counter block; in and out may alias.
int wa_aes_ctr(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out);

// AES-256-CBC with PKCS#7 padding. Encrypt: out must hold len + 16 bytes.
// Decrypt: out must hold len bytes; fails on bad length or padding. in and
// out may alias.
int wa_aes_cbc_encrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out,
                       size_t *outlen);
int wa_aes_cbc_decrypt(const uint8_t key[32], const uint8_t iv[16], const uint8_t *in, size_t len, uint8_t *out,
                       size_t *outlen);

// Constant-time comparison; 1 if equal.
int wa_ct_equal(const uint8_t *a, const uint8_t *b, size_t n);

void wa_base64(const uint8_t *in, size_t len, char *out); // out: 4*ceil(len/3)+1 bytes
