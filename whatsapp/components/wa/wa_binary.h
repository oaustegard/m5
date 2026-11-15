// SPDX-License-Identifier: MPL-2.0
// WhatsApp's binary XML ("WABinary") node format. Ported from whatsmeow
// binary/encoder.go, binary/decoder.go and binary/node.go.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "wa_pb.h"

extern const uint8_t WA_DICT_VERSION;
extern const size_t WA_SINGLE_TOKEN_COUNT;
extern const char *const WA_SINGLE_TOKENS[];
extern const size_t WA_DOUBLE_TOKEN_COUNT[4];
extern const char *const *const WA_DOUBLE_TOKENS[4];

// Bump allocator. Decoded nodes live in an arena and are freed together.
typedef struct wa_arena_chunk wa_arena_chunk;
typedef struct {
    wa_arena_chunk *head;
} wa_arena;
void *wa_arena_alloc(wa_arena *a, size_t n);
char *wa_arena_strndup(wa_arena *a, const char *s, size_t n);
void wa_arena_free(wa_arena *a);

typedef struct {
    const char *user;    // may be ""
    const char *server;  // "s.whatsapp.net", "lid", "g.us", ...
    uint8_t agent;
    uint16_t device;
    uint16_t integrator;
} wa_jid;

typedef enum { WA_V_NONE, WA_V_STR, WA_V_BYTES, WA_V_JID, WA_V_LIST } wa_vtype;

typedef struct wa_node wa_node;
typedef struct {
    wa_vtype type;
    union {
        const char *str;
        struct {
            const uint8_t *data;
            size_t len;
        } bytes;
        wa_jid jid;
        struct {
            wa_node *items;
            size_t n;
        } list;
    };
} wa_value;

typedef struct {
    const char *key;
    wa_value val;
} wa_attr;

struct wa_node {
    const char *tag;
    wa_attr *attrs;
    size_t nattrs;
    wa_value content;
};

// Value constructors for building outgoing nodes.
static inline wa_value wa_vstr(const char *s) {
    wa_value v = {.type = WA_V_STR};
    v.str = s;
    return v;
}
static inline wa_value wa_vbytes(const uint8_t *d, size_t n) {
    wa_value v = {.type = WA_V_BYTES};
    v.bytes.data = d;
    v.bytes.len = n;
    return v;
}
static inline wa_value wa_vjid(wa_jid j) {
    wa_value v = {.type = WA_V_JID};
    v.jid = j;
    return v;
}
static inline wa_value wa_vlist(wa_node *items, size_t n) {
    wa_value v = {.type = WA_V_LIST};
    v.list.items = items;
    v.list.n = n;
    return v;
}
#define WA_SERVER_JID ((wa_jid){.user = "", .server = "s.whatsapp.net"})

// Encode with the leading 0x00 "not compressed" flag byte, ready to encrypt.
// Returns 0, or -1 on allocation failure or an unencodable value.
int wa_node_encode(const wa_node *n, wa_buf *out);
// Decode an unpacked payload (flag byte already stripped). Byte contents point
// into data, so data must outlive the node. Returns NULL on malformed input.
wa_node *wa_node_decode(wa_arena *a, const uint8_t *data, size_t len);
// Strip the flag byte and inflate if the payload is zlib-compressed. *out is
// either a pointer into data or a new buffer stored in *owned (free() it).
int wa_unpack(const uint8_t *data, size_t len, const uint8_t **out, size_t *outlen, uint8_t **owned);
// Platform hook: inflate a zlib stream. Returns 0 and a malloc'd buffer.
int wa_inflate(const uint8_t *in, size_t len, uint8_t **out, size_t *outlen);

// Accessors. Attribute values of a decoded node are WA_V_STR or WA_V_JID.
const wa_value *wa_attr_get(const wa_node *n, const char *key);
const char *wa_attr_str(const wa_node *n, const char *key);  // NULL unless a string
const wa_jid *wa_attr_jid(const wa_node *n, const char *key);  // NULL unless a JID
const wa_node *wa_child(const wa_node *n, const char *tag);   // first child with tag
size_t wa_children(const wa_node *n, const wa_node **items);
bool wa_jid_eq(const wa_jid *a, const wa_jid *b);
// Render "user.agent:device@server" into buf; returns buf.
char *wa_jid_str(const wa_jid *j, char *buf, size_t n);
// Debug: XML-ish rendering into out (truncated to n bytes).
void wa_node_print(const wa_node *n, char *out, size_t cap);
