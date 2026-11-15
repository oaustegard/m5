// SPDX-License-Identifier: MPL-2.0
// Ported from whatsmeow (https://github.com/tulir/whatsmeow) binary/encoder.go,
// binary/decoder.go, binary/unpack.go and types/jid.go. Copyright (c) 2021
// Tulir Asokan; C port for the Core2.
#include "wa_binary.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    T_LIST_EMPTY = 0,
    T_DICT0 = 236,
    T_INTEROP_JID = 245,
    T_FB_JID = 246,
    T_AD_JID = 247,
    T_LIST8 = 248,
    T_LIST16 = 249,
    T_JID_PAIR = 250,
    T_HEX8 = 251,
    T_BINARY8 = 252,
    T_BINARY20 = 253,
    T_BINARY32 = 254,
    T_NIBBLE8 = 255,
    PACKED_MAX = 127,
};

// ---------------------------------------------------------------- arena

struct wa_arena_chunk {
    wa_arena_chunk *next;
    size_t used, cap;
    uint8_t data[];
};

void *wa_arena_alloc(wa_arena *a, size_t n) {
    n = (n + 7) & ~(size_t)7;
    if (!a->head || a->head->cap - a->head->used < n) {
        size_t cap = n > 4096 ? n : 4096;
        wa_arena_chunk *c = malloc(sizeof *c + cap);
        if (!c) return NULL;
        c->next = a->head;
        c->used = 0;
        c->cap = cap;
        a->head = c;
    }
    void *p = a->head->data + a->head->used;
    a->head->used += n;
    memset(p, 0, n);
    return p;
}

char *wa_arena_strndup(wa_arena *a, const char *s, size_t n) {
    char *p = wa_arena_alloc(a, n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

void wa_arena_free(wa_arena *a) {
    while (a->head) {
        wa_arena_chunk *n = a->head->next;
        free(a->head);
        a->head = n;
    }
}

// ---------------------------------------------------------------- encoder

typedef struct {
    wa_buf *b;
    bool bad;
} enc;

static void push(enc *e, uint8_t v) { wa_buf_byte(e->b, v); }

static void push_be(enc *e, uint32_t v, int n) {
    for (int i = n - 1; i >= 0; i--) push(e, (v >> (8 * i)) & 0xFF);
}

static void write_byte_length(enc *e, size_t len) {
    if (len < 256) {
        push(e, T_BINARY8);
        push(e, (uint8_t)len);
    } else if (len < (1u << 20)) {
        push(e, T_BINARY20);
        push(e, (len >> 16) & 0x0F);
        push(e, (len >> 8) & 0xFF);
        push(e, len & 0xFF);
    } else if (len < 0x7FFFFFFF) {
        push(e, T_BINARY32);
        push_be(e, (uint32_t)len, 4);
    } else {
        e->bad = true;
    }
}

static bool single_token(const char *s, uint8_t *idx) {
    for (size_t i = 1; i < WA_SINGLE_TOKEN_COUNT; i++) {
        if (WA_SINGLE_TOKENS[i][0] && strcmp(WA_SINGLE_TOKENS[i], s) == 0) {
            *idx = (uint8_t)i;
            return true;
        }
    }
    return false;
}

static bool double_token(const char *s, uint8_t *dict, uint8_t *idx) {
    for (int d = 0; d < 4; d++) {
        for (size_t i = 0; i < WA_DOUBLE_TOKEN_COUNT[d]; i++) {
            if (strcmp(WA_DOUBLE_TOKENS[d][i], s) == 0) {
                *dict = (uint8_t)d;
                *idx = (uint8_t)i;
                return true;
            }
        }
    }
    return false;
}

static bool is_nibble(const char *s, size_t n) {
    if (n > PACKED_MAX) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || s[i] == '-' || s[i] == '.')) return false;
    return true;
}

static bool is_hex(const char *s, size_t n) {
    if (n > PACKED_MAX) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'A' && s[i] <= 'F'))) return false;
    return true;
}

static uint8_t pack_nibble(char c) {
    if (c == '-') return 10;
    if (c == '.') return 11;
    if (c == 0) return 15;
    return (uint8_t)(c - '0');
}

static uint8_t pack_hex(char c) {
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'A' && c <= 'F') return (uint8_t)(10 + c - 'A');
    return 15;  // c == 0
}

static void write_packed(enc *e, const char *s, size_t n, uint8_t type) {
    push(e, type);
    uint8_t rounded = (uint8_t)((n + 1) / 2);
    if (n % 2) rounded |= 128;
    push(e, rounded);
    uint8_t (*pk)(char) = type == T_NIBBLE8 ? pack_nibble : pack_hex;
    for (size_t i = 0; i < n / 2; i++) push(e, (uint8_t)((pk(s[2 * i]) << 4) | pk(s[2 * i + 1])));
    if (n % 2) push(e, (uint8_t)((pk(s[n - 1]) << 4) | pk(0)));
}

static void write_string(enc *e, const char *s) {
    size_t n = strlen(s);
    uint8_t a, b;
    if (n && single_token(s, &a)) {
        push(e, a);
    } else if (n && double_token(s, &a, &b)) {
        push(e, (uint8_t)(T_DICT0 + a));
        push(e, b);
    } else if (is_nibble(s, n)) {
        write_packed(e, s, n, T_NIBBLE8);
    } else if (is_hex(s, n)) {
        write_packed(e, s, n, T_HEX8);
    } else {
        write_byte_length(e, n);
        wa_buf_put(e->b, s, n);
    }
}

static uint8_t jid_agent(const wa_jid *j) {
    if (strcmp(j->server, "s.whatsapp.net") == 0) return 0;
    if (strcmp(j->server, "lid") == 0) return 1;
    if (strcmp(j->server, "hosted") == 0) return 128;
    if (strcmp(j->server, "hosted.lid") == 0) return 129;
    return j->agent;
}

static void write_value(enc *e, const wa_value *v);

static void write_jid(enc *e, const wa_jid *j) {
    const char *srv = j->server;
    bool user_srv = strcmp(srv, "s.whatsapp.net") == 0 || strcmp(srv, "lid") == 0;
    if ((user_srv && j->device > 0) || strcmp(srv, "hosted") == 0 || strcmp(srv, "hosted.lid") == 0) {
        push(e, T_AD_JID);
        push(e, jid_agent(j));
        push(e, (uint8_t)j->device);
        write_string(e, j->user);
    } else if (strcmp(srv, "msgr") == 0) {
        push(e, T_FB_JID);
        write_string(e, j->user);
        push_be(e, j->device, 2);
        write_string(e, srv);
    } else if (strcmp(srv, "interop") == 0) {
        push(e, T_INTEROP_JID);
        write_string(e, j->user);
        push_be(e, j->device, 2);
        push_be(e, j->integrator, 2);
        write_string(e, srv);
    } else {
        push(e, T_JID_PAIR);
        if (!j->user || !j->user[0])
            push(e, T_LIST_EMPTY);
        else
            write_string(e, j->user);
        write_string(e, srv);
    }
}

static void write_list_start(enc *e, size_t n) {
    if (n == 0) {
        push(e, T_LIST_EMPTY);
    } else if (n < 256) {
        push(e, T_LIST8);
        push(e, (uint8_t)n);
    } else {
        push(e, T_LIST16);
        push_be(e, (uint32_t)n, 2);
    }
}

static bool attr_present(const wa_value *v) {
    return v->type != WA_V_NONE && !(v->type == WA_V_STR && (!v->str || !v->str[0]));
}

static void write_node(enc *e, const wa_node *n) {
    if (strcmp(n->tag, "0") == 0) {
        push(e, T_LIST8);
        push(e, T_LIST_EMPTY);
        return;
    }
    size_t nattr = 0;
    for (size_t i = 0; i < n->nattrs; i++) nattr += attr_present(&n->attrs[i].val);
    bool has_content = n->content.type != WA_V_NONE;
    write_list_start(e, 2 * nattr + 1 + has_content);
    write_string(e, n->tag);
    for (size_t i = 0; i < n->nattrs; i++) {
        if (!attr_present(&n->attrs[i].val)) continue;
        write_string(e, n->attrs[i].key);
        write_value(e, &n->attrs[i].val);
    }
    if (has_content) write_value(e, &n->content);
}

static void write_value(enc *e, const wa_value *v) {
    switch (v->type) {
        case WA_V_NONE:
            push(e, T_LIST_EMPTY);
            break;
        case WA_V_STR:
            write_string(e, v->str);
            break;
        case WA_V_BYTES:
            write_byte_length(e, v->bytes.len);
            wa_buf_put(e->b, v->bytes.data, v->bytes.len);
            break;
        case WA_V_JID:
            write_jid(e, &v->jid);
            break;
        case WA_V_LIST:
            write_list_start(e, v->list.n);
            for (size_t i = 0; i < v->list.n; i++) write_node(e, &v->list.items[i]);
            break;
    }
}

int wa_node_encode(const wa_node *n, wa_buf *out) {
    enc e = {out, false};
    push(&e, 0);
    write_node(&e, n);
    return (e.bad || out->oom) ? -1 : 0;
}

// ---------------------------------------------------------------- decoder

typedef struct {
    const uint8_t *d;
    size_t len, i;
    wa_arena *a;
    int depth;
} dec;

static int rd_byte(dec *r, uint8_t *out) {
    if (r->i + 1 > r->len) return -1;
    *out = r->d[r->i++];
    return 0;
}

static int rd_be(dec *r, int n, uint32_t *out) {
    if (r->i + n > r->len) return -1;
    uint32_t v = 0;
    for (int k = 0; k < n; k++) v = (v << 8) | r->d[r->i + k];
    r->i += n;
    *out = v;
    return 0;
}

static int rd_int20(dec *r, uint32_t *out) {
    if (r->i + 3 > r->len) return -1;
    *out = ((uint32_t)(r->d[r->i] & 15) << 16) | ((uint32_t)r->d[r->i + 1] << 8) | r->d[r->i + 2];
    r->i += 3;
    return 0;
}

static char unpack_nib(uint8_t v, int *err) {
    if (v < 10) return (char)('0' + v);
    if (v == 10) return '-';
    if (v == 11) return '.';
    if (v == 15) return 0;
    *err = 1;
    return 0;
}

static char unpack_hexc(uint8_t v, int *err) {
    if (v < 10) return (char)('0' + v);
    if (v < 16) return (char)('A' + v - 10);
    *err = 1;
    return 0;
}

static const char *rd_packed(dec *r, uint8_t tag) {
    uint8_t start;
    if (rd_byte(r, &start)) return NULL;
    size_t n = start & 127;
    char *s = wa_arena_alloc(r->a, 2 * n + 1);
    if (!s) return NULL;
    int err = 0;
    for (size_t k = 0; k < n; k++) {
        uint8_t b;
        if (rd_byte(r, &b)) return NULL;
        char (*up)(uint8_t, int *) = tag == T_NIBBLE8 ? unpack_nib : unpack_hexc;
        s[2 * k] = up((b & 0xF0) >> 4, &err);
        s[2 * k + 1] = up(b & 0x0F, &err);
    }
    if (err) return NULL;
    size_t sl = 2 * n;
    if ((start >> 7) && sl) sl--;
    s[sl] = 0;
    return s;
}

static int rd_list_size(dec *r, uint8_t tag, size_t *out) {
    uint32_t v;
    switch (tag) {
        case T_LIST_EMPTY:
            *out = 0;
            return 0;
        case T_LIST8:
            if (rd_be(r, 1, &v)) return -1;
            *out = v;
            return 0;
        case T_LIST16:
            if (rd_be(r, 2, &v)) return -1;
            *out = v;
            return 0;
        default:
            return -1;
    }
}

static int rd_value(dec *r, bool as_string, wa_value *out);
static wa_node *rd_node(dec *r, wa_node *into);

// Reads a value that must be a string (or nil -> ""), for JID parts and keys.
static const char *rd_str(dec *r) {
    wa_value v;
    if (rd_value(r, true, &v)) return NULL;
    if (v.type == WA_V_NONE) return "";
    return v.type == WA_V_STR ? v.str : NULL;
}

static int rd_value(dec *r, bool as_string, wa_value *out) {
    memset(out, 0, sizeof *out);
    uint8_t tag;
    if (rd_byte(r, &tag)) return -1;
    uint32_t size;
    switch (tag) {
        case T_LIST_EMPTY:
            out->type = WA_V_NONE;
            return 0;
        case T_LIST8:
        case T_LIST16: {
            size_t n;
            if (rd_list_size(r, tag, &n)) return -1;
            if (++r->depth > 64) return -1;
            wa_node *items = n ? wa_arena_alloc(r->a, n * sizeof *items) : NULL;
            if (n && !items) return -1;
            for (size_t k = 0; k < n; k++)
                if (!rd_node(r, &items[k])) return -1;
            r->depth--;
            *out = wa_vlist(items, n);
            return 0;
        }
        case T_BINARY8:
            if (rd_be(r, 1, &size)) return -1;
            goto raw;
        case T_BINARY20:
            if (rd_int20(r, &size)) return -1;
            goto raw;
        case T_BINARY32:
            if (rd_be(r, 4, &size)) return -1;
        raw:
            if (r->i + size > r->len) return -1;
            if (as_string) {
                const char *s = wa_arena_strndup(r->a, (const char *)r->d + r->i, size);
                if (!s) return -1;
                *out = wa_vstr(s);
            } else {
                *out = wa_vbytes(r->d + r->i, size);
            }
            r->i += size;
            return 0;
        case T_DICT0:
        case T_DICT0 + 1:
        case T_DICT0 + 2:
        case T_DICT0 + 3: {
            uint8_t idx;
            if (rd_byte(r, &idx)) return -1;
            int d = tag - T_DICT0;
            if (idx >= WA_DOUBLE_TOKEN_COUNT[d]) return -1;
            *out = wa_vstr(WA_DOUBLE_TOKENS[d][idx]);
            return 0;
        }
        case T_JID_PAIR: {
            wa_jid j = {0};
            if (!(j.user = rd_str(r))) return -1;
            wa_value sv;
            if (rd_value(r, true, &sv) || sv.type != WA_V_STR) return -1;
            j.server = sv.str;
            *out = wa_vjid(j);
            return 0;
        }
        case T_AD_JID: {
            uint8_t agent, device;
            if (rd_byte(r, &agent) || rd_byte(r, &device)) return -1;
            wa_jid j = {0};
            if (!(j.user = rd_str(r))) return -1;
            j.device = device;
            switch (agent) {
                case 1: j.server = "lid"; break;
                case 128: j.server = "hosted"; break;
                case 129: j.server = "hosted.lid"; break;
                default: j.server = "s.whatsapp.net"; j.agent = agent; break;
            }
            *out = wa_vjid(j);
            return 0;
        }
        case T_FB_JID:
        case T_INTEROP_JID: {
            wa_jid j = {0};
            uint32_t device, integ = 0;
            if (!(j.user = rd_str(r)) || rd_be(r, 2, &device)) return -1;
            if (tag == T_INTEROP_JID && rd_be(r, 2, &integ)) return -1;
            if (!(j.server = rd_str(r))) return -1;
            if (strcmp(j.server, tag == T_FB_JID ? "msgr" : "interop") != 0) return -1;
            j.device = (uint16_t)device;
            j.integrator = (uint16_t)integ;
            *out = wa_vjid(j);
            return 0;
        }
        case T_NIBBLE8:
        case T_HEX8: {
            const char *s = rd_packed(r, tag);
            if (!s) return -1;
            *out = wa_vstr(s);
            return 0;
        }
        default:
            if (tag >= 1 && tag < WA_SINGLE_TOKEN_COUNT) {
                *out = wa_vstr(WA_SINGLE_TOKENS[tag]);
                return 0;
            }
            return -1;
    }
}

static wa_node *rd_node(dec *r, wa_node *n) {
    memset(n, 0, sizeof *n);
    uint8_t tag;
    size_t list_size;
    if (rd_byte(r, &tag) || rd_list_size(r, tag, &list_size)) return NULL;
    const char *desc = rd_str(r);
    if (!desc || !desc[0] || list_size == 0) return NULL;
    n->tag = desc;
    n->nattrs = (list_size - 1) >> 1;
    if (n->nattrs) {
        n->attrs = wa_arena_alloc(r->a, n->nattrs * sizeof *n->attrs);
        if (!n->attrs) return NULL;
        for (size_t k = 0; k < n->nattrs; k++) {
            if (!(n->attrs[k].key = rd_str(r))) return NULL;
            if (rd_value(r, true, &n->attrs[k].val)) return NULL;
        }
    }
    if (list_size % 2 == 1) return n;
    if (rd_value(r, false, &n->content)) return NULL;
    return n;
}

wa_node *wa_node_decode(wa_arena *a, const uint8_t *data, size_t len) {
    dec r = {data, len, 0, a, 0};
    wa_node *n = wa_arena_alloc(a, sizeof *n);
    if (!n || !rd_node(&r, n)) return NULL;
    if (r.i != len) return NULL;
    return n;
}

int wa_unpack(const uint8_t *data, size_t len, const uint8_t **out, size_t *outlen, uint8_t **owned) {
    *owned = NULL;
    if (len < 1) return -1;
    if (data[0] & 2) {
        if (wa_inflate(data + 1, len - 1, owned, outlen)) return -1;
        *out = *owned;
    } else {
        *out = data + 1;
        *outlen = len - 1;
    }
    return 0;
}

// ---------------------------------------------------------------- accessors

const wa_value *wa_attr_get(const wa_node *n, const char *key) {
    for (size_t i = 0; i < n->nattrs; i++)
        if (strcmp(n->attrs[i].key, key) == 0) return &n->attrs[i].val;
    return NULL;
}

const char *wa_attr_str(const wa_node *n, const char *key) {
    const wa_value *v = wa_attr_get(n, key);
    return v && v->type == WA_V_STR ? v->str : NULL;
}

const wa_jid *wa_attr_jid(const wa_node *n, const char *key) {
    const wa_value *v = wa_attr_get(n, key);
    return v && v->type == WA_V_JID ? &v->jid : NULL;
}

size_t wa_children(const wa_node *n, const wa_node **items) {
    if (n->content.type != WA_V_LIST) {
        *items = NULL;
        return 0;
    }
    *items = n->content.list.items;
    return n->content.list.n;
}

const wa_node *wa_child(const wa_node *n, const char *tag) {
    const wa_node *items;
    size_t c = wa_children(n, &items);
    for (size_t i = 0; i < c; i++)
        if (strcmp(items[i].tag, tag) == 0) return &items[i];
    return NULL;
}

bool wa_jid_eq(const wa_jid *a, const wa_jid *b) {
    return strcmp(a->user ? a->user : "", b->user ? b->user : "") == 0 && strcmp(a->server, b->server) == 0 &&
           a->device == b->device && a->agent == b->agent && a->integrator == b->integrator;
}

char *wa_jid_str(const wa_jid *j, char *buf, size_t n) {
    if (j->agent)
        snprintf(buf, n, "%s.%u:%u@%s", j->user, j->agent, j->device, j->server);
    else if (j->device)
        snprintf(buf, n, "%s:%u@%s", j->user, j->device, j->server);
    else if (j->user && j->user[0])
        snprintf(buf, n, "%s@%s", j->user, j->server);
    else
        snprintf(buf, n, "%s", j->server);
    return buf;
}

typedef struct {
    char *p;
    size_t left;
} pbuf;

static void pf(pbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#include <stdarg.h>
static void pf(pbuf *b, const char *fmt, ...) {
    if (b->left <= 1) return;
    va_list ap;
    va_start(ap, fmt);
    int w = vsnprintf(b->p, b->left, fmt, ap);
    va_end(ap);
    if (w < 0) return;
    size_t adv = (size_t)w < b->left ? (size_t)w : b->left - 1;
    b->p += adv;
    b->left -= adv;
}

static void print_value(pbuf *b, const wa_value *v) {
    char jb[96];
    switch (v->type) {
        case WA_V_NONE: break;
        case WA_V_STR: pf(b, "%s", v->str); break;
        case WA_V_JID: pf(b, "%s", wa_jid_str(&v->jid, jb, sizeof jb)); break;
        case WA_V_BYTES: {
            bool printable = v->bytes.len < 200;
            for (size_t i = 0; printable && i < v->bytes.len; i++)
                printable = v->bytes.data[i] >= 0x20 && v->bytes.data[i] < 0x7F;
            if (printable)
                pf(b, "%.*s", (int)v->bytes.len, (const char *)v->bytes.data);
            else
                pf(b, "<%zu bytes>", v->bytes.len);
            break;
        }
        case WA_V_LIST: break;
    }
}

static void print_node(pbuf *b, const wa_node *n) {
    pf(b, "<%s", n->tag);
    for (size_t i = 0; i < n->nattrs; i++) {
        pf(b, " %s=\"", n->attrs[i].key);
        print_value(b, &n->attrs[i].val);
        pf(b, "\"");
    }
    if (n->content.type == WA_V_NONE) {
        pf(b, "/>");
        return;
    }
    pf(b, ">");
    if (n->content.type == WA_V_LIST)
        for (size_t i = 0; i < n->content.list.n; i++) print_node(b, &n->content.list.items[i]);
    else
        print_value(b, &n->content);
    pf(b, "</%s>", n->tag);
}

void wa_node_print(const wa_node *n, char *out, size_t cap) {
    pbuf b = {out, cap};
    if (cap) out[0] = 0;
    print_node(&b, n);
}
