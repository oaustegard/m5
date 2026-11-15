// SPDX-License-Identifier: MPL-2.0
#include "wa_pb.h"

#include <stdlib.h>
#include <string.h>

void wa_buf_free(wa_buf *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

void wa_buf_put(wa_buf *b, const void *data, size_t len) {
    if (b->oom || len == 0) return;
    if (b->len + len > b->cap) {
        size_t cap = b->cap ? b->cap : 64;
        while (cap < b->len + len) cap *= 2;
        uint8_t *n = realloc(b->data, cap);
        if (!n) {
            b->oom = true;
            return;
        }
        b->data = n;
        b->cap = cap;
    }
    memcpy(b->data + b->len, data, len);
    b->len += len;
}

void wa_buf_byte(wa_buf *b, uint8_t v) { wa_buf_put(b, &v, 1); }

static void put_varint(wa_buf *b, uint64_t v) {
    uint8_t tmp[10];
    size_t n = 0;
    do {
        uint8_t byte = v & 0x7F;
        v >>= 7;
        if (v) byte |= 0x80;
        tmp[n++] = byte;
    } while (v);
    wa_buf_put(b, tmp, n);
}

static void put_key(wa_buf *b, uint32_t field, uint8_t wire) { put_varint(b, ((uint64_t)field << 3) | wire); }

void wa_pb_varint(wa_buf *b, uint32_t field, uint64_t v) {
    put_key(b, field, 0);
    put_varint(b, v);
}

void wa_pb_bytes(wa_buf *b, uint32_t field, const void *data, size_t len) {
    put_key(b, field, 2);
    put_varint(b, len);
    wa_buf_put(b, data, len);
}

void wa_pb_str(wa_buf *b, uint32_t field, const char *s) { wa_pb_bytes(b, field, s, strlen(s)); }

void wa_pb_sfixed32(wa_buf *b, uint32_t field, int32_t v) {
    put_key(b, field, 5);
    uint32_t u = (uint32_t)v;
    uint8_t le[4] = {u & 0xFF, (u >> 8) & 0xFF, (u >> 16) & 0xFF, u >> 24};
    wa_buf_put(b, le, 4);
}

void wa_pb_msg(wa_buf *b, uint32_t field, wa_buf *sub) {
    if (sub->oom) b->oom = true;
    wa_pb_bytes(b, field, sub->data, sub->len);
    wa_buf_free(sub);
}

static int get_varint(wa_pb_reader *r, uint64_t *out) {
    uint64_t v = 0;
    for (int shift = 0; shift < 64; shift += 7) {
        if (r->p >= r->end) return -1;
        uint8_t byte = *r->p++;
        v |= (uint64_t)(byte & 0x7F) << shift;
        if (!(byte & 0x80)) {
            *out = v;
            return 0;
        }
    }
    return -1;
}

int wa_pb_next(wa_pb_reader *r, wa_pb_field *f) {
    if (r->p >= r->end) return 0;
    uint64_t key;
    if (get_varint(r, &key)) return -1;
    f->field = (uint32_t)(key >> 3);
    f->wire = key & 7;
    f->data = NULL;
    f->len = 0;
    f->varint = 0;
    switch (f->wire) {
        case 0:
            return get_varint(r, &f->varint) ? -1 : 1;
        case 1:
            if (r->end - r->p < 8) return -1;
            for (int i = 7; i >= 0; i--) f->varint = (f->varint << 8) | r->p[i];
            r->p += 8;
            return 1;
        case 5:
            if (r->end - r->p < 4) return -1;
            for (int i = 3; i >= 0; i--) f->varint = (f->varint << 8) | r->p[i];
            r->p += 4;
            return 1;
        case 2: {
            uint64_t len;
            if (get_varint(r, &len) || len > (uint64_t)(r->end - r->p)) return -1;
            f->data = r->p;
            f->len = (size_t)len;
            r->p += len;
            return 1;
        }
        default:
            return -1;
    }
}

int wa_pb_get_bytes(const uint8_t *msg, size_t len, uint32_t field, const uint8_t **out, size_t *outlen) {
    wa_pb_reader r = {msg, msg + len};
    wa_pb_field f;
    int found = 0, rc;
    while ((rc = wa_pb_next(&r, &f)) == 1) {
        if (f.field == field && f.wire == 2) {
            *out = f.data;
            *outlen = f.len;
            found = 1;
        }
    }
    return rc < 0 ? 0 : found;
}

int wa_pb_get_varint(const uint8_t *msg, size_t len, uint32_t field, uint64_t *out) {
    wa_pb_reader r = {msg, msg + len};
    wa_pb_field f;
    int found = 0, rc;
    while ((rc = wa_pb_next(&r, &f)) == 1) {
        if (f.field == field && f.wire == 0) {
            *out = f.varint;
            found = 1;
        }
    }
    return rc < 0 ? 0 : found;
}
