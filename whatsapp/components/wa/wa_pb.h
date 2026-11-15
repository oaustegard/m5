// SPDX-License-Identifier: MPL-2.0
// A growable byte buffer and the few protobuf wire-format operations the
// handshake and pairing messages need. Field numbers come from whatsmeow's
// .proto files (waWa6, waCert, waAdv, waCompanionReg).
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    size_t len, cap;
    bool oom;  // set on allocation failure; every later append is a no-op
} wa_buf;

void wa_buf_free(wa_buf *b);
void wa_buf_put(wa_buf *b, const void *data, size_t len);
void wa_buf_byte(wa_buf *b, uint8_t v);

// Writers. A field is skipped only when the caller does not call the writer.
void wa_pb_varint(wa_buf *b, uint32_t field, uint64_t v);
void wa_pb_bytes(wa_buf *b, uint32_t field, const void *data, size_t len);
void wa_pb_str(wa_buf *b, uint32_t field, const char *s);
void wa_pb_sfixed32(wa_buf *b, uint32_t field, int32_t v);
// Writes sub as a length-delimited field, then frees it.
void wa_pb_msg(wa_buf *b, uint32_t field, wa_buf *sub);

// Reader.
typedef struct {
    uint32_t field;
    uint8_t wire;      // 0 varint, 1 fixed64, 2 length-delimited, 5 fixed32
    uint64_t varint;   // wire 0, 1, 5
    const uint8_t *data;  // wire 2
    size_t len;
} wa_pb_field;

typedef struct {
    const uint8_t *p, *end;
} wa_pb_reader;

// 1 = a field was read, 0 = end of message, -1 = malformed.
int wa_pb_next(wa_pb_reader *r, wa_pb_field *f);
// Last occurrence of a length-delimited field (protobuf "last wins"). 1 if found.
int wa_pb_get_bytes(const uint8_t *msg, size_t len, uint32_t field, const uint8_t **out, size_t *outlen);
// Last occurrence of a varint field. 1 if found.
int wa_pb_get_varint(const uint8_t *msg, size_t len, uint32_t field, uint64_t *out);
