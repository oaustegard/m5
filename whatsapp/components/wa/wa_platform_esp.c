// SPDX-License-Identifier: MIT
// Platform hooks the wa core expects: randomness and zlib inflate.
#include <stdlib.h>

#include "esp_random.h"
#include "miniz.h"  // ESP32 ROM miniz (no malloc helpers)
#include "wa_binary.h"
#include "wa_crypto.h"

int wa_random(uint8_t *out, size_t n) {
    // True random once WiFi or Bluetooth is running; the app starts WiFi
    // before it generates any keys.
    esp_fill_random(out, n);
    return 0;
}

int wa_inflate(const uint8_t *in, size_t len, uint8_t **out, size_t *outlen) {
    size_t cap = len * 4 + 1024;
    for (int tries = 0; tries < 8; tries++, cap *= 4) {
        uint8_t *buf = malloc(cap);
        if (!buf) return -1;
        size_t n = tinfl_decompress_mem_to_mem(buf, cap, in, len, TINFL_FLAG_PARSE_ZLIB_HEADER);
        if (n != TINFL_DECOMPRESS_MEM_TO_MEM_FAILED) {
            *out = buf;
            *outlen = n;
            return 0;
        }
        free(buf);
    }
    return -1;
}
