// SPDX-License-Identifier: MPL-2.0
// Host harness for the wa core. bridge.py owns the WebSocket and talks to this
// process over stdin/stdout with frames of [type:1][len:4 BE][payload]:
//   in:  'O' socket opened, 'D' binary message, 'C' socket closed
//   out: 'S' send binary message, 'R' reconnect (close and reopen), 'Q' quit
// Logs and events go to stderr, one per line; QR payloads as "QR <secs> <text>".
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include "wa.h"
#include "wa_crypto.h"

static const char *store_path = "wa-store.bin";
static wa_store store;
static wa_client client;
static int quit_after_login = 0;

int wa_random(uint8_t *out, size_t n) {
    while (n) {
        ssize_t r = getrandom(out, n, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        out += r;
        n -= (size_t)r;
    }
    return 0;
}

int wa_inflate(const uint8_t *in, size_t len, uint8_t **out, size_t *outlen) {
    size_t cap = len * 4 + 1024;
    for (int tries = 0; tries < 8; tries++, cap *= 4) {
        uint8_t *buf = malloc(cap);
        if (!buf) return -1;
        uLongf dl = cap;
        int rc = uncompress(buf, &dl, in, len);
        if (rc == Z_OK) {
            *out = buf;
            *outlen = dl;
            return 0;
        }
        free(buf);
        if (rc != Z_BUF_ERROR) return -1;
    }
    return -1;
}

static int write_all(int fd, const void *p, size_t n) {
    const uint8_t *b = p;
    while (n) {
        ssize_t w = write(fd, b, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        b += w;
        n -= (size_t)w;
    }
    return 0;
}

static int emit_frame(char type, const uint8_t *data, size_t len) {
    uint8_t hdr[5] = {(uint8_t)type, len >> 24, len >> 16, len >> 8, len};
    if (write_all(1, hdr, 5) || (len && write_all(1, data, len))) return -1;
    return 0;
}

static int cb_send(void *ctx, const uint8_t *data, size_t len) {
    (void)ctx;
    return emit_frame('S', data, len);
}

static uint64_t cb_now_ms(void *ctx) {
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int64_t cb_unix(void *ctx) {
    (void)ctx;
    return (int64_t)time(NULL);
}

static void cb_log(void *ctx, const char *msg) {
    (void)ctx;
    fprintf(stderr, "LOG %s\n", msg);
}

static void save_store(void *ctx, const wa_store *s) {
    (void)ctx;
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s.tmp", store_path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || write_all(fd, s, sizeof *s) || close(fd) || rename(tmp, store_path)) {
        fprintf(stderr, "LOG failed to save store: %s\n", strerror(errno));
        return;
    }
    fprintf(stderr, "LOG store saved (paired=%d)\n", s->paired);
}

static void cb_event(void *ctx, const wa_event *ev) {
    (void)ctx;
    switch (ev->type) {
        case WA_EV_QR:
            fprintf(stderr, "QR %d %s\n", ev->seconds, ev->text);
            break;
        case WA_EV_QR_EXHAUSTED:
            fprintf(stderr, "EVENT qr_exhausted\n");
            emit_frame('Q', NULL, 0);
            break;
        case WA_EV_PAIRED:
            fprintf(stderr, "EVENT paired %s\n", ev->text);
            break;
        case WA_EV_PAIR_ERROR:
            fprintf(stderr, "EVENT pair_error %s\n", ev->text);
            break;
        case WA_EV_LOGGED_IN:
            fprintf(stderr, "EVENT logged_in user=%s device=%u lid=%s platform=%s\n", store.user, store.device,
                    store.lid_user, store.platform);
            if (quit_after_login) emit_frame('Q', NULL, 0);
            break;
        case WA_EV_LOGGED_OUT:
            fprintf(stderr, "EVENT logged_out %s\n", ev->text);
            emit_frame('Q', NULL, 0);
            break;
        case WA_EV_RECONNECT:
            fprintf(stderr, "EVENT reconnect\n");
            emit_frame('R', NULL, 0);
            break;
        case WA_EV_ERROR:
            fprintf(stderr, "EVENT error %s\n", ev->text);
            emit_frame('Q', NULL, 0);
            break;
        case WA_EV_NODE:
            break;
    }
    fflush(stderr);
}

static int read_exact(int fd, uint8_t *p, size_t n) {
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r == 0) return -1;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--store") == 0 && i + 1 < argc)
            store_path = argv[++i];
        else if (strcmp(argv[i], "--quit-after-login") == 0)
            quit_after_login = 1;
    }
    setvbuf(stderr, NULL, _IOLBF, 0);

    int fd = open(store_path, O_RDONLY);
    if (fd >= 0 && read(fd, &store, sizeof store) == (ssize_t)sizeof store && store.version == WA_STORE_VERSION) {
        fprintf(stderr, "LOG loaded store (paired=%d user=%s)\n", store.paired, store.user);
    } else {
        if (wa_store_init(&store)) return fprintf(stderr, "LOG key generation failed\n"), 1;
        save_store(NULL, &store);
        fprintf(stderr, "LOG new device keys generated\n");
    }
    if (fd >= 0) close(fd);

    wa_callbacks cb = {cb_send, cb_event, save_store, cb_now_ms, cb_unix, cb_log, NULL};
    wa_client_init(&client, &store, &cb);

    for (;;) {
        struct pollfd p = {0, POLLIN, 0};
        int pr = poll(&p, 1, 100);
        if (pr > 0) {
            uint8_t hdr[5];
            if (read_exact(0, hdr, 5)) break;
            size_t len = ((size_t)hdr[1] << 24) | ((size_t)hdr[2] << 16) | ((size_t)hdr[3] << 8) | hdr[4];
            uint8_t *buf = len ? malloc(len) : NULL;
            if (len && (!buf || read_exact(0, buf, len))) break;
            switch (hdr[0]) {
                case 'O':
                    wa_client_on_open(&client);
                    break;
                case 'D':
                    wa_client_on_data(&client, buf, len);
                    break;
                case 'C':
                    wa_client_on_close(&client);
                    break;
            }
            free(buf);
        }
        wa_client_tick(&client);
    }
    wa_client_free(&client);
    return 0;
}
