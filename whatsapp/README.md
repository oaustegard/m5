# whatsapp

A WhatsApp companion client for the Core2, ported from
[whatsmeow](https://github.com/tulir/whatsmeow) (Go) to C. The Core2 links to
a phone the way WhatsApp Web does: it shows a QR code, the phone scans it, and
the Core2 becomes a linked device.

This uses WhatsApp's unofficial multi-device protocol. Meta can ban accounts
that use unofficial clients, so link a spare number rather than your own.

| milestone | status |
|---|---|
| Noise handshake, server certificate chain, `pair-device` QR refs | works against `web.whatsapp.com` (host build) |
| pairing (`pair-success`, device signature) and login | works: paired with an iPhone from the host build, re-login reached `<success>` |
| prekey upload, receiving and decrypting messages (Signal sessions) | written; the Signal layer is tested against whatsmeow's libsignal (`host/sigpeer`), never against WhatsApp's servers |
| ESP-IDF app: WiFi setup, WebSocket, QR on screen, store in NVS | the e86f64f version built (ESP-IDF 5.4.4, 1.2 MB image); the message list and key partition since then have not been compiled; never flashed or run on a Core2 |
| sending messages | not started (`wa_sig_encrypt` covers sessions the other side started) |

## Layout

- `components/wa/`: the portable core (an ESP-IDF component). It has no
  threads and no I/O: the platform owns the WebSocket and feeds it bytes.
  - `wa_client.c`: handshake, frames, pairing and login, ported from
    whatsmeow's `handshake.go`, `socket/`, `pair.go` and `store/clientpayload.go`.
  - `wa_binary.c`, `wa_tokens.c`: the binary node format. `tools/gen_tokens.py`
    generates the token table from whatsmeow.
  - `wa_crypto.c`: X25519, libsignal's curve25519 signatures, HKDF and
    AES-GCM over mbedTLS (hardware AES and SHA on the ESP32) and Monocypher.
  - `wa_pb.c`: the few protobuf messages, written by hand.
  - `wa_signal.c`: X3DH (receiving side), the double ratchet and sender keys,
    with sessions, sender keys and one-time prekeys in a platform key-value
    store (`wa_kv`). Written from the Signal specifications and checked
    against go.mau.fi/libsignal; it keeps fewer archived states and skipped
    keys than libsignal (2 and 12 per session, 8 per sender key).
  - `wa_message.c`: after login, uploads 50 prekeys when either side holds
    fewer than 5; decrypts `<message>` stanzas (pkmsg, msg, skmsg), sends
    delivery receipts, acks and retry receipts, and turns the decrypted
    `waE2E.Message` into text or a label such as `[photo] caption`.
- `main/`: the Core2 app. `provision.c` runs an open setup network
  (`Muninn-Core2`, form at http://192.168.4.1) until WiFi credentials are
  saved to NVS; `main.cpp` joins WiFi, sets the clock by SNTP, and runs the
  core with `esp_websocket_client` events passed through a queue to the main
  loop. Messages show as a list, newest at the bottom. Signal keys live in
  their own 1 MB NVS partition (`wakeys`). Hold A for 3 s to forget WiFi;
  hold C for 5 s to unlink.
- `host/`: a Linux build for testing against the real servers.

## Host testing

```sh
# mbedTLS 3.6 (the version ESP-IDF 5.4 ships), built with `make lib`
cd host
make MBEDTLS=/path/to/mbedtls
./test-wa                  # offline: RFC vectors, signature and codec round trips
# Signal interop: a Go peer on go.mau.fi/libsignal (GPL-3.0, test-only)
(cd sigpeer && go build)
WA_SIGPEER=sigpeer/sigpeer ./test-wa   # adds X3DH, ratchet, sender key and client-path checks
pip install websockets==15.0.1 'qrcode[pil]==8.2'
python3 bridge.py          # connects; writes qr.png next to the store for each QR
```

`bridge.py` holds the WebSocket (through `HTTPS_PROXY` if set) and relays it
to `wa-host` over stdin and stdout. The device keys and pairing state persist
in `wa-store.bin`, Signal sessions and prekeys in `wa-store.bin.keys/`.
Decrypted messages print as `MESSAGE <chat> <sender> (<kind>) <id>: <text>`.

## Firmware

```sh
. $IDF_PATH/export.sh      # ESP-IDF v5.4.4
idf.py set-target esp32
idf.py -p /dev/cu.usbserial-* build flash monitor
```

First boot shows the setup network's QR code (it joins the open
`Muninn-Core2` network). Enter your WiFi at http://192.168.4.1. The Core2
restarts, connects to WhatsApp and shows the pairing QR code. Scan it from
WhatsApp → Linked devices → Link a device.

Things to check on first hardware run, since none of this has run on a
device yet:

- that M5GFX's `qrcode()` picks a QR version large enough for the ~277-byte
  payload (it starts from version 1 and steps up),
- that TLS to `web.whatsapp.com` works with the built-in CA bundle and PSRAM
  buffers,
- that `esp_websocket_client` delivers binary continuation chunks with
  `op_code` 0x0 (main.cpp passes 0x2 and 0x0 through),
- the heap and stack headroom of the main task (16 KB) during the handshake
  and while decrypting (a session record is about 4 KB, held on the heap),
- that `fonts::efontJA_14` renders message text and fits in the image.

## License

The files ported from whatsmeow are MPL-2.0, as whatsmeow is; see
`components/wa/LICENSE`. Monocypher is BSD-2-Clause or CC0. `host/sigpeer`
links go.mau.fi/libsignal and is GPL-3.0; it is a test tool and nothing in the
firmware or the core links it.
