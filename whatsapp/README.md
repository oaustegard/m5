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
| prekey upload, receiving and decrypting messages (Signal sessions) | not started |
| ESP-IDF app: WiFi setup, WebSocket, QR on screen, store in NVS | builds (ESP-IDF 5.4.4, 1.2 MB image); never flashed or run on a Core2 |

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
- `main/`: the Core2 app. `provision.c` runs an open setup network
  (`Muninn-Core2`, form at http://192.168.4.1) until WiFi credentials are
  saved to NVS; `main.cpp` joins WiFi, sets the clock by SNTP, and runs the
  core with `esp_websocket_client` events passed through a queue to the main
  loop. Hold A for 3 s to forget WiFi; hold C for 5 s to unlink.
- `host/`: a Linux build for testing against the real servers.

## Host testing

```sh
# mbedTLS 3.6 (the version ESP-IDF 5.4 ships), built with `make lib`
cd host
make MBEDTLS=/path/to/mbedtls
./test-wa                  # offline: RFC vectors, signature and codec round trips
pip install websockets==15.0.1 'qrcode[pil]==8.2'
python3 bridge.py          # connects; writes qr.png next to the store for each QR
```

`bridge.py` holds the WebSocket (through `HTTPS_PROXY` if set) and relays it
to `wa-host` over stdin and stdout. The device keys and pairing state persist
in `wa-store.bin`.

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
- the heap and stack headroom of the main task (16 KB) during the handshake.

## License

The files ported from whatsmeow are MPL-2.0, as whatsmeow is; see
`components/wa/LICENSE`. Monocypher is BSD-2-Clause or CC0.
