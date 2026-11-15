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
| pairing (`pair-success`, device signature) and login | written, not yet tried with a phone |
| prekey upload, receiving and decrypting messages (Signal sessions) | not started |
| ESP-IDF app: WiFi, WebSocket, QR on screen, store in NVS | not started |

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

## License

The files ported from whatsmeow are MPL-2.0, as whatsmeow is; see
`components/wa/LICENSE`. Monocypher is BSD-2-Clause or CC0.
