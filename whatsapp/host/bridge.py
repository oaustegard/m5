#!/usr/bin/env python3
"""Run the host build of the wa core against WhatsApp's real servers.

Owns the WebSocket (through HTTPS_PROXY if set) and relays it to ./wa-host
over stdin/stdout. Prints the core's log; renders each QR payload to
qr.png and qr.txt next to the store so a phone can scan it.

    python3 bridge.py [--store wa-store.bin] [--quit-after-login] [--max-runs N]
"""
import argparse
import asyncio
import os
import ssl
import struct
import sys

import websockets

URL = "wss://web.whatsapp.com/ws/chat"
HERE = os.path.dirname(os.path.abspath(__file__))


def render_qr(text, outdir):
    try:
        import qrcode
    except ImportError:
        return
    img = qrcode.make(text, box_size=8, border=4)
    img.save(os.path.join(outdir, "qr.png"))
    with open(os.path.join(outdir, "qr.txt"), "w") as f:
        f.write(text + "\n")


async def pump_stderr(proc, outdir, state):
    while True:
        line = await proc.stderr.readline()
        if not line:
            return
        s = line.decode(errors="replace").rstrip()
        if s.startswith("QR "):
            _, secs, text = s.split(" ", 2)
            render_qr(text, outdir)
            print(f"[qr] new code, valid {secs}s -> {outdir}/qr.png", flush=True)
            state["qr_count"] += 1
        else:
            print(s, flush=True)


async def run(args):
    ctx = ssl.create_default_context()
    ca = os.environ.get("SSL_CERT_FILE") or "/root/.ccr/ca-bundle.crt"
    if os.path.exists(ca):
        ctx.load_verify_locations(ca)
    outdir = os.path.dirname(os.path.abspath(args.store))
    cmd = [os.path.join(HERE, "wa-host"), "--store", args.store]
    if args.quit_after_login:
        cmd.append("--quit-after-login")
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    state = {"qr_count": 0}
    err_task = asyncio.create_task(pump_stderr(proc, outdir, state))

    def to_core(kind, data=b""):
        proc.stdin.write(kind + struct.pack(">I", len(data)) + data)

    runs = 0
    while runs < args.max_runs:
        runs += 1
        print(f"[bridge] connecting ({runs})", flush=True)
        reconnect = False
        quit_ = False
        async with websockets.connect(
            URL,
            ssl=ctx,
            origin="https://web.whatsapp.com",
            additional_headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
            max_size=1 << 24,
            open_timeout=30,
        ) as ws:
            to_core(b"O")
            await proc.stdin.drain()

            async def ws_to_core():
                async for msg in ws:
                    if isinstance(msg, (bytes, bytearray)):
                        to_core(b"D", bytes(msg))
                        await proc.stdin.drain()

            reader = asyncio.create_task(ws_to_core())
            try:
                while True:
                    read_hdr = asyncio.create_task(proc.stdout.readexactly(5))
                    done, _ = await asyncio.wait({read_hdr, reader}, return_when=asyncio.FIRST_COMPLETED)
                    if reader in done:
                        read_hdr.cancel()
                        exc = reader.exception()
                        print(f"[bridge] websocket closed ({exc or ws.close_code})", flush=True)
                        to_core(b"C")
                        await proc.stdin.drain()
                        reconnect = True
                        break
                    hdr = read_hdr.result()
                    kind, n = hdr[:1], struct.unpack(">I", hdr[1:])[0]
                    data = await proc.stdout.readexactly(n) if n else b""
                    if kind == b"S":
                        await ws.send(data)
                    elif kind == b"R":
                        print("[bridge] core asked to reconnect", flush=True)
                        reconnect = True
                        break
                    elif kind == b"Q":
                        quit_ = True
                        break
            finally:
                reader.cancel()
        if quit_ or not reconnect:
            break
        await asyncio.sleep(1)
    proc.stdin.close()
    await asyncio.sleep(0.3)
    proc.terminate()
    await err_task


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--store", default=os.path.join(HERE, "wa-store.bin"))
    p.add_argument("--quit-after-login", action="store_true")
    p.add_argument("--max-runs", type=int, default=3)
    asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
