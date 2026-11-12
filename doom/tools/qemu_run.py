#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the QEMU variant of Core2 DOOM, boot it in Espressif's QEMU, and
capture a screenshot each time the firmware prints "SHOT <name>".

Run from doom/ with ESP-IDF exported (`. $IDF_PATH/export.sh`) and QEMU
installed (`python $IDF_PATH/tools/idf_tools.py install qemu-xtensa`):

    python tools/qemu_run.py            # build, boot, screenshot
    python tools/qemu_run.py --no-build

Outputs land in build-qemu/run/: serial.log and one PNG per SHOT line.
Exit status is 0 only if the input script reached "SCRIPT DONE".
"""

import argparse
import glob
import os
import shutil
import struct
import subprocess
import sys
import time
import zlib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(HERE, "build-qemu")
RUN = os.path.join(BUILD, "run")

# eFuse block for an ESP32 chip revision 3, as idf.py qemu generates it
EFUSE_REV3 = bytes.fromhex(
    "00000000000000000000000000800000000000000000100000000000000000000000000000000000"
    + "00" * 40 + "00" * 40 + "00000000"
)

FAIL_MARKERS = ("Guru Meditation", "abort() was called", "I_Error", "Backtrace:",
                "assert failed", "Rebooting...")


def build():
    subprocess.run(
        ["idf.py", "-B", BUILD, "-D", f"SDKCONFIG={BUILD}/sdkconfig",
         "-D", "SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.qemu", "build"],
        cwd=HERE, check=True)


def flash_image():
    out = os.path.join(BUILD, "flash.bin")
    subprocess.run([sys.executable, "-m", "esptool", "--chip", "esp32", "merge_bin",
                    "--fill-flash-size", "16MB", "-o", out, "@flash_args"],
                   cwd=BUILD, check=True, stdout=subprocess.DEVNULL)
    efuse = os.path.join(BUILD, "qemu_efuse.bin")
    with open(efuse, "wb") as f:
        f.write(EFUSE_REV3)
    return out, efuse


def find_qemu():
    exe = shutil.which("qemu-system-xtensa")
    if exe:
        return exe
    hits = glob.glob(os.path.expanduser(
        "~/.espressif/tools/qemu-xtensa/*/qemu/bin/qemu-system-xtensa"))
    if not hits:
        sys.exit("qemu-system-xtensa not found; run idf_tools.py install qemu-xtensa")
    return sorted(hits)[-1]


def ppm_to_png(ppm_path, png_path):
    with open(ppm_path, "rb") as f:
        data = f.read()
    # P6\n<w> <h>\n<max>\n<rgb bytes>
    parts = data.split(maxsplit=4)
    assert parts[0] == b"P6", parts[0]
    w, h = int(parts[1]), int(parts[2])
    pixels = parts[4][: w * h * 3]
    raw = b"".join(b"\x00" + pixels[y * w * 3:(y + 1) * w * 3] for y in range(h))

    def chunk(tag, body):
        return (struct.pack(">I", len(body)) + tag + body
                + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF))

    with open(png_path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)))
        f.write(chunk(b"IDAT", zlib.compress(raw, 9)))
        f.write(chunk(b"IEND", b""))


class Monitor:
    """The QEMU monitor on the -nographic stdio mux, reached with Ctrl-A c.

    Espressif's QEMU stops routing UART0 to stdio once -serial or -monitor
    is given explicitly, so the harness keeps the default mux and toggles
    between serial and monitor on stdin."""

    def __init__(self, proc):
        self.proc = proc

    def _send(self, data):
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def screendump(self, path, size):
        self._send(b"\x01c")
        time.sleep(0.2)
        self._send(f"screendump {path}\n".encode())
        deadline = time.time() + 10
        while time.time() < deadline:
            if os.path.exists(path) and os.path.getsize(path) >= size:
                break
            time.sleep(0.1)
        self._send(b"\x01c")
        time.sleep(0.2)
        self._send(b"!")   # releases the firmware, which froze on the frame
        return os.path.exists(path)

    def quit(self):
        self._send(b"\x01x")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--timeout", type=int, default=240, help="seconds")
    args = ap.parse_args()

    if not args.no_build:
        build()
    flash, efuse = flash_image()

    shutil.rmtree(RUN, ignore_errors=True)
    os.makedirs(RUN)
    qemu = [
        find_qemu(), "-M", "esp32", "-m", "4M",
        "-drive", f"file={flash},if=mtd,format=raw",
        "-drive", f"file={efuse},if=none,format=raw,id=efuse",
        "-global", "driver=nvram.esp32.efuse,property=drive,value=efuse",
        "-global", "driver=timer.esp32.timg,property=wdt_disable,value=true",
        "-nographic",
    ]
    proc = subprocess.Popen(qemu, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.PIPE)
    os.set_blocking(proc.stdout.fileno(), False)
    mon = Monitor(proc)

    ok = False
    deadline = time.time() + args.timeout
    pending = b""
    with open(os.path.join(RUN, "serial.log"), "wb") as log:
        while time.time() < deadline and proc.poll() is None:
            chunk = proc.stdout.read()
            if not chunk:
                time.sleep(0.05)
                continue
            log.write(chunk)
            log.flush()
            pending += chunk
            *lines, pending = pending.split(b"\n")
            for raw in lines:
                line = raw.decode(errors="replace").rstrip("\r")
                if line.startswith(("SHOT", "SCRIPT", "FPS", "MUSIC", "SFX")) or \
                        any(m in line for m in FAIL_MARKERS):
                    print(line, flush=True)
                if line.startswith("SHOT "):
                    name = line.split()[1]
                    ppm = os.path.join(RUN, name + ".ppm")
                    if mon.screendump(ppm, 320 * 240 * 3):
                        ppm_to_png(ppm, os.path.join(RUN, name + ".png"))
                        os.remove(ppm)
                    else:
                        print(f"screendump {name} failed", flush=True)
                if line == "SCRIPT DONE":
                    ok = True
                    deadline = 0
                if any(m in line for m in FAIL_MARKERS):
                    deadline = min(deadline, time.time() + 2)

    try:
        mon.quit()
        proc.wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        proc.kill()
    print(f"{'PASS' if ok else 'FAIL'}: output in {RUN}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
