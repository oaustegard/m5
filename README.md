# m5

Projects for M5Stack devices. The first target is the Core2: an ESP32-D0WDQ6-V3
at 240 MHz with 16 MB flash, 8 MB PSRAM, a 320×240 ILI9342C screen, a
capacitive touch panel (whose three circles under the screen act as buttons A,
B and C), an MPU6886 IMU and an I2S speaker.

Each project is a self-contained ESP-IDF project in its own directory.

| project | what it is | status |
|---|---|---|
| [`doom/`](doom/) | PrBoom with shareware DOOM1.WAD: tilt to move, touch to fire, vibration on shots, hits and damage | builds and plays in QEMU; not yet run on a Core2 |

## Toolchain

Projects use ESP-IDF 5.4; the code was written against v5.4.4. Install it
with [Espressif's getting-started guide](https://docs.espressif.com/projects/esp-idf/en/v5.4.4/esp32/get-started/index.html).
Hardware access goes through
[M5Unified](https://github.com/m5stack/M5Unified), which the build fetches
from the Espressif component registry. M5Unified detects which power chip the
board has (AXP192 on the original Core2, AXP2101 on v1.1), so one build serves
both.

With the Core2 connected over USB-C:

```sh
. $IDF_PATH/export.sh
cd doom
idf.py set-target esp32
idf.py -p /dev/ttyACM0 build flash monitor   # use your serial port
```

## License

Each directory is licensed as permissively as its sources allow. A
`LICENSE` file in a project directory overrides the root one for everything
under it, except files whose `SPDX-License-Identifier` header names another
license.

| path | license | why |
|---|---|---|
| everything without its own `LICENSE` | MIT (root `LICENSE`) | default |
| `doom/` | GPL-3.0 (`doom/LICENSE`) | `doom/main/doom_main.c` is adapted from a GPL-3.0 file in retro-go (an ESP32 emulator firmware), and the PrBoom engine is GPL-2.0-or-later, so the combination is GPL-3.0 |
| `doom/main/m5_hal.cpp`, `doom/main/m5_hal.h` | MIT (root `LICENSE`, by SPDX header) | original to this repo; reusable outside `doom/` |
| `doom/wads/DOOM1.WAD` | id Software's shareware terms, stated in the WAD's original distribution | redistributable unmodified; not GPL |
