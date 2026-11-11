# m5

Projects for M5Stack devices. The first target is the Core2: an ESP32-D0WDQ6-V3
at 240 MHz with 16 MB flash, 8 MB PSRAM, a 320×240 ILI9342C screen, a
capacitive touch panel (whose three circles under the screen act as buttons A,
B and C), an MPU6886 IMU and an I2S speaker.

Each project is a self-contained ESP-IDF project in its own directory.

| project | what it is | status |
|---|---|---|
| [`doom/`](doom/) | PrBoom with shareware DOOM1.WAD, tilt to move, touch to fire | written, not yet built or run on hardware |

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

Code in this repository is under the GPL-2.0 (see `LICENSE`). The Doom
engine is PrBoom, which is GPL-2.0-or-later. `doom/wads/DOOM1.WAD` is not
GPL: it is id Software's shareware data file, redistributable unmodified.
