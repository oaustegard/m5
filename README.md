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

ESP-IDF 5.4 (`v5.4.4` was the target). Hardware access goes through
[M5Unified](https://github.com/m5stack/M5Unified), pulled from the Espressif
component registry at build time. M5Unified detects which power chip the board
has (AXP192 on the original Core2, AXP2101 on v1.1), so one build serves both.

```sh
. $IDF_PATH/export.sh
cd doom
idf.py set-target esp32
idf.py build flash monitor
```

## License

GPL-2.0. The Doom engine is PrBoom, which is GPL-2.0-or-later.
