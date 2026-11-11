# DOOM on the M5Stack Core2

PrBoom 2.5 with the shareware episode, taken from retro-go's `prboom-go` and
given a Core2 platform layer. **This code has not been compiled or run yet.**
Expect a round of build fixes and on-device tuning before the first playable
frame.

## Layout

| path | contents |
|---|---|
| `components/prboom/` | the engine, from [ducalex/retro-go](https://github.com/ducalex/retro-go) `prboom-go/components/prboom` at `4ced120` |
| `main/doom_main.c` | the `I_*` platform layer: video, sound, music, input, boot |
| `main/m5_hal.cpp` | a C wrapper over M5Unified for display DMA, touch, IMU and speaker |
| `wads/DOOM1.WAD` | the shareware IWAD, packed into the `wads` flash partition at build time |
| `partitions.csv` | 3 MB app, 12 MB read-only WAD partition, 960 KB wear-levelled save partition |

The engine has one change from upstream. `G_BuildTiccmd` adds `analog_turn`
and `analog_forward` (declared in `g_game.h`) to each tic, so tilt gives
proportional movement instead of the on/off steps the joystick path produces.
Lines marked `m5:` in `g_game.c` and `g_game.h`.

## Build and flash

```sh
. $IDF_PATH/export.sh       # ESP-IDF 5.4
idf.py set-target esp32
idf.py build flash monitor
```

`idf.py flash` writes the app and the FAT image of `wads/` together. Any IWAD
up to 12 MB fits: the registered `DOOM.WAD` (11 MB) does and `DOOM2.WAD`
(14.6 MB) does not. To use another IWAD, change `IWAD` in `main/doom_main.c`.
Saves and `prboom.cfg` go to `/saves`, which keeps them across reflashes of the
app.

## Controls

| | in game | in menus |
|---|---|---|
| tilt forward / back | move | — |
| tilt left / right | turn | — |
| touch the screen | fire, while held | left third: slider left · middle: select · right third: slider right |
| A (left circle) | use / open; hold 1.2 s to re-centre tilt | up |
| B (middle circle) | next weapon | select (also answers yes) |
| C (right circle) | automap; hold 0.5 s for the menu | down; hold to go back |

The neutral tilt is whatever pose the device is in when the first tic runs, so
hold it the way you mean to play while it boots. The FT6336U panel tracks two
touch points, so firing while pressing a circle should work; that is untested.

## Design

- **Display.** Doom renders 8-bit indexed 320×240 frames into a buffer in
  internal RAM. `hal_display_frame` converts 20-line bands to byte-swapped
  RGB565 and ping-pongs two DMA buffers, so conversion overlaps the SPI
  transfer.
- **Memory.** After the framebuffer and DMA buffers are allocated,
  `heap_caps_malloc_extmem_enable(0)` sends every later allocation (the zone
  heap, the lump cache) to PSRAM, as retro-go does.
- **Sound.** Each sound effect plays straight from its cached WAD lump on one
  of M5Unified's speaker channels (1 to 7), which do their own mixing and
  resampling from 11 kHz. The engine's volume is mapped to channel volume;
  stereo separation is ignored.
- **Music.** The OPL2 emulator renders 22,050 Hz stereo on core 1 into three
  rotating buffers queued on speaker channel 0. Music defaults to volume 8 of
  15 and stops rendering at 0, which is the setting to use if frame rate
  suffers.
- **Cores.** The game loop owns core 0; the speaker task and music render run
  on core 1. The task watchdog is off because the game loop never idles.

## Known gaps

- Tilt axis signs (`TILT_TURN_SIGN`, `TILT_MOVE_SIGN`) and thresholds in
  `doom_main.c` are guesses until someone holds the device.
- No strafe control.
- No SD card support; WADs come from flash only.
- A Bluetooth gamepad through Bluepad32 is the planned fix for the controls.
  The open question is whether the Bluetooth controller's internal RAM fits
  beside Doom's.
- PSRAM runs at 80 MHz. If the board fails PSRAM init at boot, set
  `CONFIG_SPIRAM_SPEED_40M=y` in `sdkconfig.defaults`.

## Credits and licenses

PrBoom is by Florian Schulze, Colin Phipps, Neil Stevens, Andrey Budko and
the Boom and MBF authors before them (GPL-2.0-or-later; see
`components/prboom/COPYING` and `AUTHORS`). The ESP32 port lineage runs
through Espressif's `esp32-doom` (Jeroen Domburg) and ducalex's retro-go.
`DOOM1.WAD` is id Software's shareware release, which may be redistributed
unmodified.
