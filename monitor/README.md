# A 2-inch external monitor

The Core2 as a deliberately tiny external display for a Mac. `m5mon`, a
command-line tool in `mac/`, adds a virtual display to macOS (or mirrors part
of a real one), captures it at 320×240, and streams the parts that changed
to the Core2 over WiFi or the USB cable. Touching the Core2's screen clicks
and drags on the Mac.

| path | contents |
|---|---|
| `main/main.cpp` | firmware: TCP server on port 5320 (advertised as `m5mon.local`), the same protocol on the USB serial port, drawing, touch and buttons |
| `mac/` | `m5mon`, a Swift package: ScreenCaptureKit capture, change detection, encoding, the virtual display, touch to mouse events |

## How it works

ScreenCaptureKit scales the captured area to 320×240 on the GPU. `m5mon`
converts each frame to RGB565 and compares it with what the Core2 is
showing, in 16-row bands; each run of changed bands becomes one rectangle,
trimmed to the columns that changed. A rectangle goes out as raw DEFLATE
(lossless; the ESP32 inflates it with the copy of miniz in its ROM) or, if
that is several times larger, as JPEG. Once the picture has been still for
0.3 s, areas last sent as JPEG are re-sent losslessly. The Mac keeps at most
two frames waiting for the Core2's acknowledgement and skips frames beyond
that, so a slow link drops frame rate instead of building up lag.

The virtual display uses CoreGraphics' undocumented `CGVirtualDisplay`
classes, the same ones DeskPad and BetterDisplay use. macOS treats it as real
hardware: it appears in System Settings > Displays as "M5 Core2", windows
can be dragged onto it, and it disappears when `m5mon` exits. It is
320×240 points at one pixel per point, so each Mac pixel is one Core2
pixel and nothing is scaled. macOS will not run a HiDPI desktop smaller
than 800×600, and refuses to switch any display to a mode it does not mark
usable, but a non-HiDPI virtual display gets half the size of the mode it
is created with: asking for 640×480 yields a 320×240 desktop.
`--virtual 800` (or wider) makes a HiDPI display instead, shown scaled down.

The wire format is described at the top of `main/main.cpp`.

## Build and flash

```sh
. $IDF_PATH/export.sh
idf.py set-target esp32
idf.py -p /dev/cu.usbserial-XXXX -b 460800 build flash
cd mac && swift build -c release
```

The partition table keeps `nvs` where the other projects in this repo put
it, so WiFi credentials saved by `whatsapp/` survive flashing this. To set
them (or change them), with the Core2 plugged in:

```sh
mac/.build/release/m5mon --setup-wifi
```

That reads the Mac's current network from `ipconfig` and its password from
the Keychain (macOS asks first), sends both over USB, and the Core2
restarts and joins. Without WiFi the monitor still works over the cable.

## The app

```sh
sh mac/make-app.sh          # builds "M5 Monitor.app" into /Applications
```

Open M5 Monitor from Applications (or Spotlight) and the "M5 Core2"
display appears, along with a small control window: whether the Core2 is
connected, a touch switch, where the display sits next to the main screen,
and a button that stops and removes the display. Closing the window leaves
it running; opening the app again brings the window back. The same controls
are under a display icon in the menu bar, though on a MacBook with a notch
that icon is easily hidden. "Stop Sharing" in macOS's screen-recording
indicator also stops it.

It uses USB when the Core2 is plugged in and WiFi otherwise, waits for the
Core2 if it is not there yet, and picks up again after the Mac sleeps. The
first launch asks for Screen Recording permission (then open it again);
turning on touch asks for Accessibility. `make-app.sh` signs with an Apple
Development certificate if the keychain has one, so permissions survive
rebuilds; an ad-hoc signature (the fallback) loses them each time. It logs
to `~/Library/Logs/M5 Monitor.log`.

## Command line

```sh
mac/.build/release/m5mon                    # virtual display, over USB if plugged in, else WiFi
mac/.build/release/m5mon --serial           # force the USB cable
mac/.build/release/m5mon --follow 640       # a 640×480 box that follows the mouse
mac/.build/release/m5mon --region 0,0,800,600
mac/.build/release/m5mon --display 0        # the whole main display, letterboxed
```

macOS asks for Screen Recording permission for the terminal app the first
time. Touch input is off unless you pass `--touch`, and then needs
Accessibility permission for the same app. If the link drops while a finger
is down, `m5mon` releases the mouse button rather than leave it held.

On the Core2: tap to click, drag to drag, tap twice to double-click. The
three buttons under the screen are A scroll up, B right-click and C scroll
down. With no Mac streaming, the screen shows the Core2's address and how
it is connected.

Mirroring the main display over USB runs at about 25 fps. WiFi needs the
terminal app to have Local Network permission (macOS asks the first time);
without it connecting to `m5mon.local` fails with "No route to host" and
`m5mon` falls back to the cable.

Over USB the link starts at 115200 baud and switches to 2 Mbaud for
streaming; `--baud 921600` is the fallback for cables or adapters that do
not manage that. The Core2 drops back to 115200 after 3 s without a message,
so `idf.py monitor` works again once `m5mon` has stopped.
