#!/bin/sh
# Builds "M5 Monitor.app" (the m5mon binary in a bundle, run as a menu bar
# app) and copies it to /Applications. Usage: sh make-app.sh [destination]
set -eu
cd "$(dirname "$0")"
dest="${1:-/Applications}"
swift build -c release
app=".build/M5 Monitor.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp .build/release/m5mon "$app/Contents/MacOS/M5 Monitor"

# Icon
tmp=$(mktemp -d)
swift tools/icon.swift "$tmp/icon_1024.png"
mkdir "$tmp/AppIcon.iconset"
for s in 16 32 128 256 512; do
  sips -z $s $s "$tmp/icon_1024.png" --out "$tmp/AppIcon.iconset/icon_${s}x${s}.png" >/dev/null
  sips -z $((s*2)) $((s*2)) "$tmp/icon_1024.png" --out "$tmp/AppIcon.iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$tmp/AppIcon.iconset" -o "$app/Contents/Resources/AppIcon.icns"
rm -rf "$tmp"

cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>M5 Monitor</string>
  <key>CFBundleDisplayName</key><string>M5 Monitor</string>
  <key>CFBundleIdentifier</key><string>com.github.oaustegard.m5monitor</string>
  <key>CFBundleExecutable</key><string>M5 Monitor</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
  <key>NSLocalNetworkUsageDescription</key><string>M5 Monitor streams to the Core2 over WiFi when it is not plugged in.</string>
  <key>NSBonjourServices</key><array><string>_m5mon._tcp</string></array>
</dict></plist>
PLIST
# macOS ties Screen Recording and Accessibility grants to the signature. An
# ad-hoc one changes with every build, so each rebuild would lose them; a
# development certificate keeps them (the grant then follows the bundle ID
# and team). Falls back to ad hoc when there is none.
identity=$(security find-identity -v -p codesigning | sed -n 's/.*"\(Apple Development[^"]*\)".*/\1/p' | head -1)
codesign --force --sign "${identity:--}" "$app"
rm -rf "$dest/M5 Monitor.app"
cp -R "$app" "$dest/"
echo "installed $dest/M5 Monitor.app"
