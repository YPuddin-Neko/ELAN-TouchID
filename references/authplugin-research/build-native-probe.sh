#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="elan-fingerprint-macos/build/research/NativeTouchProbe.app"
SERVICE="$OUT/Contents/XPCServices/ElanBioTransport.xpc"
mkdir -p "$OUT/Contents/MacOS"
mkdir -p "$SERVICE/Contents/MacOS"
clang -arch x86_64 -O2 -fobjc-arc references/authplugin-research/native-stack-probe.m \
    -framework Foundation -framework LocalAuthentication -o "$OUT/Contents/MacOS/NativeTouchProbe"
cat > "$OUT/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.github.hackintosh-tools.native-touch-probe</string><key>CFBundleName</key><string>NativeTouchProbe</string><key>CFBundleExecutable</key><string>NativeTouchProbe</string><key>CFBundlePackageType</key><string>APPL</string><key>LSUIElement</key><true/></dict></plist>
PLIST
clang -arch x86_64 -O2 -fobjc-arc references/authplugin-research/native-xpc-service.m \
    -framework Foundation -o "$SERVICE/Contents/MacOS/ElanBioTransport"
cat > "$SERVICE/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.github.hackintosh-tools.native-bio-transport</string><key>CFBundleExecutable</key><string>ElanBioTransport</string><key>CFBundlePackageType</key><string>XPC!</string><key>CFBundleVersion</key><string>1</string><key>XPCService</key><dict><key>ServiceType</key><string>Application</string></dict></dict></plist>
PLIST
codesign --force --sign - "$SERVICE"
codesign --force --sign - "$OUT"
codesign --verify --strict "$SERVICE"
codesign --verify --strict "$OUT"
ditto -c -k --sequesterRsrc --keepParent "$OUT" elan-fingerprint-macos/build/research/NativeTouchProbe.zip
