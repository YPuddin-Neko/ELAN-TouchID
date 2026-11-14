#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$PWD/elan-fingerprint-macos"
OUT="$ROOT/build/research/ELANCredentialProbe.app"
mkdir -p "$OUT/Contents/MacOS" "$OUT/Contents/Frameworks"
lipo "$ROOT/build/ELANFingerprint.app/Contents/Frameworks/libusb-local.dylib" -verify_arch x86_64
cp "$ROOT/build/ELANFingerprint.app/Contents/Frameworks/libusb-local.dylib" "$OUT/Contents/Frameworks/"
for source in match sift; do
  clang -arch x86_64 -mmacosx-version-min=14.0 -O2 -I "$ROOT/src" -I "$ROOT/vendor/elanpress" \
    -c "$ROOT/vendor/elanpress/elanpress-$source.c" -o "$ROOT/build/research/credential-$source.o"
done
clang -arch x86_64 -mmacosx-version-min=14.0 -O2 -fobjc-arc -Wno-deprecated-declarations \
  -I "$ROOT/src" -I "$ROOT/vendor/libusb/libusb" -I "$ROOT/vendor/elanpress" \
  references/authplugin-research/native-elan-credential-probe.m \
  "$ROOT/build/research/credential-match.o" "$ROOT/build/research/credential-sift.o" \
  "$OUT/Contents/Frameworks/libusb-local.dylib" -framework Cocoa -framework Security \
  -framework OpenDirectory -framework ApplicationServices -framework LocalAuthentication -lm \
  -o "$OUT/Contents/MacOS/ELANCredentialProbe"
cat > "$OUT/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.github.hackintosh-tools.elan-credential-probe</string><key>CFBundleName</key><string>ELANCredentialProbe</string><key>CFBundleExecutable</key><string>ELANCredentialProbe</string><key>CFBundlePackageType</key><string>APPL</string><key>LSUIElement</key><true/></dict></plist>
PLIST
codesign --force --sign - "$OUT/Contents/Frameworks/libusb-local.dylib"
codesign --force --sign - --entitlements references/authplugin-research/native-credential-probe.entitlements "$OUT"
codesign --verify --deep --strict "$OUT"
ditto -c -k --sequesterRsrc --keepParent "$OUT" "$ROOT/build/research/ELANCredentialProbe.zip"
