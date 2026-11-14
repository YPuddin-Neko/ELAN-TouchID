#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
ARCH="${ARCH:-$(uname -m)}"
OUT="build/auth-$ARCH"
BUNDLE="$OUT/ELANFingerprintAuth.bundle"
PREVIEW="$OUT/ELANAuthPreview.app"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources" "$PREVIEW/Contents/MacOS"
cp assets/ElanAuthPlugin-Info.plist "$BUNDLE/Contents/Info.plist"
IBTOOL_BIN="$(xcrun --find ibtool)"
if [[ -n "${ELAN_IBTOOL_FRAMEWORK_PATH:-}" ]]; then
    DYLD_FRAMEWORK_PATH="$ELAN_IBTOOL_FRAMEWORK_PATH" "$IBTOOL_BIN" --compile "$BUNDLE/Contents/Resources/ElanAuthView.nib" assets/ElanAuthView.xib
else
    "$IBTOOL_BIN" --compile "$BUNDLE/Contents/Resources/ElanAuthView.nib" assets/ElanAuthView.xib
fi
COMMON=(-arch "$ARCH" -mmacosx-version-min=14.0 -O2 -fobjc-arc -Wno-deprecated-declarations -I src)
FRAMEWORKS=(-framework Cocoa -framework Security -framework SecurityInterface -framework SystemConfiguration)
clang "${COMMON[@]}" -bundle src/ElanAuthPlugin.m "${FRAMEWORKS[@]}" -o "$BUNDLE/Contents/MacOS/ElanAuthPlugin"
clang "${COMMON[@]}" src/ElanAuthProbe.m "${FRAMEWORKS[@]}" -o "$OUT/elan-auth-probe"
clang "${COMMON[@]}" src/ElanAuthPreview.m "${FRAMEWORKS[@]}" -o "$PREVIEW/Contents/MacOS/ElanAuthPreview"
cat > "$PREVIEW/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>io.github.hackintosh-tools.elan-auth-preview</string><key>CFBundleName</key><string>ELANAuthPreview</string><key>CFBundleExecutable</key><string>ElanAuthPreview</string><key>CFBundlePackageType</key><string>APPL</string><key>NSHighResolutionCapable</key><true/></dict></plist>
PLIST
codesign --force --sign - "$BUNDLE"
codesign --force --sign - "$PREVIEW"
codesign --verify --strict "$BUNDLE"
codesign --verify --strict "$PREVIEW"
cp assets/elan-auth-test-right.plist "$OUT/elan-auth-test-right.plist"
cp assets/elan-credential-probe-right.plist "$OUT/elan-credential-probe-right.plist"
cp scripts/install-auth-prototype.command "$OUT/install-auth-prototype.command"
cp scripts/install-and-test-auth.command "$OUT/install-and-test-auth.command"
cp scripts/update-and-test-auth.command "$OUT/update-and-test-auth.command"
cp scripts/run-native-credential-probe.command "$OUT/run-native-credential-probe.command"
chmod +x "$OUT/install-auth-prototype.command" "$OUT/install-and-test-auth.command" "$OUT/update-and-test-auth.command"
chmod +x "$OUT/run-native-credential-probe.command"
"$OUT/elan-auth-probe" --self-test "$PWD/$BUNDLE/Contents/MacOS/ElanAuthPlugin"
