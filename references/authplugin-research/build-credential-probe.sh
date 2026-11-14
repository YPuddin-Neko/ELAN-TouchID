#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
bash references/authplugin-research/build-native-probe.sh
OUT=elan-fingerprint-macos/build/research/NativeCredentialProbe.app
ditto elan-fingerprint-macos/build/research/NativeTouchProbe.app "$OUT"
/usr/libexec/PlistBuddy -c 'Set :CFBundleIdentifier io.github.hackintosh-tools.native-credential-probe' "$OUT/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Set :CFBundleName NativeCredentialProbe' "$OUT/Contents/Info.plist"
codesign --force --sign - --entitlements references/authplugin-research/native-credential-probe.entitlements "$OUT"
codesign --verify --strict "$OUT"
ditto -c -k --sequesterRsrc --keepParent "$OUT" elan-fingerprint-macos/build/research/NativeCredentialProbe.zip
