#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
ROOT_DIR="$PWD"
ARCH="${ARCH:-$(uname -m)}"
APP_ONLY=0
if [[ "${1:-}" == "--app-only" ]]; then APP_ONLY=1; fi
APP="build/ELANFingerprint.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Frameworks" build/Icon.iconset build/generated dist
cp assets/Info.plist "$APP/Contents/Info.plist"
# libusb Xcode configuration supports a native C-only build on macOS.
printf '#define LIBUSB_DESCRIBE "119604c-public-snapshot"\n' > build/generated/version_describe.h
clang -arch "$ARCH" -mmacosx-version-min=14.0 -O2 -dynamiclib -ffile-prefix-map="$ROOT_DIR=/build" -I build/generated -I vendor/libusb/Xcode -I vendor/libusb/libusb \
 vendor/libusb/libusb/core.c vendor/libusb/libusb/descriptor.c vendor/libusb/libusb/hotplug.c \
 vendor/libusb/libusb/io.c vendor/libusb/libusb/strerror.c vendor/libusb/libusb/sync.c \
 vendor/libusb/libusb/os/darwin_usb.c vendor/libusb/libusb/os/events_posix.c vendor/libusb/libusb/os/threads_posix.c \
 -framework IOKit -framework CoreFoundation -framework Security \
 -install_name @executable_path/../Frameworks/libusb-local.dylib -o "$APP/Contents/Frameworks/libusb-local.dylib"
clang -arch "$ARCH" -mmacosx-version-min=14.0 -O2 -ffile-prefix-map="$ROOT_DIR=/build" -I src -I vendor/elanpress -c vendor/elanpress/elanpress-match.c -o build/match.o
clang -arch "$ARCH" -mmacosx-version-min=14.0 -O2 -ffile-prefix-map="$ROOT_DIR=/build" -I src -I vendor/elanpress -c vendor/elanpress/elanpress-sift.c -o build/sift.o
clang -arch "$ARCH" -mmacosx-version-min=14.0 -O2 -fobjc-arc -Wno-deprecated-declarations -ffile-prefix-map="$ROOT_DIR=/build" -I src -I vendor/libusb/libusb -I vendor/elanpress \
 src/ElanUnlock.m build/match.o build/sift.o "$APP/Contents/Frameworks/libusb-local.dylib" \
 -framework Cocoa -framework Security -framework OpenDirectory -framework ApplicationServices -framework LocalAuthentication -lm -o "$APP/Contents/MacOS/ElanUnlock"
clang -O2 -fobjc-arc -ffile-prefix-map="$ROOT_DIR=/build" src/make_fingerprint_icon.m -framework Cocoa -o build/make-icon
./build/make-icon "$ROOT_DIR/build/icon.png"
for size in 16 32 128 256 512; do
 sips -z "$size" "$size" build/icon.png --out "build/Icon.iconset/icon_${size}x${size}.png" >/dev/null
 doubled=$((size * 2))
 sips -z "$doubled" "$doubled" build/icon.png --out "build/Icon.iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns build/Icon.iconset -o "$APP/Contents/Resources/Fingerprint.icns"
cp LICENSE "$APP/Contents/Resources/LICENSE.txt"
cp UPSTREAM.md "$APP/Contents/Resources/UPSTREAM.md"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"
"$APP/Contents/MacOS/ElanUnlock" --self-test
if [[ "$APP_ONLY" == 1 ]]; then exit 0; fi
mkdir -p build/dmg
ditto "$APP" build/dmg/ELANFingerprint.app
ln -sfn /Applications build/dmg/Applications
hdiutil create -volname ELANFingerprint -srcfolder build/dmg -ov -format UDZO "dist/ELANFingerprint-macOS-$ARCH.dmg"
