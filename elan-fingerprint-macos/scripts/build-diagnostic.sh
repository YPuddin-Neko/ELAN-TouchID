#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
ARCH="${ARCH:-$(uname -m)}"
OUT="build/diagnostic-$ARCH"
SOURCE=src/elan_match_test.c
NAME=elan-diagnostic
if [[ "${1:-}" == "--compare" ]]; then SOURCE=src/elan_capture_compare.c; NAME=elan-capture-compare; fi
mkdir -p "$OUT/generated"
printf '#define LIBUSB_DESCRIBE "119604c-public-snapshot"\n' > "$OUT/generated/version_describe.h"
clang -arch "$ARCH" -O2 -I "$OUT/generated" -I vendor/libusb/Xcode -I vendor/libusb/libusb \
  -I src -I vendor/elanpress \
  vendor/libusb/libusb/core.c vendor/libusb/libusb/descriptor.c vendor/libusb/libusb/hotplug.c \
  vendor/libusb/libusb/io.c vendor/libusb/libusb/strerror.c vendor/libusb/libusb/sync.c \
  vendor/libusb/libusb/os/darwin_usb.c vendor/libusb/libusb/os/events_posix.c \
  vendor/libusb/libusb/os/threads_posix.c \
  vendor/elanpress/elanpress-match.c vendor/elanpress/elanpress-sift.c "$SOURCE" \
  -framework IOKit -framework CoreFoundation -framework Security -lm \
  -o "$OUT/$NAME"
codesign --force --sign - "$OUT/$NAME"
echo "$OUT/$NAME"
