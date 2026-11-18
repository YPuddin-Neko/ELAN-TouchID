#!/bin/sh
set -eu
if [ "$#" -ne 2 ]; then
    echo "Usage: sh build.sh /path/to/MacKernelSDK /path/to/output" >&2
    exit 2
fi
sdk=$(cd "$1" && pwd)
src=$(cd "$(dirname "$0")" && pwd)
out=$2
bundle="$out/ELANFingerprintUSB.kext/Contents"
mkdir -p "$bundle/MacOS"
xcrun clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
    "$src/test_sensor_profile.cpp" -o "$out/test-sensor-profile"
"$out/test-sensor-profile"
xcrun clang++ -std=c++14 -Wall -Wextra -Werror -fsanitize=address,undefined \
    "$src/test_direct_enrollment_policy.cpp" -framework IOKit -framework CoreFoundation \
    -o "$out/test-direct-enrollment-policy"
"$out/test-direct-enrollment-policy"
xcrun clang++ -std=c++14 -fobjc-arc -Wall -Wextra -Werror -fsanitize=address,undefined \
    "$src/test_settings_enrollment_peer.mm" -framework Foundation -framework Security -lbsm \
    -o "$out/test-settings-enrollment-peer"
"$out/test-settings-enrollment-peer"
xcrun clang++ -arch x86_64 -std=c++14 -mmacosx-version-min=15.2 -O2 -mkernel \
    -fapple-kext -nostdinc++ -fno-exceptions -fno-rtti -fno-common -fno-builtin \
    -fno-stack-protector -mno-red-zone -DKERNEL -DKERNEL_PRIVATE -D__KERNEL__ \
    -I"$sdk/Headers" -c "$src/ELANFingerprintUSB.cpp" -o "$out/ELANFingerprintUSB.o"
xcrun ld -kext -arch x86_64 -macos_version_min 15.2 -o "$bundle/MacOS/ELANFingerprintUSB" \
    "$out/ELANFingerprintUSB.o" "$sdk/Library/x86_64/libkmod.a"
cp "$src/Info.plist" "$bundle/Info.plist"
plutil -lint "$bundle/Info.plist"
xcrun clang++ -arch x86_64 -std=c++14 -mmacosx-version-min=15.2 -O2 -fobjc-arc \
    -Wall -Wextra -Werror "$src/InspectSensor.mm" "$src/SensorRegistry.mm" "$src/AccessoryDiscovery.mm" -framework Security -framework IOKit -framework Foundation \
    -framework LocalAuthentication -o "$out/ELANInspectSensor"
codesign --force --sign - "$out/ELANInspectSensor"
codesign --verify --strict "$out/ELANInspectSensor"
xcrun clang++ -arch x86_64 -std=c++14 -mmacosx-version-min=15.2 -O2 -fobjc-arc \
    -Wall -Wextra -Werror "$src/SettingsDeviceReader.mm" "$src/AccessoryDiscovery.mm" \
    -framework Security -framework LocalAuthentication -framework Foundation -o "$out/ELANSettingsDeviceReader"
codesign --force --sign - "$out/ELANSettingsDeviceReader"
codesign --verify --strict "$out/ELANSettingsDeviceReader"
python3 -B "$src/../build-native-provider.py" --sensor-service-only --out "$out/sensor-service-build"
cp "$out/sensor-service-build/ELANSensorService" "$out/ELANSensorService"
codesign --verify --strict "$out/ELANSensorService"
plutil -lint "$src/io.github.hackintosh-tools.elan-usb.plist"
