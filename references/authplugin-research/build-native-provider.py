#!/usr/bin/env python3
import argparse
import importlib.util
import json
import plistlib
import subprocess
from pathlib import Path

source = Path(__file__).resolve().parent
root = source.parents[1]
project = root
DEFAULT_OUT = project / "build/research/native-provider-06"
VERSION = "0.4.0"
out = DEFAULT_OUT
identity_spec = importlib.util.spec_from_file_location('native_kernel_identity', source / 'native-kernel-identity.py')
identity = importlib.util.module_from_spec(identity_spec)
identity_spec.loader.exec_module(identity)


def run(command, log):
    process = subprocess.run([str(x) for x in command], text=True, capture_output=True)
    (out / log).write_text(process.stdout + process.stderr)
    if process.returncode:
        raise RuntimeError(f"{log}: {process.stdout}{process.stderr}")


def main(argv=None):
    global out
    parser = argparse.ArgumentParser(description='Build the native provider programs without running or installing them.')
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT, help='Build output directory')
    parser.add_argument('--sensor-service-only', action='store_true',
                        help='Build the ordinary-user service with the native Settings enrollment backend.')
    args = parser.parse_args(argv)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    incomplete = {'schema_version': 1, 'state': 'incomplete', 'version': VERSION,
                  'installed': False, 'runtime_verified': False, 'deployment_authorized': False}
    manifest_name = 'sensor-service-build.json' if args.sensor_service_only else 'worker-build.json'
    (out / manifest_name).write_text(json.dumps(incomplete, indent=2) + '\n')
    objects = out / "worker-objects"
    objects.mkdir(parents=True, exist_ok=True)
    generated = objects / "generated"
    generated.mkdir(exist_ok=True)
    (generated / "version_describe.h").write_text('#define LIBUSB_DESCRIBE "119604c-public-snapshot"\n')
    flags = ["-arch", "x86_64", "-mmacosx-version-min=15.2", "-O2"]
    includes = ["-I" + str(x) for x in [generated, project / "vendor/libusb/Xcode",
                project / "vendor/libusb/libusb", project / "vendor/elanpress", project / "src"]]
    usb = project / "vendor/libusb/libusb"
    inputs = [usb / name for name in ["core.c", "descriptor.c", "hotplug.c", "io.c", "strerror.c", "sync.c",
                                     "os/darwin_usb.c", "os/events_posix.c", "os/threads_posix.c"]]
    inputs += [project / "vendor/elanpress" / ("elanpress-" + name + ".c") for name in ["match", "sift"]]
    compiled = []
    for index, path in enumerate(inputs):
        target = objects / f"{index}.o"
        run(["xcrun", "clang", *flags, *includes, "-c", path, "-o", target], f"worker-object-{index}.log")
        compiled.append(target)
    bridge = objects / "provider-client.o"
    run(["xcrun", "clang++", *flags, "-std=c++14", "-Wall", "-Wextra", "-Werror", "-c",
         source / "native-provider-client.cpp", "-o", bridge], "worker-client-build.log")
    compiled.append(bridge)
    frameworks = ["Foundation", "Security", "LocalAuthentication", "IOKit", "CoreFoundation", "CoreGraphics", "SystemConfiguration", "ApplicationServices", "AppKit", "OpenDirectory"]
    if args.sensor_service_only:
        service_sources = source / "usb-sensor"
        service = out / "ELANSensorService"
        for unit in ["SensorService", "SensorRegistry", "AccessoryDiscovery", "SettingsListener"]:
            obj = objects / (unit + ".o")
            run(["xcrun", "clang++", *flags, "-std=c++14", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
                 "-c", service_sources / (unit + ".mm"), "-o", obj], "compile-" + unit)
            compiled.append(obj)
        facade = source / "agent-integration-candidate/production-session-candidate/EnrollmentProtocolFacade.m"
        run(["xcrun", "clang", *flags, *includes, "-fobjc-arc", "-Wno-deprecated-declarations",
             "-DELAN_SENSOR_SERVICE_BACKEND=1", source / "native-elan-provider.m", facade,
             *[project / "src" / ("ElanFingerprint" + model + ".m")
               for model in ["Catalog","Matcher","Session","Enrollment"]], *compiled,
             *[v for framework in frameworks for v in ["-framework", framework]],
             "-lc++", "-lm", "-lbsm", "-o", service], "sensor-service-link")
        run(["codesign", "--force", "--sign", "-", "--identifier", "io.github.hackintosh-tools.elan-unlock", "--options", "runtime", service], "sensor-service-sign")
        run(["codesign", "--verify", "--strict", service], "sensor-service-verify")
        report = {**incomplete, "state": "complete", "architecture": "x86_64", "runtime_privilege": "console user",
                  "enrollment_policy": "direct driver check at start and commit"}
        (out / manifest_name).write_text(json.dumps(report, indent=2) + '\n')
        return
    app = out / "ELANNativeProvider.app"
    executable = app / "Contents/MacOS/ELANNativeProvider"
    executable.parent.mkdir(parents=True, exist_ok=True)
    run(["xcrun", "clang", *flags, *includes, "-fobjc-arc", "-Wno-deprecated-declarations",
         source / "native-elan-provider.m", project / "src/ElanFingerprintCatalog.m",
         project / "src/ElanFingerprintMatcher.m", project / "src/ElanFingerprintSession.m", project / "src/ElanFingerprintEnrollment.m", *compiled,
         *[value for framework in frameworks for value in ["-framework", framework]],
         "-lc++", "-lm", "-o", executable], "worker-build.log")
    info = {"CFBundleIdentifier": "io.github.hackintosh-tools.elan-native-provider",
            "CFBundleName": "ELANNativeProvider", "CFBundleExecutable": "ELANNativeProvider",
            "CFBundlePackageType": "APPL", "CFBundleVersion": VERSION, "LSUIElement": True}
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
    run(["codesign", "--force", "--sign", "-", "--options", "runtime", app], "worker-sign.log")
    run(["codesign", "--verify", "--deep", "--strict", app], "worker-verify.log")
    run(["otool", "-L", executable], "worker-libraries.log")
    test_app = out / "ELANNativeAuthTest.app"
    test_binary = test_app / "Contents/MacOS/ELANNativeAuthTest"
    test_binary.parent.mkdir(parents=True, exist_ok=True)
    run(["xcrun", "clang", *flags, "-fobjc-arc", "-Wall", "-Wextra", source / "native-system-auth-test.m",
         "-framework", "Foundation", "-framework", "LocalAuthentication", "-o", test_binary], "auth-test-build.log")
    (test_app / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "io.github.hackintosh-tools.elan-native-auth-test", "CFBundleName": "ELAN 原生认证测试",
        "CFBundleExecutable": "ELANNativeAuthTest", "CFBundlePackageType": "APPL", "CFBundleVersion": VERSION, "LSUIElement": True}))
    run(["codesign", "--force", "--sign", "-", "--options", "runtime", test_app], "auth-test-sign.log")
    run(["codesign", "--verify", "--strict", test_app], "auth-test-verify.log")
    transport_test = out / "NativeMatchTransportTest"
    run(["xcrun", "clang", *flags, "-fobjc-arc", "-Wall", "-Wextra", source / "native-provider-transport-test.m",
         "-framework", "Foundation", "-o", transport_test], "match-transport-build.log")
    run(["codesign", "--force", "--sign", "-", transport_test], "match-transport-sign.log")
    run(["codesign", "--verify", "--strict", transport_test], "match-transport-verify.log")
    artifacts = {str(path.relative_to(out)): identity.executable_identity(path)
                 for path in [executable, test_binary, transport_test]}
    manifest = {"schema_version": 1, "state": "complete", "app": str(app), "version": VERSION, "artifacts": artifacts,
                "static_libusb": True, "runtime_signature": True,
                "private_entitlements": False, "custom_authentication_ui": False,
                "password_submission": False, "runtime_verified": False,
                "installed": False, "deployment_authorized": False,
                "scope": "UID501 native matching, initial and extended enrollment with password-context authorization, and identity management; unlock-token requests rejected",
                "system_service_name": "com.apple.biometrickitd", "service_registered": False}
    manifest.update({"protected_configuration_interface_prepared": True,
                     "protected_configuration_live_settings_verified": False,
                     "catalog_schema": 2,
                     "native_unlock_toggle_supported": False})
    manifest["native_auth_test_app"] = str(test_app)
    manifest["catalog_and_multifinger_match_integrated"] = True
    manifest["native_enrollment_handlers_integrated"] = True
    manifest["native_enrollment_hardware_verified"] = False
    manifest["native_enrollment_ui_verified"] = False
    manifest["native_extended_enrollment_integrated"] = True
    manifest["native_extended_enrollment_hardware_verified"] = False
    manifest["native_initial_enrollment_samples"] = 8
    manifest["native_identity_management_handlers_integrated"] = True
    manifest["apple_settings_peer_prepared"] = True
    manifest["settings_session_integration_prepared"] = True
    manifest["settings_session_runtime_verified"] = False
    manifest["user_session_guard_integrated"] = True
    manifest["session_transition_runtime_verified"] = False
    manifest["noninteractive_background_mode_prepared"] = True
    manifest["background_keychain_runtime_verified"] = False
    manifest["power_transition_guard_prepared"] = True
    manifest["sleep_wake_runtime_verified"] = False
    manifest["managed_service_mode_prepared"] = True
    manifest["persistent_startup_runtime_verified"] = False
    (out / "worker-build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
