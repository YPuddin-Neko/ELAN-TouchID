#!/usr/bin/env python3
import argparse
import importlib.util
import json
import subprocess
from pathlib import Path

source = Path(__file__).resolve().parent
root = source.parents[1]
DEFAULT_OUT = root / "build/research/native-provider-06"
out = DEFAULT_OUT
identity_spec = importlib.util.spec_from_file_location("native_kernel_identity", source / "native-kernel-identity.py")
identity = importlib.util.module_from_spec(identity_spec)
identity_spec.loader.exec_module(identity)


def run(command, log):
    result = subprocess.run([str(x) for x in command], text=True, capture_output=True)
    (out / log).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"{log}: {result.stdout}{result.stderr}")


def main(argv=None):
    global out
    parser = argparse.ArgumentParser(description="Build native preflight programs without running or installing them; run only offline host tests.")
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    out = parser.parse_args(argv).out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    incomplete = {"schema_version": 1, "state": "incomplete", "version": "0.4.0",
                  "installed": False, "runtime_verified": False, "deployment_authorized": False}
    (out / "preflight-build.json").write_text(json.dumps(incomplete, indent=2) + "\n")
    test = out / "test-platform-cache"
    run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
         source / "kernel-provider/test_platform_cache.cpp", "-o", test], "platform-tests-build.log")
    run([test], "platform-tests.log")
    for compiler, filename, target, flags in [
        ("clang++", "native-platform-process-probe.cpp", "NativePlatformProcessProbe", ["-std=c++14"]),
        ("clang", "native-namespace-probe.c", "NativeNamespaceProbe", []),
    ]:
        binary = out / target
        run(["xcrun", compiler, *flags, "-arch", "x86_64", "-mmacosx-version-min=15.2",
             "-Wall", "-Wextra", "-Werror", source / filename, "-o", binary], target + "-build.log")
        run(["codesign", "--force", "--sign", "-", binary], target + "-sign.log")
        run(["codesign", "--verify", "--strict", binary], target + "-verify.log")
    (out / "run-namespace-study.py").write_bytes((source / "run-namespace-study.py").read_bytes())
    broker = out / "ELANNativeBroker"
    run(["xcrun", "clang++", "-std=c++14", "-arch", "x86_64", "-mmacosx-version-min=15.2", "-fobjc-arc",
         "-Wall", "-Wextra", "-Werror", source / "native-provider-broker.mm", "-framework", "Foundation",
         "-framework", "Security", "-framework", "IOKit", "-framework", "SystemConfiguration", "-o", broker], "broker-build.log")
    run(["codesign", "--force", "--sign", "-", "--options", "runtime", broker], "broker-sign.log")
    run(["codesign", "--verify", "--strict", broker], "broker-verify.log")
    slice_test = out / "test-executable-slice"
    run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
         source / "test-native-executable-slice.cpp", "-o", slice_test], "executable-slice-build.log")
    run([slice_test], "executable-slice-tests.log")
    wire_sources = [source / "test-native-provider-wire.cpp", source / "native-provider-client.cpp"]
    wire_host = out / "test-provider-wire"
    run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", "-fno-sanitize-recover=all", *wire_sources, "-o", wire_host], "wire-host-build.log")
    run([wire_host], "wire-host-tests.log")
    wire_target = out / "NativeProviderWireTest"
    run(["xcrun", "clang++", "-std=c++14", "-arch", "x86_64", "-mmacosx-version-min=15.2",
         "-Wall", "-Wextra", "-Werror", *wire_sources, "-o", wire_target], "wire-target-build.log")
    run(["codesign", "--force", "--sign", "-", wire_target], "wire-target-sign.log")
    run(["codesign", "--verify", "--strict", wire_target], "wire-target-verify.log")
    session_host = out / "test-settings-session"
    run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
         source / "test-native-settings-session.cpp", "-o", session_host], "settings-session-host-build.log")
    run([session_host], "settings-session-host-tests.log")
    session_target = out / "NativeSettingsSessionTest"
    run(["xcrun", "clang++", "-std=c++14", "-arch", "x86_64", "-mmacosx-version-min=15.2", "-Wall", "-Wextra", "-Werror",
         source / "test-native-settings-session.cpp", "-o", session_target], "settings-session-target-build.log")
    run(["codesign", "--force", "--sign", "-", session_target], "settings-session-target-sign.log")
    run(["codesign", "--verify", "--strict", session_target], "settings-session-target-verify.log")
    user_session_host = out / "test-user-session"
    run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
         source / "test-native-user-session.cpp", "-o", user_session_host], "user-session-host-build.log")
    run([user_session_host], "user-session-host-tests.log")
    for compiler, filename, target, extra in [
        ("clang++", "test-native-user-session.cpp", "NativeUserSessionTest", ["-std=c++14"]),
        ("clang", "native-user-session-probe.c", "NativeUserSessionProbe", ["-framework", "CoreGraphics", "-framework", "SystemConfiguration", "-framework", "Security", "-framework", "CoreFoundation"]),
    ]:
        binary = out / target
        run(["xcrun", compiler, "-arch", "x86_64", "-mmacosx-version-min=15.2", "-Wall", "-Wextra", "-Werror",
             source / filename, *extra, "-o", binary], target + "-build.log")
        run(["codesign", "--force", "--sign", "-", binary], target + "-sign.log")
        run(["codesign", "--verify", "--strict", binary], target + "-verify.log")
    retry_object = out / "lac-retry-own.o"
    run(["xcrun", "clang++", "-std=c++14", "-arch", "x86_64", "-O2", "-Wall", "-Wextra", "-Werror",
         "-c", source / "native-lac-retry-own.cpp", "-o", retry_object], "lac-retry-own-build.log")
    for filename, name, extra in [
        ("native-lac-metadata.m", "NativeLACMetadata", []),
        ("native-lac-lifecycle.m", "NativeLACLifecycle", [retry_object]),
    ]:
        binary = out / name
        run(["xcrun", "clang", "-arch", "x86_64", "-fobjc-arc", "-O2", source / filename, *extra,
             "-framework", "Foundation", "-framework", "LocalAuthentication", "-o", binary], name + "-build.log")
        run(["codesign", "--force", "--sign", "-", binary], name + "-sign.log")
        run(["codesign", "--verify", "--strict", binary], name + "-verify.log")
    manifest = {"output": str(out), "architecture": "x86_64", "platform_build": "24H32",
                "local_platform_tests_passed": True, "installed_kernel_version": "unchanged",
                "scope": ["cooperating-child platform cache", "own-named launchd namespace"],
                "apple_service_override_prepared": False, "external_credential_submission_prepared": False}
    manifest["root_broker_prepared"] = True
    manifest["managed_controller_lease_prepared"] = True
    manifest["worker_complete"] = False
    manifest["lac_own_process_lifecycle_probe_prepared"] = True
    manifest["system_process_retry_reset_deployed"] = False
    manifest["catalog_and_enrollment_wire_host_tests_passed"] = True
    manifest["settings_wire_host_tests_passed"] = True
    manifest["executable_slice_host_tests_passed"] = True
    manifest["settings_session_host_tests_passed"] = True
    manifest["settings_process_control_prepared"] = True
    manifest["settings_system_process_modified"] = False
    manifest["user_session_guard_host_tests_passed"] = True
    manifest["console_owner_broker_guard_prepared"] = True
    manifest.update({"schema_version": 1, "state": "complete", "version": "0.4.0",
                     "installed": False, "runtime_verified": False, "deployment_authorized": False,
                     "artifacts": {name: identity.executable_identity(out / name) for name in [
                         "NativePlatformProcessProbe", "NativeNamespaceProbe", "ELANNativeBroker",
                         "NativeProviderWireTest", "NativeSettingsSessionTest", "NativeUserSessionTest",
                         "NativeUserSessionProbe", "NativeLACMetadata", "NativeLACLifecycle"]}})
    (out / "preflight-build.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
