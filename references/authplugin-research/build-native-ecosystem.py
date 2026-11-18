#!/usr/bin/env python3
import json
import subprocess
from pathlib import Path

source = Path(__file__).resolve().parent
root = source.parents[1]
out = root / "build/research/native-ecosystem-01"
out.mkdir(parents=True, exist_ok=True)


def run(command, log):
    result = subprocess.run([str(value) for value in command], text=True, capture_output=True)
    (out / log).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"{log}: {result.stdout}{result.stderr}")


project = root
includes = ["-I" + str(project / "src"), "-I" + str(project / "vendor/elanpress")]
binary = out / "NativeEnrollmentProbe"
run(["xcrun", "clang", "-arch", "x86_64", "-mmacosx-version-min=15.2", "-O2", "-fobjc-arc",
     "-Wno-deprecated-declarations", *includes, source / "native-enrollment-probe.m", project / "src/ElanFingerprintCatalog.m",
     project / "src/ElanFingerprintMatcher.m", project / "src/ElanFingerprintSession.m",
     project / "src/ElanFingerprintEnrollment.m",
     project / "vendor/elanpress/elanpress-match.c", project / "vendor/elanpress/elanpress-sift.c",
     "-framework", "Foundation", "-framework", "LocalAuthentication", "-framework", "Security",
     "-o", binary], "enrollment-build.log")
run(["codesign", "--force", "--sign", "-", binary], "enrollment-sign.log")
run(["codesign", "--verify", "--strict", binary], "enrollment-verify.log")
catalog_sources = [source / "test-fingerprint-catalog.m", project / "src/ElanFingerprintCatalog.m"]
catalog_host = out / "test-fingerprint-catalog"
run(["xcrun", "clang", "-fobjc-arc", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-Wno-deprecated-declarations",
     "-fsanitize=address,undefined", "-fno-sanitize-recover=all", *includes, *catalog_sources,
     "-framework", "Foundation", "-framework", "Security", "-o", catalog_host], "catalog-host-build.log")
run([catalog_host], "catalog-host-tests.log")
catalog_target = out / "NativeFingerprintCatalogTest"
run(["xcrun", "clang", "-arch", "x86_64", "-mmacosx-version-min=15.2", "-O2", "-fobjc-arc",
     "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-Wno-deprecated-declarations", *includes, *catalog_sources,
     "-framework", "Foundation", "-framework", "Security", "-o", catalog_target], "catalog-target-build.log")
run(["codesign", "--force", "--sign", "-", catalog_target], "catalog-target-sign.log")
run(["codesign", "--verify", "--strict", catalog_target], "catalog-target-verify.log")
matcher_sources = [source / "test-fingerprint-matcher.m", project / "src/ElanFingerprintCatalog.m",
                   project / "src/ElanFingerprintMatcher.m", project / "vendor/elanpress/elanpress-match.c",
                   project / "vendor/elanpress/elanpress-sift.c"]
for name, extra, host in [
    ("test-fingerprint-matcher", ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"], True),
    ("NativeFingerprintMatcherTest", ["-arch", "x86_64", "-mmacosx-version-min=15.2", "-O2"], False),
]:
    matcher = out / name
    run(["xcrun", "clang", "-fobjc-arc", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
         "-Wno-deprecated-declarations", *extra, *includes, *matcher_sources,
         "-framework", "Foundation", "-framework", "Security", "-o", matcher], name + "-build.log")
    if host: run([matcher], name + "-tests.log")
    else:
        run(["codesign", "--force", "--sign", "-", matcher], name + "-sign.log")
        run(["codesign", "--verify", "--strict", matcher], name + "-verify.log")
authorization = out / "NativeEnrollmentAuthorizationProbe"
run(["xcrun", "clang", "-arch", "x86_64", "-mmacosx-version-min=15.2", "-fobjc-arc", "-fblocks",
     "-Wall", "-Wextra", "-Werror", source / "native-enrollment-authorization-probe.m",
     "-framework", "Foundation", "-framework", "LocalAuthentication", "-o", authorization],
    "enrollment-authorization-build.log")
run(["codesign", "--force", "--sign", "-", authorization], "enrollment-authorization-sign.log")
run(["codesign", "--verify", "--strict", authorization], "enrollment-authorization-verify.log")
settings = out / "NativeSettingsAccessProbe"
run(["xcrun", "clang", "-arch", "x86_64", "-mmacosx-version-min=15.2", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
     source / "native-settings-access-probe.m", "-framework", "Foundation", "-framework", "Security", "-o", settings],
    "settings-access-build.log")
run(["codesign", "--force", "--sign", "-", settings], "settings-access-sign.log")
run(["codesign", "--verify", "--strict", settings], "settings-access-verify.log")
session_sources = [source / "test-fingerprint-session.m", project / "src/ElanFingerprintCatalog.m",
                   project / "src/ElanFingerprintMatcher.m", project / "src/ElanFingerprintSession.m",
                   project / "vendor/elanpress/elanpress-match.c", project / "vendor/elanpress/elanpress-sift.c"]
for label, target_name, files in [
    ("fingerprint-session", "NativeFingerprintSessionTest", session_sources),
    ("fingerprint-enrollment", "NativeFingerprintEnrollmentTest", [source / "test-fingerprint-enrollment.m",
        project / "src/ElanFingerprintEnrollment.m", *session_sources[1:]]),
    ("provider-peer", "NativeProviderPeerTest", [source / "test-native-provider-peer.m"]),
]:
    for host in [True, False]:
        target = out / ("test-" + label if host else target_name)
        extra = ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"] if host else ["-arch", "x86_64", "-mmacosx-version-min=15.2", "-O2"]
        run(["xcrun", "clang", "-fobjc-arc", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
             "-Wno-deprecated-declarations", *extra, *includes, *files,
             "-framework", "Foundation", "-framework", "Security", "-o", target], target.name + "-build.log")
        if host: run([target], target.name + "-tests.log")
        else:
            run(["codesign", "--force", "--sign", "-", target], target.name + "-sign.log")
            run(["codesign", "--verify", "--strict", target], target.name + "-verify.log")
ui_code = out / "NativeEnrollmentUICode"
run(["xcrun", "clang", "-arch", "x86_64", "-mmacosx-version-min=15.2", "-O2", "-fobjc-arc", "-Wall", "-Wextra", "-Werror",
     source / "native-enrollment-ui-code.m", "-framework", "Foundation", "-o", ui_code], "enrollment-ui-code-build.log")
run(["codesign", "--force", "--sign", "-", ui_code], "enrollment-ui-code-sign.log")
run(["codesign", "--verify", "--strict", ui_code], "enrollment-ui-code-verify.log")
print(json.dumps({"binary": str(binary), "installed": False, "system_service_changed": False}))
