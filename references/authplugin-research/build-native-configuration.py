#!/usr/bin/env python3
import json
import subprocess
from pathlib import Path

source = Path(__file__).resolve().parent
root = source.parents[1]
out = root / 'elan-fingerprint-macos/build/research/native-ecosystem-01'
out.mkdir(parents=True, exist_ok=True)
binary = out / 'NativeConfigurationProbe'
project = root / 'elan-fingerprint-macos'
includes = ['-I' + str(project / 'src'), '-I' + str(project / 'vendor/elanpress')]
model = [project / 'src' / ('ElanFingerprint' + name + '.m') for name in ['Catalog', 'Matcher', 'Session']]
model += [project / 'vendor/elanpress' / ('elanpress-' + name + '.c') for name in ['match', 'sift']]


def run(args, name):
    process = subprocess.run([str(x) for x in args], capture_output=True, text=True)
    (out / name).write_text(process.stdout + process.stderr)
    if process.returncode:
        raise RuntimeError(name + ': ' + process.stdout + process.stderr)


run(['xcrun', 'clang', '-arch', 'x86_64', '-mmacosx-version-min=15.2', '-O2', '-fobjc-arc',
     '-Wall', '-Wextra', '-Wno-unused-function', '-Wno-unused-parameter',
     '-Wno-deprecated-declarations', *includes, source / 'native-configuration-probe.m', *model,
     '-framework', 'Foundation', '-framework', 'LocalAuthentication', '-framework', 'Security',
     '-o', binary], 'configuration-build.log')
run(['codesign', '--force', '--sign', '-', binary], 'configuration-sign.log')
run(['codesign', '--verify', '--strict', binary], 'configuration-verify.log')
host = out / 'test-native-configuration'
run(['xcrun', 'clang', '-fobjc-arc', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-deprecated-declarations',
     '-fsanitize=address,undefined', '-fno-sanitize-recover=all', *includes,
     source / 'test-native-configuration.m', *model, '-framework', 'Foundation', '-framework', 'Security', '-o', host], 'configuration-model-build.log')
run([host], 'configuration-model-host.log')
print(json.dumps({'binary': str(binary), 'installed': False, 'system_service_changed': False}))
