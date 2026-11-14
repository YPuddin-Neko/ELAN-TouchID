#!/usr/bin/env python3
import json
import subprocess
from pathlib import Path

source = Path(__file__).resolve().parent
out = source.parents[1] / 'elan-fingerprint-macos/build/research/native-provider-06'
out.mkdir(parents=True, exist_ok=True)


def run(arguments, log):
    result = subprocess.run([str(arg) for arg in arguments], capture_output=True, text=True)
    (out / log).write_text(result.stdout + result.stderr)
    if result.returncode: raise RuntimeError(result.stdout + result.stderr)


host = out / 'test-controller-lease'
target = out / 'NativeControllerLeaseTest'
flags = ['-std=c++14', '-Wall', '-Wextra', '-Werror']
run(['xcrun', 'clang++', *flags, '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
     source / 'test-native-controller-lease.cpp', '-o', host], 'controller-host-build.log')
run([host], 'controller-host-tests.log')
run(['xcrun', 'clang++', *flags, '-arch', 'x86_64', '-mmacosx-version-min=15.2',
     source / 'test-native-controller-lease.cpp', '-o', target], 'controller-target-build.log')
run(['codesign', '--force', '--sign', '-', target], 'controller-target-sign.log')
run(['codesign', '--verify', '--strict', target], 'controller-target-verify.log')
print(json.dumps({'host_tests_passed': True, 'host_address_undefined_sanitizers': True, 'target': str(target)}, indent=2))
