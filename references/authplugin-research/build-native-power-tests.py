#!/usr/bin/env python3
import json
import subprocess
from pathlib import Path

source = Path(__file__).resolve().parent
out = source.parents[1] / 'build/research/native-provider-06'
out.mkdir(parents=True, exist_ok=True)


def run(arguments, log):
    result = subprocess.run([str(arg) for arg in arguments], capture_output=True, text=True)
    (out / log).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)


host = out / 'test-native-power-state'
target = out / 'NativePowerStateTest'
flags = ['-std=c++14', '-Wall', '-Wextra', '-Werror']
run(['xcrun', 'clang++', *flags, '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
     source / 'test-native-power-state.cpp', '-o', host], 'power-host-build.log')
run([host], 'power-host-tests.log')
run(['xcrun', 'clang++', *flags, '-arch', 'x86_64', '-mmacosx-version-min=15.2',
     source / 'test-native-power-state.cpp', '-o', target], 'power-target-build.log')
run(['codesign', '--force', '--sign', '-', target], 'power-target-sign.log')
run(['codesign', '--verify', '--strict', target], 'power-target-verify.log')
print(json.dumps({'host_state_tests_passed': True, 'host_address_undefined_sanitizers': True,
                  'target_state_test': str(target), 'actual_power_transition_tested': False}, indent=2))
