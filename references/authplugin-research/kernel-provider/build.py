#!/usr/bin/env python3
import json
import plistlib
import subprocess
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
ROOT = SOURCE.parents[2]
SDK = ROOT.parent / 'MacKernelSDK'
LILU = ROOT.parent / 'build/bluetooth/IntelBluetoothFirmware-a414375505fa3b014be32f8fca31b5bbfdf9f10f/Lilu.kext/Contents/Resources'
OUT = ROOT / 'elan-fingerprint-macos/build/research/native-kernel-probe-06'
NAME = 'ELANNativeProbe'
IDENTIFIER = 'io.github.hackintosh-tools.elan-native-probe'
VERSION = '0.4.0'


def run(command, log_name):
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True)
    (OUT / (log_name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout


def main():
    for dependency in [SDK / 'Library/x86_64/libkmod.a', LILU / 'Library/plugin_start.cpp']:
        if not dependency.is_file():
            raise FileNotFoundError(dependency)
    OUT.mkdir(parents=True, exist_ok=True)
    tests = ['credential_study', 'provider_session', 'enrollment_authorization', 'platform_cache', 'lac_retry', 'settings_cache']
    for name in tests:
        test = OUT / ('test-' + name.replace('_', '-'))
        run(['xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
             SOURCE / ('test_' + name + '.cpp'), '-o', test], 'test-' + name + '-build')
        run([test], 'test-' + name)
    module = OUT / 'module.cpp'
    module.write_text('''#include <mach/kmod.h>
extern "C" {
extern kern_return_t ELANNativeProbe_kern_start(kmod_info_t *, void *);
extern kern_return_t ELANNativeProbe_kern_stop(kmod_info_t *, void *);
extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);
KMOD_EXPLICIT_DECL(io.github.hackintosh-tools.elan-native-probe, "@VERSION@", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = ELANNativeProbe_kern_start;
__private_extern__ kmod_stop_func_t *_antimain = ELANNativeProbe_kern_stop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;
}
'''.replace('@VERSION@', VERSION))
    flags = ['-std=gnu++14', '-arch', 'x86_64', '-O2', '-g0', '-mmacosx-version-min=15.2',
             '-mkernel', '-nostdinc++', '-fapple-kext', '-fno-exceptions', '-fno-rtti',
             '-fno-common', '-fno-builtin', '-fno-stack-protector', '-mno-red-zone',
             '-Werror=return-type', '-DKERNEL', '-DKERNEL_PRIVATE', '-D__KERNEL__',
             '-DLILU_CUSTOM_IOKIT_INIT=1', '-DPRODUCT_NAME=' + NAME, '-DMODULE_VERSION=' + VERSION,
             '-I' + str(SDK / 'Headers'), '-I' + str(LILU)]
    objects = []
    for index, source in enumerate([SOURCE / 'ElanNativeProbe.cpp', LILU / 'Library/plugin_start.cpp', module]):
        target = OUT / (str(index) + '.o')
        run(['xcrun', 'clang++', *flags, '-c', source, '-o', target], 'compile-' + str(index))
        objects.append(target)
    bundle = OUT / (NAME + '.kext')
    executable = bundle / 'Contents/MacOS' / NAME
    executable.parent.mkdir(parents=True, exist_ok=True)
    run(['xcrun', 'ld', '-kext', '-arch', 'x86_64', '-macos_version_min', '15.2',
         '-o', executable, *objects, SDK / 'Library/x86_64/libkmod.a'], 'link')
    info = {
        'CFBundleIdentifier': IDENTIFIER, 'CFBundleName': NAME, 'CFBundleExecutable': NAME,
        'CFBundlePackageType': 'KEXT', 'CFBundleInfoDictionaryVersion': '6.0',
        'CFBundleVersion': VERSION, 'CFBundleShortVersionString': VERSION,
        'OSBundleRequired': 'Root',
        'OSBundleLibraries': {**{x: '12.0.0' for x in ['com.apple.kpi.bsd', 'com.apple.kpi.iokit',
                                                    'com.apple.kpi.libkern', 'com.apple.kpi.mach',
                                                    'com.apple.kpi.unsupported']}, 'as.vit9696.Lilu': '1.2.0'},
        'IOKitPersonalities': {NAME: {'CFBundleIdentifier': IDENTIFIER, 'IOClass': NAME,
                                     'IOProviderClass': 'IOResources', 'IOResourceMatch': 'IOKit',
                                     'IOMatchCategory': NAME}}
    }
    (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
    client = OUT / 'elan-native-probe'
    run(['xcrun', 'clang++', '-std=c++14', '-arch', 'x86_64', '-O2', '-Wall', '-Wextra',
         '-Werror', '-mmacosx-version-min=15.2', SOURCE / 'probe-client.cpp',
         '-framework', 'IOKit', '-framework', 'CoreFoundation', '-o', client], 'client-build')
    run(['codesign', '--force', '--sign', '-', client], 'client-sign')
    run(['codesign', '--verify', '--strict', client], 'client-verify')
    manifest = {'bundle': str(bundle), 'client': str(client), 'version': VERSION,
                'supported_acm_uuid': '38EBFC61-0BF9-3089-996B-3F6B2A32F20C',
                'supported_darwin': '24.6.0', 'source': str(SOURCE), 'installed': False,
                'credentials_added': False, 'kernel_hooks': False, 'global_availability_writes': False,
                'prepared_operations': ['status', 'empty-context-lifecycle', 'isolated-credential-study',
                                        'isolated-policy-study', 'restore-study-availability',
                                        'provider-begin', 'provider-real-match', 'provider-end',
                                        'user-coreauthd-platform-enable', 'user-coreauthd-platform-restore',
                                        'provider-catalog-begin', 'provider-catalog-replace', 'provider-authorize-enrollment',
                                        'settings-platform-enable', 'settings-platform-restore'],
                'deployment_authorized': False, 'runtime_verified': False,
                'policy_study_changes_availability_temporarily': True,
                'external_context_handles_accepted': True,
                'provider_user': 501,
                'platform_process_scope': 'stopped UID501 coreauthd and separate Touch ID & Password extension slots; platform cache and process-specific retry state; process exit required for cleanup',
                'client_close_restoration_prepared': True,
                'user_space_provider_complete': False,
                'ready_for_installation': False}
    manifest['host_state_machine_tests'] = tests
    manifest['catalog_max_identities'] = 3
    manifest['enrollment_authorization_runtime_verified'] = False
    manifest['settings_image_uuid'] = '418ECD95-E742-3847-9621-84135A94B634'
    manifest['settings_platform_runtime_verified'] = False
    (OUT / 'build.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
