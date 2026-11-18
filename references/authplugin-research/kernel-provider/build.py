#!/usr/bin/env python3
import argparse
import importlib.util
import json
import plistlib
import re
import shutil
import uuid
import subprocess
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
ROOT = SOURCE.parents[2]
SDK = ROOT.parent / 'MacKernelSDK'
LILU = ROOT.parent / 'build/bluetooth/IntelBluetoothFirmware-a414375505fa3b014be32f8fca31b5bbfdf9f10f/Lilu.kext/Contents/Resources'
OUT = ROOT / 'build/research/native-kernel-authorization-015'
NAME = 'ELANNativeProbe'
IDENTIFIER = 'io.github.hackintosh-tools.elan-native-probe'
VERSION = '0.6.0'
BUNDLE_NAME = 'ELANNativeProbeAuthorization015'
identity_spec = importlib.util.spec_from_file_location('native_kernel_identity', SOURCE.parent / 'native-kernel-identity.py')
identity = importlib.util.module_from_spec(identity_spec)
identity_spec.loader.exec_module(identity)


def run(command, log_name):
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True)
    (OUT / (log_name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout


def main(argv=None):
    global SDK, LILU, OUT
    parser = argparse.ArgumentParser(description='Build the native provider kernel candidate without installing it.')
    parser.add_argument('--sdk', type=Path, default=SDK, help='MacKernelSDK directory')
    parser.add_argument('--lilu', type=Path, default=LILU, help='Lilu Resources directory')
    parser.add_argument('--out', type=Path, default=OUT, help='Build output directory')
    parser.add_argument('--enrollment-service', type=Path,
                        help='Pin this signed ELANSensorService binary for direct password-context checks.')
    parser.add_argument('--automatic-settings', action='store_true',
                        help='Route the first device lookup in the pinned Touch ID settings extension.')
    parser.add_argument('--service-home', type=Path,
                        help='Pin the installed automatic service to this user’s Library/Application Support.')
    args = parser.parse_args(argv)
    if args.automatic_settings and not args.enrollment_service:
        parser.error('--automatic-settings requires --enrollment-service')
    if args.automatic_settings and not args.service_home:
        parser.error('--automatic-settings requires the target account’s --service-home')
    if args.service_home and (not args.automatic_settings or args.service_home.parent != Path('/Users') or
                              not re.fullmatch(r'[A-Za-z0-9_-]+', args.service_home.name)):
        parser.error('--service-home requires --automatic-settings and an absolute /Users/<account> path')
    SDK, LILU, OUT = args.sdk.resolve(), args.lilu.resolve(), args.out.resolve()

    if args.enrollment_service and args.out == ROOT / 'build/research/native-kernel-authorization-015':
        OUT = OUT.with_name('native-kernel-direct-enrollment')
    version = '0.6.1' if args.enrollment_service else VERSION
    bundle_name = 'ELANNativeProbeDirectEnrollment' if args.enrollment_service else BUNDLE_NAME
    if args.automatic_settings:
        version = '0.6.2'
        bundle_name = 'ELANNativeProbeAutomaticSettings'
        if OUT.name == 'native-kernel-direct-enrollment':
            OUT = OUT.with_name('native-kernel-automatic-settings')
    OUT.mkdir(parents=True, exist_ok=True)
    # A failed rebuild must not leave old success metadata beside an untouched binary.
    incomplete = {'schema_version': 1, 'state': 'incomplete', 'installed': False,
                  'runtime_verified': False, 'ready_for_installation': False}
    for name in (identity.MANIFEST_NAME, 'build.json'):
        (OUT / name).write_text(json.dumps(incomplete, indent=2) + '\n')
    for dependency in [SDK / 'Library/x86_64/libkmod.a', LILU / 'Library/plugin_start.cpp']:
        if not dependency.is_file():
            raise FileNotFoundError(dependency)
    tests = ['enrollment_diagnostics', 'settings_enrollment_authorization', 'credential_study', 'provider_session', 'enrollment_authorization', 'platform_cache', 'lac_retry', 'settings_cache', 'connection_cache', 'connection_image', 'settings_recovery', 'platform_process', 'map_protection_abi', 'operation_gate', 'provider_operation_lifecycle', 'startup_observation', 'startup_correlation', 'startup_observer_kernel', 'startup_trial_lifecycle']
    if args.automatic_settings:
        tests.extend(['settings_route', 'settings_hardware_gate', 'settings_agent_gate', 'coreauth_sample', 'late_cache_base', 'settings_late_admission', 'settings_startup_diagnostics'])
    for name in tests:
        test = OUT / ('test-' + name.replace('_', '-'))
        run(['xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
             *(['-I' + str(SOURCE / 'observer-test-shim')] if name == 'startup_observer_kernel' else []),
             *(['-I' + str(SOURCE / 'platform-test-shim')] if name == 'platform_process' else []),
             *(['-I' + str(SOURCE / 'provider-operation-test-shim')] if name in ('provider_operation_lifecycle', 'startup_trial_lifecycle') else []),
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
'''.replace('@VERSION@', version))
    flags = ['-std=gnu++14', '-arch', 'x86_64', '-O2', '-g0', '-mmacosx-version-min=15.2',
             '-mkernel', '-nostdinc++', '-fapple-kext', '-fno-exceptions', '-fno-rtti',
             '-fno-common', '-fno-builtin', '-fno-stack-protector', '-mno-red-zone',
             '-Werror=return-type', '-DKERNEL', '-DKERNEL_PRIVATE', '-D__KERNEL__',
             '-DLILU_CUSTOM_IOKIT_INIT=1', '-DPRODUCT_NAME=' + NAME, '-DMODULE_VERSION=' + version,
             '-I' + str(SDK / 'Headers'), '-I' + str(LILU)]
    if args.enrollment_service:
        service = args.enrollment_service.resolve(strict=True)
        if service.name != 'ELANSensorService':
            raise ValueError('expected ELANSensorService')
        run(['codesign', '--verify', '--strict', service], 'enrollment-service-verify')
        run(['codesign', '-d', '--verbose=4', service], 'enrollment-service-signature')
        signature = (OUT / 'enrollment-service-signature.log').read_text()
        cdhash = re.search(r'^CDHash=([a-f0-9]{40})$', signature, re.M)
        if (not cdhash or not re.search(r'^Hash type=sha256 size=32$', signature, re.M) or
                not re.search(r'flags=0x[0-9a-f]+\([^)]*runtime[^)]*\)', signature)):
            raise ValueError('expected hardened SHA-256 code signature')
        service_uuid = uuid.UUID(identity.macho_uuid(service.read_bytes(), expected_kind=2))
        def byte_array(data):
            return '{' + ', '.join(hex(n) for n in data) + '}'
        install_root = args.service_home or Path('/')
        install_path = str(install_root / 'Library/Application Support/ELANFingerprint/ELANSensorService')
        profile = ('static const ElanPermitIdentity::Config directServiceIdentity = {{true, ' +
                   byte_array(service_uuid.bytes) + ', ' + byte_array(bytes.fromhex(cdhash[1])) +
                   ', 2, 501, ' + json.dumps(install_path) + '}, true};\n')
        (OUT / 'ElanEnrollmentServiceIdentity.h').write_text(profile)
        flags += ['-DELAN_DIRECT_ENROLLMENT=1', '-I' + str(OUT)]
    objects = []
    components = SOURCE.parent / 'agent-integration-candidate'
    units = [SOURCE / 'ElanNativeProbe.cpp', components / 'startup-retirement/KernelRuntime.cpp', LILU / 'Library/plugin_start.cpp', module]
    if args.automatic_settings:
        flags += ['-DELAN_AUTOMATIC_SETTINGS=1', '-DELAN_PINNED_CAPTURE_ONLY=1']
        units += [SOURCE / 'SettingsStartupKernel.cpp', components / 'early-boundary-observation/CurrentThreadCapture.cpp',
                  components / 'startup-fresh-writer/runtime/KernelRuntime.cpp']
    for index, source in enumerate(units):
        target = OUT / (str(index) + '.o')
        run(['xcrun', 'clang++', *flags, *(['-fvisibility=hidden'] if source.name == 'KernelRuntime.cpp' else []), '-c', source, '-o', target], 'compile-' + str(index))
        objects.append(target)
    bundle = OUT / (bundle_name + '.kext')
    executable = bundle / 'Contents/MacOS' / NAME
    executable.parent.mkdir(parents=True, exist_ok=True)
    run(['xcrun', 'ld', '-kext', '-arch', 'x86_64', '-macos_version_min', '15.2',
         '-o', executable, *objects, SDK / 'Library/x86_64/libkmod.a'], 'link')
    info = {
        'CFBundleIdentifier': IDENTIFIER, 'CFBundleName': NAME, 'CFBundleExecutable': NAME,
        'CFBundlePackageType': 'KEXT', 'CFBundleInfoDictionaryVersion': '6.0',
        'CFBundleVersion': version, 'CFBundleShortVersionString': version,
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
    kernel_identity = identity.artifact_identity(bundle, version)
    manifest = {'bundle': str(bundle), 'client': str(client), 'version': version,
                'kernel_identity': kernel_identity,
                'supported_acm_uuid': '38EBFC61-0BF9-3089-996B-3F6B2A32F20C',
                'supported_darwin': '24.6.0', 'source': str(SOURCE), 'installed': False,
                'credentials_added': False, 'kernel_hooks': False, 'global_availability_writes': False,
                'prepared_operations': ['status', 'empty-context-lifecycle', 'isolated-credential-study',
                                        'isolated-policy-study', 'restore-study-availability',
                                        'provider-begin', 'provider-real-match', 'provider-end',
                                        'user-coreauthd-platform-enable', 'user-coreauthd-platform-restore',
                                        'provider-catalog-begin', 'provider-catalog-replace', 'provider-authorize-enrollment',
                                        'settings-platform-enable', 'settings-platform-restore', 'startup-trial-arm',
                                        'startup-trial-cancel', 'exact-coreauth-retire', 'exact-startup-trial-retire'],
                'deployment_authorized': False, 'runtime_verified': False,
                'settings_connection_recovery_runtime_ready': False,
                'startup_exec_observer_runtime_enabled': False,
                'startup_private_hooks_implemented': False,
                'policy_study_changes_availability_temporarily': True,
                'external_context_handles_accepted': True,
                'provider_user': 501,
                'platform_process_scope': 'stopped UID501 coreauthd and separate Touch ID & Password extension slots; platform cache and process-specific retry state; process exit required for cleanup',
                'client_close_restoration_prepared': True,
                'user_space_provider_complete': False,
                'ready_for_installation': False}
    if args.enrollment_service:
        manifest['direct_enrollment_service'] = {'service_uuid': str(service_uuid), 'service_cdhash': cdhash[1],
            'uid': 501, 'install_path': install_path, 'runtime_verified': False, 'legacy_connection_privileges': 'root'}
    if args.automatic_settings:
        manifest['direct_enrollment_service']['legacy_connection_privileges'] = 'disabled'
        manifest.update(kernel_hooks=True, global_availability_writes=True, startup_private_hooks_implemented=True, prepared_operations=[
                        'publish-current-session-listener', 'bind-acm-biometry-availability-to-listener',
                        'check-apple-enrollment-password-context', 'route-native-settings-startup'],
                        policy_study_changes_availability_temporarily=False,
                        platform_process_scope='24H32 Touch ID & Password extension on its initial dyld main thread',
                        startup_routing='24H32 signed UID 501 Touch ID settings extension, same audit session as pinned live listener',
                        replaces_startup_writer=True, requires_manual_root_at_runtime=False)
    manifest['host_state_machine_tests'] = tests
    manifest['catalog_max_identities'] = 3
    manifest['enrollment_authorization_runtime_verified'] = False
    manifest['settings_image_uuid'] = '418ECD95-E742-3847-9621-84135A94B634'
    manifest['settings_platform_runtime_verified'] = False
    (OUT / 'build.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (OUT / identity.MANIFEST_NAME).write_text(json.dumps(kernel_identity, indent=2) + '\n')
    if args.automatic_settings:
        package = OUT / 'automatic-settings-062'
        package.mkdir(exist_ok=True)
        shutil.copytree(bundle, package / bundle.name, dirs_exist_ok=True)
        shutil.copy2(service, package / service.name)
        sensor_source = SOURCE.parent / 'usb-sensor'
        agent = sensor_source / 'io.github.hackintosh-tools.elan-usb.plist'
        plist = plistlib.loads(agent.read_bytes())
        plist['ProgramArguments'] = [install_path]
        (package / agent.name).write_bytes(plistlib.dumps(plist, sort_keys=False))
        shutil.copy2(sensor_source / 'install-automatic-settings.py', package)
        (package / 'candidate.json').write_text(json.dumps({
            'kernel_build': kernel_identity, 'pinned_enrollment_service': manifest['direct_enrollment_service'],
            'os_build': '24H32', 'settings_runtime_verified': False
        }, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
