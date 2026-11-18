#!/usr/bin/env python3
"""Stage a verified current-version candidate. No deployment or target access."""
import sys
sys.dont_write_bytecode = True
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess

SOURCE = Path(__file__).resolve().parent
VERSION = '0.4.0'
WORKER = ('ELANNativeProvider.app/Contents/MacOS/ELANNativeProvider',
          'ELANNativeAuthTest.app/Contents/MacOS/ELANNativeAuthTest', 'NativeMatchTransportTest')
PREFLIGHT = ('NativePlatformProcessProbe', 'NativeNamespaceProbe', 'ELANNativeBroker',
             'NativeProviderWireTest', 'NativeSettingsSessionTest', 'NativeUserSessionTest',
             'NativeUserSessionProbe', 'NativeLACMetadata', 'NativeLACLifecycle')
SCRIPTS = ('native-provider-deployment.py', 'native-session-lifecycle.py',
           'native-settings-diagnostic.py', 'native-settings-result.py',
           'native-kernel-identity.py', 'native-update-preflight.py', 'native-current-update.py', 'native-fat-update.py',
           'native-upgrade-plan.py', 'native-upgrade-files.py', 'native-settings-recovery-plan.py')
spec = importlib.util.spec_from_file_location('package_identity', SOURCE / 'native-kernel-identity.py')
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


class PackageError(ValueError):
    pass


def regular_tree(path):
    mode = path.lstat().st_mode
    if stat.S_ISREG(mode):
        return [path]
    if not stat.S_ISDIR(mode):
        raise PackageError('Only regular files and directories are allowed: ' + str(path))
    files = []
    for child in sorted(path.iterdir()):
        files.extend(regular_tree(child))
    return files


def copy(origin, destination):
    regular_tree(origin)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if origin.is_dir():
        shutil.copytree(origin, destination)
    else:
        shutil.copy2(origin, destination)


def verify_signature(path):
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(path)],
                   check=True, capture_output=True, timeout=30)


def read_manifest(path, expected):
    regular_tree(path)
    value = json.loads(path.read_text(), object_pairs_hook=identity._unique_pairs)
    if (value.get('state') != 'complete' or value.get('version') != VERSION or
            set(value.get('artifacts', {})) != set(expected) or
            value.get('installed') is not False or value.get('runtime_verified') is not False):
        raise PackageError('Incomplete or incompatible user-space build manifest')
    return value


def stage(user_build, kernel_build, out, source=SOURCE):
    user_build, kernel_build, out, source = map(Path, (user_build, kernel_build, out, source))
    # mkdir without exist_ok reserves a fresh output; an interrupted package stays incomplete.
    out.mkdir(parents=False)
    incomplete = {'schema_version': 1, 'state': 'incomplete', 'version': VERSION,
                  'installed': False, 'runtime_verified': False, 'deployment_authorized': False,
                  'baseline_verified': False, 'apply_ready': False}
    (out / 'package.json').write_text(json.dumps(incomplete, indent=2) + '\n')
    worker = read_manifest(user_build / 'worker-build.json', WORKER)
    preflight = read_manifest(user_build / 'preflight-build.json', PREFLIGHT)
    expected = dict(worker['artifacts'], **preflight['artifacts'])
    for name, item in expected.items():
        if identity.executable_identity(user_build / name) != item:
            raise PackageError('User-space identity mismatch: ' + name)
    for name in ('ELANNativeProvider.app', 'ELANNativeAuthTest.app', 'NativeMatchTransportTest', *PREFLIGHT):
        copy(user_build / name, out / 'userland' / name)
        verify_signature(out / 'userland' / name)
    for app, identifier in [('ELANNativeProvider', 'io.github.hackintosh-tools.elan-native-provider'),
                            ('ELANNativeAuthTest', 'io.github.hackintosh-tools.elan-native-auth-test')]:
        info = plistlib.loads((out / 'userland' / (app + '.app') / 'Contents/Info.plist').read_bytes())
        if any(info.get(k) != v for k, v in {'CFBundleVersion': VERSION, 'CFBundleExecutable': app,
                                            'CFBundleIdentifier': identifier}.items()):
            raise PackageError('App metadata mismatch')
    artifacts = {name: identity.executable_identity(out / 'userland' / name) for name in expected}
    if artifacts != expected:
        raise PackageError('Copied user-space identity mismatch')
    kernel_id = identity.load_manifest(kernel_build / 'kernel-identity.json', VERSION)
    identity.verify_artifact(kernel_build / 'ELANNativeProbe.kext', kernel_id, VERSION)
    for name in ('ELANNativeProbe.kext', 'kernel-identity.json', 'elan-native-probe'):
        copy(kernel_build / name, out / 'kernel' / name)
    identity.verify_artifact(out / 'kernel/ELANNativeProbe.kext', kernel_id, VERSION)
    client_id = identity.executable_identity(out / 'kernel/elan-native-probe')
    verify_signature(out / 'kernel/elan-native-probe')
    for name in SCRIPTS:
        ast.parse((source / name).read_bytes(), filename=name)
        copy(source / name, out / 'scripts' / name)
    copy(source / 'kernel-provider/manage-efi.py', out / 'kernel/manage-efi.py')
    ast.parse((out / 'kernel/manage-efi.py').read_bytes())
    for name in ('worker-build.json', 'preflight-build.json'):
        copy(user_build / name, out / 'manifests' / name)
    (out / 'OPERATIONS.txt').write_text("""Current-version update candidate. Not installed or approved for deployment.

Run update, resume, rollback-after-reboot, and resume-rollback from the retained
staging package's scripts/native-current-update.py, not the installed /Library
copy that is being replaced or rolled back. The old generation may not contain
these modules. Rollback can remove the newly installed update modules.

Keep this complete package, transaction records, and APFS backups until recovery
has been checked. Do not clean them up early. Each operation requires its stated
identity, baseline, runtime, receipt, and approval checks. After-reboot recovery
requires a separate recovery plan and approval.

Strict mode retains all runtime checks. Disk-only mode must be explicitly
selected; it does not relax strict mode and does not authorize deployment.
Disk-only changes disk artifacts only. When old-session memory state cannot be
verified, a reboot is mandatory before using the candidate. Do not start native
authentication or settings tests before that reboot and post-boot identity checks.

FAT updates require exclusive maintenance. Do not reboot before a complete
receipt is written. This protocol does not guarantee recovery from power loss.
Keep the original config and kext backups available for manual recovery.
No authentication service is started by packaging. Native settings still need
separately authorized target verification. The separate early observer is not
part of this package.
""")
    sha256, install_map = {}, {}
    for path in regular_tree(out):
        relative = path.relative_to(out).as_posix()
        if relative == 'package.json':
            continue
        sha256[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        if '/' not in relative:
            continue
        prefix, tail = relative.split('/', 1)
        if prefix in ('userland', 'scripts'):
            install_map[relative] = tail
        elif prefix == 'kernel':
            install_map[relative] = 'payload/native-kernel-probe-06/' + tail
    record = dict(incomplete, state='staged', sha256=sha256, install_map=install_map,
                  kernel_identity=kernel_id, artifacts=artifacts, kernel_client_identity=client_id,
                  signatures_verified=True, legacy_installer_supported_baseline='0.3.0',
                  current_update_backend_verified=False, rollback_scope='receipt_bound_separate_recovery_approval_after_reboot',
                  fat_update_mode='preserve_original_kext_then_switch_config',
                  exclusive_maintenance_required=True, power_loss_recovery_guaranteed=False,
                  pending=['installed baseline identity', 'session idle verification',
                           'boot EFI verification', 'authorized update and rollback verification'])
    (out / 'package.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user-build', type=Path, required=True)
    parser.add_argument('--kernel-build', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(stage(args.user_build, args.kernel_build, args.out), indent=2))


if __name__ == '__main__':
    main()
