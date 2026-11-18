#!/usr/bin/env python3
"""Identity-bound current-version disk update; never starts authentication or reboots.

prepare() only reads. apply() requires the digest of a separately reviewed plan.
The caller must obtain action-time approval before invoking apply or rollback.
A digest binds content; it does not obtain that approval. Only the fixed live()
factory queries the target OS. Constructor injection is for offline fixtures.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import shutil
import stat
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
INSTALL = Path('/Library/ELANFingerprintNativeTest')
KERNEL = 'payload/native-kernel-probe-06/ELANNativeProbe.kext'
VOLUME = 'B7358F29-CFB6-3C07-9821-E4C734C75236'
BUNDLE = 'ELANNativeProbe.kext'
PROGRAMS = ('ELANNativeBroker', 'ELANNativeProvider.app', 'ELANNativeAuthTest.app', 'NativeNamespaceProbe')
MAX_FILE = 128 * 1024 * 1024
RUNTIME_SCRIPTS = {'native-provider-deployment.py', 'native-session-lifecycle.py',
                   'native-settings-diagnostic.py', 'native-settings-result.py',
                   'native-kernel-identity.py', 'native-update-preflight.py', 'native-current-update.py', 'native-fat-update.py'}

class UpdateError(RuntimeError): pass

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

identity = load('current_update_identity', 'native-kernel-identity.py')
preflight = load('current_update_preflight', 'native-update-preflight.py')
fat = load('current_update_fat', 'native-fat-update.py')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def relative(value):
    if type(value) is not str or not value or str(PurePosixPath(value)) != value or PurePosixPath(value).is_absolute() or '..' in PurePosixPath(value).parts:
        raise UpdateError('invalid_relative_path')
    return value


def safe_path(path):
    path = Path(path).absolute()
    for component in reversed((path, *path.parents)):
        if component.is_symlink(): raise UpdateError('symlink_input')
    return path


def read(path):
    path = safe_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE: raise UpdateError('invalid_file')
        data = stream.read(MAX_FILE + 1); after = os.fstat(stream.fileno())
    if len(data) != before.st_size or (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise UpdateError('changed_file')
    return data


def tree(path):
    """Only explicitly managed program/payload trees are inspected, never state or keychains."""
    path = safe_path(path)
    if not path.exists(): return None
    result = {}
    for item in [path, *sorted(path.rglob('*'))] if path.is_dir() else [path]:
        safe_path(item); info = item.lstat()
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)): raise UpdateError('invalid_file_type')
        name = '.' if item == path else str(item.relative_to(path))
        result[name] = {'mode': stat.S_IMODE(info.st_mode), 'kind': 'dir' if item.is_dir() else 'file'}
        if item.is_file(): result[name]['sha256'] = hashlib.sha256(read(item)).hexdigest()
    return result


def copy(source, destination):
    if source.is_dir(): shutil.copytree(source, destination, copy_function=shutil.copy2)
    else: shutil.copy2(source, destination)
    if tree(source) != tree(destination): raise UpdateError('copy_readback_mismatch')


def atomic_file(path, data, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix='.elan-current-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fchmod(stream.fileno(), mode); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def swap(left, right, flags=2):
    library = ctypes.CDLL(None, use_errno=True)
    call = library.renameatx_np
    call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    call.restype = ctypes.c_int
    if call(-2, os.fsencode(left), -2, os.fsencode(right), flags):
        error = ctypes.get_errno(); raise OSError(error, os.strerror(error))


def command(args):
    result = subprocess.run([str(x) for x in args], capture_output=True, timeout=15)
    return result.returncode, result.stdout


def live_runtime(mode='strict'):
    if mode not in ('strict', 'disk_only_mandatory_reboot'): raise UpdateError('invalid_maintenance_mode')
    for name in ('elan-native-provider-501.sock', 'elan-native-provider-501.state', 'elan-native-settings-501.state'):
        if os.path.lexists('/private/var/run/' + name): raise UpdateError('session_artifact_present')
    if os.path.lexists('/Library/LaunchDaemons/io.github.hackintosh-tools.elan-native-session.plist'):
        raise UpdateError('background_autostart_present')
    status, _ = command(['/bin/launchctl', 'print', 'system/io.github.hackintosh-tools.elan-native-session'])
    if status != 113: raise UpdateError('background_job_not_proven_absent')
    status, output = command(['/bin/ps', '-axo', 'comm='])
    if status: raise UpdateError('process_query_failed')
    if any(Path(line.strip()).name in ('ELANNativeBroker', 'ELANNativeProvider', 'ELANNativeAuthTest', 'NativeNamespaceProbe') for line in output.decode().splitlines()):
        raise UpdateError('native_program_running')
    status, output = command(['/usr/sbin/ioreg', '-a', '-r', '-c', 'ELANNativeProbe'])
    if status: raise UpdateError('driver_query_failed')
    rows = plistlib.loads(output)
    if type(rows) is not list or len(rows) != 1 or any(rows[0].get(key) is not False for key in ('AuthenticationEnabled', 'ProviderSessionActive')):
        raise UpdateError('driver_not_idle')
    pending = rows[0].get('ProviderRestorePending')
    if mode == 'strict' and pending is not False: raise UpdateError('driver_not_idle')
    if pending is not None and type(pending) is not bool: raise UpdateError('invalid_restore_pending_property')
    return {'programs_absent': True, 'autostart_absent': True, 'driver_session_inactive': True,
            'restore_pending': 'unknown' if pending is None else ('pending' if pending else 'clear'),
            'maintenance_mode': mode, 'running_apple_process_state_repaired': False,
            'mandatory_reboot_before_component_use': mode == 'disk_only_mandatory_reboot'}


class Backend:
    def __init__(self, install, oc, observe, idle, signatures, swap_fn=swap, fault=None, runtime=None):
        self.install, self.oc = safe_path(install), safe_path(oc)
        self.observe, self.idle, self.signatures = observe, idle, signatures
        self.swap, self.fault = swap_fn, fault
        self.runtime = runtime if runtime is not None else observe
        self.location_check = lambda: None
        self.allow_same_device_fat = False
        self.maintenance_mode = 'strict'
        self.storage_status = lambda: {'filesystem': 'injected_fixture', 'exchange_supported': True}

    @classmethod
    def live(cls, maintenance_mode='strict'):
        if maintenance_mode not in ('strict', 'disk_only_mandatory_reboot'): raise UpdateError('invalid_maintenance_mode')
        status, output = command(['/usr/sbin/diskutil', 'info', '-plist', VOLUME])
        info = plistlib.loads(output) if status == 0 else {}
        if info.get('VolumeUUID') != VOLUME or info.get('Internal') is not False or not info.get('MountPoint'):
            raise UpdateError('external_efi_not_verified')
        oc = safe_path(Path(info['MountPoint']) / 'EFI/OC')
        def location_check():
            status, output = command(['/usr/sbin/diskutil', 'info', '-plist', VOLUME])
            current = plistlib.loads(output) if status == 0 else {}
            if (current.get('VolumeUUID') != VOLUME or current.get('Internal') is not False or
                    not current.get('MountPoint') or safe_path(Path(current['MountPoint']) / 'EFI/OC') != oc):
                raise UpdateError('external_efi_changed')
            status, output = command(['/usr/sbin/sysctl', '-n', 'kern.osversion'])
            if status or output.strip() != b'24H32': raise UpdateError('unsupported_os_build')
        location_check()
        def observe():
            result = preflight.inspect(INSTALL)
            if result['state'] != 'observed': raise UpdateError(result['reason'])
            return result
        def signatures(root):
            for name in PROGRAMS:
                status, _ = command(['/usr/bin/codesign', '--verify', '--strict', root / name])
                if status: raise UpdateError('signature_invalid')
        def runtime():
            status, output = command(['/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid'])
            if status: raise UpdateError('boot_query_failed')
            boot = output.decode().strip().upper()
            status, output = command(['/usr/bin/kmutil', 'showloaded', '--list-only'])
            if status: raise UpdateError('loaded_query_failed')
            return {'boot_uuid': boot, 'loaded_kernel': identity.loaded_identity(output.decode(), '0.4.0')}
        backend = cls(INSTALL, oc, observe, lambda: live_runtime(maintenance_mode), signatures, runtime=runtime)
        backend.maintenance_mode = maintenance_mode
        backend.location_check = location_check
        def storage_status():
            location_check()
            status, output = command(['/usr/sbin/diskutil', 'info', '-plist', VOLUME])
            current = plistlib.loads(output) if status == 0 else {}
            filesystem = str(current.get('FilesystemType', '')).lower()
            return {'filesystem': filesystem, 'exchange_supported': filesystem in ('apfs', 'hfs')}
        backend.storage_status = storage_status
        return backend

    def _active_bundle(self):
        _, _, name = fat.entry(read(self.oc / 'config.plist'))
        return self.oc / 'Kexts' / name

    def _efi(self):
        config = read(self.oc / 'config.plist')
        fat.entry(config)
        return hashlib.sha256(config).hexdigest()

    def prepare(self, package):
        self.location_check()
        package = safe_path(package)
        manifest = json.loads(read(package / 'package.json'))
        if manifest.get('schema_version') != 1 or manifest.get('version') != '0.4.0': raise UpdateError('unsupported_package')
        mapping = manifest['install_map']; hashes = manifest['sha256']
        if type(mapping) is not dict or not mapping or len(set(mapping.values())) != len(mapping): raise UpdateError('invalid_install_map')
        for origin, destination in mapping.items():
            relative(origin); relative(destination)
            if origin.startswith('userland/'):
                wanted = origin[len('userland/'):]
            elif origin.startswith('scripts/') and '/' not in origin[len('scripts/'):] and origin.endswith('.py'):
                wanted = origin[len('scripts/'):]
            elif origin.startswith('kernel/'):
                wanted = 'payload/native-kernel-probe-06/' + origin[len('kernel/'):]
            else:
                raise UpdateError('invalid_package_role')
            if destination != wanted: raise UpdateError('invalid_install_destination')
            top = destination.split('/')[0]
            if top in ('state', 'previous', 'logs', 'receipts') or top.startswith('.'):
                raise UpdateError('unmanaged_destination')
            if hashlib.sha256(read(package / origin)).hexdigest() != hashes.get(origin): raise UpdateError('package_hash_mismatch')
        required = {str(x) for x in preflight.PROGRAMS.values()} | RUNTIME_SCRIPTS | {KERNEL + '/Contents/Info.plist', KERNEL + '/Contents/MacOS/ELANNativeProbe', 'payload/native-kernel-probe-06/kernel-identity.json', 'payload/native-kernel-probe-06/elan-native-probe', 'payload/native-kernel-probe-06/manage-efi.py'}
        if not required <= set(mapping.values()): raise UpdateError('incomplete_package')
        candidate = identity.artifact_identity(package / 'kernel' / BUNDLE, '0.4.0')
        if candidate != manifest['kernel_identity']: raise UpdateError('candidate_identity_mismatch')
        if identity.load_manifest(package / 'kernel/kernel-identity.json', '0.4.0') != candidate:
            raise UpdateError('candidate_identity_manifest_mismatch')
        identity.executable_identity(package / 'kernel/elan-native-probe')
        self.signatures(package / 'userland')
        observed = self.observe(); inactive = self.idle()
        if observed.get('state') != 'observed': raise UpdateError('baseline_unavailable')
        source = observed['artifacts']['kernel']
        efi_identity = identity.artifact_identity(self._active_bundle(), '0.4.0')
        if source != efi_identity or observed['loaded_kernel']['macho_uuid'] != source['macho_uuid']:
            raise UpdateError('source_identity_mismatch')
        tops = sorted({name.split('/')[0] for name in mapping.values()})
        source_files = {name: tree(self.install / name) for name in tops}
        for record in source_files.values():
            if record is not None and any(value['mode'] & 0o022 for value in record.values()): raise UpdateError('writable_source_asset')
        efi_files = tree(self._active_bundle())
        record = {'schema_version': 1, 'version': '0.4.0', 'boot_uuid': observed['boot_uuid'], 'source_identity': source,
                  'target_identity': candidate, 'source_files': source_files, 'efi_files': efi_files,
                  'config_sha256': self._efi(), 'install_map': mapping,
                  'package_sha256': {name: hashes[name] for name in mapping}, 'runtime': inactive,
                  'storage': self.storage_status(), 'maintenance_mode': self.maintenance_mode,
                  'reboot_required': True, 'starts_authentication': False,
                  'exclusive_maintenance_required': True, 'no_reboot_until_complete': True, 'power_loss_safe': False,
                  'must_reboot_before_component_use': True, 'running_apple_process_state_repaired': False}
        if self.observe() != observed or self.idle() != inactive or self._efi() != record['config_sha256']:
            raise UpdateError('baseline_changed')
        record['approval_digest'] = digest(record)
        return record

    def _runtime_check(self, plan):
        self.location_check()
        runtime = self.runtime()
        if runtime.get('boot_uuid') != plan['boot_uuid'] or runtime['loaded_kernel']['macho_uuid'] != plan['source_identity']['macho_uuid']:
            raise UpdateError('runtime_identity_changed')
        if self.idle() != plan['runtime']: raise UpdateError('runtime_activity_changed')

    def _state(self, names):
        return {name: tree(self.install / name) for name in names}, tree(self._active_bundle()), self._efi()

    def _save(self, transaction, record):
        atomic_file(transaction / 'transaction.json', (json.dumps(record, sort_keys=True, indent=2) + '\n').encode())

    def _verify_exchange_support(self):
        # FAT has been observed returning success for RENAME_SWAP while doing a
        # destructive ordinary rename. Never probe with an installed asset.
        self.location_check()
        if self.storage_status().get('exchange_supported') is not True:
            raise UpdateError('efi_atomic_exchange_unsupported; no installation changed')
        directory = Path(tempfile.mkdtemp(prefix='.elan-exchange-check-', dir=self.oc))
        left, right = directory / 'a', directory / 'b'
        try:
            left.write_bytes(b'ELAN exchange fixture A'); right.write_bytes(b'ELAN exchange fixture B')
            self.swap(left, right)
            if not left.is_file() or not right.is_file() or read(left) != b'ELAN exchange fixture B' or read(right) != b'ELAN exchange fixture A':
                raise UpdateError('efi_exchange_semantics_invalid; no installation changed')
        finally:
            for path in (left, right):
                if path.exists(): path.unlink()
            directory.rmdir()

    def _exchange_efi(self, name, data, mode, expected, transaction, record):
        # No os.replace fallback: retain the bytes displaced at the exchange itself.
        fd, staged = tempfile.mkstemp(prefix='.elan-current-' + transaction.name + '-', dir=self.oc)
        os.close(fd); staged = Path(staged)
        atomic_file(staged, data, mode)
        record.setdefault('retained_efi_files', []).append(str(staged))
        self._save(transaction, record)
        self.swap(self._active_bundle() / name, staged)
        if tree(staged) != {'.': expected}:
            record['conflict'] = True
            self._save(transaction, record)
            raise UpdateError('foreign_efi_displaced_and_retained')

    def _point(self, name):
        if self.fault: self.fault(name)

    def apply(self, package, approved_digest, exclusive_maintenance=False):
        """Caller must obtain explicit approval of this exact plan before invocation."""
        if not approved_digest: raise UpdateError('approval_required')
        lockdir = self.install / 'state'
        if not lockdir.is_dir(): raise UpdateError('runtime_lock_directory_missing')
        safe_path(lockdir)
        fd = os.open(lockdir / 'runtime.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            plan = self.prepare(package)
            if plan['approval_digest'] != approved_digest: raise UpdateError('approval_plan_changed')
            if plan['storage'].get('filesystem') == 'msdos':
                if not exclusive_maintenance: raise UpdateError('exclusive_maintenance_confirmation_required')
                return self._apply_fat(package, plan)
            self._verify_exchange_support()
            transaction = Path(tempfile.mkdtemp(prefix='.elan-current-update-', dir=self.install.parent))
            os.chmod(transaction, 0o700)
            (transaction / 'before').mkdir(); (transaction / 'after').mkdir()
            for name, state in plan['source_files'].items():
                if state is not None:
                    copy(self.install / name, transaction / 'before' / name)
                    copy(self.install / name, transaction / 'after' / name)
            for origin, destination in plan['install_map'].items():
                target = transaction / 'after' / destination
                target.parent.mkdir(parents=True, exist_ok=True)
                data = read(Path(package) / origin)
                if hashlib.sha256(data).hexdigest() != plan['package_sha256'][origin]: raise UpdateError('package_changed')
                mode = stat.S_IMODE((Path(package) / origin).stat().st_mode) & ~0o022
                atomic_file(target, data, mode)
            self.signatures(transaction / 'after')
            staged_payload = transaction / 'after/payload/native-kernel-probe-06'
            identity.verify_artifact(staged_payload / BUNDLE,
                                     identity.load_manifest(staged_payload / 'kernel-identity.json', '0.4.0'), '0.4.0')
            copy(self._active_bundle(), transaction / 'efi-before')
            copy(self._active_bundle(), transaction / 'efi-after')
            for origin, destination in plan['install_map'].items():
                if destination.startswith(KERNEL + '/'):
                    target = transaction / 'efi-after' / destination[len(KERNEL) + 1:]
                    if not target.is_file(): raise UpdateError('efi_layout_change')
                    data = read(Path(package) / origin)
                    if hashlib.sha256(data).hexdigest() != plan['package_sha256'][origin]: raise UpdateError('package_changed')
                    atomic_file(target, data, stat.S_IMODE(target.stat().st_mode))
            if identity.artifact_identity(transaction / 'efi-after', '0.4.0') != plan['target_identity']:
                raise UpdateError('staged_efi_identity_mismatch')
            after = {name: tree(transaction / 'after' / name) for name in plan['source_files']}
            efi_after = tree(transaction / 'efi-after')
            record = {'plan': plan, 'after': after, 'efi_after': efi_after, 'phase': 'prepared'}
            self._save(transaction, record)
            if self._state(after) != (plan['source_files'], plan['efi_files'], plan['config_sha256']): raise UpdateError('source_changed_before_apply')
            if self.prepare(package)['approval_digest'] != approved_digest: raise UpdateError('runtime_changed_before_apply')
            expected = dict(plan['source_files']); expected_efi = plan['efi_files']
            try:
                for name in after:
                    self._runtime_check(plan)
                    if self._state(after) != (expected, expected_efi, plan['config_sha256']): raise UpdateError('concurrent_change')
                    destination = self.install / name
                    if expected[name] is None:
                        swap(transaction / 'after' / name, destination, flags=4)
                    else:
                        self.swap(destination, transaction / 'after' / name)
                        if tree(transaction / 'after' / name) != expected[name]:
                            record['conflict'] = True
                            raise UpdateError('foreign_install_displaced_and_retained')
                    expected[name] = after[name]
                    if tree(destination) != after[name]: raise UpdateError('install_readback_mismatch')
                    self._point('installed:' + name)
                record['phase'] = 'userland'; self._save(transaction, record)
                for name, info in efi_after.items():
                    if info['kind'] != 'file' or expected_efi.get(name) == info: continue
                    self._runtime_check(plan)
                    if self._state(after) != (expected, expected_efi, plan['config_sha256']): raise UpdateError('concurrent_change')
                    self._exchange_efi(name, read(transaction / 'efi-after' / name), info['mode'], expected_efi[name], transaction, record)
                    expected_efi = dict(expected_efi); expected_efi[name] = info
                    self._point('efi:' + name)
                self._runtime_check(plan)
                if self._state(after) != (after, efi_after, plan['config_sha256']): raise UpdateError('commit_readback_mismatch')
                record['phase'] = 'committed'; self._save(transaction, record)
                return {'state': 'committed', 'transaction': str(transaction), 'reboot_required': True, 'authentication_started': False, 'rollback_scope': 'original_boot_only', 'maintenance_mode': plan['maintenance_mode'],
                        'must_reboot_before_component_use': True, 'running_apple_process_state_repaired': False}
            except BaseException:
                record['phase'] = 'interrupted'; self._save(transaction, record)
                # Keep both generations. Explicit rollback verifies every file before restoration.
                raise UpdateError('update_interrupted; retained transaction: ' + str(transaction)) from None
        finally:
            os.close(fd)

    def rollback(self, transaction, approved_digest):
        """Restore a retained pre-reboot transaction after separately approved review."""
        transaction = safe_path(transaction)
        if transaction.parent != self.install.parent or not transaction.name.startswith('.elan-current-update-'):
            raise UpdateError('invalid_transaction_location')
        record = json.loads(read(transaction / 'transaction.json')); plan = record['plan']
        if record.get('kind') == 'fat_retained_bundle':
            return self._recover_fat(transaction, approved_digest, rollback=True)
        if not approved_digest or plan['approval_digest'] != approved_digest: raise UpdateError('approval_required')
        if record.get('conflict'): raise UpdateError('retained_foreign_change_requires_review')
        value = dict(plan); value.pop('approval_digest')
        if digest(value) != approved_digest: raise UpdateError('transaction_plan_changed')
        fd = os.open(self.install / 'state/runtime.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.location_check()
            observed = self.runtime(); self.idle()
            if observed.get('boot_uuid') != plan['boot_uuid'] or observed['loaded_kernel']['macho_uuid'] != plan['source_identity']['macho_uuid']:
                raise UpdateError('rollback_requires_original_boot')
            self._verify_exchange_support()
            names = plan['source_files']; current, current_efi, config = self._state(names)
            if config != plan['config_sha256']: raise UpdateError('foreign_config_preserved')
            for name, before in names.items():
                if current[name] not in (before, record['after'][name]): raise UpdateError('foreign_install_preserved')
                if tree(transaction / 'before' / name) != before: raise UpdateError('backup_changed')
            if tree(transaction / 'efi-before') != plan['efi_files']: raise UpdateError('backup_changed')
            if set(current_efi) != set(plan['efi_files']) or any(current_efi[n] not in (plan['efi_files'][n], record['efi_after'].get(n)) for n in current_efi):
                raise UpdateError('foreign_efi_preserved')
            for name, info in plan['efi_files'].items():
                if info['kind'] != 'file' or current_efi[name] == info: continue
                self._runtime_check(plan)
                if self._state(names) != (current, current_efi, config): raise UpdateError('rollback_concurrent_change')
                self._exchange_efi(name, read(transaction / 'efi-before' / name), info['mode'], current_efi[name], transaction, record)
                current_efi = dict(current_efi); current_efi[name] = info
            for name, before in names.items():
                if current[name] == before: continue
                self._runtime_check(plan)
                if self._state(names) != (current, current_efi, config): raise UpdateError('rollback_concurrent_change')
                if before is None:
                    retained = transaction / ('removed-' + name)
                    swap(self.install / name, retained, flags=4)
                    if tree(retained) != current[name]:
                        record['conflict'] = True; self._save(transaction, record)
                        raise UpdateError('foreign_install_displaced_and_retained')
                else:
                    staging = Path(tempfile.mkdtemp(prefix='restore-', dir=transaction))
                    restored = staging / name
                    copy(transaction / 'before' / name, restored)
                    self.swap(self.install / name, restored)
                    if tree(restored) != current[name]:
                        record['conflict'] = True; self._save(transaction, record)
                        raise UpdateError('foreign_install_displaced_and_retained')
                current[name] = before
            self._runtime_check(plan)
            if self._state(names) != (names, plan['efi_files'], config): raise UpdateError('rollback_readback_mismatch')
            record['phase'] = 'rolled_back'; self._save(transaction, record)
            return {'state': 'rolled_back', 'reboot_required': plan.get('maintenance_mode') == 'disk_only_mandatory_reboot',
                    'maintenance_mode': plan.get('maintenance_mode', 'strict'), 'running_apple_process_state_repaired': False}
        finally:
            os.close(fd)

    def _fat_transaction(self, transaction, plan):
        return fat.Transaction(self.oc, transaction / 'fat', lambda: self._runtime_check(plan),
                               fault=lambda name: self._point('fat:' + name),
                               allow_same_device=self.allow_same_device_fat)

    def _apply_fat(self, package, plan):
        transaction = Path(tempfile.mkdtemp(prefix='.elan-current-update-', dir=self.install.parent))
        os.chmod(transaction, 0o700)
        (transaction / 'before').mkdir(); (transaction / 'after').mkdir()
        for name, state in plan['source_files'].items():
            if state is not None:
                copy(self.install / name, transaction / 'before' / name)
                copy(self.install / name, transaction / 'after' / name)
        for origin, destination in plan['install_map'].items():
            target = transaction / 'after' / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            data = read(Path(package) / origin)
            if hashlib.sha256(data).hexdigest() != plan['package_sha256'][origin]: raise UpdateError('package_changed')
            atomic_file(target, data, stat.S_IMODE((Path(package) / origin).stat().st_mode) & ~0o022)
        self.signatures(transaction / 'after')
        payload = transaction / 'after/payload/native-kernel-probe-06'
        identity.verify_artifact(payload / BUNDLE, identity.load_manifest(payload / 'kernel-identity.json', '0.4.0'), '0.4.0')
        after = {name: tree(transaction / 'after' / name) for name in plan['source_files']}
        record = {'kind': 'fat_retained_bundle', 'plan': plan, 'after': after, 'phase': 'prepared'}
        self._save(transaction, record)
        if self._state(after) != (plan['source_files'], plan['efi_files'], plan['config_sha256']): raise UpdateError('source_changed_before_apply')
        engine = self._fat_transaction(transaction, plan)
        try:
            journal = engine.prepare(payload / BUNDLE, plan['approval_digest'])
        except BaseException:
            record['phase'] = 'preparation_interrupted'; self._save(transaction, record)
            raise UpdateError('local_preparation_interrupted; no installation changed; retained transaction: ' + str(transaction)) from None
        if journal['before_config_sha256'] != plan['config_sha256'] or self._state(after) != (plan['source_files'], plan['efi_files'], plan['config_sha256']):
            raise UpdateError('approved_source_changed_during_preparation')
        return self._finish_fat(transaction, record)

    def _finish_fat(self, transaction, record):
        plan = record['plan']; after = record['after']; before = plan['source_files']
        engine = self._fat_transaction(transaction, plan)
        try:
            journal = engine.load(plan['approval_digest'])
            expected_efi = {name: value['sha256'] for name, value in plan['efi_files'].items() if value['kind'] == 'file'}
            if journal['before_config_sha256'] != plan['config_sha256'] or journal['source_files'] != expected_efi:
                raise UpdateError('leaf_transaction_not_bound_to_approval')
            if identity.artifact_identity(transaction / 'fat/candidate', '0.4.0') != plan['target_identity']:
                raise UpdateError('leaf_candidate_not_bound_to_approval')
            engine.classify(journal)
            current = {name: tree(self.install / name) for name in after}
            if any(current[name] not in (before[name], after[name]) for name in after): raise UpdateError('foreign_install_preserved')
            for name in after:
                if current[name] == after[name]:
                    if before[name] != after[name] and tree(transaction / 'after' / name) != before[name]:
                        record['conflict'] = True
                        raise UpdateError('unverified_displaced_generation')
                    continue
                self._runtime_check(plan)
                if {n: tree(self.install / n) for n in after} != current: raise UpdateError('concurrent_change')
                if tree(transaction / 'after' / name) != after[name]: raise UpdateError('staged_userland_changed')
                if before[name] is None:
                    swap(transaction / 'after' / name, self.install / name, flags=4)
                else:
                    self.swap(self.install / name, transaction / 'after' / name)
                    if tree(transaction / 'after' / name) != before[name]:
                        record['conflict'] = True
                        raise UpdateError('foreign_install_displaced_and_retained')
                current[name] = after[name]
                if tree(self.install / name) != after[name]: raise UpdateError('install_readback_mismatch')
                self._point('installed:' + name)
            record['phase'] = 'userland'; self._save(transaction, record)
            result = engine.resume(plan['approval_digest'])
            if {name: tree(self.install / name) for name in after} != after: raise UpdateError('foreign_install_preserved')
            if identity.artifact_identity(self._active_bundle(), '0.4.0') != plan['target_identity']: raise UpdateError('efi_identity_mismatch')
            record['phase'] = 'committed'; self._save(transaction, record)
            return dict(result, transaction=str(transaction), authentication_started=False, rollback_scope='original_boot_only',
                        maintenance_mode=plan['maintenance_mode'], must_reboot_before_component_use=True, running_apple_process_state_repaired=False)
        except BaseException:
            record['phase'] = 'interrupted'; self._save(transaction, record)
            raise UpdateError('update_interrupted; retained transaction: ' + str(transaction)) from None

    def _recover_fat(self, transaction, approved_digest, rollback=False, recovery=None):
        transaction = safe_path(transaction)
        if transaction.parent != self.install.parent or not transaction.name.startswith('.elan-current-update-'):
            raise UpdateError('invalid_transaction_location')
        record = json.loads(read(transaction / 'transaction.json')); plan = record['plan']
        value = dict(plan); value.pop('approval_digest')
        if not approved_digest or plan['approval_digest'] != approved_digest or digest(value) != approved_digest:
            raise UpdateError('approval_required')
        if record.get('kind') != 'fat_retained_bundle' or record.get('conflict'): raise UpdateError('transaction_requires_review')
        guard = (lambda: self._runtime_check(plan)) if recovery is None else (lambda: self._cross_runtime_check(recovery))
        fd = os.open(self.install / 'state/runtime.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            guard()
            if not (transaction / 'fat/journal.json').is_file():
                if record['phase'] not in ('preparation_interrupted', 'rolled_back') or self._state(plan['source_files']) != (plan['source_files'], plan['efi_files'], plan['config_sha256']):
                    raise UpdateError('incomplete_preparation_requires_review')
                if not rollback: raise UpdateError('local_preparation_incomplete; original unchanged; use rollback or a new approved apply')
                record['phase'] = 'rolled_back'; self._save(transaction, record)
                return {'state': 'rolled_back', 'changed': False, 'reboot_required': plan.get('maintenance_mode') == 'disk_only_mandatory_reboot'}
            if record.get('pending_action') == 'rollback': rollback = True
            if not rollback: return self._finish_fat(transaction, record)
            before, after = plan['source_files'], record['after']
            current = {name: tree(self.install / name) for name in before}
            for name in before:
                if current[name] not in (before[name], after[name]): raise UpdateError('foreign_install_preserved')
                if tree(transaction / 'before' / name) != before[name]: raise UpdateError('backup_changed')
            record['pending_action'] = 'rollback'; self._save(transaction, record)
            engine = self._fat_transaction(transaction, plan) if recovery is None else fat.Transaction(
                self.oc, transaction / 'fat', guard, fault=lambda name: self._point('fat:' + name),
                allow_same_device=self.allow_same_device_fat)
            result = engine.rollback(approved_digest)
            for name in before:
                if current[name] == before[name]:
                    retained_name = record.get('recovery_steps', {}).get(name)
                    if retained_name and tree(transaction / retained_name) != after[name]:
                        record['conflict'] = True; self._save(transaction, record)
                        raise UpdateError('unverified_displaced_recovery_generation')
                    continue
                guard()
                if {n: tree(self.install / n) for n in before} != current: raise UpdateError('concurrent_change')
                directory = Path(tempfile.mkdtemp(prefix='restore-', dir=transaction))
                retained = directory / name
                record.setdefault('recovery_steps', {})[name] = str(retained.relative_to(transaction))
                self._save(transaction, record)
                if before[name] is None:
                    swap(self.install / name, retained, flags=4)
                else:
                    copy(transaction / 'before' / name, retained)
                    self.swap(self.install / name, retained)
                if tree(retained) != current[name]:
                    record['conflict'] = True; self._save(transaction, record)
                    raise UpdateError('foreign_install_displaced_and_retained')
                current[name] = before[name]
            if {n: tree(self.install / n) for n in before} != before: raise UpdateError('rollback_readback_mismatch')
            guard()
            record['phase'] = 'rolled_back'; self._save(transaction, record)
            if plan.get('maintenance_mode') == 'disk_only_mandatory_reboot':
                result.update(reboot_required=True, must_reboot_before_component_use=True, running_apple_process_state_repaired=False)
            if recovery is not None:
                result.update(reboot_required=True, loaded_generation='target_until_reboot', recovery_approval_digest=recovery['approval_digest'])
            return result
        finally:
            os.close(fd)

    def resume(self, transaction, approved_digest):
        return self._recover_fat(Path(transaction), approved_digest)

    def _read_outer(self, transaction):
        transaction = safe_path(transaction)
        if transaction.parent != self.install.parent or not transaction.name.startswith('.elan-current-update-'):
            raise UpdateError('invalid_transaction_location')
        record = json.loads(read(transaction / 'transaction.json'))
        plan = record['plan']; value = dict(plan); value.pop('approval_digest')
        if record.get('kind') != 'fat_retained_bundle' or record.get('conflict') or digest(value) != plan['approval_digest']:
            raise UpdateError('transaction_requires_review')
        return transaction, record

    def _cross_runtime_check(self, recovery):
        self.location_check()
        current = self.runtime()
        if current.get('boot_uuid') != recovery['boot_uuid'] or current.get('loaded_kernel') != recovery['loaded_kernel']:
            raise UpdateError('recovery_boot_or_loaded_identity_changed')
        if self.idle() != recovery['runtime']: raise UpdateError('recovery_runtime_activity_changed')

    def prepare_rollback(self, transaction):
        """Read-only review for a NEW approval after reboot into the candidate."""
        transaction, record = self._read_outer(transaction); plan = record['plan']
        self.location_check(); runtime = self.runtime(); inactive = self.idle()
        if runtime.get('boot_uuid') == plan['boot_uuid'] or not preflight._valid_uuid(runtime.get('boot_uuid')):
            raise UpdateError('cross_boot_recovery_requires_new_boot')
        loaded = runtime.get('loaded_kernel', {})
        if (loaded.get('macho_uuid') != plan['target_identity']['macho_uuid'] or
                loaded.get('version') != plan['target_identity']['version'] or
                loaded.get('bundle_identifier') != plan['target_identity']['bundle_identifier']):
            raise UpdateError('recovery_requires_loaded_target')
        observed = self.observe()
        if (observed.get('state') != 'observed' or observed.get('boot_uuid') != runtime['boot_uuid'] or
                observed.get('loaded_kernel') != loaded or observed['artifacts']['kernel'] != plan['target_identity']):
            raise UpdateError('recovery_target_baseline_unavailable')
        for name, after in record['after'].items():
            if tree(self.install / name) != after: raise UpdateError('recovery_requires_complete_target_userland')
            if tree(transaction / 'before' / name) != plan['source_files'][name]: raise UpdateError('backup_changed')
        self.signatures(transaction / 'before')
        engine = fat.Transaction(self.oc, transaction / 'fat', lambda: None,
                                 allow_same_device=self.allow_same_device_fat)
        journal = engine.load(plan['approval_digest'])
        expected_source = {n: v['sha256'] for n, v in plan['efi_files'].items() if v['kind'] == 'file'}
        if journal['source_files'] != expected_source or journal['before_config_sha256'] != plan['config_sha256']:
            raise UpdateError('leaf_transaction_not_bound_to_approval')
        if engine.classify(journal) != 'after' or not fat.payload_matches(fat.snapshot(self._active_bundle()), journal['target_files']):
            raise UpdateError('recovery_requires_complete_target_efi')
        if identity.artifact_identity(self._active_bundle(), '0.4.0') != plan['target_identity']:
            raise UpdateError('recovery_target_identity_mismatch')
        recovery = {'schema_version': 1, 'action': 'cross_boot_rollback', 'transaction': str(transaction),
                    'original_plan_digest': plan['approval_digest'], 'backup_manifest_digest': digest(plan['source_files']),
                    'boot_uuid': runtime['boot_uuid'],
                    'loaded_kernel': loaded, 'runtime': inactive, 'target_config_sha256': journal['after_config_sha256'],
                    'source_identity': plan['source_identity'], 'target_identity': plan['target_identity'],
                    'reboot_required_after_rollback': True, 'exclusive_maintenance_required': True, 'maintenance_mode': self.maintenance_mode,
                    'power_loss_safe': False}
        recovery['approval_digest'] = digest(recovery)
        self._cross_runtime_check(recovery)
        if self.observe() != observed: raise UpdateError('recovery_baseline_changed')
        return recovery

    def rollback_after_reboot(self, transaction, approved_digest, exclusive_maintenance=False):
        if not exclusive_maintenance: raise UpdateError('exclusive_maintenance_confirmation_required')
        fd = os.open(self.install / 'state/runtime.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            recovery = self.prepare_rollback(transaction)
            if not approved_digest or recovery['approval_digest'] != approved_digest:
                raise UpdateError('new_boot_recovery_approval_required')
            transaction, record = self._read_outer(transaction)
            record['cross_recovery'] = recovery
            self._save(transaction, record)
        finally:
            os.close(fd)
        return self.resume_rollback(transaction, approved_digest)

    def resume_rollback(self, transaction, approved_digest):
        transaction, record = self._read_outer(transaction)
        recovery = record.get('cross_recovery')
        if not isinstance(recovery, dict): raise UpdateError('cross_boot_recovery_not_approved')
        value = dict(recovery); token = value.pop('approval_digest', None)
        if (not approved_digest or approved_digest != token or digest(value) != token or
                recovery['original_plan_digest'] != record['plan']['approval_digest'] or
                recovery['transaction'] != str(transaction)):
            raise UpdateError('new_boot_recovery_approval_required')
        self._cross_runtime_check(recovery)
        return self._recover_fat(transaction, record['plan']['approval_digest'], rollback=True, recovery=recovery)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'apply', 'resume', 'rollback', 'prepare-rollback', 'rollback-after-reboot', 'resume-rollback'])
    parser.add_argument('--package', type=Path)
    parser.add_argument('--transaction', type=Path)
    parser.add_argument('--approval-digest')
    parser.add_argument('--exclusive-maintenance', action='store_true')
    parser.add_argument('--disk-only-mandatory-reboot', action='store_true',
                        help='Only maintain disk files even if legacy restore state is unknown/pending; reboot before using components.')
    args = parser.parse_args(argv)
    backend = Backend.live('disk_only_mandatory_reboot' if args.disk_only_mandatory_reboot else 'strict')
    if args.action not in ('prepare', 'prepare-rollback') and os.geteuid() != 0: raise UpdateError('administrator_required')
    if args.action == 'prepare-rollback': result = backend.prepare_rollback(args.transaction)
    elif args.action == 'rollback-after-reboot': result = backend.rollback_after_reboot(args.transaction, args.approval_digest, args.exclusive_maintenance)
    elif args.action == 'resume-rollback': result = backend.resume_rollback(args.transaction, args.approval_digest)
    elif args.action == 'rollback': result = backend.rollback(args.transaction, args.approval_digest)
    elif args.action == 'resume': result = backend.resume(args.transaction, args.approval_digest)
    elif args.action == 'apply': result = backend.apply(args.package, args.approval_digest, args.exclusive_maintenance)
    else: result = backend.prepare(args.package)
    print(json.dumps(result, indent=2, sort_keys=True))

if __name__ == '__main__': main()
