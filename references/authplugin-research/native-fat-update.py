#!/usr/bin/env python3
"""Retained-bundle EFI update for an exclusively maintained, mounted FAT volume.

The original bundle is never moved or rewritten. Publication changes only its
owned OpenCore BundlePath. A local backup/journal supports process-interruption
resume and rollback. This is not a power-loss guarantee: do not reboot during a
transaction; filesystem damage can require manual restoration of config.plist.
"""
import sys
sys.dont_write_bytecode = True
import importlib.util
import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import tempfile

MAX_FILE = 128 * 1024 * 1024
NAME = re.compile(r'ELANNativeProbe(?:-update-[a-f0-9]{20})?\.kext\Z')

class FATUpdateError(RuntimeError): pass


def read(path):
    path = Path(path)
    for component in (path, *path.parents):
        if component.is_symlink(): raise FATUpdateError('symlink')
    with path.open('rb') as stream:
        a = os.fstat(stream.fileno())
        import stat
        if not stat.S_ISREG(a.st_mode) or a.st_size > MAX_FILE: raise FATUpdateError('invalid_file')
        data = stream.read(MAX_FILE + 1); b = os.fstat(stream.fileno())
    if len(data) != a.st_size or (a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) != (b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns): raise FATUpdateError('changed_file')
    return data


def sha(data): return hashlib.sha256(data).hexdigest()


def _appledouble(data):
    here = Path(__file__).resolve().parent
    paths = [here / 'kernel-provider/manage-efi.py', here / 'payload/native-kernel-probe-06/manage-efi.py', here.parent / 'kernel/manage-efi.py']
    path = next((p for p in paths if p.is_file() and not p.is_symlink()), None)
    if path is None: raise FATUpdateError('appledouble_validator_missing')
    spec = importlib.util.spec_from_file_location('fat_appledouble_validator', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.valid_appledouble(data)


def snapshot(root, allow_empty=False):
    root = Path(root)
    if root.is_symlink() or not root.is_dir(): raise FATUpdateError('invalid_bundle')
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink(): raise FATUpdateError('symlink')
        if path.is_dir(): continue
        data = read(path)
        if path.name.startswith('._'):
            sibling = path.with_name(path.name[2:])
            if not sibling.exists() or sibling.is_symlink() or not _appledouble(data): raise FATUpdateError('invalid_appledouble')
        result[str(path.relative_to(root))] = sha(data)
    if not result and not allow_empty: raise FATUpdateError('empty_bundle')
    return result


def syncdir(path):
    fd = os.open(path, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def create(path, data):
    with Path(path).open('xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    syncdir(Path(path).parent)


def replace(path, data, preserve_metadata=False):
    path = Path(path); fd, temporary = tempfile.mkstemp(prefix='.elan-publish-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        if preserve_metadata:
            copyfile = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True).copyfile
            copyfile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32]
            copyfile.restype = ctypes.c_int
            if copyfile(os.fsencode(path), os.fsencode(temporary), None, 4):
                error = ctypes.get_errno(); raise OSError(error, os.strerror(error))
            original_side = path.with_name('._' + path.name)
            staged_side = Path(temporary).with_name('._' + Path(temporary).name)
            before = read(original_side) if original_side.exists() else None
            staged = read(staged_side) if staged_side.exists() else None
            if before != staged: raise FATUpdateError('staged_config_metadata_mismatch')
            with open(temporary, 'rb') as stream: os.fsync(stream.fileno())
        os.replace(temporary, path); syncdir(path.parent)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def entry(config):
    parsed = plistlib.loads(config)
    found = [(index, value) for index, value in enumerate(parsed['Kernel']['Add'])
             if NAME.fullmatch(value.get('BundlePath', '')) or re.fullmatch(NAME.pattern, value.get('BundlePath', ''), re.IGNORECASE)]
    if len(found) != 1: raise FATUpdateError('ambiguous_owned_entry')
    index, value = found[0]
    if not NAME.fullmatch(value.get('BundlePath', '')): raise FATUpdateError('noncanonical_owned_entry')
    expected = {'Arch': 'x86_64', 'BundlePath': value['BundlePath'], 'Comment': 'ELAN native credential interface probe 0.4.0', 'Enabled': True,
                'ExecutablePath': 'Contents/MacOS/ELANNativeProbe', 'MaxKernel': '24.6.0', 'MinKernel': '24.6.0', 'PlistPath': 'Contents/Info.plist'}
    if value != expected: raise FATUpdateError('owned_entry_changed')
    return parsed, index, value['BundlePath']


def _write_stream(stream, data):
    stream.write(data)


def publish_new(path, data, scratch):
    # An interrupted write leaves a unique orphan outside the bundle. No partial
    # file is ever published under an expected candidate filename.
    fd, temporary = tempfile.mkstemp(prefix='.elan-fat-copy-', dir=scratch)
    with os.fdopen(fd, 'wb') as stream:
        _write_stream(stream, data); stream.flush(); os.fsync(stream.fileno())
    if read(temporary) != data: raise FATUpdateError('staged_file_changed')
    call = ctypes.CDLL(None, use_errno=True).renameatx_np
    call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    call.restype = ctypes.c_int
    # RENAME_EXCL was separately verified on a blank FAT32 volume. Unlike SWAP,
    # it fails with EEXIST and preserves both files when the destination exists.
    if call(-2, os.fsencode(temporary), -2, os.fsencode(path), 4):
        error = ctypes.get_errno(); raise OSError(error, os.strerror(error))
    syncdir(Path(path).parent); syncdir(scratch)


def payload_matches(actual, expected):
    # Native macOS copy/write may synthesize valid AppleDouble on FAT. Only
    # extra strictly validated companions are allowed, never extra payload files.
    return all(actual.get(n) == h for n, h in expected.items()) and all(
        n in expected or Path(n).name.startswith('._') for n in actual)


def _copy_checked(source, destination, expected, resume=False):
    destination = Path(destination)
    if not destination.exists(): destination.mkdir()
    elif not resume: raise FATUpdateError('destination_exists')
    present = snapshot(destination, allow_empty=True)
    if any((name not in expected and not Path(name).name.startswith('._')) or (name in expected and expected[name] != value) for name, value in present.items()):
        raise FATUpdateError('unknown_candidate_content')
    for name in sorted(expected, key=lambda n: (Path(n).name.startswith('._'), n)):
        wanted = expected[name]
        target = destination / name
        if target.is_symlink(): raise FATUpdateError('symlink')
        if name in present: continue
        if target.exists():
            if sha(read(target)) == wanted: continue
            raise FATUpdateError('new_companion_content_mismatch: ' + name)
        data = read(Path(source) / name)
        if sha(data) != wanted: raise FATUpdateError('source_changed')
        target.parent.mkdir(parents=True, exist_ok=True)
        publish_new(target, data, destination.parent)
    if not payload_matches(snapshot(destination), expected): raise FATUpdateError('copy_mismatch')
    syncdir(destination)


class Transaction:
    def __init__(self, oc, directory, guard, fault=None, allow_same_device=False):
        self.oc, self.directory = Path(oc), Path(directory)
        self.guard, self.fault = guard, fault
        # Backups must be independent of the EFI filesystem, not another path on it.
        if self.oc.stat().st_dev == self.directory.parent.stat().st_dev:
            if not allow_same_device:
                raise FATUpdateError('independent_backup_required')

    def point(self, name):
        if self.fault: self.fault(name)

    def save(self, record):
        replace(self.directory / 'journal.json', (json.dumps(record, sort_keys=True, indent=2) + '\n').encode())

    def prepare(self, candidate, token):
        if not re.fullmatch('[a-f0-9]{64}', token): raise FATUpdateError('invalid_approval_digest')
        self.guard()
        config = read(self.oc / 'config.plist'); parsed, index, source_name = entry(config)
        target_name = 'ELANNativeProbe-update-' + token[:20] + '.kext'
        if target_name == source_name or (self.oc / 'Kexts' / target_name).exists(): raise FATUpdateError('candidate_path_exists')
        original = snapshot(self.oc / 'Kexts' / source_name); candidate_files = snapshot(candidate)
        parsed['Kernel']['Add'][index]['BundlePath'] = target_name
        after = plistlib.dumps(parsed, sort_keys=False)
        companion = self.oc / '._config.plist'
        record = {'schema_version': 1, 'approval_digest': token, 'source_name': source_name, 'target_name': target_name,
                  'before_config_sha256': sha(config), 'after_config_sha256': sha(after),
                  'source_files': original, 'target_files': candidate_files,
                  'config_companion_sha256': sha(read(companion)) if companion.exists() else None,
                  'phase': 'prepared', 'power_loss_safe': False, 'exclusive_maintenance_required': True}
        self.directory.mkdir(mode=0o700)
        create(self.directory / 'config-before.plist', config); create(self.directory / 'config-after.plist', after)
        if companion.exists(): create(self.directory / 'config-before.appledouble', read(companion))
        _copy_checked(self.oc / 'Kexts' / source_name, self.directory / 'source', original)
        _copy_checked(candidate, self.directory / 'candidate', candidate_files)
        self.save(record); self.point('prepared')
        return record

    def load(self, approved_digest):
        record = json.loads(read(self.directory / 'journal.json'))
        if not approved_digest or record['approval_digest'] != approved_digest: raise FATUpdateError('approval_required')
        if not NAME.fullmatch(record['source_name']) or record['target_name'] != 'ELANNativeProbe-update-' + approved_digest[:20] + '.kext': raise FATUpdateError('invalid_journal')
        for label in ('before', 'after'):
            if sha(read(self.directory / ('config-' + label + '.plist'))) != record[label + '_config_sha256']:
                raise FATUpdateError('backup_changed')
        if record['config_companion_sha256'] is not None and sha(read(self.directory / 'config-before.appledouble')) != record['config_companion_sha256']:
            raise FATUpdateError('backup_changed')
        if not payload_matches(snapshot(self.directory / 'source'), record['source_files']) or not payload_matches(snapshot(self.directory / 'candidate'), record['target_files']):
            raise FATUpdateError('backup_changed')
        return record

    def classify(self, record):
        self.guard()
        if snapshot(self.oc / 'Kexts' / record['source_name']) != record['source_files']: raise FATUpdateError('original_bundle_changed')
        companion = self.oc / '._config.plist'
        if (sha(read(companion)) if companion.exists() else None) != record['config_companion_sha256']: raise FATUpdateError('config_companion_changed')
        current = sha(read(self.oc / 'config.plist'))
        if current == record['before_config_sha256']: return 'before'
        if current == record['after_config_sha256']: return 'after'
        raise FATUpdateError('unknown_config_preserved')

    def resume(self, approved_digest):
        record = self.load(approved_digest)
        state = self.classify(record)
        if record['phase'] == 'rollback_intent': return self.rollback(approved_digest)
        target = self.oc / 'Kexts' / record['target_name']
        if state == 'after':
            if not payload_matches(snapshot(target), record['target_files']): raise FATUpdateError('published_candidate_changed')
            record['phase'] = 'committed'; self.save(record)
            return {'state': 'committed', 'active_bundle': record['target_name'], 'reboot_required': True, 'power_loss_safe': False}
        record['phase'] = 'staging'; self.save(record); self.point('before_stage')
        _copy_checked(self.directory / 'candidate', target, record['target_files'], resume=True)
        self.point('staged')
        if self.classify(record) != 'before': raise FATUpdateError('config_changed_before_publish')
        record['phase'] = 'publish_intent'; self.save(record); self.point('publish_intent')
        if self.classify(record) != 'before': raise FATUpdateError('config_changed_before_publish')
        replace(self.oc / 'config.plist', read(self.directory / 'config-after.plist'), preserve_metadata=True)
        self.point('published')
        if self.classify(record) != 'after' or not payload_matches(snapshot(target), record['target_files']): raise FATUpdateError('publish_readback_mismatch')
        record['phase'] = 'committed'; self.save(record); self.point('committed')
        return {'state': 'committed', 'active_bundle': record['target_name'], 'reboot_required': True, 'power_loss_safe': False}

    def rollback(self, approved_digest):
        record = self.load(approved_digest); state = self.classify(record)
        if state == 'after':
            if not payload_matches(snapshot(self.oc / 'Kexts' / record['target_name']), record['target_files']): raise FATUpdateError('published_candidate_changed')
            record['phase'] = 'rollback_intent'; self.save(record); self.point('rollback_intent')
            if self.classify(record) != 'after': raise FATUpdateError('config_changed_before_rollback')
            replace(self.oc / 'config.plist', read(self.directory / 'config-before.plist'), preserve_metadata=True)
            self.point('rolled_back_config')
        if self.classify(record) != 'before': raise FATUpdateError('rollback_readback_mismatch')
        record['phase'] = 'rolled_back'; self.save(record)
        return {'state': 'rolled_back', 'active_bundle': record['source_name'], 'reboot_required': False, 'candidate_retained': True, 'power_loss_safe': False}
