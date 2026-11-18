#!/usr/bin/env python3
"""Observe fixed installed artifacts and loaded UUIDs without preparing an update."""
import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import uuid

DEFAULT_ROOT = Path('/Library/ELANFingerprintNativeTest')
KERNEL = 'payload/native-kernel-probe-06/ELANNativeProbe.kext'
KERNEL_ID = 'io.github.hackintosh-tools.elan-native-probe'
PROGRAMS = {
    'broker': 'ELANNativeBroker',
    'provider': 'ELANNativeProvider.app/Contents/MacOS/ELANNativeProvider',
    'auth_test': 'ELANNativeAuthTest.app/Contents/MacOS/ELANNativeAuthTest',
    'namespace_probe': 'NativeNamespaceProbe',
}
APPS = {
    'provider': ('ELANNativeProvider.app', 'io.github.hackintosh-tools.elan-native-provider', 'ELANNativeProvider'),
    'auth_test': ('ELANNativeAuthTest.app', 'io.github.hackintosh-tools.elan-native-auth-test', 'ELANNativeAuthTest'),
}
SCRIPTS = {'deployment': 'native-provider-deployment.py', 'session_lifecycle': 'native-session-lifecycle.py'}
BOOT_COMMAND = ('/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid')
LOADED_COMMAND = ('/usr/bin/kmutil', 'showloaded', '--list-only')
MAX_BINARY, MAX_METADATA = 64 * 1024 * 1024, 1024 * 1024
UUID_PATTERN = r'[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}'
IDENTITY_REASONS = frozenset({
    'invalid_file', 'changed_file', 'invalid_macho', 'unsupported_macho', 'invalid_load_commands',
    'ambiguous_uuid', 'invalid_uuid', 'invalid_executable', 'symlink_artifact',
    'artifact_metadata_mismatch', 'invalid_artifact', 'driver_not_loaded',
    'ambiguous_loaded_driver', 'invalid_loaded_output', 'loaded_version_mismatch',
})


class InspectionError(ValueError):
    pass


class _UniqueMetadata(dict):
    def __setitem__(self, key, value):
        if key in self:
            raise InspectionError('duplicate_metadata')
        super().__setitem__(key, value)


def _result(state, reason):
    return {'schema_version': 1, 'state': state, 'reason': reason,
            'runtime_session_idle_verified': False, 'boot_efi_verified': False,
            'update_authorized': False, 'apply_ready': False}


def _checked_path(root, relative='', limit=None):
    path = root
    parts = Path(relative).parts
    try:
        for index, part in enumerate(('', *parts)):
            if part:
                path = path / part
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise InspectionError('symlink_input')
            final = index == len(parts)
            if not final or not parts:
                if not stat.S_ISDIR(info.st_mode):
                    raise InspectionError('invalid_directory')
            elif not stat.S_ISREG(info.st_mode):
                raise InspectionError('invalid_file')
            if final and limit is not None and info.st_size > limit:
                raise InspectionError('input_too_large')
    except FileNotFoundError:
        raise InspectionError('missing_input') from None
    except OSError:
        raise InspectionError('unreadable_input') from None
    return path


def _read_fixed(root, relative):
    path = _checked_path(root, relative, MAX_METADATA)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_METADATA:
                raise InspectionError('invalid_file')
            data = stream.read(MAX_METADATA + 1)
            after = os.fstat(stream.fileno())
        fingerprint = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if len(data) != before.st_size or len(data) > MAX_METADATA or fingerprint(before) != fingerprint(after):
            raise InspectionError('changed_input')
        return data
    except OSError:
        raise InspectionError('unreadable_input') from None


def _metadata(root, relative):
    data = _read_fixed(root, relative)
    try:
        value = plistlib.loads(data, dict_type=_UniqueMetadata)
        if not isinstance(value, dict):
            raise InspectionError('invalid_metadata')
    except InspectionError:
        raise
    except Exception:
        raise InspectionError('invalid_metadata') from None
    return value, hashlib.sha256(data).hexdigest()


def _load_identity():
    try:
        path = Path(__file__).with_name('native-kernel-identity.py')
        if path.is_symlink() or not path.is_file():
            raise ValueError()
        spec = importlib.util.spec_from_file_location('update_identity', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        raise InspectionError('identity_helper_unavailable') from None


def _identity_call(function, *args):
    try:
        return function(*args)
    except Exception as error:
        reason = str(error)
        raise InspectionError(reason if reason in IDENTITY_REASONS else 'identity_unavailable') from None


def _valid_uuid(value):
    return type(value) is str and re.fullmatch(UUID_PATTERN, value) is not None and uuid.UUID(value).int != 0


def _identity(value, version, kind):
    fields = {'bundle_identifier', 'version', 'macho_uuid'} if kind == 'loaded' else {
        'schema_version', 'architecture', 'macho_uuid', 'sha256'}
    if kind == 'kernel':
        fields |= {'bundle_identifier', 'version'}
    if type(value) is not dict or set(value) != fields or not _valid_uuid(value['macho_uuid']):
        raise InspectionError('invalid_identity_record')
    if kind != 'loaded' and (type(value['schema_version']) is not int or value['schema_version'] != 1 or
            value['architecture'] != 'x86_64' or type(value['sha256']) is not str or
            re.fullmatch(r'[0-9a-f]{64}', value['sha256']) is None):
        raise InspectionError('invalid_identity_record')
    if kind != 'program' and (value['bundle_identifier'] != KERNEL_ID or value['version'] != version):
        raise InspectionError('invalid_identity_record')
    return dict(value)


def _snapshot(root, version, module):
    metadata = {}
    kernel_info, metadata['kernel'] = _metadata(root, KERNEL + '/Contents/Info.plist')
    expected = {'CFBundleIdentifier': KERNEL_ID, 'CFBundleExecutable': 'ELANNativeProbe',
                'CFBundleVersion': version, 'CFBundleShortVersionString': version}
    if any(kernel_info.get(key) != value for key, value in expected.items()):
        raise InspectionError('metadata_mismatch')
    _checked_path(root, KERNEL + '/Contents/MacOS/ELANNativeProbe', MAX_BINARY)
    kernel = _identity(_identity_call(module.artifact_identity, root / KERNEL, version), version, 'kernel')
    programs = {}
    for name, relative in PROGRAMS.items():
        if name in APPS:
            bundle, identifier, executable = APPS[name]
            info, metadata[name] = _metadata(root, bundle + '/Contents/Info.plist')
            expected = {'CFBundleIdentifier': identifier, 'CFBundleExecutable': executable,
                        'CFBundleVersion': version, 'CFBundlePackageType': 'APPL'}
            if (any(info.get(key) != value for key, value in expected.items()) or
                    ('CFBundleShortVersionString' in info and info['CFBundleShortVersionString'] != version)):
                raise InspectionError('metadata_mismatch')
        path = _checked_path(root, relative, MAX_BINARY)
        programs[name] = _identity(_identity_call(module.executable_identity, path), version, 'program')
    scripts = {name: hashlib.sha256(_read_fixed(root, relative)).hexdigest() for name, relative in SCRIPTS.items()}
    return {'kernel': kernel, 'programs': programs, 'metadata_sha256': metadata, 'script_sha256': scripts}


def _command(args, check=False, timeout=15):
    if tuple(args) not in (BOOT_COMMAND, LOADED_COMMAND) or check is not False or timeout != 15:
        raise InspectionError('command_not_allowed')
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    return {'status': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}


def _query(command_fn, args, limit):
    try:
        result = command_fn(list(args), check=False, timeout=15)
        if (type(result) is not dict or type(result.get('status')) is not int or result['status'] != 0 or
                type(result.get('stdout')) is not str or len(result['stdout']) > limit):
            raise InspectionError('query_failed')
        return result['stdout']
    except InspectionError:
        raise
    except Exception:
        raise InspectionError('query_failed') from None


def _boot(command_fn):
    value = _query(command_fn, BOOT_COMMAND, 128).strip().upper()
    if not _valid_uuid(value):
        raise InspectionError('invalid_boot_uuid')
    return value


def inspect(root, version='0.4.0', identity_module=None, command_fn=None):
    try:
        if type(version) is not str or len(version) > 32 or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
            raise InspectionError('invalid_version')
        root = Path(root)
        _checked_path(root)
        module = _load_identity() if identity_module is None else identity_module
        if any(not callable(getattr(module, name, None)) for name in ('artifact_identity', 'executable_identity', 'loaded_identity')):
            raise InspectionError('identity_helper_unavailable')
        command_fn = _command if command_fn is None else command_fn
        boot = _boot(command_fn)
        first = _snapshot(root, version, module)
        loaded = _identity(_identity_call(module.loaded_identity, _query(command_fn, LOADED_COMMAND, MAX_METADATA), version), version, 'loaded')
        if loaded['macho_uuid'] != first['kernel']['macho_uuid']:
            raise InspectionError('loaded_uuid_mismatch')
        second = _snapshot(root, version, module)
        loaded_again = _identity(_identity_call(module.loaded_identity, _query(command_fn, LOADED_COMMAND, MAX_METADATA), version), version, 'loaded')
        boot_again = _boot(command_fn)
        if first != second or loaded != loaded_again:
            raise InspectionError('changed_input')
        if boot != boot_again:
            raise InspectionError('changed_boot_session')
        result = _result('observed', 'baseline_observed')
        result.update(version=version, boot_uuid=boot, artifacts=first, loaded_kernel=loaded)
        return result
    except InspectionError as error:
        return _result('unavailable', str(error))
    except KeyboardInterrupt:
        return _result('unavailable', 'cancelled')
    except Exception:
        return _result('unavailable', 'inspection_failed')


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InspectionError('invalid_arguments')


def main(argv=None, identity_module=None, command_fn=None):
    parser = _Parser(prog='native-update-preflight', add_help=False)
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT)
    parser.add_argument('--version', default='0.4.0')
    try:
        args = parser.parse_args(argv)
        result = inspect(args.root, args.version, identity_module, command_fn)
    except InspectionError:
        result = _result('unavailable', 'invalid_arguments')
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['state'] == 'observed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
