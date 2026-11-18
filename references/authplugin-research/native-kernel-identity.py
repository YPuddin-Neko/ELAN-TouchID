#!/usr/bin/env python3
"""Compare a kernel test artifact with the UUID of the loaded driver, without loading code."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import subprocess
import uuid
from xml.parsers.expat import ExpatError

IDENTIFIER = 'io.github.hackintosh-tools.elan-native-probe'
EXECUTABLE = 'ELANNativeProbe'
MANIFEST_NAME = 'kernel-identity.json'
MAX_BINARY = 64 * 1024 * 1024
MAX_METADATA = 1024 * 1024
UUID_PATTERN = r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}'
FIELDS = {'schema_version', 'bundle_identifier', 'version', 'architecture', 'macho_uuid', 'sha256'}


class IdentityError(ValueError):
    pass


def _version(value):
    if type(value) is not str or len(value) > 32 or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value):
        raise IdentityError('invalid_version')
    return value


def _read_regular(path, limit):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise IdentityError('invalid_file')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if (len(data) != before.st_size or len(data) > limit or
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise IdentityError('changed_file')
    return data


def macho_uuid(data, expected_kind=11):
    """Require an explicitly selected thin x86_64 kext or executable format."""
    if type(expected_kind) is not int or expected_kind not in (2, 11):
        raise IdentityError('unsupported_macho')
    if not isinstance(data, bytes) or not 32 <= len(data) <= MAX_BINARY:
        raise IdentityError('invalid_macho')
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<8I', data)
    if (magic != 0xfeedfacf or cpu != 0x01000007 or subtype not in (3, 8) or kind != expected_kind or
            reserved or not 1 <= count <= 4096 or size > MAX_METADATA or size > len(data) - 32):
        raise IdentityError('unsupported_macho')
    end, cursor, found = 32 + size, 32, None
    for _ in range(count):
        if end - cursor < 8:
            raise IdentityError('invalid_load_commands')
        command, length = struct.unpack_from('<2I', data, cursor)
        if length < 8 or length % 8 or length > end - cursor:
            raise IdentityError('invalid_load_commands')
        if command == 0x1b:
            if length != 24 or found is not None:
                raise IdentityError('ambiguous_uuid')
            value = uuid.UUID(bytes=data[cursor + 8:cursor + 24])
            if value.int == 0:
                raise IdentityError('invalid_uuid')
            found = str(value).upper()
        cursor += length
    if cursor != end or found is None:
        raise IdentityError('invalid_load_commands')
    return found


def executable_identity(path):
    """Hash program bytes and decode their UUID without executing the program."""
    try:
        data = _read_regular(Path(path), MAX_BINARY)
        return {'schema_version': 1, 'architecture': 'x86_64',
                'macho_uuid': macho_uuid(data, expected_kind=2),
                'sha256': hashlib.sha256(data).hexdigest()}
    except IdentityError:
        raise
    except (OSError, ValueError, TypeError):
        raise IdentityError('invalid_executable') from None


def artifact_identity(bundle, expected_version):
    version = _version(expected_version)
    bundle = Path(bundle)
    try:
        for relative in ('', 'Contents', 'Contents/Info.plist', 'Contents/MacOS', 'Contents/MacOS/' + EXECUTABLE):
            if (bundle / relative).is_symlink():
                raise IdentityError('symlink_artifact')
        info = plistlib.loads(_read_regular(bundle / 'Contents/Info.plist', MAX_METADATA))
        expected = {'CFBundleIdentifier': IDENTIFIER, 'CFBundleExecutable': EXECUTABLE,
                    'CFBundleVersion': version, 'CFBundleShortVersionString': version}
        if not isinstance(info, dict) or any(info.get(key) != value for key, value in expected.items()):
            raise IdentityError('artifact_metadata_mismatch')
        data = _read_regular(bundle / 'Contents/MacOS' / EXECUTABLE, MAX_BINARY)
        return {'schema_version': 1, 'bundle_identifier': IDENTIFIER, 'version': version,
                'architecture': 'x86_64', 'macho_uuid': macho_uuid(data),
                'sha256': hashlib.sha256(data).hexdigest()}
    except IdentityError:
        raise
    except (OSError, ValueError, TypeError, RecursionError, OverflowError, ExpatError, plistlib.InvalidFileException):
        raise IdentityError('invalid_artifact') from None


def validate_manifest(value, expected_version):
    version = _version(expected_version)
    if (type(value) is not dict or set(value) != FIELDS or
            type(value['schema_version']) is not int or value['schema_version'] != 1 or
            value['bundle_identifier'] != IDENTIFIER or value['version'] != version or
            value['architecture'] != 'x86_64' or type(value['macho_uuid']) is not str or
            not re.fullmatch(UUID_PATTERN, value['macho_uuid']) or
            value['macho_uuid'] != value['macho_uuid'].upper() or
            uuid.UUID(value['macho_uuid']).int == 0 or type(value['sha256']) is not str or
            not re.fullmatch(r'[0-9a-f]{64}', value['sha256'])):
        raise IdentityError('invalid_manifest')
    return dict(value)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IdentityError('invalid_manifest')
        result[key] = value
    return result


def load_manifest(path, expected_version):
    try:
        value = json.loads(_read_regular(Path(path), MAX_METADATA), object_pairs_hook=_unique_pairs)
        return validate_manifest(value, expected_version)
    except IdentityError:
        raise
    except (OSError, ValueError, TypeError, RecursionError):
        raise IdentityError('invalid_manifest') from None


def verify_artifact(bundle, manifest, expected_version):
    expected = validate_manifest(manifest, expected_version)
    if artifact_identity(bundle, expected_version) != expected:
        raise IdentityError('artifact_mismatch')
    return expected


def loaded_identity(output, expected_version):
    version = _version(expected_version)
    if type(output) is not str or len(output) > MAX_METADATA:
        raise IdentityError('invalid_loaded_output')
    candidates = [line for line in output.splitlines() if IDENTIFIER in line]
    if not candidates:
        raise IdentityError('driver_not_loaded')
    if len(candidates) != 1:
        raise IdentityError('ambiguous_loaded_driver')
    # Parse one whole kmutil row. Never export kernel addresses or unrelated kexts.
    pattern = (r'\s*[0-9]+\s+[0-9]+\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+' +
               re.escape(IDENTIFIER) + r'\s+\(([0-9]+\.[0-9]+\.[0-9]+)\)\s+(' + UUID_PATTERN +
               r')\s+<(?:[0-9]+(?:\s+[0-9]+)*)?>\s*')
    match = re.fullmatch(pattern, candidates[0])
    if not match or uuid.UUID(match.group(2)).int == 0:
        raise IdentityError('invalid_loaded_output')
    if match.group(1) != version:
        raise IdentityError('loaded_version_mismatch')
    return {'bundle_identifier': IDENTIFIER, 'version': version, 'macho_uuid': match.group(2).upper()}


def check_loaded(manifest, output, expected_version):
    expected = validate_manifest(manifest, expected_version)
    loaded = loaded_identity(output, expected_version)
    if loaded['macho_uuid'] != expected['macho_uuid']:
        raise IdentityError('loaded_uuid_mismatch')
    return loaded


def _command(args, check=False, timeout=15):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=check)
    return {'status': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}


def _loaded_output(command_fn):
    try:
        result = command_fn(['/usr/bin/kmutil', 'showloaded', '--list-only'], check=False, timeout=15)
        if type(result) is not dict or type(result.get('status')) is not int or result['status'] != 0:
            raise IdentityError('loaded_query_failed')
        return result['stdout']
    except IdentityError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError):
        raise IdentityError('loaded_query_failed') from None


def require_running_identity(bundle, manifest_path, expected_version, command_fn=_command):
    expected = verify_artifact(bundle, load_manifest(manifest_path, expected_version), expected_version)
    return check_loaded(expected, _loaded_output(command_fn), expected_version)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--live', action='store_true')
    source.add_argument('--bundle', type=Path)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--version', default='0.4.0')
    args = parser.parse_args(argv)
    try:
        expected = load_manifest(args.manifest, args.version) if args.manifest else None
        if args.live:
            output = _loaded_output(_command)
            identity = check_loaded(expected, output, args.version) if expected else loaded_identity(output, args.version)
        else:
            identity = verify_artifact(args.bundle, expected, args.version) if expected else artifact_identity(args.bundle, args.version)
        result = {'schema_version': 1, 'state': 'loaded' if args.live else 'artifact', 'identity': identity}
        status = 0
    except IdentityError as error:
        result = {'schema_version': 1, 'state': 'unavailable', 'reason': str(error)}
        status = 1
    except KeyboardInterrupt:
        result = {'schema_version': 1, 'state': 'unavailable', 'reason': 'cancelled'}
        status = 130
    print(json.dumps(result, indent=2))
    return status


if __name__ == '__main__':
    raise SystemExit(main())
