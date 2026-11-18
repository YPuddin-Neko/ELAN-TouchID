import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile
import unittest
import uuid
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('kernel_identity', Path(__file__).with_name('native-kernel-identity.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
VERSION = '0.4.0'
UUID = '5A6A3016-833C-37A0-BDA0-40E4FBFF4798'
OTHER = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'


def binary(identifier=UUID, extra=b''):
    command = struct.pack('<II', 0x1b, 24) + uuid.UUID(identifier).bytes
    return struct.pack('<8I', 0xfeedfacf, 0x01000007, 3, 11, 1, 24, 0, 0) + command + extra


def row(identifier=UUID, version=VERSION):
    return '   59    0 0xffffff8004051000 0x11000    0x11000    ' + module.IDENTIFIER + ' (' + version + ') ' + identifier + ' <57 9 7 6 3 1>\n'


def bundle_fixture(root):
    bundle = Path(root) / 'ELANNativeProbe.kext'
    executable = bundle / 'Contents/MacOS/ELANNativeProbe'
    executable.parent.mkdir(parents=True)
    executable.write_bytes(binary())
    info = {'CFBundleIdentifier': module.IDENTIFIER, 'CFBundleExecutable': module.EXECUTABLE,
            'CFBundleVersion': VERSION, 'CFBundleShortVersionString': VERSION}
    (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
    return bundle, executable


class KernelIdentityTests(unittest.TestCase):
    def test_macho_uuid(self):
        self.assertEqual(module.macho_uuid(binary()), UUID)
        self.assertEqual(module.macho_uuid(binary(extra=b'payload')), UUID)

    def test_executable_role_cannot_replace_kext_role(self):
        data = bytearray(binary()); struct.pack_into('<I', data, 12, 2)
        data = bytes(data)
        self.assertEqual(module.macho_uuid(data, expected_kind=2), UUID)
        with self.assertRaises(module.IdentityError): module.macho_uuid(data)
        with self.assertRaises(module.IdentityError): module.macho_uuid(binary(), expected_kind=2)
        for kind in (True, 2.0, '2', None, 6, 0):
            with self.subTest(kind=kind), self.assertRaises(module.IdentityError):
                module.macho_uuid(data, expected_kind=kind)
        for length in range(len(data)):
            with self.subTest(length=length), self.assertRaises(module.IdentityError):
                module.macho_uuid(data[:length], expected_kind=2)

    def test_executable_identity_is_read_only_and_hashes_complete_bytes(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(module.subprocess, 'run') as run:
            path = Path(directory) / 'program'
            data = bytearray(binary()); struct.pack_into('<I', data, 12, 2)
            path.write_bytes(bytes(data))
            first = module.executable_identity(path)
            self.assertEqual(first['macho_uuid'], UUID)
            self.assertEqual(set(first), {'schema_version', 'architecture', 'macho_uuid', 'sha256'})
            path.write_bytes(bytes(data) + b'changed')
            second = module.executable_identity(path)
            self.assertEqual(first['macho_uuid'], second['macho_uuid'])
            self.assertNotEqual(first['sha256'], second['sha256'])
            link = Path(directory) / 'link'; link.symlink_to(path)
            with self.assertRaises(module.IdentityError): module.executable_identity(link)
            fifo = Path(directory) / 'fifo'; os.mkfifo(str(fifo))
            with self.assertRaises(module.IdentityError): module.executable_identity(fifo)
            with self.assertRaises(module.IdentityError): module.executable_identity(Path(directory) / 'absent')
            path.write_bytes(binary())
            with self.assertRaises(module.IdentityError): module.executable_identity(path)
            run.assert_not_called()

    def test_macho_header_failures(self):
        original = binary()
        for index, value in [(0, 0xcafebabe), (1, 0x0100000c), (2, 0), (3, 2),
                             (4, 0), (4, 4097), (5, 100), (7, 1)]:
            data = bytearray(original); struct.pack_into('<I', data, index * 4, value)
            with self.subTest(index=index, value=value), self.assertRaises(module.IdentityError):
                module.macho_uuid(bytes(data))
        for length in range(len(original)):
            with self.subTest(length=length), self.assertRaises(module.IdentityError):
                module.macho_uuid(original[:length])

    def test_load_commands_fail_closed(self):
        for command, size in [(0x1b, 0), (0x1b, 8), (0x1b, 23), (0x1b, 32), (1, 24)]:
            data = bytearray(binary()); struct.pack_into('<II', data, 32, command, size)
            with self.subTest(command=command, size=size), self.assertRaises(module.IdentityError):
                module.macho_uuid(bytes(data))
        data = bytearray(binary() + binary()[32:]); struct.pack_into('<II', data, 16, 2, 48)
        with self.assertRaises(module.IdentityError): module.macho_uuid(bytes(data))
        with self.assertRaises(module.IdentityError): module.macho_uuid(binary('00000000-0000-0000-0000-000000000000'))
        data = bytearray(binary() + b'\0' * 8); struct.pack_into('<I', data, 20, 32)
        with self.assertRaises(module.IdentityError): module.macho_uuid(bytes(data))

    def test_artifact_and_matching_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, executable = bundle_fixture(directory)
            expected = module.artifact_identity(bundle, VERSION)
            manifest = Path(directory) / module.MANIFEST_NAME
            manifest.write_text(json.dumps(expected))
            self.assertEqual(module.load_manifest(manifest, VERSION), expected)
            self.assertEqual(module.verify_artifact(bundle, expected, VERSION), expected)
            command = lambda *args, **kwargs: {'status': 0, 'stdout': row(), 'stderr': 'IGNORED_PRIVATE'}
            result = module.require_running_identity(bundle, manifest, VERSION, command)
            self.assertEqual(result['macho_uuid'], UUID)
            executable.write_bytes(binary(extra=b'changed-with-same-uuid'))
            with self.assertRaisesRegex(module.IdentityError, 'artifact_mismatch'):
                module.require_running_identity(bundle, manifest, VERSION, command)

    def test_artifact_metadata(self):
        for key, value in [('CFBundleIdentifier', 'other'), ('CFBundleExecutable', '../other'),
                           ('CFBundleVersion', '0.3.0'), ('CFBundleShortVersionString', '0.3.0')]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                bundle, _ = bundle_fixture(directory)
                path = bundle / 'Contents/Info.plist'; info = plistlib.loads(path.read_bytes())
                info[key] = value; path.write_bytes(plistlib.dumps(info))
                with self.assertRaises(module.IdentityError): module.artifact_identity(bundle, VERSION)

    def test_symlink_and_special_files(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, _ = bundle_fixture(directory)
            link = Path(directory) / 'linked.kext'; link.symlink_to(bundle)
            with self.assertRaises(module.IdentityError): module.artifact_identity(link, VERSION)
            fifo = Path(directory) / 'fifo'; os.mkfifo(str(fifo))
            with self.assertRaises(module.IdentityError): module.load_manifest(fifo, VERSION)
            link = Path(directory) / 'manifest-link'; link.symlink_to(bundle / 'Contents/Info.plist')
            with self.assertRaises(module.IdentityError): module.load_manifest(link, VERSION)

    def test_manifest_schema_types_and_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, _ = bundle_fixture(directory)
            original = module.artifact_identity(bundle, VERSION)
            for key, value in [('schema_version', True), ('schema_version', 2), ('extra', 'PRIVATE'),
                               ('macho_uuid', UUID.lower()), ('macho_uuid', 'invalid'),
                               ('architecture', 'arm64'), ('sha256', 'x' * 64), ('version', '0.3.0')]:
                data = copy.deepcopy(original); data[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(module.IdentityError):
                    module.validate_manifest(data, VERSION)
            for key in original:
                data = dict(original); del data[key]
                with self.subTest(missing=key), self.assertRaises(module.IdentityError):
                    module.validate_manifest(data, VERSION)
            manifest = Path(directory) / 'duplicate.json'
            manifest.write_text(json.dumps(original)[:-1] + ', "schema_version": 1}')
            with self.assertRaises(module.IdentityError): module.load_manifest(manifest, VERSION)

    def test_oversized_and_invalid_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'large.json'
            with path.open('wb') as stream: stream.truncate(module.MAX_METADATA + 1)
            with self.assertRaises(module.IdentityError): module.load_manifest(path, VERSION)
            path.write_bytes(b'\xffPRIVATE')
            with self.assertRaises(module.IdentityError): module.load_manifest(path, VERSION)
            bundle, _ = bundle_fixture(directory)
            (bundle / 'Contents/Info.plist').write_bytes(b'<?xml version="1.0"?><plist><invalid')
            with self.assertRaises(module.IdentityError): module.artifact_identity(bundle, VERSION)

    def test_loaded_rows_are_strict_and_sanitized(self):
        self.assertEqual(module.loaded_identity('Index Refs Address\n' + row(UUID.lower()), VERSION)['macho_uuid'], UUID)
        self.assertNotIn('0xffffff', json.dumps(module.loaded_identity(row(), VERSION)))
        for text in ('', row() + row(), row().replace(module.IDENTIFIER, module.IDENTIFIER + '-other'),
                     row().replace('0x11000', 'invalid', 1), row('00000000-0000-0000-0000-000000000000'),
                     row().replace('<57 9 7 6 3 1>', 'PRIVATE'), row(version='0.3.0'), 'X' * (module.MAX_METADATA + 1)):
            with self.subTest(text=text[:100]), self.assertRaises(module.IdentityError):
                module.loaded_identity(text, VERSION)

    def test_same_version_different_loaded_uuid_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, _ = bundle_fixture(directory)
            expected = module.artifact_identity(bundle, VERSION)
            with self.assertRaisesRegex(module.IdentityError, 'loaded_uuid_mismatch'):
                module.check_loaded(expected, row(OTHER), VERSION)

    def test_artifact_failure_precedes_query(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(module, '_command') as command:
            with self.assertRaises(module.IdentityError):
                module.require_running_identity(Path(directory) / 'missing', Path(directory) / 'missing.json', VERSION, command)
            command.assert_not_called()

    def test_cli_live_fixed_command_and_no_private_output(self):
        output = io.StringIO()
        with patch.object(module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, row(), 'PRIVATE')) as run:
            with contextlib.redirect_stdout(output): self.assertEqual(module.main(['--live']), 0)
        self.assertEqual(run.call_args.args[0], ['/usr/bin/kmutil', 'showloaded', '--list-only'])
        self.assertNotIn('PRIVATE', output.getvalue()); self.assertNotIn('0xffffff', output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['state'], 'loaded')

    def test_cli_failures_are_json_only(self):
        for error in (OSError('PRIVATE_PATH'), subprocess.TimeoutExpired('PRIVATE_COMMAND', 15)):
            output = io.StringIO()
            with patch.object(module.subprocess, 'run', side_effect=error), contextlib.redirect_stdout(output):
                self.assertEqual(module.main(['--live']), 1)
            self.assertNotIn('PRIVATE', output.getvalue())
            self.assertEqual(json.loads(output.getvalue())['reason'], 'loaded_query_failed')
        output = io.StringIO()
        with patch.object(module.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, 'PRIVATE', 'PRIVATE')), contextlib.redirect_stdout(output):
            self.assertEqual(module.main(['--live']), 1)
        self.assertNotIn('PRIVATE', output.getvalue())

    def test_bundle_cli_never_queries_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, _ = bundle_fixture(directory)
            with patch.object(module.subprocess, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(module.main(['--bundle', str(bundle)]), 0)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
