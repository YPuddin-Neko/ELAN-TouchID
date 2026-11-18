import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest
import uuid
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('update_preflight', Path(__file__).with_name('native-update-preflight.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
IDENTITY = module._load_identity()
UUID = '5A6A3016-833C-37A0-BDA0-40E4FBFF4798'
OTHER = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'
BOOT = '4426B06A-1C50-44A8-BD32-EF5CAD0640B6'


def binary(kind=2, identifier=UUID):
    return struct.pack('<8I', 0xfeedfacf, 0x01000007, 3, kind, 1, 24, 0, 0) + struct.pack('<II', 0x1b, 24) + uuid.UUID(identifier).bytes


def row(identifier=UUID, version='0.4.0'):
    return f'59 0 0xffffff8004051000 0x11000 0x11000 {module.KERNEL_ID} ({version}) {identifier} <57 9 7 6 3 1>\n'


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / 'install'
        self.root.mkdir()
        self.write(module.KERNEL + '/Contents/MacOS/ELANNativeProbe', binary(11))
        self.write(module.KERNEL + '/Contents/Info.plist', plistlib.dumps({
            'CFBundleIdentifier': module.KERNEL_ID, 'CFBundleExecutable': 'ELANNativeProbe',
            'CFBundleVersion': '0.4.0', 'CFBundleShortVersionString': '0.4.0'}))
        for relative in module.PROGRAMS.values():
            self.write(relative, binary())
        for bundle, identifier, executable in module.APPS.values():
            self.write(bundle + '/Contents/Info.plist', plistlib.dumps({
                'CFBundleIdentifier': identifier, 'CFBundleExecutable': executable,
                'CFBundleVersion': '0.4.0', 'CFBundlePackageType': 'APPL'}))
        for relative in module.SCRIPTS.values():
            self.write(relative, b'# inert fixture\n')
        self.calls = []

    def write(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def command(self, args, **kwargs):
        self.assertEqual(kwargs, {'check': False, 'timeout': 15})
        self.assertIn(tuple(args), (module.BOOT_COMMAND, module.LOADED_COMMAND))
        self.calls.append(tuple(args))
        return {'status': 0, 'stdout': BOOT if tuple(args) == module.BOOT_COMMAND else row(), 'stderr': 'PRIVATE'}

    def inspect(self, **kwargs):
        return module.inspect(self.root, command_fn=kwargs.pop('command_fn', self.command), **kwargs)

    def unavailable(self, reason=None, **kwargs):
        result = self.inspect(**kwargs)
        self.assertEqual(result['state'], 'unavailable', result)
        if reason:
            self.assertEqual(result['reason'], reason)
        self.assertFalse(result['apply_ready'])
        self.assertFalse(result['update_authorized'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        return result

    def test_observation_is_read_only_and_never_authorizes_update(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch.object(module.subprocess, 'run') as run:
            result = self.inspect()
            run.assert_not_called()
        self.assertEqual(result['state'], 'observed', result)
        self.assertEqual(result['loaded_kernel']['macho_uuid'], UUID)
        self.assertEqual(set(result['artifacts']['programs']), set(module.PROGRAMS))
        for key in ('apply_ready', 'update_authorized', 'runtime_session_idle_verified', 'boot_efi_verified'):
            self.assertIs(result[key], False)
        self.assertEqual(self.calls, [module.BOOT_COMMAND, module.LOADED_COMMAND, module.LOADED_COMMAND, module.BOOT_COMMAND])
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_same_version_different_loaded_uuid_rejected(self):
        def command(args, **kwargs):
            result = self.command(args, **kwargs)
            if tuple(args) == module.LOADED_COMMAND:
                result['stdout'] = row(OTHER)
            return result
        self.unavailable('loaded_uuid_mismatch', command_fn=command)

    def test_missing_each_fixed_input(self):
        paths = [p for p in self.root.rglob('*') if p.is_file()]
        for path in paths:
            with self.subTest(path=path.relative_to(self.root)):
                data = path.read_bytes(); path.unlink()
                self.unavailable('missing_input')
                path.write_bytes(data)

    def test_symlink_file_and_directory_rejected(self):
        path = self.root / module.PROGRAMS['broker']
        data = path.read_bytes(); path.unlink()
        other = self.root / 'other'; other.write_bytes(data); path.symlink_to(other)
        self.unavailable('symlink_input')
        path.unlink(); path.write_bytes(data)
        bundle = self.root / module.APPS['provider'][0]
        moved = self.root / 'moved'; bundle.rename(moved); bundle.symlink_to(moved)
        self.unavailable('symlink_input')

    def test_fifo_and_oversized_input_rejected(self):
        path = self.root / module.SCRIPTS['deployment']; path.unlink(); os.mkfifo(path)
        self.unavailable('invalid_file'); path.unlink()
        with path.open('wb') as stream: stream.truncate(module.MAX_METADATA + 1)
        self.unavailable('input_too_large')

    def test_kernel_executable_roles_are_distinct(self):
        self.write(module.PROGRAMS['broker'], binary(11))
        self.unavailable('unsupported_macho')
        self.write(module.PROGRAMS['broker'], binary())
        self.write(module.KERNEL + '/Contents/MacOS/ELANNativeProbe', binary())
        self.unavailable('unsupported_macho')

    def test_app_metadata_version_mismatch(self):
        path = self.root / module.APPS['provider'][0] / 'Contents/Info.plist'
        info = plistlib.loads(path.read_bytes()); info['CFBundleVersion'] = '0.3.0'
        path.write_bytes(plistlib.dumps(info)); self.unavailable('metadata_mismatch')

    def test_duplicate_metadata_rejected(self):
        path = self.root / module.APPS['provider'][0] / 'Contents/Info.plist'
        data = path.read_bytes().replace(b'</dict>', b'<key>CFBundleVersion</key><string>0.4.0</string></dict>')
        path.write_bytes(data); self.unavailable('duplicate_metadata')

    def test_changed_binary_scripts_and_metadata_rejected(self):
        paths = [module.PROGRAMS['broker'], module.SCRIPTS['deployment'], module.APPS['provider'][0] + '/Contents/Info.plist']
        for relative in paths:
            with self.subTest(relative=relative):
                path = self.root / relative; original = path.read_bytes()
                def command(args, **kwargs):
                    result = self.command(args, **kwargs)
                    if tuple(args) == module.LOADED_COMMAND:
                        path.write_bytes(original + (b'\n' if relative.endswith('.plist') else b'changed'))
                    return result
                self.unavailable('changed_input', command_fn=command)
                path.write_bytes(original)

    def test_changed_loaded_driver_and_boot_rejected(self):
        for changing, reason in [(module.LOADED_COMMAND, 'changed_input'), (module.BOOT_COMMAND, 'changed_boot_session')]:
            counts = {}
            def command(args, **kwargs):
                result = self.command(args, **kwargs); key = tuple(args)
                counts[key] = counts.get(key, 0) + 1
                if key == changing and counts[key] == 2:
                    result['stdout'] = row(OTHER) if key == module.LOADED_COMMAND else OTHER
                return result
            self.unavailable(reason, command_fn=command)

    def test_query_failure_and_malformed_boot(self):
        for response in ({'status': 1, 'stdout': 'PRIVATE'}, {'status': True, 'stdout': BOOT},
                         {'status': 0, 'stdout': None}, {'status': 0, 'stdout': 'x' * 129}):
            self.unavailable('query_failed', command_fn=lambda *a, **k: response)
        self.unavailable('invalid_boot_uuid', command_fn=lambda *a, **k: {'status': 0, 'stdout': 'invalid'})
        def raises(*args, **kwargs): raise RuntimeError('PRIVATE')
        self.unavailable('query_failed', command_fn=raises)

    def test_invalid_version_and_helper(self):
        for version in ('x', None, True, '0.4.0/../secret'):
            self.unavailable('invalid_version', version=version)
        self.unavailable('identity_helper_unavailable', identity_module=object())

    def test_loaded_missing_duplicate_and_wrong_version(self):
        for output in ('', row() + row(), row(version='0.3.0')):
            def command(args, **kwargs):
                result = self.command(args, **kwargs)
                if tuple(args) == module.LOADED_COMMAND: result['stdout'] = output
                return result
            self.unavailable(command_fn=command)

    def test_unrelated_private_files_are_not_read(self):
        (self.root / 'secret-keychain').symlink_to('/does/not/exist')
        self.assertEqual(self.inspect()['state'], 'observed')

    def test_cli_json_and_exit_status(self):
        for args, expected in [(['--root', str(self.root)], 0), (['--unknown'], 1)]:
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                status = module.main(args, command_fn=self.command)
            self.assertEqual(status, expected)
            self.assertIs(json.loads(stream.getvalue())['apply_ready'], False)

    def test_production_command_allowlist(self):
        with patch.object(module.subprocess, 'run') as run:
            with self.assertRaises(module.InspectionError): module._command(['/bin/launchctl', 'kickstart', 'anything'])
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
