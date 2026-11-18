import hashlib
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest
import uuid
from contextlib import redirect_stdout
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parent
VERSION = '0.6.0'
FIRST_UUID = '11111111-2222-3333-4444-555555555555'
SECOND_UUID = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'


def binary(identifier=FIRST_UUID, payload=b'kernel fixture'):
    command = struct.pack('<II', 0x1b, 24) + uuid.UUID(identifier).bytes
    return struct.pack('<8I', 0xfeedfacf, 0x01000007, 3, 11, 1, 24, 0, 0) + command + payload


def load_builder():
    spec = importlib.util.spec_from_file_location('kernel_identity_builder', SOURCE / 'kernel-provider/build.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class KernelBuildIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.sdk, self.lilu = self.root / 'sdk', self.root / 'lilu'
        for dependency in [self.sdk / 'Library/x86_64/libkmod.a', self.lilu / 'Library/plugin_start.cpp']:
            dependency.parent.mkdir(parents=True, exist_ok=True)
            dependency.write_bytes(b'fixture')
        self.builder = load_builder()
        self.out = self.root / 'out'
        self.data = binary()
        self.final_data = None
        self.fail_phase = None
        self.commands = []
        self.stdout = io.StringIO()

    @property
    def bundle(self):
        return self.out / 'ELANNativeProbeAuthorization015.kext'

    @property
    def executable(self):
        return self.bundle / 'Contents/MacOS/ELANNativeProbe'

    @property
    def identity_path(self):
        return self.out / self.builder.identity.MANIFEST_NAME

    def assert_incomplete(self):
        with self.assertRaises(self.builder.identity.IdentityError):
            self.builder.identity.load_manifest(self.identity_path, VERSION)
        for path in [self.identity_path, self.out / 'build.json']:
            record = json.loads(path.read_text())
            self.assertEqual(record['state'], 'incomplete')
            self.assertFalse(record['runtime_verified'])
            self.assertFalse(record['ready_for_installation'])
            self.assertNotIn('kernel_identity', record)

    def fake_run(self, command, log_name):
        self.assert_incomplete()
        self.commands.append(log_name)
        if log_name == self.fail_phase:
            raise RuntimeError('injected build command failure')
        if log_name == 'link' and self.data is not None:
            self.executable.write_bytes(self.data)
        if log_name == 'client-build':
            (self.out / 'elan-native-probe').write_bytes(b'client fixture')
        if log_name == 'client-verify' and self.final_data is not None:
            self.executable.write_bytes(self.final_data)
        return ''

    def build(self, sdk=None):
        self.stdout = io.StringIO()
        with patch.object(self.builder, 'run', side_effect=self.fake_run), \
                patch.object(self.builder.subprocess, 'run', side_effect=AssertionError('unexpected external command')), \
                redirect_stdout(self.stdout):
            self.builder.main(['--sdk', str(sdk or self.sdk), '--lilu', str(self.lilu), '--out', str(self.out)])

    def verify_success(self, expected_data, expected_uuid):
        helper = self.builder.identity
        record = helper.load_manifest(self.identity_path, VERSION)
        build = json.loads((self.out / 'build.json').read_text())
        printed = json.loads(self.stdout.getvalue())
        self.assertEqual(record, helper.artifact_identity(self.bundle, VERSION))
        self.assertEqual(record, helper.verify_artifact(self.bundle, record, VERSION))
        self.assertEqual(record, build['kernel_identity'])
        self.assertEqual(record, printed['kernel_identity'])
        self.assertEqual(set(record), {'schema_version', 'bundle_identifier', 'version', 'architecture', 'macho_uuid', 'sha256'})
        self.assertEqual(record['macho_uuid'], expected_uuid)
        self.assertEqual(record['sha256'], hashlib.sha256(expected_data).hexdigest())
        self.assertEqual(record['architecture'], 'x86_64')
        self.assertEqual(record['version'], VERSION)
        self.assertEqual(self.builder.VERSION, VERSION)
        info = plistlib.loads((self.bundle / 'Contents/Info.plist').read_bytes())
        self.assertEqual(info['CFBundleVersion'], VERSION)
        self.assertEqual(info['CFBundleShortVersionString'], VERSION)
        for flag in ['installed', 'deployment_authorized', 'runtime_verified', 'ready_for_installation',
                     'settings_connection_recovery_runtime_ready', 'startup_exec_observer_runtime_enabled',
                     'startup_private_hooks_implemented', 'enrollment_authorization_runtime_verified',
                     'settings_platform_runtime_verified']:
            self.assertIs(build[flag], False, flag)
        self.assertEqual(len(build['host_state_machine_tests']), 17)
        self.assertEqual(self.commands[-1], 'client-verify')
        return record

    def test_success_uses_actual_artifact_and_keeps_runtime_disabled(self):
        self.build()
        self.verify_success(self.data, FIRST_UUID)

    def test_identity_reads_final_artifact_after_command_validation(self):
        self.final_data = binary(SECOND_UUID, b'final artifact bytes')
        self.build()
        self.verify_success(self.final_data, SECOND_UUID)

    def test_rebuild_same_version_emits_new_uuid_and_digest(self):
        self.build()
        old = self.verify_success(self.data, FIRST_UUID)
        self.data = binary(SECOND_UUID)
        self.build()
        new = self.verify_success(self.data, SECOND_UUID)
        self.assertNotEqual(old['macho_uuid'], new['macho_uuid'])
        self.assertNotEqual(old['sha256'], new['sha256'])

    def test_missing_and_malformed_binary_never_publish_identity(self):
        wrong_arch = bytearray(binary())
        struct.pack_into('<I', wrong_arch, 4, 0x0100000c)
        no_uuid = struct.pack('<8I', 0xfeedfacf, 0x01000007, 3, 11, 1, 8, 0, 0) + struct.pack('<2I', 1, 8)
        for index, data in enumerate([None, b'', b'not a Mach-O', bytes(wrong_arch), no_uuid, binary(str(uuid.UUID(int=0)))]):
            with self.subTest(case=index):
                self.out = self.root / ('invalid-' + str(index))
                self.data = data
                with self.assertRaises(self.builder.identity.IdentityError):
                    self.build()
                self.assert_incomplete()
                self.assertEqual(self.stdout.getvalue(), '')

    def test_failed_rebuild_invalidates_old_success_before_commands(self):
        for phase in ['test-credential_study-build', 'compile-0', 'link', 'client-build', 'client-sign', 'client-verify', 'identity']:
            with self.subTest(phase=phase):
                self.out = self.root / phase
                self.data, self.fail_phase = binary(), None
                self.build()
                original = self.verify_success(self.data, FIRST_UUID)
                self.commands = []
                self.fail_phase = phase
                if phase == 'identity':
                    self.data = b'invalid replacement'
                with self.assertRaises((RuntimeError, self.builder.identity.IdentityError)):
                    self.build()
                self.assert_incomplete()
                self.assertEqual(self.stdout.getvalue(), '')
                if phase in ['test-credential_study-build', 'compile-0', 'link']:
                    self.assertEqual(self.executable.read_bytes(), binary())
                    self.assertEqual(self.builder.identity.verify_artifact(self.bundle, original, VERSION), original)

    def test_dependency_failure_also_invalidates_preexisting_records(self):
        self.build()
        self.commands = []
        with self.assertRaises(FileNotFoundError):
            self.build(sdk=self.root / 'missing-sdk')
        self.assert_incomplete()
        self.assertEqual(self.commands, [])
        self.assertEqual(self.executable.read_bytes(), binary())
        self.assertEqual(self.stdout.getvalue(), '')

    def test_success_manifest_write_failure_does_not_publish_dedicated_identity(self):
        original = Path.write_text

        def write_text(path, text, *args, **kwargs):
            if path == self.out / 'build.json' and 'kernel_identity' in json.loads(text):
                raise OSError('injected metadata write failure')
            return original(path, text, *args, **kwargs)

        with patch.object(Path, 'write_text', new=write_text), self.assertRaises(OSError):
            self.build()
        self.assert_incomplete()
        self.assertEqual(self.stdout.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
