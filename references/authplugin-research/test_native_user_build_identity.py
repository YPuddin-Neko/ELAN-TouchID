import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import uuid
from contextlib import redirect_stdout
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parent
BUILDERS = [('build-native-provider.py', 'worker-build.json', 3),
            ('build-provider-preflight.py', 'preflight-build.json', 9)]


def executable(payload=b''):
    command = struct.pack('<II', 0x1b, 24) + uuid.UUID('11111111-2222-3333-4444-555555555555').bytes
    return struct.pack('<8I', 0xfeedfacf, 0x01000007, 3, 2, 1, 24, 0, 0) + command + payload


def load(name):
    spec = importlib.util.spec_from_file_location('builder_' + name, SOURCE / name)
    module = importlib.util.module_from_spec(spec)
    with patch('subprocess.run', side_effect=AssertionError('import executed a command')):
        spec.loader.exec_module(module)
    return module


class UserBuildIdentityTests(unittest.TestCase):
    def test_import_has_no_build_side_effects(self):
        for name, _, _ in BUILDERS:
            with self.subTest(builder=name), patch.object(Path, 'mkdir', side_effect=AssertionError('import mkdir')):
                load(name)

    def test_complete_manifest_uses_final_signed_executable_bytes(self):
        for name, manifest_name, count in BUILDERS:
            with self.subTest(builder=name), tempfile.TemporaryDirectory() as directory:
                builder = load(name)
                out = Path(directory)
                commands = []
                def run(command, log):
                    current = json.loads((out / manifest_name).read_text())
                    self.assertEqual(current['state'], 'incomplete')
                    command = list(map(str, command))
                    commands.append(command)
                    if '-o' in command:
                        target = Path(command[command.index('-o') + 1])
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(executable(b'linked'))
                    if command[0] == 'codesign' and '--force' in command:
                        target = Path(command[-1])
                        if target.suffix == '.app':
                            target = target / 'Contents/MacOS' / target.stem
                        target.write_bytes(executable(b'signed'))
                with patch.object(builder, 'run', side_effect=run), redirect_stdout(io.StringIO()):
                    builder.main(['--out', directory])
                manifest = json.loads((out / manifest_name).read_text())
                self.assertEqual(manifest['state'], 'complete')
                self.assertEqual(len(manifest['artifacts']), count)
                for artifact in manifest['artifacts'].values():
                    self.assertEqual(artifact['sha256'], hashlib.sha256(executable(b'signed')).hexdigest())
                    self.assertEqual(artifact['architecture'], 'x86_64')
                self.assertFalse(manifest['installed'])
                self.assertFalse(manifest['runtime_verified'])
                self.assertFalse(manifest['deployment_authorized'])
                # Production programs are built/inspected, never launched by the builders.
                for command in commands:
                    self.assertFalse(Path(command[0]).name.startswith(('Native', 'ELAN')))

    def test_build_failure_invalidates_old_success(self):
        for name, manifest_name, _ in BUILDERS:
            with self.subTest(builder=name), tempfile.TemporaryDirectory() as directory:
                builder = load(name)
                target = Path(directory) / manifest_name
                target.write_text('{"state":"complete","artifacts":{"stale":true}}')
                with patch.object(builder, 'run', side_effect=RuntimeError('build failed')):
                    with self.assertRaises(RuntimeError):
                        builder.main(['--out', directory])
                manifest = json.loads(target.read_text())
                self.assertEqual(manifest['state'], 'incomplete')
                self.assertNotIn('artifacts', manifest)

    def test_identity_failure_does_not_publish_success(self):
        for name, manifest_name, _ in BUILDERS:
            with self.subTest(builder=name), tempfile.TemporaryDirectory() as directory:
                builder = load(name)
                with patch.object(builder, 'run'), patch.object(builder.identity, 'executable_identity', side_effect=ValueError('invalid Mach-O')):
                    with self.assertRaises(ValueError):
                        builder.main(['--out', directory])
                self.assertEqual(json.loads((Path(directory) / manifest_name).read_text())['state'], 'incomplete')


if __name__ == '__main__':
    unittest.main()
