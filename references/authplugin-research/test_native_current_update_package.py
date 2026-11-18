import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import runpy
import struct
import tempfile
import unittest
import uuid
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('current_package', SOURCE / 'package-native-current-update.py')
pkg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pkg)


def binary(kind):
    command = struct.pack('<II', 0x1b, 24) + uuid.UUID('11111111-2222-3333-4444-555555555555').bytes
    return struct.pack('<8I', 0xfeedfacf, 0x01000007, 3, kind, 1, 24, 0, 0) + command


class CurrentPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.user, self.kernel, self.out = root / 'user', root / 'kernel', root / 'out'
        for name in (*pkg.WORKER, *pkg.PREFLIGHT):
            path = self.user / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(binary(2))
        for app, ident in [('ELANNativeProvider', 'io.github.hackintosh-tools.elan-native-provider'),
                           ('ELANNativeAuthTest', 'io.github.hackintosh-tools.elan-native-auth-test')]:
            (self.user / (app + '.app') / 'Contents/Info.plist').write_bytes(plistlib.dumps({
                'CFBundleVersion': '0.4.0', 'CFBundleExecutable': app, 'CFBundleIdentifier': ident}))
        for name, names in [('worker-build.json', pkg.WORKER), ('preflight-build.json', pkg.PREFLIGHT)]:
            (self.user / name).write_text(json.dumps({'state': 'complete', 'version': '0.4.0',
                'installed': False, 'runtime_verified': False,
                'artifacts': {n: pkg.identity.executable_identity(self.user / n) for n in names}}))
        bundle = self.kernel / 'ELANNativeProbe.kext'
        (bundle / 'Contents/MacOS').mkdir(parents=True)
        (bundle / 'Contents/MacOS/ELANNativeProbe').write_bytes(binary(11))
        (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': pkg.identity.IDENTIFIER,
            'CFBundleExecutable': 'ELANNativeProbe', 'CFBundleVersion': '0.4.0', 'CFBundleShortVersionString': '0.4.0'}))
        (self.kernel / 'kernel-identity.json').write_text(json.dumps(pkg.identity.artifact_identity(bundle, '0.4.0')))
        (self.kernel / 'elan-native-probe').write_bytes(binary(2))
        self.signature = patch.object(pkg, 'verify_signature')
        self.signature.start()
        self.addCleanup(self.signature.stop)

    def stage(self):
        return pkg.stage(self.user, self.kernel, self.out)

    def test_complete_staging_and_map(self):
        record = self.stage()
        self.assertEqual(record['state'], 'staged')
        self.assertFalse(record['apply_ready'])
        self.assertFalse(record['installed'])
        self.assertEqual(len(record['artifacts']), 12)
        self.assertEqual(record['install_map']['kernel/ELANNativeProbe.kext/Contents/MacOS/ELANNativeProbe'],
                         'payload/native-kernel-probe-06/ELANNativeProbe.kext/Contents/MacOS/ELANNativeProbe')
        for name, digest in record['sha256'].items():
            self.assertEqual(hashlib.sha256((self.out / name).read_bytes()).hexdigest(), digest)
        self.assertFalse(any(n.startswith('manifests/') for n in record['install_map']))
        self.assertFalse(list(self.out.glob('*.command')))

    def test_packaged_update_modules_are_importable_without_commands(self):
        record = self.stage()
        with patch('subprocess.run', side_effect=AssertionError('import must not run commands')):
            for filename in ('native-current-update.py', 'native-fat-update.py', 'native-update-preflight.py',
                             'native-upgrade-plan.py', 'native-upgrade-files.py'):
                module = runpy.run_path(str(self.out / 'scripts' / filename), run_name='package_dependency_check')
                self.assertIn('__name__', module)
        self.assertIn('scripts/native-current-update.py', record['install_map'])
        self.assertIn('scripts/native-fat-update.py', record['install_map'])
        self.assertIn('OPERATIONS.txt', record['sha256'])
        self.assertNotIn('OPERATIONS.txt', record['install_map'])

    def test_output_cannot_be_overwritten(self):
        self.stage()
        before = (self.out / 'package.json').read_bytes()
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertEqual(before, (self.out / 'package.json').read_bytes())

    def test_changed_binary_rejected(self):
        (self.user / 'ELANNativeBroker').write_bytes(binary(2) + b'changed')
        with self.assertRaises(pkg.PackageError):
            self.stage()
        self.assertEqual(json.loads((self.out / 'package.json').read_text())['state'], 'incomplete')

    def test_stale_manifest_rejected(self):
        (self.user / 'worker-build.json').write_text('{"state":"incomplete"}')
        with self.assertRaises(pkg.PackageError):
            self.stage()

    def test_symlink_in_bundle_rejected(self):
        (self.user / 'ELANNativeProvider.app/foreign').symlink_to('/etc/hosts')
        with self.assertRaises(pkg.PackageError):
            self.stage()

    def test_wrong_kernel_identity_rejected(self):
        (self.kernel / 'ELANNativeProbe.kext/Contents/MacOS/ELANNativeProbe').write_bytes(binary(11) + b'changed')
        with self.assertRaises(pkg.identity.IdentityError):
            self.stage()

    def test_signature_failure_leaves_incomplete(self):
        with patch.object(pkg, 'verify_signature', side_effect=RuntimeError('signature')):
            with self.assertRaises(RuntimeError):
                self.stage()
        self.assertEqual(json.loads((self.out / 'package.json').read_text())['state'], 'incomplete')


if __name__ == '__main__':
    unittest.main()
