import hashlib
import uuid
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module; spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
f = load('native_upgrade_files', HERE / 'native-upgrade-files.py')
u = f.plan
m = load('native_upgrade_files_efi', HERE / 'kernel-provider/manage-efi.py')


def release(version):
    kernel = {'Contents/Info.plist': plistlib.dumps({'CFBundleVersion': version}),
              'Contents/MacOS/ELANNativeProbe': (struct.pack('<8I', 0xfeedfacf, 0x01000007, 3, 11, 1, 24, 0, 0) + struct.pack('<2I', 0x1b, 24) + uuid.uuid5(uuid.NAMESPACE_DNS, version).bytes)}
    broker = ('broker-' + version).encode()
    return u.Release.verified(version, kernel, broker, u.kernel_digest(kernel), hashlib.sha256(broker).hexdigest())


def real_releases():
    build = HERE.parents[1] / 'elan-fingerprint-macos/build/research'
    releases = {}
    for version, package, label in [('0.4.0', 'settings-kernel-diagnostic-041-r2', 'original'),
                                    ('0.4.1', 'settings-kernel-diagnostic-041-r2', 'candidate'),
                                    ('0.4.2', 'settings-kernel-diagnostic-042', 'candidate')]:
        root = build / package
        manifest = json.loads((root / 'manifest.json').read_text())
        kernel = m.bundle_files(root / label / 'ELANNativeProbe.kext')
        for name, data in kernel.items():
            expected = manifest['sha256'][label + '/ELANNativeProbe.kext/' + name]
            if hashlib.sha256(data).hexdigest() != expected: raise ValueError('Real payload changed')
        broker_name = 'ELANNativeBroker-original' if label == 'original' else 'ELANNativeBroker-fixed'
        broker = (root / broker_name).read_bytes()
        releases[version] = u.Release.verified(version, kernel, broker, u.kernel_digest(kernel), manifest['sha256'][broker_name])
    return releases


class UpgradeFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('ELAN_FAT_TEST_ROOT'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.releases = {version: release(version) for version in ('0.4.0', '0.4.1', '0.4.2')}
        self.backend = f.TestFilesystemBackend.initialize(self.root, self.releases['0.4.1'], m.bundle_files)

    def plan(self, action='upgrade', target='0.4.2'):
        return u.make_plan(action, self.backend.read_state(), self.releases, target)

    def add_sidecar(self):
        target = self.root / 'kernel/Contents/Info.plist'
        side = target.with_name('._' + target.name)
        if os.environ.get('ELAN_FAT_TEST_ROOT'):
            subprocess.run(['/usr/bin/xattr', '-w', 'com.example.elan-offline-sidecar', 'metadata', str(target)], check=True)
            return side, side.read_bytes()
        data = struct.pack('>II16sHIII', 0x51607, 0x20000, bytes(16), 1, 9, 38, 32) + bytes(32)
        side.write_bytes(data)
        return side, data

    def assert_source(self):
        state = self.backend.read_state(); original = self.releases['0.4.1']
        self.assertEqual((state.disk_version, state.kernel_hash, state.broker_hash),
                         ('0.4.1', original.kernel_hash, original.broker_hash))

    def test_same_version_runtime_identity_mismatch_and_missing_rejected(self):
        path = self.root / 'runtime.json'
        original = json.loads(path.read_text())
        for value in ('', self.releases['0.4.2'].kernel_uuid):
            path.write_text(json.dumps(dict(original, loaded_uuid=value)))
            with self.assertRaises(u.PlanError): self.plan(target='0.4.1')
            self.assertEqual(self.backend.events, [])
        original.pop('loaded_uuid')
        path.write_text(json.dumps(original))
        with self.assertRaises(u.PlanError): self.plan()

    def test_receipt_binds_source_target_loaded_and_disk_identity(self):
        source = self.releases['0.4.1']; target = self.releases['0.4.2']
        u.execute(self.plan(), self.backend)
        receipt, = (self.root / 'receipts').glob('*.json')
        record = json.loads(receipt.read_text())
        self.assertEqual(record['source_uuid'], source.kernel_uuid)
        self.assertEqual(record['loaded_uuid'], source.kernel_uuid)
        self.assertEqual(record['target_uuid'], target.kernel_uuid)
        self.assertEqual(record['disk_uuid'], target.kernel_uuid)
        with zipfile.ZipFile(self.backend.last_backup) as backup:
            self.assertEqual(json.loads(backup.read('files/runtime.json'))['loaded_uuid'], source.kernel_uuid)

    def test_direct_upgrade_then_explicit_stable_rollback(self):
        before = plistlib.loads((self.root / 'config.plist').read_bytes())
        result = u.execute(self.plan(), self.backend)
        self.assertTrue(result.reboot_required)
        state = self.backend.read_state(); self.assertEqual(state.loaded_version, '0.4.1'); self.assertEqual(state.disk_version, '0.4.2')
        self.assertEqual(plistlib.loads((self.root / 'config.plist').read_bytes())['Unrelated'], before['Unrelated'])
        with self.assertRaises(u.PlanError): self.plan('rollback', None)
        (self.root / 'runtime.json').write_text(json.dumps({'loaded_version': '0.4.2', 'loaded_uuid': self.releases['0.4.2'].kernel_uuid, 'boot_id': 'test-boot-2', 'idle': True}))
        u.execute(self.plan('rollback', None), self.backend)
        self.assertEqual(self.backend.read_state().disk_version, '0.4.0')

    def test_each_write_boundary_recovers_upgrade_source(self):
        components = ['broker:broker', 'kernel:kernel/Contents/Info.plist',
                      'kernel:kernel/Contents/MacOS/ELANNativeProbe', 'kernel:config.plist']
        for position in ('before_replace:', 'after_replace:'):
            for component in components:
                with self.subTest(point=position + component):
                    fired = []
                    def fault(point, backend):
                        if point == position + component and not fired:
                            fired.append(True); raise OSError('injected operation failure')
                    self.backend.fault = fault
                    with self.assertRaises(u.TransactionError) as result: u.execute(self.plan(), self.backend)
                    self.assertTrue(fired)
                    self.assertTrue(result.exception.rollback_complete)
                    self.assert_source()

    def test_keyboard_interrupt_each_forward_phase_recovers_source(self):
        components = ['broker:broker', 'kernel:kernel/Contents/Info.plist',
                      'kernel:kernel/Contents/MacOS/ELANNativeProbe', 'kernel:config.plist']
        for position in ('before_replace:', 'after_replace:'):
            for component in components:
                with self.subTest(point=position + component):
                    fired = []
                    def fault(point, backend):
                        if point == position + component and not fired:
                            fired.append(True); raise KeyboardInterrupt('injected cancellation')
                    self.backend.fault = fault
                    with self.assertRaises(u.TransactionError) as result: u.execute(self.plan(), self.backend)
                    self.assertTrue(fired); self.assertTrue(result.exception.rollback_complete)
                    self.assert_source()

    def test_keyboard_interrupt_during_backup_has_no_upgrade_writes(self):
        before = self.backend.read_state()
        def fault(point, backend):
            if point == 'backup_written': raise KeyboardInterrupt('backup cancelled')
        self.backend.fault = fault
        with self.assertRaises(u.TransactionError) as result: u.execute(self.plan(), self.backend)
        self.assertTrue(result.exception.rollback_complete); self.assertEqual(self.backend.read_state(), before)

    def test_receipt_errors_preserve_committed_kernel_and_broker(self):
        for point in ('before_receipt', 'after_receipt'):
            for error in (OSError, KeyboardInterrupt):
                with self.subTest(point=point, error=error):
                    with tempfile.TemporaryDirectory(dir=os.environ.get('ELAN_FAT_TEST_ROOT')) as directory:
                        backend = f.TestFilesystemBackend.initialize(directory, self.releases['0.4.1'], m.bundle_files)
                        def fault(name, value):
                            if name == point: raise error('injected receipt failure')
                        backend.fault = fault
                        transaction = u.make_plan('upgrade', backend.read_state(), self.releases, '0.4.2')
                        result = u.execute(transaction, backend)
                        self.assertTrue(result.receipt_pending); self.assertTrue(result.reboot_required)
                        state = backend.read_state(); target = self.releases['0.4.2']
                        self.assertEqual((state.disk_version, state.kernel_hash, state.broker_hash),
                                         (target.version, target.kernel_hash, target.broker_hash))

    def test_keyboard_interrupt_each_local_recovery_phase_is_pending(self):
        components = ['config.plist', 'kernel/Contents/MacOS/ELANNativeProbe', 'kernel/Contents/Info.plist']
        for position in ('before_replace:', 'after_replace:'):
            for component in components:
                with self.subTest(point=position + component):
                    with tempfile.TemporaryDirectory(dir=os.environ.get('ELAN_FAT_TEST_ROOT')) as directory:
                        backend = f.TestFilesystemBackend.initialize(directory, self.releases['0.4.1'], m.bundle_files)
                        def fault(name, value):
                            if name == 'after_replace:kernel:config.plist': raise OSError('trigger local recovery')
                            if name == position + 'local_restore:' + component: raise KeyboardInterrupt('recovery cancelled')
                        backend.fault = fault
                        transaction = u.make_plan('upgrade', backend.read_state(), self.releases, '0.4.2')
                        with self.assertRaises(u.TransactionError) as result: u.execute(transaction, backend)
                        self.assertFalse(result.exception.rollback_complete); self.assertTrue(result.exception.pending)
                        self.assertTrue(backend.last_backup.is_file())

    def test_backup_archives_payload_metadata_and_config(self):
        side, data = self.add_sidecar()
        before = self.backend._snapshot()
        u.execute(self.plan(), self.backend)
        with zipfile.ZipFile(self.backend.last_backup) as backup:
            saved = json.loads(backup.read('manifest.json'))
            self.assertEqual(saved, f._manifest(before))
            for name, record in before.items():
                if 'data' in record: self.assertEqual(backup.read('files/' + name), record['data'])
            self.assertEqual(backup.read('files/kernel/Contents/._Info.plist'), data)

    def test_backup_corruption_never_writes_managed_state(self):
        before = self.backend.read_state()
        def fault(point, backend):
            if point == 'backup_written': backend.last_backup.write_bytes(b'broken zip')
        self.backend.fault = fault
        with self.assertRaises(u.TransactionError) as result: u.execute(self.plan(), self.backend)
        self.assertTrue(result.exception.rollback_complete)
        self.assertIsInstance(result.exception.__cause__, zipfile.BadZipFile)
        self.assertEqual(self.backend.read_state(), before)

    def test_foreign_config_change_preserved(self):
        def fault(point, backend):
            if point == 'before_replace:kernel:kernel/Contents/Info.plist':
                config = plistlib.loads((self.root / 'config.plist').read_bytes()); config['Unrelated'] = 'foreign'
                (self.root / 'config.plist').write_bytes(plistlib.dumps(config))
        self.backend.fault = fault
        with self.assertRaises(u.TransactionError) as result: u.execute(self.plan(), self.backend)
        self.assertFalse(result.exception.rollback_complete)
        self.assertEqual(plistlib.loads((self.root / 'config.plist').read_bytes())['Unrelated'], 'foreign')

    def test_foreign_file_after_partial_step_preserved(self):
        foreign = self.root / 'kernel/unknown'
        def fault(point, backend):
            if point == 'after_replace:kernel:kernel/Contents/Info.plist': foreign.write_bytes(b'keep')
        self.backend.fault = fault
        with self.assertRaises(u.TransactionError) as result: u.execute(self.plan(), self.backend)
        self.assertFalse(result.exception.rollback_complete); self.assertEqual(foreign.read_bytes(), b'keep')

    @unittest.skipUnless(sys.platform == 'darwin', 'Uses the macOS xattr utility')
    def test_native_xattr_change_invalidates_plan_and_is_archived(self):
        path = self.root / 'broker'
        subprocess.run(['/usr/bin/xattr', '-w', 'com.example.elan-offline-test', 'first', str(path)], check=True)
        pending = self.plan()
        self.backend.backup(pending.before)
        with zipfile.ZipFile(self.backend.last_backup) as saved:
            metadata = json.loads(saved.read('manifest.json'))
            self.assertEqual(metadata['broker']['xattrs']['com.example.elan-offline-test'], b'first'.hex())
            if (self.root / '._broker').exists():
                self.assertEqual(saved.read('files/._broker'), (self.root / '._broker').read_bytes())
        subprocess.run(['/usr/bin/xattr', '-w', 'com.example.elan-offline-test', 'second', str(path)], check=True)
        with self.assertRaises(u.ConcurrentChange): u.execute(pending, self.backend)

    def test_stat_metadata_change_invalidates_plan(self):
        pending = self.plan(); path = self.root / 'kernel/Contents/Info.plist'; st = path.stat()
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000_000))
        with self.assertRaises(u.ConcurrentChange): u.execute(pending, self.backend)
        self.assertEqual(self.backend.events, [])

    def test_appledouble_change_invalidates_plan(self):
        side, data = self.add_sidecar()
        pending = self.plan(); side.write_bytes(data[:-1] + b'1')
        with self.assertRaises(u.ConcurrentChange): u.execute(pending, self.backend)
        self.assertEqual(side.read_bytes(), data[:-1] + b'1')

    def test_local_restore_failure_preserves_incomplete_state(self):
        def fault(point, backend):
            if point in ('after_replace:kernel:config.plist', 'before_replace:local_restore:config.plist'):
                raise OSError('injected recovery fault')
        self.backend.fault = fault
        with self.assertRaises(u.TransactionError) as result: u.execute(self.plan(), self.backend)
        self.assertFalse(result.exception.rollback_complete)
        self.assertEqual(self.backend.read_state().disk_version, '0.4.2')

    def test_non_test_root_and_missing_marker_rejected(self):
        with self.assertRaises(ValueError): f.TestFilesystemBackend('/Library', m.bundle_files)
        (self.root / '.offline-test').write_bytes(b'wrong')
        with self.assertRaises(ValueError): self.backend.read_state()

    @unittest.skipIf(bool(os.environ.get('ELAN_FAT_TEST_ROOT')), 'FAT cannot create symbolic links')
    def test_symlink_never_followed(self):
        target = self.root / 'kernel/Contents/Info.plist'; target.unlink(); target.symlink_to(self.root / 'config.plist')
        with self.assertRaises(ValueError): self.backend.read_state()

    def test_real_packaged_payload_direct_upgrade_and_failure_recovery(self):
        releases = real_releases()
        with tempfile.TemporaryDirectory(dir=os.environ.get('ELAN_FAT_TEST_ROOT')) as directory:
            backend = f.TestFilesystemBackend.initialize(directory, releases['0.4.1'], m.bundle_files)
            original = backend.read_state()
            def fail(point, value):
                if point == 'after_replace:kernel:config.plist': raise OSError('real-payload injected failure')
            backend.fault = fail
            pending = u.make_plan('upgrade', original, releases, '0.4.2')
            with self.assertRaises(u.TransactionError) as result: u.execute(pending, backend)
            self.assertTrue(result.exception.rollback_complete)
            state = backend.read_state(); self.assertEqual(state.disk_version, '0.4.1')
            self.assertEqual((state.kernel_hash, state.broker_hash), (original.kernel_hash, original.broker_hash))
            backend.fault = None
            u.execute(u.make_plan('upgrade', state, releases, '0.4.2'), backend)
            self.assertEqual(backend.read_state().kernel_hash, releases['0.4.2'].kernel_hash)


if __name__ == '__main__': unittest.main()
