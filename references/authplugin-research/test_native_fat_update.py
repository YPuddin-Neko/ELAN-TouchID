import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('native_fat', Path(__file__).with_name('native-fat-update.py'))
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
TOKEN = 'a' * 64

class FATUpdateTests(unittest.TestCase):
    def setUp(self):
        self.local = tempfile.TemporaryDirectory(); self.addCleanup(self.local.cleanup)
        self.localroot = Path(self.local.name).resolve()
        self.external = tempfile.TemporaryDirectory(dir=os.environ.get('ELAN_FAT_TEST_ROOT')); self.addCleanup(self.external.cleanup)
        self.oc = Path(self.external.name).resolve() / 'EFI/OC'; (self.oc / 'Kexts/ELANNativeProbe.kext/Contents/MacOS').mkdir(parents=True)
        self.source = self.oc / 'Kexts/ELANNativeProbe.kext'
        (self.source / 'Contents/MacOS/ELANNativeProbe').write_bytes(b'original kernel fixture')
        (self.source / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleVersion': '0.4.0'}))
        entry = {'Arch': 'x86_64', 'BundlePath': 'ELANNativeProbe.kext', 'Comment': 'ELAN native credential interface probe 0.4.0', 'Enabled': True,
                 'ExecutablePath': 'Contents/MacOS/ELANNativeProbe', 'MaxKernel': '24.6.0', 'MinKernel': '24.6.0', 'PlistPath': 'Contents/Info.plist'}
        self.config = plistlib.dumps({'Kernel': {'Add': [entry]}, 'Unrelated': {'BootArgs': 'preserve'}})
        (self.oc / 'config.plist').write_bytes(self.config)
        self.candidate = self.localroot / 'candidate'; shutil.copytree(self.source, self.candidate)
        (self.candidate / 'Contents/MacOS/ELANNativeProbe').write_bytes(b'candidate kernel fixture')
        self.txn = self.localroot / 'transaction'
        self.guards = 0
        self.t = f.Transaction(self.oc, self.txn, self.guard, allow_same_device=not bool(os.environ.get('ELAN_FAT_TEST_ROOT')))
        self.original = f.snapshot(self.source)

    def guard(self): self.guards += 1
    def prepare(self): return self.t.prepare(self.candidate, TOKEN)

    def test_update_and_rollback_preserve_original_bundle_and_unrelated_config(self):
        record = self.prepare(); result = self.t.resume(TOKEN)
        self.assertEqual(result['state'], 'committed'); self.assertFalse(result['power_loss_safe'])
        current = plistlib.loads((self.oc / 'config.plist').read_bytes()); previous = plistlib.loads(self.config)
        self.assertNotEqual(current['Kernel']['Add'][0]['BundlePath'], 'ELANNativeProbe.kext')
        current['Kernel']['Add'][0]['BundlePath'] = 'ELANNativeProbe.kext'; self.assertEqual(current, previous)
        self.assertEqual(f.snapshot(self.source), self.original)
        self.assertEqual(self.t.rollback(TOKEN)['state'], 'rolled_back')
        self.assertEqual((self.oc / 'config.plist').read_bytes(), self.config)
        self.assertEqual(f.snapshot(self.source), self.original)
        self.assertTrue((self.oc / 'Kexts' / record['target_name']).is_dir())

    def test_each_named_interruption_resumes_using_observed_state(self):
        self.prepare()
        for point in ('before_stage', 'staged', 'publish_intent', 'published', 'committed'):
            with self.subTest(point=point):
                def fault(name):
                    if name == point: raise KeyboardInterrupt()
                self.t.fault = fault
                with self.assertRaises(KeyboardInterrupt): self.t.resume(TOKEN)
                self.t.fault = None
                self.assertEqual(self.t.resume(TOKEN)['state'], 'committed')
                self.t.rollback(TOKEN)
                self.assertEqual(f.snapshot(self.source), self.original)

    def test_partial_file_write_leaves_only_orphan_and_can_resume(self):
        record = self.prepare()
        def partial(stream, data):
            stream.write(data[:3]); stream.flush(); raise KeyboardInterrupt()
        with patch.object(f, '_write_stream', side_effect=partial):
            with self.assertRaises(KeyboardInterrupt): self.t.resume(TOKEN)
        self.assertEqual((self.oc / 'config.plist').read_bytes(), self.config)
        self.assertTrue(list((self.oc / 'Kexts').glob('.elan-fat-copy-*')))
        self.assertEqual(self.t.resume(TOKEN)['state'], 'committed')
        self.assertEqual(f.snapshot(self.source), self.original)

    def test_receipt_write_failure_after_publication_can_resume(self):
        self.prepare(); save = self.t.save
        def fail(record):
            if record['phase'] == 'committed': raise OSError('receipt failure')
            save(record)
        self.t.save = fail
        with self.assertRaises(OSError): self.t.resume(TOKEN)
        self.t.save = save
        self.assertEqual(self.t.resume(TOKEN)['state'], 'committed')

    def test_unknown_config_or_candidate_preserved(self):
        record = self.prepare(); (self.oc / 'config.plist').write_bytes(b'foreign')
        for operation in (self.t.resume, self.t.rollback):
            with self.assertRaisesRegex(f.FATUpdateError, 'unknown_config'): operation(TOKEN)
        self.assertEqual((self.oc / 'config.plist').read_bytes(), b'foreign')
        (self.oc / 'config.plist').write_bytes(self.config)
        target = self.oc / 'Kexts' / record['target_name']; target.mkdir(); (target / 'unknown').write_bytes(b'foreign')
        with self.assertRaisesRegex(f.FATUpdateError, 'unknown_candidate'): self.t.resume(TOKEN)
        self.assertEqual((target / 'unknown').read_bytes(), b'foreign')
        self.assertEqual(self.t.rollback(TOKEN)['state'], 'rolled_back')

    def test_case_variant_duplicate_entry_rejected(self):
        value = plistlib.loads(self.config); duplicate = dict(value['Kernel']['Add'][0]); duplicate['BundlePath'] = 'elannativeprobe.kext'
        value['Kernel']['Add'].append(duplicate); (self.oc / 'config.plist').write_bytes(plistlib.dumps(value))
        with self.assertRaisesRegex(f.FATUpdateError, 'ambiguous'): self.prepare()
        self.assertFalse(self.txn.exists())

    def test_backup_corruption_and_changed_original_rejected(self):
        self.prepare(); (self.txn / 'config-before.plist').write_bytes(b'bad')
        with self.assertRaisesRegex(f.FATUpdateError, 'backup_changed'): self.t.resume(TOKEN)
        (self.txn / 'config-before.plist').write_bytes(self.config)
        (self.source / 'Contents/Info.plist').write_bytes(b'foreign')
        with self.assertRaisesRegex(f.FATUpdateError, 'original_bundle_changed'): self.t.resume(TOKEN)

    def test_rollback_interruption_and_idempotence(self):
        self.prepare(); self.t.resume(TOKEN)
        for point in ('rollback_intent', 'rolled_back_config'):
            def fail(name):
                if name == point: raise KeyboardInterrupt()
            self.t.fault = fail
            with self.assertRaises(KeyboardInterrupt): self.t.rollback(TOKEN)
            self.t.fault = None; self.assertEqual(self.t.rollback(TOKEN)['state'], 'rolled_back')
            self.assertEqual(self.t.rollback(TOKEN)['state'], 'rolled_back')
            self.t.resume(TOKEN)

    def test_valid_appledouble_is_preserved_and_malformed_rejected(self):
        # Raw sidecar fixture uses the existing validator; no Finder/xattr writes.
        data = struct.pack('>II16sHIII', 0x51607, 0x20000, bytes(16), 1, 9, 38, 4) + b'meta'
        (self.source / 'Contents/._Info.plist').write_bytes(data)
        self.original = f.snapshot(self.source)
        self.prepare(); self.t.resume(TOKEN); self.t.rollback(TOKEN)
        self.assertEqual((self.source / 'Contents/._Info.plist').read_bytes(), data)
        (self.source / 'Contents/._Info.plist').write_bytes(b'bad')
        with self.assertRaisesRegex(f.FATUpdateError, 'invalid_appledouble'): f.snapshot(self.source)

    def test_wrong_approval_and_independent_backup_requirement(self):
        self.prepare()
        with self.assertRaisesRegex(f.FATUpdateError, 'approval_required'): self.t.resume('b' * 64)
        if not os.environ.get('ELAN_FAT_TEST_ROOT'):
            with self.assertRaisesRegex(f.FATUpdateError, 'independent_backup'):
                f.Transaction(self.oc, self.localroot / 'other', self.guard)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS xattr fixture')
    def test_real_finderinfo_metadata_survives_publish_and_rollback(self):
        config = self.oc / 'config.plist'
        value = '5445585474747874' + '00' * 24
        subprocess.run(['/usr/bin/xattr', '-wx', 'com.apple.FinderInfo', value, str(config)], check=True)
        side = self.oc / '._config.plist'
        original_side = side.read_bytes() if side.exists() else None
        self.prepare(); self.t.resume(TOKEN)
        for _ in range(2):
            actual = subprocess.check_output(['/usr/bin/xattr', '-px', 'com.apple.FinderInfo', str(config)]).decode()
            self.assertEqual(''.join(actual.split()).lower(), value.lower())
            self.assertEqual(side.read_bytes() if side.exists() else None, original_side)
            self.t.rollback(TOKEN)

if __name__ == '__main__': unittest.main()
