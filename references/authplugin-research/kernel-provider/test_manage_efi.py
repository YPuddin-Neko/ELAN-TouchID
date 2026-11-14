import copy
import importlib.util
import io
import json
import plistlib
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('manage_efi', Path(__file__).with_name('manage-efi.py'))
manage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manage)


class EFIManagementTests(unittest.TestCase):
    def transaction_fixture(self, root):
        oc, package = root / 'EFI/OC', root / 'packages/native-kernel-probe-06'
        previous = package.parent / manage.PREVIOUS_PACKAGE
        for parent, version in [(previous, manage.PREVIOUS_VERSION), (oc / 'Kexts', manage.PREVIOUS_VERSION), (package, manage.VERSION)]:
            bundle = parent / manage.BUNDLE
            (bundle / 'Contents/MacOS').mkdir(parents=True)
            (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': manage.IDENTIFIER, 'CFBundleVersion': version}))
            (bundle / 'Contents/MacOS/ELANNativeProbe').write_bytes(version.encode())
        entry = dict(manage.ENTRY); entry['Comment'] = 'ELAN native credential interface probe ' + manage.PREVIOUS_VERSION
        config = {'Kernel': {'Add': [{'BundlePath': 'Lilu.kext', 'Enabled': True}, entry, {'BundlePath': 'ExistingUSB.kext', 'Enabled': True}]},
                  'NVRAM': {'Add': {'guid': {'boot-args': 'preserved=1'}}}}
        (oc / 'config.plist').write_bytes(plistlib.dumps(config))
        return oc, package, previous, config

    def test_failure_after_config_write_restores_only_owned_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oc, package, previous, original = self.transaction_fixture(root)
            real_write = manage.write_config
            calls = []
            def write_then_fail(path, before, candidate):
                real_write(path, before, candidate)
                calls.append(True)
                if len(calls) == 1:
                    current = plistlib.loads(path.read_bytes())
                    current['NVRAM']['Add']['guid']['boot-args'] += ' other-change=1'
                    path.write_bytes(plistlib.dumps(current))
                    raise OSError('readback failed')
            with patch.object(manage, 'locate', return_value=oc), patch.object(manage, 'PACKAGE', package), \
                    patch.object(manage, 'BACKUPS', root / 'backups'), patch.object(manage, 'write_config', side_effect=write_then_fail), \
                    redirect_stdout(io.StringIO()), self.assertRaisesRegex(OSError, 'readback failed'):
                manage.upgrade()
            original['NVRAM']['Add']['guid']['boot-args'] += ' other-change=1'
            self.assertEqual(plistlib.loads((oc / 'config.plist').read_bytes()), original)
            self.assertEqual(manage.bundle_files(oc / 'Kexts' / manage.BUNDLE), manage.bundle_files(previous / manage.BUNDLE))

    def test_partial_bundle_replacement_restores_both_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oc, package, previous, original = self.transaction_fixture(root)
            real_replace = manage.os.replace
            calls = []
            def fail_second(source, destination):
                calls.append(destination)
                if len(calls) == 2:
                    raise OSError('second file failed')
                real_replace(source, destination)
            with patch.object(manage, 'locate', return_value=oc), patch.object(manage, 'PACKAGE', package), \
                    patch.object(manage, 'BACKUPS', root / 'backups'), patch.object(manage.os, 'replace', side_effect=fail_second), \
                    redirect_stdout(io.StringIO()), self.assertRaisesRegex(OSError, 'second file failed'):
                manage.upgrade()
            self.assertEqual(plistlib.loads((oc / 'config.plist').read_bytes()), original)
            self.assertEqual(manage.bundle_files(oc / 'Kexts' / manage.BUNDLE), manage.bundle_files(previous / manage.BUNDLE))

    def test_install_remove_preserves_subsequent_other_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oc = root / 'EFI/OC'
            package = root / 'package'
            backups = root / 'Desktop/ELAN 指纹适配/备份'
            (oc / 'Kexts').mkdir(parents=True)
            bundle = package / manage.BUNDLE
            (bundle / 'Contents/MacOS').mkdir(parents=True)
            (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps({
                'CFBundleIdentifier': manage.IDENTIFIER, 'CFBundleVersion': manage.VERSION}))
            (bundle / 'Contents/MacOS/ELANNativeProbe').write_bytes(b'fixture-kext')
            original = {'Kernel': {'Add': [{'BundlePath': 'Lilu.kext', 'Enabled': True},
                                          {'BundlePath': 'ExistingUSB.kext', 'Enabled': True}]},
                        'Misc': {'Debug': {'Target': 3}},
                        'NVRAM': {'Add': {'fixture-guid': {'boot-args': 'existing=1'}}}}
            path = oc / 'config.plist'
            original_bytes = plistlib.dumps(original)
            path.write_bytes(original_bytes)
            with patch.object(manage, 'locate', return_value=oc), patch.object(manage, 'PACKAGE', package), \
                    patch.object(manage, 'BACKUPS', backups), redirect_stdout(io.StringIO()):
                with patch('sys.argv', ['manage-efi.py', 'prepare']):
                    manage.main()
                self.assertEqual(path.read_bytes(), original_bytes)
                self.assertFalse((oc / 'Kexts' / manage.BUNDLE).exists())
                with patch('sys.argv', ['manage-efi.py', 'apply']):
                    manage.main()
                installed = plistlib.loads(path.read_bytes())
                self.assertEqual(manage.remove_entry(installed), original)
                self.assertEqual((oc / 'Kexts' / manage.BUNDLE / 'Contents/MacOS/ELANNativeProbe').read_bytes(), b'fixture-kext')
                installed['NVRAM']['Add']['fixture-guid']['boot-args'] += ' later=1'
                installed['Kernel']['Add'].append({'BundlePath': 'LaterDriver.kext', 'Enabled': True})
                path.write_bytes(plistlib.dumps(installed))
                expected = manage.remove_entry(installed)
                with patch('sys.argv', ['manage-efi.py', 'remove']):
                    manage.main()
                self.assertEqual(plistlib.loads(path.read_bytes()), expected)
                self.assertFalse((oc / 'Kexts' / manage.BUNDLE).exists())
                receipts = list(backups.glob('*/receipt.json'))
                self.assertEqual(len(receipts), 2)
                self.assertEqual(set(p.name for p in oc.iterdir()), {'config.plist', 'Kexts'})
                self.assertTrue(all(json.loads(p.read_text())['other_configuration_preserved'] for p in receipts))

    def test_conflicting_config_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.plist'
            changed = plistlib.dumps({'other-work': True})
            path.write_bytes(changed)
            with self.assertRaisesRegex(RuntimeError, 'changed during preparation'):
                manage.write_config(path, b'old configuration', {'replacement': True})
            self.assertEqual(path.read_bytes(), changed)

    def test_modified_probe_entry_requires_review(self):
        changed = copy.deepcopy(manage.ENTRY)
        changed['Enabled'] = False
        config = {'Kernel': {'Add': [changed]}}
        with self.assertRaisesRegex(RuntimeError, 'differs from this package'):
            manage.remove_entry(config)

    def test_upgrade_and_remove_preserve_other_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oc = root / 'EFI/OC'
            package = root / 'packages/native-kernel-probe-06'
            previous = root / 'packages' / manage.PREVIOUS_PACKAGE
            backups = root / 'Desktop/ELAN 指纹适配/备份'
            old_entry = copy.deepcopy(manage.ENTRY)
            old_entry['Comment'] = 'ELAN native credential interface probe ' + manage.PREVIOUS_VERSION
            original = {'Kernel': {'Add': [{'BundlePath': 'Lilu.kext', 'Enabled': True}, old_entry,
                                          {'BundlePath': 'OtherUSB.kext', 'Enabled': True}]},
                        'NVRAM': {'Add': {'guid': {'boot-args': 'other=1'}}}}
            for parent, version in [(previous, manage.PREVIOUS_VERSION), (oc / 'Kexts', manage.PREVIOUS_VERSION), (package, manage.VERSION)]:
                bundle = parent / manage.BUNDLE
                (bundle / 'Contents/MacOS').mkdir(parents=True)
                (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps({
                    'CFBundleIdentifier': manage.IDENTIFIER, 'CFBundleVersion': version}))
                (bundle / 'Contents/MacOS/ELANNativeProbe').write_bytes(version.encode())
            config_path = oc / 'config.plist'
            config_path.write_bytes(plistlib.dumps(original))
            old_files = manage.bundle_files(previous / manage.BUNDLE)
            with patch.object(manage, 'locate', return_value=oc), patch.object(manage, 'PACKAGE', package), \
                    patch.object(manage, 'BACKUPS', backups), redirect_stdout(io.StringIO()):
                original_bytes = config_path.read_bytes()
                manage.upgrade(prepare_only=True)
                self.assertEqual(config_path.read_bytes(), original_bytes)
                self.assertEqual(manage.bundle_files(oc / 'Kexts' / manage.BUNDLE), old_files)
                self.assertFalse(backups.exists())
                manage.upgrade()
                upgraded = plistlib.loads(config_path.read_bytes())
                self.assertEqual(upgraded['Kernel']['Add'][1], manage.ENTRY)
                upgraded['Kernel']['Add'][1] = old_entry
                self.assertEqual(upgraded, original)
                self.assertEqual(manage.bundle_files(oc / 'Kexts' / manage.BUNDLE), manage.bundle_files(package / manage.BUNDLE))
                saved = next(backups.iterdir())
                self.assertEqual(manage.bundle_files(saved / manage.BUNDLE), old_files)
                later = plistlib.loads(config_path.read_bytes())
                later['NVRAM']['Add']['guid']['boot-args'] += ' later=1'
                later['Kernel']['Add'].append({'BundlePath': 'LaterUSB.kext', 'Enabled': True})
                config_path.write_bytes(plistlib.dumps(later))
                before_rollback = config_path.read_bytes()
                manage.upgrade(prepare_only=True, rollback=True)
                self.assertEqual(config_path.read_bytes(), before_rollback)
                manage.upgrade(rollback=True)
                expected_restored = copy.deepcopy(later)
                expected_restored['Kernel']['Add'][1] = old_entry
                self.assertEqual(plistlib.loads(config_path.read_bytes()), expected_restored)
                self.assertEqual(manage.bundle_files(oc / 'Kexts' / manage.BUNDLE), old_files)
                manage.upgrade()
                with patch('sys.argv', ['manage-efi.py', 'remove']):
                    manage.main()
                expected = copy.deepcopy(expected_restored)
                expected['Kernel']['Add'].remove(old_entry)
                self.assertEqual(plistlib.loads(config_path.read_bytes()), expected)


if __name__ == '__main__':
    unittest.main()
