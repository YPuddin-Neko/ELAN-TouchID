import io
import os
import struct
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from test_manage_efi import manage
import test_manage_efi as base


def metadata():
    return struct.pack('>II16sHIII', 0x51607, 0x20000, b'Mac OS X        ', 1, 9, 38, 32) + bytes(32)


class AppleDoubleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('ELAN_FAT_TEST_ROOT'))
        self.addCleanup(self.tmp.cleanup)
        self.backups = tempfile.TemporaryDirectory()
        self.addCleanup(self.backups.cleanup)
        self.root = Path(self.tmp.name)
        self.oc, self.package, self.previous, self.config = base.EFIManagementTests().transaction_fixture(self.root)
        self.installed = self.oc / 'Kexts' / manage.BUNDLE
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        for name, value in [('locate', lambda: self.oc), ('PACKAGE', self.package), ('BACKUPS', Path(self.backups.name))]:
            self.stack.enter_context(patch.object(manage, name, value))
        self.stack.enter_context(redirect_stdout(io.StringIO()))

    def add_metadata(self):
        for name in ['Contents/Info.plist', 'Contents/MacOS/ELANNativeProbe']:
            file = self.installed / name
            if os.environ.get('ELAN_FAT_TEST_ROOT'):
                subprocess.run(['/usr/bin/xattr', '-w', 'com.example.elan-fat-test', 'retained', str(file)], check=True)
            else:
                file.with_name('._' + file.name).write_bytes(metadata())

    def test_valid_metadata_excluded_from_payload_but_archived(self):
        self.add_metadata(); before = manage.bundle_snapshot(self.installed)
        self.assertEqual(manage.bundle_files(self.installed), manage.bundle_files(self.previous / manage.BUNDLE))
        manage.upgrade()
        saved = next(Path(self.backups.name).iterdir())
        self.assertEqual(manage.bundle_snapshot(saved / manage.BUNDLE), before)
        manage.upgrade(rollback=True)
        self.assertEqual(manage.bundle_files(self.installed), manage.bundle_files(self.previous / manage.BUNDLE))

    def test_metadata_created_during_replacement_no_false_failure(self):
        replace = manage.replace_bundle_files
        def wrapped(destination, contents):
            replace(destination, contents); self.add_metadata()
        with patch.object(manage, 'replace_bundle_files', side_effect=wrapped):
            manage.upgrade(); manage.upgrade(rollback=True)
        self.assertEqual(manage.bundle_files(self.installed), manage.bundle_files(self.previous / manage.BUNDLE))

    def test_config_failure_with_new_metadata_rolls_back(self):
        replace = manage.replace_bundle_files
        def wrapped(destination, contents):
            replace(destination, contents); self.add_metadata()
        with patch.object(manage, 'replace_bundle_files', side_effect=wrapped), patch.object(manage, 'write_config', side_effect=OSError('injected config error')):
            with self.assertRaisesRegex(OSError, 'injected config error'): manage.upgrade()
        self.assertEqual(manage.bundle_files(self.installed), manage.bundle_files(self.previous / manage.BUNDLE))

    def test_failed_backup_does_not_replace(self):
        before = manage.bundle_files(self.installed)
        with patch.object(manage, 'archive_bundle', side_effect=OSError('backup failed')):
            with self.assertRaises(OSError): manage.upgrade()
        self.assertEqual(manage.bundle_files(self.installed), before)

    def test_unknown_payload_preserved(self):
        unknown = self.installed / 'unexpected'; unknown.write_bytes(b'keep')
        with self.assertRaises(RuntimeError): manage.upgrade()
        self.assertEqual(unknown.read_bytes(), b'keep')

    def test_unknown_payload_during_failure_not_overwritten(self):
        real = manage.replace_bundle_files
        def changed(destination, contents):
            real(destination, contents)
            (destination / 'unexpected').write_bytes(b'keep')
            raise OSError('injected')
        with patch.object(manage, 'replace_bundle_files', side_effect=changed):
            with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'): manage.upgrade()
        self.assertEqual((self.installed / 'unexpected').read_bytes(), b'keep')

    def test_malformed_sidecar_rejected(self):
        side = self.installed / 'Contents/._Info.plist'; side.write_bytes(b'not metadata')
        with self.assertRaisesRegex(RuntimeError, 'malformed AppleDouble'): manage.upgrade()
        self.assertEqual(side.read_bytes(), b'not metadata')

    def test_orphan_sidecar_rejected(self):
        side = self.installed / '._missing'; side.write_bytes(metadata())
        with self.assertRaises(RuntimeError): manage.bundle_files(self.installed)

    def test_parser_rejects_malformed_ranges(self):
        good = metadata(); self.assertTrue(manage.valid_appledouble(good))
        for size in [0, 25, 26, 37, 69]: self.assertFalse(manage.valid_appledouble(good[:size]))
        for offset, value in [(0, 0), (4, 0), (26, 0), (30, 0), (30, 71), (34, 33)]:
            bad = bytearray(good); struct.pack_into('>I', bad, offset, value)
            self.assertFalse(manage.valid_appledouble(bad))
        for count in [0, 17]:
            bad = bytearray(good); struct.pack_into('>H', bad, 24, count)
            self.assertFalse(manage.valid_appledouble(bad))
        for second in [(9, 82, 32), (2, 65, 32)]:
            bad = struct.pack('>II16sH', 0x51607, 0x20000, bytes(16), 2) + struct.pack('>III', 9, 50, 32) + struct.pack('>III', *second) + bytes(64)
            self.assertFalse(manage.valid_appledouble(bad))

if __name__ == '__main__': unittest.main()
