import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('deployment', Path(__file__).with_name('native-provider-deployment.py'))
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)


class InstallationUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.package, self.install, self.oc = root / 'package', root / 'installed', root / 'EFI/OC'
        self.desktop = root / 'Desktop/ELAN 指纹适配'
        self.package.mkdir(); self.install.mkdir(); self.oc.mkdir(parents=True)
        (self.package / 'asset').write_bytes(b'candidate')
        (self.install / 'asset').write_bytes(b'previous')
        (self.install / 'history.json').write_text('old history')
        (self.oc / 'config.plist').write_bytes(b'previous EFI')
        self.module = Mock()
        self.module.locate.return_value = self.oc
        self.module.upgrade.side_effect = self.upgrade
        self.published = []
        for name, value in [('PACKAGE', self.package), ('INSTALL', self.install), ('DESKTOP', self.desktop), ('ASSETS', ['asset'])]:
            self.stack.enter_context(patch.object(deployment, name, value))
        for name in ['require_root', 'verify_signatures', 'require_kernel_artifact', 'secure_tree', 'previous_cleanup', 'namespace_preflight']:
            self.stack.enter_context(patch.object(deployment, name))
        self.stack.enter_context(patch.object(deployment.os, 'chown'))
        self.stack.enter_context(patch.object(deployment, 'publish', side_effect=self.publish))
        self.stack.enter_context(patch.object(deployment, 'environment', return_value={'boot_uuid': 'fixture'}))
        self.stack.enter_context(patch.object(deployment, 'loaded_version', return_value=deployment.PREVIOUS_VERSION))
        self.stack.enter_context(patch.object(deployment, 'efi', return_value=self.module))
        self.stack.enter_context(patch.object(deployment, 'verify_previous', side_effect=self.verify_previous))
        self.stack.enter_context(patch.object(deployment, 'previous_efi_matches', side_effect=lambda *_: (self.oc / 'config.plist').read_bytes() == b'previous EFI'))
        self.stack.enter_context(redirect_stdout(io.StringIO()))

    def verify_previous(self, root, package):
        if (root / 'asset').read_bytes() != b'previous':
            raise RuntimeError('previous installation differs')

    def publish(self, directory, label):
        self.published.append(json.loads((directory / 'result.json').read_text()))
        return 'fixture'

    def upgrade(self, prepare_only=False, rollback=False):
        if prepare_only:
            return
        (self.oc / 'config.plist').write_bytes(b'previous EFI' if rollback else b'candidate EFI')
        receipt = self.install / 'payload' / deployment.KERNEL_PACKAGE / 'upgrade-receipt.json'
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text(json.dumps({'version': deployment.VERSION, 'backup': 'fixture'}))

    def assert_previous(self):
        self.assertEqual((self.install / 'asset').read_bytes(), b'previous')
        self.assertEqual((self.install / 'history.json').read_text(), 'old history')
        self.assertEqual((self.oc / 'config.plist').read_bytes(), b'previous EFI')
        self.assertFalse(self.install.with_name(self.install.name + '.pending').exists())

    def test_copy_failure_preserves_previous_installation_and_efi(self):
        with patch.object(deployment.shutil, 'copy2', side_effect=OSError('copy failed')):
            with self.assertRaisesRegex(OSError, 'copy failed'):
                deployment.install()
        self.assert_previous()
        self.assertEqual(self.module.upgrade.call_args_list, [unittest.mock.call(prepare_only=True)])

    def test_namespace_failure_does_not_upgrade(self):
        with patch.object(deployment, 'namespace_preflight', side_effect=RuntimeError('routing failed')):
            with self.assertRaisesRegex(RuntimeError, 'routing failed'):
                deployment.install()
        self.assert_previous()
        self.assertFalse(self.published[-1]['installed'])
        self.assertFalse(self.published[-1]['efi_changed'])
        self.assertEqual(self.module.upgrade.call_args_list, [unittest.mock.call(prepare_only=True)])

    def test_failed_job_cleanup_retains_pending_records(self):
        def routing(study, root=None):
            study.jobs = ['gui/501/' + deployment.PREFIX + '1-1-fixture']
            deployment.save(study.directory / 'jobs.json', study.jobs)
            raise RuntimeError('routing failed')
        with patch.object(deployment, 'namespace_preflight', side_effect=routing), \
                patch.object(deployment, 'unload_job', side_effect=RuntimeError('job remains')):
            with self.assertRaisesRegex(RuntimeError, 'job remains'):
                deployment.install()
        pending = self.install.with_name(self.install.name + '.pending')
        self.assertTrue(next((pending / 'state').glob('*/jobs.json')).is_file())
        self.assertEqual((self.install / 'asset').read_bytes(), b'previous')

    def test_atomic_activation_failure_leaves_previous_in_place(self):
        with patch.object(deployment, 'swap_directories', side_effect=OSError('swap failed')):
            with self.assertRaisesRegex(OSError, 'swap failed'):
                deployment.install()
        self.assert_previous()

    def test_upgrade_error_after_efi_write_restores_previous_helpers(self):
        def fail(prepare_only=False, rollback=False):
            self.upgrade(prepare_only, rollback)
            if not prepare_only and not rollback:
                raise OSError('receipt failed')
        self.module.upgrade.side_effect = fail
        with self.assertRaisesRegex(OSError, 'receipt failed'):
            deployment.install()
        self.assert_previous()
        record = json.loads(next((self.desktop / '备份').glob('*/failed-upgrade.json')).read_text())
        self.assertTrue(record['previous_restored'])
        self.assertFalse(record['efi_changed'])
        self.assertEqual(self.module.upgrade.call_args_list[-1], unittest.mock.call(rollback=True))

    def test_rollback_receipt_error_uses_actual_efi_readback(self):
        def fail(prepare_only=False, rollback=False):
            self.upgrade(prepare_only, rollback)
            if not prepare_only:
                raise OSError('receipt failed')
        self.module.upgrade.side_effect = fail
        with self.assertRaisesRegex(OSError, 'receipt failed'):
            deployment.install()
        self.assert_previous()

    def test_incomplete_efi_rollback_retains_recovery_helpers_and_backup(self):
        def fail(prepare_only=False, rollback=False):
            if rollback:
                raise OSError('EFI unavailable')
            self.upgrade(prepare_only, rollback)
            if not prepare_only:
                raise OSError('receipt failed')
        self.module.upgrade.side_effect = fail
        with self.assertRaisesRegex(OSError, 'receipt failed'):
            deployment.install()
        self.assertEqual((self.install / 'asset').read_bytes(), b'candidate')
        self.assertEqual((self.install.with_name(self.install.name + '.pending') / 'asset').read_bytes(), b'previous')
        record = json.loads((self.install / 'installation.json').read_text())
        self.assertTrue(record['efi_changed'])
        self.assertFalse(record['previous_restored'])
        self.assertEqual((Path(record['previous_installation']) / 'asset').read_bytes(), b'previous')

    def test_success_and_rollback_restore_exact_previous_installation(self):
        deployment.install()
        self.assertEqual((self.install / 'asset').read_bytes(), b'candidate')
        record = json.loads((self.install / 'installation.json').read_text())
        self.assertTrue(record['installed'] and record['reboot_required'])
        self.assertEqual((Path(record['previous_installation']) / 'asset').read_bytes(), b'previous')
        with patch.object(deployment, 'cleanup'):
            deployment.rollback()
        self.assert_previous()
        self.assertTrue(next((self.desktop / '备份').glob('ELAN-native-withdrawn-*')).is_dir())

    def test_changed_previous_installation_is_not_replaced(self):
        (self.install / 'asset').write_bytes(b'other work')
        with self.assertRaisesRegex(RuntimeError, 'previous installation differs'):
            deployment.install()
        self.assertEqual((self.install / 'asset').read_bytes(), b'other work')
        self.module.upgrade.assert_not_called()

    def test_prepared_payload_is_included_in_copy_comparison(self):
        def prepare_payload(prepare_only=False, rollback=False):
            if prepare_only:
                (self.package / 'asset').write_bytes(b'candidate-prepared')
            self.upgrade(prepare_only, rollback)
        self.module.upgrade.side_effect = prepare_payload
        deployment.install()
        self.assertEqual((self.install / 'asset').read_bytes(), b'candidate-prepared')

    def test_post_commit_old_file_cleanup_does_not_activate_partial_old_copy(self):
        real_remove = deployment.shutil.rmtree
        pending = self.install.with_name(self.install.name + '.pending')
        def remove_failure(path, *args, **kwargs):
            if path == pending:
                (path / 'asset').unlink()
                raise OSError('old cleanup failed')
            return real_remove(path, *args, **kwargs)
        with patch.object(deployment.shutil, 'rmtree', side_effect=remove_failure):
            with self.assertRaisesRegex(OSError, 'old cleanup failed'):
                deployment.install()
        self.assertEqual((self.install / 'asset').read_bytes(), b'candidate')
        record = json.loads((self.install / 'installation.json').read_text())
        self.assertTrue(record['installed'] and record['committed'])
        with patch.object(deployment, 'cleanup'):
            deployment.rollback()
        self.assert_previous()

    def test_restore_copy_failure_occurs_before_efi_downgrade(self):
        deployment.install()
        self.module.upgrade.reset_mock()
        with patch.object(deployment, 'cleanup'), patch.object(deployment.shutil, 'copytree', side_effect=OSError('restore copy failed')):
            with self.assertRaisesRegex(OSError, 'restore copy failed'):
                deployment.rollback()
        self.assertEqual((self.install / 'asset').read_bytes(), b'candidate')
        self.assertEqual((self.oc / 'config.plist').read_bytes(), b'candidate EFI')
        self.module.upgrade.assert_not_called()


class JobUnloadTests(unittest.TestCase):
    def test_unload_waits_for_launchd_to_remove_job(self):
        pending = {'status': 0, 'stdout': 'state = running', 'stderr': ''}
        absent = {'status': 113, 'stdout': '', 'stderr': 'Could not find service "test"'}
        with patch.object(deployment, 'command', side_effect=[pending, pending, pending, absent]) as command, \
                patch.object(deployment.time, 'sleep') as sleep:
            deployment.unload_job('gui/501/test')
        self.assertEqual(sum(call.args[0][1] == 'bootout' for call in command.call_args_list), 1)
        self.assertEqual(sleep.call_count, 2)

    def test_unload_does_not_treat_permission_error_as_absence(self):
        denied = {'status': 1, 'stdout': '', 'stderr': 'Operation not permitted'}
        with patch.object(deployment, 'command', return_value=denied), \
                patch.object(deployment.time, 'monotonic', side_effect=[0, 11]), self.assertRaises(RuntimeError):
            deployment.unload_job('gui/501/test')


class SettingsResultTests(unittest.TestCase):
    def test_attach_error_preserves_exact_iokit_code(self):
        with self.assertRaisesRegex(RuntimeError, r'Settings attach failed: -536870206 \(0xe00002c2\)'):
            deployment.validate_settings_integration('settings_attach=-536870206 pid=4190\n')

    def test_success_and_empty_integration_logs(self):
        for value in ['', 'settings_attach=0 pid=23\nsettings_restore=0\n']:
            deployment.validate_settings_integration(value)

    def test_restore_error_at_end_of_capture(self):
        with self.assertRaisesRegex(RuntimeError, 'Settings restore failed: -1'):
            deployment.validate_settings_integration('settings_restore=-1')

    def test_no_answer_does_not_mask_attach_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'worker.out'
            output.write_text('')
            def answer(_):
                output.write_text('settings_attach=-536870206 pid=4190\n')
                return 'n'
            with patch('builtins.input', side_effect=answer):
                with self.assertRaisesRegex(RuntimeError, '0xe00002c2'):
                    deployment.settings_steps(output, {})

    identity = '12345678-1234-1234-1234-123456789ABC'

    def test_original_settings_peer_is_required(self):
        state = {}
        deployment.validate_settings_step('open', 'settings_attach=0 pid=23\ncatalog_read peer=23 count=1\n', state)
        self.assertEqual(state['initial_count'], 1)
        for value in ['catalog_read peer=23 count=1\n',
                      'settings_attach=0 pid=23\ncatalog_read peer=24 count=1\n',
                      'settings_attach=0 pid=23\ncatalog_read peer=23 count=3\n']:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                deployment.validate_settings_step('open', value, {})

    def test_cancel_rejects_saved_identity(self):
        value = 'enrollment_end accepted=1 saved=0 cancelled=1\n'
        deployment.validate_settings_step('cancel-enrollment', value, {})
        with self.assertRaises(RuntimeError):
            deployment.validate_settings_step('cancel-enrollment', value + 'enrollment_saved uuid=' + self.identity, {})

    def test_initial_enrollment_alone_does_not_pass_both_phases(self):
        state = {'initial_count': 1}
        saved = 'enrollment_saved uuid=' + self.identity + ' count=2\n'
        with self.assertRaises(RuntimeError):
            deployment.validate_settings_step('enroll', saved, state)
        deployment.validate_settings_step('enroll', saved + 'supplement_end accepted=1 added=6 cancelled=1\n', state)
        self.assertEqual(state['new_identity'], self.identity)

    def test_changes_must_target_only_new_fingerprint(self):
        state = {'initial_count': 1, 'new_identity': self.identity}
        for action, count in [('rename', 2), ('remove', 1)]:
            value = f'catalog_mutation action={action} uuid={self.identity} before=2 after={count} saved=1 invalidated=0\n'
            deployment.validate_settings_step(action, value, state)
            for bad in [value.replace(self.identity, '11111111-1111-1111-1111-111111111111'),
                        value.replace('saved=1', 'saved=0'), value + value]:
                with self.subTest(action=action, value=bad), self.assertRaises(RuntimeError):
                    deployment.validate_settings_step(action, bad, state)

    def test_reopen_requires_catalog_read_and_rejects_attach_failure(self):
        state = {'initial_count': 1}
        deployment.validate_settings_step('reopen', 'catalog_read peer=24 count=2\n', state)
        with self.assertRaises(RuntimeError):
            deployment.validate_settings_step('reopen', 'settings_attach=-33010 pid=24\ncatalog_read peer=24 count=2\n', state)


class AuthenticationResultTests(unittest.TestCase):
    def test_unavailable_and_timeout_do_not_count_as_cancel(self):
        values = ['SYSTEM_BIOMETRY available=0 type=0 error=-6\nSYSTEM_AUTHENTICATION_CONTEXT invalidated=1\n',
                  'SYSTEM_AUTHENTICATION interrupted_or_timed_out=1\nSYSTEM_AUTHENTICATION_CONTEXT invalidated=1\n',
                  'SYSTEM_AUTHENTICATION success=0 error=-4\n']
        for value in values:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                deployment.validate_authentication('cancel', value, '')

    def test_negative_steps_require_cancel_and_wrong_finger_evidence(self):
        cancelled = 'SYSTEM_AUTHENTICATION success=0 error=-2\n'
        deployment.validate_authentication('cancel', cancelled, '')
        deployment.validate_authentication('wrong-finger', cancelled, 'actual_match=0 kernel_status=0')
        with self.assertRaises(RuntimeError):
            deployment.validate_authentication('wrong-finger', cancelled, '')

    def test_negative_step_rejects_any_successful_match(self):
        for callback, capture in [('SYSTEM_AUTHENTICATION success=1 error=0\n', 'actual_match=0 kernel_status=0'),
                                  ('SYSTEM_AUTHENTICATION success=0 error=-2\n', 'actual_match=1 kernel_status=0')]:
            with self.subTest(callback=callback, capture=capture), self.assertRaises(RuntimeError):
                deployment.validate_authentication('wrong-finger', callback, capture)

    def test_positive_step_requires_system_and_hardware_success(self):
        success = 'SYSTEM_AUTHENTICATION success=1 error=0\n'
        matched = 'actual_match=1 kernel_status=0'
        deployment.validate_authentication('enrolled-center', success, matched)
        deployment.validate_authentication('enrolled-offset', success, matched)
        for callback, capture in [(success, ''), ('SYSTEM_AUTHENTICATION success=0 error=-1\n', matched)]:
            with self.subTest(callback=callback, capture=capture), self.assertRaises(RuntimeError):
                deployment.validate_authentication('enrolled-center', callback, capture)


if __name__ == '__main__':
    unittest.main()
