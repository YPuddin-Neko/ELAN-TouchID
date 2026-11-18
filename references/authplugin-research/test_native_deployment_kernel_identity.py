import importlib.util
import io
import json
from pathlib import Path
import plistlib
import shutil
import struct
import sys
import tempfile
import unittest
import uuid
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parent
CANDIDATE_UUID = 'D15479ED-37C6-31EF-BE6E-4D95E3F19DDC'
LOADED_OLD_UUID = '5A6A3016-833C-37A0-BDA0-40E4FBFF4798'
spec = importlib.util.spec_from_file_location('deployment_test_identity', SOURCE / 'native-kernel-identity.py')
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


def write_bundle(bundle, version='0.4.0', identifier=CANDIDATE_UUID):
    executable = bundle / 'Contents/MacOS/ELANNativeProbe'
    executable.parent.mkdir(parents=True, exist_ok=True)
    executable.write_bytes(struct.pack('<8I', 0xfeedfacf, 0x01000007, 3, 11, 1, 24, 0, 0) +
                           struct.pack('<II', 0x1b, 24) + uuid.UUID(identifier).bytes)
    info = {'CFBundleIdentifier': identity.IDENTIFIER, 'CFBundleExecutable': identity.EXECUTABLE,
            'CFBundleVersion': version, 'CFBundleShortVersionString': version}
    (bundle / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
    return identity.artifact_identity(bundle, version)


def loaded_row(identifier=CANDIDATE_UUID):
    return ('   59    0 0xffffff8004051000 0x11000 0x11000 ' + identity.IDENTIFIER +
            ' (0.4.0) ' + identifier + ' <57 9 7 6 3 1>\n')


class ReachedPipeline(RuntimeError):
    pass


class DeploymentKernelIdentityTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.install = self.root / 'installed'
        self.install.mkdir()
        for name in ('native-provider-deployment.py', 'native-kernel-identity.py', 'native-session-lifecycle.py',
                     'native-settings-diagnostic.py', 'native-settings-result.py'):
            shutil.copy2(SOURCE / name, self.install / name)
        spec = importlib.util.spec_from_file_location('identity_deployment', self.install / 'native-provider-deployment.py')
        self.d = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.d)
        spec = importlib.util.spec_from_file_location('identity_session_lifecycle', self.install / 'native-session-lifecycle.py')
        self.lifecycle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.lifecycle)
        self.d.INSTALL = self.install
        self.bundle = self.install / 'payload' / self.d.KERNEL_PACKAGE / 'ELANNativeProbe.kext'
        self.manifest = self.bundle.parent / 'kernel-identity.json'
        self.events = []
        self.command_error = None
        self.loaded = loaded_row()
        self.reset_identity()
        self.stack.enter_context(patch.object(self.d, 'require_root', side_effect=lambda **kw: self.events.append('permission')))
        self.stack.enter_context(patch.object(self.d, 'verify_signatures', side_effect=lambda *a: self.events.append('signature')))
        self.stack.enter_context(patch.object(self.d, 'environment', side_effect=lambda: {'machine': 'fixture'}))
        self.stack.enter_context(patch.object(self.d, 'loaded_version', return_value=self.d.VERSION))
        self.stack.enter_context(patch.object(self.d, 'command', side_effect=self.command))
        self.stop = self.stack.enter_context(patch.object(self.d, 'stop_background', side_effect=lambda: self.events.append('stop')))
        self.cleanup = self.stack.enter_context(patch.object(self.d, 'cleanup', side_effect=lambda: self.events.append('cleanup')))
        self.stack.enter_context(patch.object(self.d, 'runtime_lock', self.runtime_lock))
        self.stack.enter_context(patch.object(self.d.signal, 'signal'))
        self.stack.enter_context(patch.object(self.d.subprocess, 'Popen', side_effect=AssertionError('No services permitted')))
        self.stack.enter_context(patch.object(self.d.subprocess, 'run', side_effect=AssertionError('No system commands permitted')))
        self.stack.enter_context(patch('builtins.input', return_value='cancel'))
        self.output, self.errors = io.StringIO(), io.StringIO()
        self.stack.enter_context(redirect_stdout(self.output))
        self.stack.enter_context(redirect_stderr(self.errors))

    def reset_identity(self):
        self.d.PACKAGE = self.install
        self.d.KERNEL_PACKAGE = 'native-kernel-probe-06'
        shutil.copy2(SOURCE / 'native-kernel-identity.py', self.install / 'native-kernel-identity.py')
        self.expected = write_bundle(self.bundle)
        self.manifest.write_text(json.dumps(self.expected))
        self.loaded = loaded_row()
        self.command_error = None
        self.events.clear()

    def command(self, args, check=True, timeout=30):
        self.assertEqual(args, ['/usr/bin/kmutil', 'showloaded', '--list-only'])
        self.assertIs(check, False)
        self.assertEqual(timeout, 15)
        self.events.append('identity')
        if self.command_error:
            raise self.command_error
        return {'status': 0, 'stdout': self.loaded, 'stderr': 'PRIVATE_RUNTIME_STDERR'}

    @contextmanager
    def runtime_lock(self):
        self.events.append('lock')
        try:
            yield
        finally:
            self.events.append('unlock')

    def run_cli(self, action):
        self.output.seek(0); self.output.truncate()
        self.errors.seek(0); self.errors.truncate()
        with patch.object(sys, 'argv', ['deployment', action]):
            return self.d.cli()

    def assert_no_startup_effects(self):
        for event in ('stop', 'lock', 'unlock', 'cleanup', 'pipeline', 'save', 'efi'):
            self.assertNotIn(event, self.events)
        self.assertFalse((self.install / 'state').exists())
        self.assertFalse((self.install / 'studies').exists())
        self.assertNotIn('PRIVATE_', self.output.getvalue() + self.errors.getvalue())
        self.assertNotIn('0xffffff', self.output.getvalue() + self.errors.getvalue())

    def corrupt(self, case):
        if case == 'loaded_uuid':
            self.loaded = loaded_row(LOADED_OLD_UUID)
        elif case == 'missing_manifest':
            self.assertTrue(self.manifest.resolve().is_relative_to(self.root.resolve()))
            self.manifest.unlink()
        elif case == 'invalid_manifest':
            self.manifest.write_text('{PRIVATE_MANIFEST')
        elif case == 'stale_manifest':
            self.manifest.write_text(json.dumps(dict(self.expected, macho_uuid=LOADED_OLD_UUID)))
        elif case == 'changed_sha':
            executable = self.bundle / 'Contents/MacOS/ELANNativeProbe'
            executable.write_bytes(executable.read_bytes() + b'changed-with-same-UUID')
        elif case == 'missing_helper':
            helper = self.install / 'native-kernel-identity.py'
            self.assertTrue(helper.resolve().is_relative_to(self.root.resolve()))
            helper.unlink()
        elif case == 'invalid_helper':
            (self.install / 'native-kernel-identity.py').write_text('def PRIVATE_SYNTAX\n')
        elif case == 'wrong_helper_api':
            (self.install / 'native-kernel-identity.py').write_text('IdentityError = ValueError\n')
        elif case == 'helper_import_error':
            (self.install / 'native-kernel-identity.py').write_text('raise RuntimeError("PRIVATE_IMPORT")\n')
        elif case == 'query_error':
            self.command_error = OSError('PRIVATE_COMMAND')
        elif case == 'duplicate_loaded':
            self.loaded += self.loaded
        else:
            raise AssertionError(case)

    def test_all_startup_cli_actions_reject_same_version_different_uuid_before_effects(self):
        for action in ('test', 'test-settings', 'test-session', 'diagnose-settings', 'enable-background', 'serve-background'):
            with self.subTest(action=action):
                self.reset_identity(); self.corrupt('loaded_uuid')
                self.assertEqual(self.run_cli(action), 0 if action == 'serve-background' else 1)
                self.assert_no_startup_effects()
                self.assertEqual(self.events.count('identity'), 1)
                if action == 'diagnose-settings':
                    result = json.loads(self.output.getvalue())
                    self.assertEqual(result['failure_stage'], 'kernel_identity')
                    self.assertEqual(result['run_state'], 'failed')
                    self.assertNotIn(CANDIDATE_UUID, self.output.getvalue())
                    self.assertNotIn(LOADED_OLD_UUID, self.output.getvalue())

    def test_manifest_binary_helper_and_query_failures_block_actual_outer_entry(self):
        for case in ('missing_manifest', 'invalid_manifest', 'stale_manifest', 'changed_sha', 'missing_helper',
                     'invalid_helper', 'wrong_helper_api', 'helper_import_error', 'query_error', 'duplicate_loaded'):
            with self.subTest(case=case):
                self.reset_identity(); self.corrupt(case)
                self.assertEqual(self.run_cli('test-settings'), 1)
                self.assert_no_startup_effects()
                self.assertEqual(self.events.count('identity'), int(case in ('query_error', 'duplicate_loaded')))

    def test_diagnostic_dependency_failures_are_sanitized_json(self):
        for case in ('missing_manifest', 'changed_sha', 'missing_helper', 'invalid_helper', 'helper_import_error', 'query_error'):
            with self.subTest(case=case):
                self.reset_identity(); self.corrupt(case)
                self.assertEqual(self.run_cli('diagnose-settings'), 1)
                self.assert_no_startup_effects()
                result = json.loads(self.output.getvalue())
                self.assertEqual((result['run_state'], result['failure_stage']), ('failed', 'kernel_identity'))
                self.assertNotIn(str(self.root), self.output.getvalue() + self.errors.getvalue())

    def test_direct_test_and_session_handlers_cannot_bypass_identity(self):
        for call in (lambda: self.d.test(), lambda: self.d.test(settings=True), self.d.test_session, self.d.enable_background):
            with self.subTest(call=call):
                self.reset_identity(); self.corrupt('loaded_uuid')
                with self.assertRaisesRegex(ValueError, 'loaded_uuid_mismatch'):
                    call()
                self.assert_no_startup_effects()

    def test_matching_identity_admits_existing_outer_startup_pipeline(self):
        for action, name in (('test', 'test'), ('test-settings', 'test'), ('test-session', 'test_session')):
            with self.subTest(action=action):
                self.reset_identity()
                with patch.object(self.d, name, side_effect=lambda *a, **kw: self.events.append('pipeline')):
                    self.assertEqual(self.run_cli(action), 0)
                self.assertEqual(self.events, ['permission', 'identity', 'stop', 'lock', 'pipeline', 'unlock'])

    def test_matching_direct_test_reaches_cleanup_only_after_identity(self):
        with patch.object(self.d, 'cleanup', side_effect=ReachedPipeline('pipeline')):
            with self.assertRaises(ReachedPipeline):
                self.d.test()
        self.assertEqual(self.events, ['permission', 'signature', 'identity'])

    def test_running_and_candidate_wrappers_use_actual_helper(self):
        self.assertEqual(self.d.require_kernel_artifact(), self.expected)
        self.assertEqual(self.events, [])
        result = self.d.require_kernel_identity()
        self.assertEqual(result['macho_uuid'], CANDIDATE_UUID)
        self.assertEqual(self.events, ['identity'])

    def test_runtime_recover_and_every_start_retry_recheck_before_effects(self):
        runtime = self.d.ManagedProviderRuntime()
        for method in (runtime.recover, runtime.start, runtime.start):
            with self.subTest(method=method):
                self.reset_identity(); self.corrupt('loaded_uuid')
                with self.assertRaisesRegex(ValueError, 'loaded_uuid_mismatch'):
                    method()
                self.assert_no_startup_effects()
        for method in (runtime.recover, runtime.start):
            self.reset_identity()
            with patch.object(runtime, 'report_status', side_effect=ReachedPipeline('pipeline')):
                with self.assertRaises(ReachedPipeline): method()
            self.assertEqual(self.events, ['identity'])

    def supervise(self, runtime, duration=20):
        now = [0]
        return self.lifecycle.supervise(runtime, duration=duration, clock=lambda: now[0],
            sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))

    def test_supervisor_initial_identity_rejection_does_not_run_native_cleanup(self):
        self.corrupt('loaded_uuid')
        runtime = self.d.ManagedProviderRuntime(persistent=True)
        with patch.object(runtime.power, 'close') as close:
            with self.assertRaisesRegex(ValueError, 'loaded_uuid_mismatch'):
                self.supervise(runtime)
        close.assert_called_once_with()
        self.assertEqual(self.events, ['identity'])
        self.assert_no_startup_effects()
        self.assertFalse(runtime.cleanup_needed)

    def test_supervisor_rejected_retries_do_not_repeat_already_completed_recovery(self):
        runtime = self.d.ManagedProviderRuntime()
        def power_start():
            self.loaded = loaded_row(LOADED_OLD_UUID)
        with patch.object(runtime.power, 'start', side_effect=power_start), \
                patch.object(runtime.power, 'read', return_value=(True, 0)), \
                patch.object(runtime.power, 'close') as close, \
                patch.object(runtime, 'console_active', return_value=True):
            with self.assertRaisesRegex(RuntimeError, '连续三次'):
                self.supervise(runtime)
        close.assert_called_once_with()
        self.assertEqual(self.events, ['identity', 'cleanup', 'identity', 'identity', 'identity'])
        self.assertFalse(runtime.cleanup_needed)
        self.assertFalse((self.install / 'studies').exists())
        self.assertFalse((self.install / 'state').exists())

    def test_supervisor_cleans_partial_start_even_when_later_identity_mismatches(self):
        runtime = self.d.ManagedProviderRuntime()
        def partial_start(*args):
            self.events.append('partial-start')
            self.loaded = loaded_row(LOADED_OLD_UUID)
            raise RuntimeError('Partial startup failed')
        with patch.object(runtime.power, 'start'), patch.object(runtime.power, 'read', return_value=(True, 0)), \
                patch.object(runtime.power, 'close') as close, patch.object(runtime, 'console_active', return_value=True), \
                patch.object(self.d, 'Study', side_effect=partial_start) as study:
            with self.assertRaisesRegex(RuntimeError, '连续三次'):
                self.supervise(runtime)
        study.assert_called_once_with('session')
        close.assert_called_once_with()
        self.assertEqual(self.events, ['identity', 'cleanup', 'identity', 'partial-start', 'cleanup', 'identity', 'identity'])
        self.assertFalse(runtime.cleanup_needed)

    def test_failed_stop_retains_cleanup_obligation_without_requiring_identity(self):
        runtime = self.d.ManagedProviderRuntime()
        runtime.cleanup_needed = True
        self.corrupt('missing_helper')
        self.cleanup.side_effect = [RuntimeError('Cleanup failed'), None]
        with self.assertRaisesRegex(RuntimeError, 'Cleanup failed'): runtime.stop()
        self.assertTrue(runtime.cleanup_needed)
        runtime.stop()
        self.assertFalse(runtime.cleanup_needed)
        self.assertEqual(self.cleanup.call_count, 2)
        self.assertNotIn('identity', self.events)

    def test_prepare_rejects_invalid_candidate_before_staging(self):
        self.corrupt('changed_sha')
        self.d.INSTALL = self.root / 'new-install'
        with patch.object(self.d, 'asset_bytes', return_value={}), patch.object(self.d, 'efi') as efi:
            with self.assertRaisesRegex(ValueError, 'artifact_mismatch'): self.d.prepare()
        efi.assert_not_called()
        self.assertFalse(self.d.INSTALL.exists())
        self.assertNotIn('identity', self.events)

    def test_install_rejects_invalid_candidate_before_efi_and_stage_effects(self):
        self.corrupt('changed_sha')
        self.d.INSTALL = self.root / 'old-install'
        with patch.object(self.d, 'loaded_version', return_value=self.d.PREVIOUS_VERSION), \
                patch.object(self.d, 'verify_previous'), patch.object(self.d, 'efi') as efi:
            with self.assertRaisesRegex(ValueError, 'artifact_mismatch'): self.d.install()
        efi.assert_not_called()
        self.assertFalse(self.d.INSTALL.exists())
        self.assertNotIn('identity', self.events)

    def test_valid_candidate_install_does_not_require_new_driver_loaded(self):
        self.d.INSTALL = self.root / 'old-install'
        with patch.object(self.d, 'loaded_version', return_value=self.d.PREVIOUS_VERSION), \
                patch.object(self.d, 'verify_previous'), \
                patch.object(self.d, 'efi', side_effect=ReachedPipeline('candidate admitted')):
            with self.assertRaises(ReachedPipeline): self.d.install()
        self.assertFalse(self.d.INSTALL.exists())
        self.assertNotIn('identity', self.events)

    def test_current_04_install_is_still_not_an_upgrade_path(self):
        self.d.INSTALL = self.root / 'old-install'
        with patch.object(self.d, 'efi') as efi:
            with self.assertRaisesRegex(RuntimeError, 'staged upgrade with 0.3.0 loaded'): self.d.install()
        efi.assert_not_called()
        self.assertNotIn('identity', self.events)
        self.assertEqual((self.d.VERSION, self.d.PREVIOUS_VERSION), ('0.4.0', '0.3.0'))

    def test_cleanup_and_rollback_entry_points_remain_accessible_without_identity(self):
        for action in ('cleanup', 'rollback'):
            with self.subTest(action=action):
                self.reset_identity(); self.corrupt('missing_helper')
                with patch.object(self.d, action, side_effect=lambda: self.events.append('pipeline')):
                    self.assertEqual(self.run_cli(action), 0)
                self.assertEqual(self.events, ['permission', 'stop', 'lock', 'pipeline', 'unlock'])

    def test_disable_status_and_runtime_stop_remain_accessible_without_identity(self):
        self.corrupt('missing_helper')
        self.d.disable_background()
        self.assertEqual(self.events, ['stop', 'lock', 'cleanup', 'unlock'])
        self.events.clear()
        with patch.object(self.d, 'background_job', return_value=None):
            result = self.d.background_status()
        self.assertFalse(result['registered'])
        self.assertNotIn('identity', self.events)
        runtime = self.d.ManagedProviderRuntime()
        runtime.cleanup_needed = True
        with patch.object(runtime, 'report_status'):
            runtime.stop()
        self.assertEqual(self.events, ['cleanup'])
        self.assertNotIn('identity', self.events)


if __name__ == '__main__':
    unittest.main()
