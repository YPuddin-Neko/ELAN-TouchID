import importlib.util
import io
import json
import plistlib
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from test_native_settings_diagnostic import Controller
from test_native_deployment_kernel_identity import identity, write_bundle, loaded_row

SOURCE = Path(__file__).resolve().parent
HELPERS = ['native-settings-diagnostic.py', 'native-settings-result.py', 'native-kernel-identity.py']
PREVIOUS_ASSETS = ['ELANNativeBroker', 'ELANNativeProvider.app', 'ELANNativeAuthTest.app',
                   'NativeNamespaceProbe', 'native-provider-deployment.py', 'payload']


def load_deployment(path=SOURCE / 'native-provider-deployment.py'):
    spec = importlib.util.spec_from_file_location('diagnostic_cli_deployment', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DiagnosticCliTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.c = Controller(self.root)
        self.d = load_deployment()
        self.c.VERSION = self.d.VERSION
        self.c.loaded = self.d.VERSION
        for name in HELPERS:
            shutil.copy2(SOURCE / name, self.c.INSTALL / name)
        for name, value in [('INSTALL', self.c.INSTALL), ('PACKAGE', self.c.INSTALL),
                            ('KERNEL_PACKAGE', self.c.KERNEL_PACKAGE)]:
            self.stack.enter_context(patch.object(self.d, name, value))
        for name in ['Study', 'cleanup', 'command', 'gui_auth', 'wait_output', 'broker_identity', 'save']:
            self.stack.enter_context(patch.object(self.d, name, getattr(self.c, name)))
        self.root_check = self.d.require_root
        self.stack.enter_context(patch.object(self.d, 'require_root', side_effect=self.require_root))
        self.stack.enter_context(patch.object(self.d, 'verify_signatures', side_effect=self.verify_signatures))
        self.stack.enter_context(patch.object(self.d, 'environment', side_effect=self.c.environment))
        self.stack.enter_context(patch.object(self.d, 'loaded_version', side_effect=self.loaded_version))
        self.real_identity = self.d.require_kernel_identity
        self.identity = self.stack.enter_context(patch.object(self.d, 'require_kernel_identity'))
        self.stack.enter_context(patch.object(self.d.os, 'geteuid', return_value=0))
        self.signals = self.stack.enter_context(patch.object(self.d.signal, 'signal'))
        self.stop = self.stack.enter_context(patch.object(self.d, 'stop_background', side_effect=self.stop_background))
        self.locked = False
        self.lock_count = 0
        self.stack.enter_context(patch.object(self.d, 'runtime_lock', self.runtime_lock))
        self.stack.enter_context(patch.object(self.d.subprocess, 'Popen', side_effect=self.c.popen))
        for name in ['test', 'test_session', 'settings_steps', 'efi', 'publish']:
            self.stack.enter_context(patch.object(self.d, name, side_effect=AssertionError('Unexpected action: ' + name)))
        self.answers = iter(['', ''])
        self.real_input = input
        self.stack.enter_context(patch('builtins.input', side_effect=lambda: next(self.answers)))
        self.out, self.err = io.StringIO(), io.StringIO()
        self.stack.enter_context(redirect_stdout(self.out))
        self.stack.enter_context(redirect_stderr(self.err))
        self.stack.enter_context(patch.object(sys, 'argv', ['deployment', 'diagnose-settings']))

    def require_root(self, installed):
        self.c.events.append('permission')
        self.root_check(installed=installed)

    def verify_signatures(self, root):
        self.assertEqual(root, self.c.INSTALL)
        self.c.events.append('signature')

    def loaded_version(self):
        self.c.events.append('version')
        return self.c.loaded

    def stop_background(self):
        self.c.events.append('stop_background')
        self.assertFalse(self.locked)
        return True

    @contextmanager
    def runtime_lock(self):
        self.assertFalse(self.locked, 'The CLI must not take the runner lock twice')
        self.lock_count += 1
        with self.c.runtime_lock():
            self.locked = True
            try:
                yield
            finally:
                self.locked = False

    def result(self):
        result = json.loads(self.out.getvalue())
        serialized = self.out.getvalue() + self.err.getvalue()
        for secret in ['private', str(self.root), 'private-identity']:
            self.assertNotIn(secret, serialized)
        self.assertFalse(result['auth_regression_ran'])
        self.assertFalse(result['connection_recovery_authorized'])
        self.assertIsNone(result['native_success'])
        return result

    def assert_saved_result(self, result):
        saved = self.c.study.directory / 'result.json'
        self.assertEqual(json.loads(saved.read_text()), result)

    def test_main_dispatch_leaves_lock_and_background_to_diagnostic_handler(self):
        with patch.object(self.d, 'diagnose_settings') as handler:
            self.d.main()
        handler.assert_called_once_with()
        self.stop.assert_not_called()
        self.assertEqual(self.lock_count, 0)
        self.assertEqual(self.c.events, [])

    def test_installed_main_runs_observation_with_one_lock_and_no_recovery(self):
        self.assertEqual(self.d.cli(), 0)
        result = self.result()
        self.assertEqual(result['run_state'], 'observed')
        self.assertTrue(result['settings_diagnostic_observed'])
        self.assertFalse(result['summary']['settings_function_verified'])
        self.assertEqual(self.c.gui_calls, ['baseline', 'capability', 'restored'])
        self.assertEqual(self.c.starts, [[str(self.c.INSTALL / 'ELANNativeBroker'), '--serve-managed']])
        self.assertEqual(self.c.events[:10], ['permission', 'signature', 'environment', 'version', 'stop_background',
                                            'lock', 'permission', 'signature', 'environment', 'version'])
        self.assertEqual(self.c.events[-1], 'unlock')
        self.assertEqual(self.lock_count, 1)
        self.assertEqual(self.c.cleanup_calls, 2)
        self.assertEqual(len(self.c.commands), 5)
        self.assertIn('临时原生服务', self.err.getvalue())
        self.assertIn('内存状态', self.err.getvalue())
        self.assert_saved_result(result)

    def test_matching_real_identity_allows_complete_diagnostic_pipeline(self):
        bundle = self.c.INSTALL / 'payload' / self.c.KERNEL_PACKAGE / 'ELANNativeProbe.kext'
        manifest = write_bundle(bundle)
        (bundle.parent / 'kernel-identity.json').write_text(json.dumps(manifest))
        self.identity.side_effect = self.real_identity
        queries = []
        def command(args, **kwargs):
            if args == ['/usr/bin/kmutil', 'showloaded', '--list-only']:
                self.assertEqual(kwargs, {'check': False, 'timeout': 15})
                queries.append(args)
                return {'status': 0, 'stdout': loaded_row(), 'stderr': 'private query details'}
            return self.c.command(args, **kwargs)
        with patch.object(self.d, 'command', side_effect=command):
            self.assertEqual(self.d.cli(), 0)
        self.assertEqual(self.result()['run_state'], 'observed')
        self.assertEqual(len(queries), 2)
        self.assertEqual(self.identity.call_count, 2)
        self.assertEqual(self.lock_count, 1)

    def test_identity_failure_precedes_background_stop_and_lock(self):
        self.identity.side_effect = RuntimeError('private identity data')
        self.assertEqual(self.d.cli(), 1)
        self.assertEqual(self.result()['failure_stage'], 'kernel_identity')
        self.stop.assert_not_called()
        self.assertEqual(self.lock_count, 0)
        self.assertEqual(self.c.cleanup_calls, 0)

    def test_identity_is_rechecked_inside_diagnostic_lock(self):
        self.identity.side_effect = [None, RuntimeError('private changed identity')]
        self.assertEqual(self.d.cli(), 1)
        self.assertEqual(self.result()['failure_stage'], 'preflight')
        self.assertEqual(self.identity.call_count, 2)
        self.assertEqual(self.lock_count, 1)
        self.assertEqual(self.c.cleanup_calls, 0)
        self.assertEqual(self.c.starts, [])

    def test_real_input_prompts_stay_visible_without_exporting_raw_helper_output(self):
        def cleanup():
            print('private broker recovery protocol')
            self.c.cleanup()
        def stop_background():
            print('private background protocol')
            return self.stop_background()
        self.stop.side_effect = stop_background
        with patch.object(self.d, 'cleanup', side_effect=cleanup), \
                patch('builtins.input', self.real_input), patch.object(sys, 'stdin', io.StringIO('\n\n')):
            self.assertEqual(self.d.cli(), 0)
        result = self.result()
        self.assertEqual(result['run_state'], 'observed')
        self.assertIn('请先完全退出系统设置', self.err.getvalue())
        self.assertIn('打开系统设置的“登录密码”', self.err.getvalue())
        self.assertEqual(self.c.cleanup_calls, 2)
        self.assert_saved_result(result)

    def test_unprivileged_invocation_preserves_background_before_any_other_check(self):
        with patch.object(self.d.os, 'geteuid', return_value=501):
            self.assertEqual(self.d.cli(), 1)
        self.assertEqual(self.result()['failure_stage'], 'permission')
        self.assertEqual(self.c.events, ['permission'])
        self.stop.assert_not_called()
        self.assertEqual(self.lock_count, 0)

    def test_staged_copy_cannot_start_diagnostic(self):
        with patch.object(self.d, 'PACKAGE', self.root / 'staged'):
            self.assertEqual(self.d.cli(), 1)
        self.assertEqual(self.result()['failure_stage'], 'permission')
        self.assertEqual(self.c.events, ['permission'])
        self.stop.assert_not_called()

    def test_signature_failure_preserves_service_and_sanitizes_error(self):
        with patch.object(self.d, 'verify_signatures', side_effect=RuntimeError('private signature path')):
            self.assertEqual(self.d.cli(), 1)
        self.assertEqual(self.result()['failure_stage'], 'signature')
        self.stop.assert_not_called()
        self.assertEqual(self.c.cleanup_calls, 0)

    def test_environment_failure_preserves_service(self):
        with patch.object(self.d, 'environment', side_effect=RuntimeError('private boot arguments')):
            self.assertEqual(self.d.cli(), 1)
        self.assertEqual(self.result()['failure_stage'], 'environment')
        self.stop.assert_not_called()
        self.assertEqual(self.lock_count, 0)

    def test_wrong_version_preserves_service(self):
        self.c.loaded = '0.3.0'
        self.assertEqual(self.d.cli(), 1)
        self.assertEqual(self.result()['failure_stage'], 'version')
        self.stop.assert_not_called()
        self.assertEqual(self.c.cleanup_calls, 0)

    def test_missing_runner_preserves_service(self):
        path = self.c.INSTALL / HELPERS[0]
        self.assertEqual(path.resolve().parent, self.c.INSTALL.resolve())
        path.unlink()
        self.assertEqual(self.d.cli(), 1)
        result = self.result()
        self.assertEqual(result['run_state'], 'failed')
        self.assertEqual(result['failure_stage'], 'dependency_load')
        self.stop.assert_not_called()

    def test_missing_result_dependency_preserves_service(self):
        path = self.c.INSTALL / HELPERS[1]
        self.assertEqual(path.resolve().parent, self.c.INSTALL.resolve())
        path.unlink()
        self.assertEqual(self.d.cli(), 1)
        result = self.result()
        self.assertEqual(result['run_state'], 'failed')
        self.assertEqual(result['failure_stage'], 'dependency_load')
        self.stop.assert_not_called()
        self.assertEqual(self.lock_count, 0)

    def test_missing_runner_api_preserves_service_and_sanitized_json(self):
        (self.c.INSTALL / HELPERS[0]).write_text('unrelated = True\n')
        self.assertEqual(self.d.cli(), 1)
        result = self.result()
        self.assertEqual(result['run_state'], 'failed')
        self.assertEqual(result['failure_stage'], 'dependency_load')
        self.stop.assert_not_called()

    def test_background_stop_failure_does_not_start_or_clean_runtime(self):
        self.stop.side_effect = RuntimeError('private background details')
        self.assertEqual(self.d.cli(), 1)
        self.assertEqual(self.result()['failure_stage'], 'background_stop')
        self.assertEqual(self.lock_count, 0)
        self.assertEqual(self.c.cleanup_calls, 0)
        self.assertFalse(self.c.starts)

    def test_runner_rechecks_version_after_stopping_background(self):
        with patch.object(self.d, 'loaded_version', side_effect=[self.d.VERSION, '0.3.0']):
            self.assertEqual(self.d.cli(), 1)
        self.assertEqual(self.result()['failure_stage'], 'preflight')
        self.assertEqual(self.lock_count, 1)
        self.assertEqual(self.c.cleanup_calls, 0)
        self.assertFalse(self.c.starts)

    def test_lock_failure_keeps_sanitized_runner_result_without_cleaning_other_runtime(self):
        self.c.fail = 'lock'
        self.assertEqual(self.d.cli(), 1)
        result = self.result()
        self.assertEqual(result['failure_stage'], 'lock')
        self.assertIsInstance(result['summary'], dict)
        self.assertEqual(self.c.cleanup_calls, 0)

    def test_runtime_failure_keeps_saved_sanitized_result_and_nonzero_exit(self):
        self.c.fail = 'provider'
        self.assertEqual(self.d.cli(), 1)
        result = self.result()
        self.assertEqual(result['failure_stage'], 'provider_start')
        self.assertEqual(result['run_state'], 'failed')
        self.assertFalse(self.c.process.alive)
        self.assertEqual(self.c.cleanup_calls, 2)
        self.assert_saved_result(result)

    def test_cancel_before_start_keeps_result_and_nonzero_exit(self):
        self.answers = iter(['cancel'])
        self.assertEqual(self.d.cli(), 1)
        result = self.result()
        self.assertEqual(result['run_state'], 'cancelled')
        self.assertEqual(result['failure_stage'], 'ready_prompt')
        self.assertFalse(self.c.starts)
        self.assert_saved_result(result)

    def test_cancel_during_observation_cleans_and_keeps_result(self):
        def cleanup():
            print('private broker recovery protocol')
            self.c.cleanup()
        with patch.object(self.d, 'cleanup', side_effect=cleanup), \
                patch('builtins.input', self.real_input), patch.object(sys, 'stdin', io.StringIO('\ncancel\n')):
            self.assertEqual(self.d.cli(), 1)
        result = self.result()
        self.assertEqual(result['run_state'], 'cancelled')
        self.assertEqual(result['failure_stage'], 'observation')
        self.assertFalse(self.c.process.alive)
        self.assert_saved_result(result)

    def test_signal_cancellation_uses_same_result_and_cleanup_path(self):
        def interrupted():
            handler = dict(call.args for call in self.signals.call_args_list)[self.d.signal.SIGTERM]
            handler(self.d.signal.SIGTERM, None)
        with patch('builtins.input', side_effect=interrupted):
            self.assertEqual(self.d.cli(), 1)
        result = self.result()
        self.assertEqual(result['run_state'], 'cancelled')
        self.assertEqual(self.c.cleanup_calls, 2)
        self.assert_saved_result(result)

    def test_cleanup_failure_is_not_converted_to_success(self):
        self.c.fail = 'cleanup'
        def cleanup():
            print('private broker recovery protocol')
            self.c.cleanup()
        with patch.object(self.d, 'cleanup', side_effect=cleanup):
            self.assertEqual(self.d.cli(), 1)
        result = self.result()
        self.assertEqual(result['run_state'], 'cleanup_failed')
        self.assertIn('controller_cleanup', result['cleanup_failures'])
        self.assert_saved_result(result)

    def test_result_write_failure_still_emits_sanitized_json(self):
        self.c.fail = 'result_save'
        self.assertEqual(self.d.cli(), 1)
        result = self.result()
        self.assertEqual(result['run_state'], 'cleanup_failed')
        self.assertIn('result_save', result['cleanup_failures'])
        self.assertFalse((self.c.study.directory / 'result.json').exists())

    def test_cli_does_not_offer_connection_recovery_flag(self):
        with patch.object(sys, 'argv', ['deployment', 'diagnose-settings', '--allow-connection-recovery']):
            with self.assertRaises(SystemExit) as caught:
                self.d.cli()
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(self.c.events, [])
        self.stop.assert_not_called()

    def test_existing_settings_test_dispatch_is_unchanged(self):
        with patch.object(sys, 'argv', ['deployment', 'test-settings']), patch.object(self.d, 'test') as handler:
            self.assertEqual(self.d.cli(), 0)
        handler.assert_called_once_with(settings=True)
        self.assertEqual(self.c.events, ['permission', 'stop_background', 'lock', 'unlock'])
        self.assertEqual(self.lock_count, 1)


class EntrypointTests(unittest.TestCase):
    def test_script_entrypoint_returns_nonzero_with_json_on_permission_failure(self):
        harness = '''
import runpy, sys
from unittest.mock import patch
path = sys.argv[1]
sys.argv = [path, 'diagnose-settings']
with patch('os.geteuid', return_value=501), \\
     patch('subprocess.run', side_effect=AssertionError('No system commands allowed')), \\
     patch('subprocess.Popen', side_effect=AssertionError('No child services allowed')):
    runpy.run_path(path, run_name='__main__')
'''
        process = subprocess.run([sys.executable, '-I', '-B', '-c', harness,
                                  str(SOURCE / 'native-provider-deployment.py')],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 1, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result['run_state'], 'failed')
        self.assertEqual(result['failure_stage'], 'permission')
        self.assertNotIn(str(SOURCE), process.stdout + process.stderr)
        self.assertNotIn('Traceback', process.stderr)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.source = self.root / 'references/authplugin-research'
        self.source.mkdir(parents=True)
        self.build = self.root / 'elan-fingerprint-macos/build/research'
        self.package = self.build / 'native-provider-package-06'
        self.d = load_deployment()
        for name in ['package-native-provider.py', 'native-provider-deployment.py', 'native-session-lifecycle.py', *HELPERS]:
            shutil.copy2(SOURCE / name, self.source / name)
        self.write(self.source / 'kernel-provider/manage-efi.py', 'ENTRY = {}\n')
        for name in self.d.ASSETS[:4]:
            self.asset(self.build / 'native-provider-06' / name, self.d.VERSION)
        for suffix, version in [('05', self.d.PREVIOUS_VERSION), ('06', self.d.VERSION)]:
            self.asset(self.build / ('native-kernel-probe-' + suffix) / 'ELANNativeProbe.kext', version)
        self.builder_bundle = self.build / 'native-kernel-probe-06/ELANNativeProbe.kext'
        self.builder_manifest = self.builder_bundle.parent / 'kernel-identity.json'
        self.builder_manifest.write_text(json.dumps(identity.artifact_identity(self.builder_bundle, self.d.VERSION)))
        self.write(self.build / 'native-kernel-probe-06/elan-native-probe', 'fake executable')
        for name in PREVIOUS_ASSETS:
            directory = 'native-provider-fix-03' if name in ['ELANNativeProvider.app', 'native-provider-deployment.py'] else 'native-provider-package-05'
            self.asset(self.build / directory / name, self.d.PREVIOUS_VERSION)
        self.signatures = []
        self.stack.enter_context(patch('subprocess.run', side_effect=self.verify_signature))
        self.stack.enter_context(patch('subprocess.Popen', side_effect=AssertionError('No services allowed')))
        self.output = io.StringIO()
        self.stack.enter_context(redirect_stdout(self.output))

    @staticmethod
    def write(path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def asset(self, path, version):
        if path.suffix == '.kext':
            write_bundle(path, version)
        elif path.suffix == '.app':
            self.write(path / 'Contents/Info.plist', plistlib.dumps({'CFBundleVersion': version}).decode())
            self.write(path / 'Contents/MacOS/fixture', 'fake executable')
        elif path.name == 'payload':
            self.write(path / 'original.txt', 'previous payload')
        elif path.suffix == '.py':
            self.write(path, 'VERSION = ' + repr(version) + '\n')
        else:
            self.write(path, 'fake executable ' + version)

    def verify_signature(self, args, **kwargs):
        self.assertEqual(args[:3], ['/usr/bin/codesign', '--verify', '--strict'])
        self.assertTrue(Path(args[3]).resolve().is_relative_to(self.package.resolve()))
        self.signatures.append(args[3])
        return subprocess.CompletedProcess(args, 0, '', '')

    def generate(self):
        runpy.run_path(str(self.source / 'package-native-provider.py'))

    def test_current_assets_append_helpers_without_changing_previous_03_assets(self):
        self.assertEqual(self.d.PREVIOUS_ASSETS, PREVIOUS_ASSETS)
        self.assertEqual(self.d.ASSETS, PREVIOUS_ASSETS[:5] + ['native-session-lifecycle.py', 'payload', 'previous'] + HELPERS)
        self.generate()
        current = self.d.asset_bytes(self.package)
        for name in HELPERS:
            self.assertEqual(current[name], (SOURCE / name).read_bytes())
        previous = self.package / 'previous'
        self.assertEqual(sorted(path.name for path in previous.iterdir()), sorted(PREVIOUS_ASSETS))
        for name in PREVIOUS_ASSETS:
            directory = 'native-provider-fix-03' if name in ['ELANNativeProvider.app', 'native-provider-deployment.py'] else 'native-provider-package-05'
            original = self.d.asset_bytes(self.build / directory, [name])
            self.assertEqual(self.d.asset_bytes(previous, [name]), original)
        self.assertEqual(len(self.signatures), 8)
        self.assertFalse(any((previous / name).exists() for name in HELPERS))

    def test_package_copies_builder_manifest_without_regenerating_it(self):
        expected = self.builder_manifest.read_bytes()
        self.generate()
        payload = self.package / 'payload/native-kernel-probe-06'
        self.assertEqual((payload / 'kernel-identity.json').read_bytes(), expected)
        self.assertEqual(identity.artifact_identity(payload / 'ELANNativeProbe.kext', self.d.VERSION), json.loads(expected))
        record = json.loads((self.package / 'package.json').read_text())
        self.assertEqual(record['kernel_identity_manifest'], 'payload/native-kernel-probe-06/kernel-identity.json')
        self.assertFalse((self.package / 'previous/native-kernel-identity.py').exists())

    def test_package_requires_dedicated_builder_manifest(self):
        self.assertTrue(self.builder_manifest.resolve().is_relative_to(self.root.resolve()))
        self.builder_manifest.unlink()
        with self.assertRaises(FileNotFoundError): self.generate()
        self.assertFalse((self.package / 'package.json').exists())
        self.assertEqual(self.signatures, [])

    def test_package_rejects_invalid_builder_manifest(self):
        self.builder_manifest.write_text('{invalid')
        with self.assertRaisesRegex(ValueError, 'invalid_manifest'): self.generate()
        self.assertFalse((self.package / 'package.json').exists())

    def test_package_rejects_stale_builder_manifest(self):
        manifest = json.loads(self.builder_manifest.read_text())
        manifest['sha256'] = '0' * 64
        self.builder_manifest.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'artifact_mismatch'): self.generate()
        self.assertFalse((self.package / 'package.json').exists())

    def test_package_rejects_same_uuid_changed_binary(self):
        executable = self.builder_bundle / 'Contents/MacOS/ELANNativeProbe'
        executable.write_bytes(executable.read_bytes() + b'changed after build record')
        with self.assertRaisesRegex(ValueError, 'artifact_mismatch'): self.generate()
        self.assertFalse((self.package / 'package.json').exists())

    def test_package_validates_copied_kext_not_just_build_source(self):
        original = shutil.copytree
        def tampered_copy(origin, destination, *args, **kwargs):
            result = original(origin, destination, *args, **kwargs)
            if Path(origin).resolve() == self.builder_bundle.resolve():
                executable = Path(destination) / 'Contents/MacOS/ELANNativeProbe'
                executable.write_bytes(executable.read_bytes() + b'changed while copying')
            return result
        with patch('shutil.copytree', side_effect=tampered_copy):
            with self.assertRaisesRegex(ValueError, 'artifact_mismatch'): self.generate()
        self.assertFalse((self.package / 'package.json').exists())

    def test_generated_command_targets_installed_cli_and_preserves_exit_status(self):
        self.generate()
        wrapper = self.package / '10-原生设置短诊断.command'
        text = wrapper.read_text()
        self.assertIn("/usr/bin/sudo /usr/bin/python3 -I -B '/Library/ELANFingerprintNativeTest/native-provider-deployment.py' diagnose-settings\n", text)
        self.assertIn('result=$?\n', text)
        self.assertTrue(text.endswith('exit $result\n'))
        self.assertNotIn('recovery', text)
        self.assertEqual(stat.S_IMODE(wrapper.stat().st_mode), 0o755)
        record = json.loads((self.package / 'package.json').read_text())
        self.assertIn('native-settings-diagnostic', record['test_actions'])
        self.assertFalse(record['installed'])
        instructions = (self.package / '说明.txt').read_text()
        self.assertIn('第 10 项启动临时原生服务，通过现有代理接入设置', instructions)
        self.assertIn('仍可能临时修改认证和设置扩展的内存状态', instructions)
        spec = importlib.util.spec_from_file_location('packaged_diagnostic', self.package / HELPERS[0])
        diagnostic = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(diagnostic)
        self.assertTrue(callable(diagnostic.run_diagnostic))
        self.assertTrue(callable(diagnostic._summary.summarize))

    def test_new_result_script_is_required_by_generator(self):
        path = self.source / HELPERS[1]
        self.assertEqual(path.resolve().parent, self.source.resolve())
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.generate()
        self.assertEqual(self.signatures, [])

    def test_new_helpers_are_included_in_package_syntax_validation(self):
        (self.source / HELPERS[1]).write_text('def invalid syntax\n')
        with self.assertRaises(SyntaxError):
            self.generate()
        self.assertEqual(len(self.signatures), 8)


if __name__ == '__main__':
    unittest.main()
