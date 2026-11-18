import importlib.util
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('diagnostic', Path(__file__).with_name('native-settings-diagnostic.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class FakeProcess:
    pid = 123
    def __init__(self, controller):
        self.controller = controller; self.alive = True; self.terminated = False
    def poll(self): return None if self.alive else 0
    def terminate(self): self.terminated = True; self.alive = False
    def wait(self, timeout):
        self.controller.events.append('wait')
        if self.controller.fail == 'wait': raise TimeoutError('private details')
        return 0 if not self.alive else 1


class Controller:
    VERSION = 'candidate'
    KERNEL_PACKAGE = 'kernel'
    def __init__(self, root):
        self.INSTALL = root / 'installed'; (self.INSTALL / 'state').mkdir(parents=True)
        self.root = root; self.events = []; self.gui_calls = []; self.commands = []; self.starts = []
        self.fail = None; self.cleanup_calls = 0; self.process = None; self.loaded = self.VERSION
        self.capabilities = {'baseline': 'SYSTEM_BIOMETRY available=0', 'capability': 'SYSTEM_BIOMETRY available=1', 'restored': 'SYSTEM_BIOMETRY available=0'}
    @contextmanager
    def runtime_lock(self):
        self.events.append('lock')
        if self.fail == 'lock': raise RuntimeError('private path')
        try: yield
        finally: self.events.append('unlock')
    def require_root(self, installed):
        assert installed
        if self.fail == 'preflight': raise RuntimeError('private secret')
    def verify_signatures(self, path): self.events.append('verify')
    def environment(self): self.events.append('environment'); return {'private': 'not exported'}
    def loaded_version(self): return self.loaded
    def cleanup(self):
        self.cleanup_calls += 1; self.events.append('cleanup')
        if self.cleanup_calls > 1 and self.fail == 'cleanup': raise RuntimeError('private details')
        if self.cleanup_calls == 1 and self.fail == 'initial_cleanup': raise RuntimeError('initial')
        if self.process:
            self.process.alive = False
            with (self.study.directory / 'broker.out').open('a') as f:
                f.write('PROVIDER_BROKER settings_cleanup_call=0x0 status=0 restored=1\nPROVIDER_BROKER_DONE status=0\n')
        (self.INSTALL / 'state/broker.json').unlink(missing_ok=True)
    def Study(self, label):
        c = self
        class Study:
            def __init__(s): s.directory = c.root / label; s.directory.mkdir()
            def job(s, *args):
                c.events.append('provider_job')
                output = s.directory / 'provider.out'; output.write_text('ELAN_PROVIDER ready=1\n')
                return None, output
            def close(s):
                c.events.append('study_close')
                if c.fail == 'study_close': raise RuntimeError('private details')
        self.study = Study(); return self.study
    def command(self, args):
        self.commands.append(args[-1])
        if self.fail == 'prepare': raise RuntimeError('private details')
        return {'status': 0, 'stdout': 'private kernel output', 'stderr': ''}
    def gui_auth(self, study, name):
        self.gui_calls.append(name)
        if self.fail == name: raise RuntimeError('private GUI detail')
        return self.capabilities[name]
    def wait_output(self, path, expected, *args):
        self.events.append('wait_output')
        if self.fail == 'provider' and expected.startswith('ELAN_PROVIDER'): raise RuntimeError('provider timeout')
        if self.fail == 'broker' and expected.startswith('PROVIDER_BROKER'): raise RuntimeError('broker timeout')
    def broker_identity(self, pid): return None if self.fail == 'identity' else 'private-identity'
    def save(self, path, value):
        if self.fail == 'result_save' and path.name == 'result.json': raise OSError('private path')
        path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(value))
    def popen(self, args, **kwargs):
        self.starts.append(args); kwargs['stdout'].write('PROVIDER_BROKER ready=1\n')
        if self.fail == 'popen': raise OSError('private error')
        self.process = FakeProcess(self); return self.process


class RunnerTests(unittest.TestCase):
    def test_pipe_lease_closes_on_all_exit_paths(self):
        for fail in (None, 'popen', 'provider', 'broker', 'identity'):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                c = Controller(Path(directory)); c.fail = fail
                held = []
                def launch(args, **kwargs):
                    self.assertTrue(kwargs['close_fds'])
                    self.assertTrue(stat.S_ISFIFO(os.fstat(kwargs['stdin']).st_mode))
                    self.assertFalse(os.get_inheritable(kwargs['stdin']))
                    held.append(os.dup(kwargs['stdin']))
                    return c.popen(args, **kwargs)
                try:
                    try:
                        m.run_diagnostic(c, input_fn=lambda _: '', popen_factory=launch)
                    except m.DiagnosticRunError:
                        self.assertIsNotNone(fail)
                    for fd in held:
                        os.set_blocking(fd, False)
                        self.assertEqual(os.read(fd, 1), b'')
                finally:
                    for fd in held: os.close(fd)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.c = Controller(Path(self.tmp.name)); self.answers = iter(['', ''])
    def run_it(self, **kwargs):
        return m.run_diagnostic(self.c, input_fn=lambda _: next(self.answers), popen_factory=self.c.popen, **kwargs)
    def test_observation_is_not_authentication_or_function_success(self):
        r = self.run_it()
        self.assertEqual(self.c.gui_calls, ['baseline', 'capability', 'restored'])
        self.assertFalse(r['auth_regression_ran']); self.assertIsNone(r['native_success'])
        self.assertTrue(r['settings_diagnostic_observed']); self.assertFalse(r['summary']['settings_function_verified'])
        self.assertEqual(r['run_state'], 'observed'); self.assertEqual(self.c.starts[0][-1], '--serve-managed')
        self.assertEqual(len(self.c.commands), 5); self.assertEqual(self.c.events[-1], 'unlock')
        self.assertNotIn('private', json.dumps(r))
    def test_observed_rejection_is_not_functional_success(self):
        calls = []
        def answer(_):
            calls.append(True)
            if len(calls) == 2:
                with (self.c.study.directory / 'broker.out').open('a') as f:
                    f.write('PROVIDER_BROKER settings_stage=connection_inspection call=0x0 status=0 image_matched=1 observation=2 stage=9 allowed=0\n')
                with (self.c.study.directory / 'provider.out').open('a') as f:
                    f.write('ELAN_PROVIDER settings_attach=-536870184 pid=4216\n')
            return ''
        r = m.run_diagnostic(self.c, input_fn=answer, popen_factory=self.c.popen)
        self.assertEqual(r['run_state'], 'observed'); self.assertEqual(r['summary']['diagnostic']['state'], 'rejected')
        self.assertFalse(r['summary']['settings_function_verified']); self.assertFalse(r['connection_recovery_authorized'])
        self.assertEqual(self.c.starts[0][-1], '--serve-managed')

    def test_explicit_recovery_flag_only(self):
        r = self.run_it(allow_connection_recovery=True)
        self.assertEqual(self.c.starts[0][-1], '--serve-managed-settings-recovery'); self.assertTrue(r['connection_recovery_authorized'])
        self.assertIsNone(r['summary']['recovery']['attempted'])
    def test_non_boolean_flag_rejected_before_actions(self):
        with self.assertRaises(TypeError): self.run_it(allow_connection_recovery='yes')
        self.assertEqual(self.c.events, [])
    def test_baseline_failure_cleans(self):
        self.c.capabilities['baseline'] = 'SYSTEM_BIOMETRY available=1'
        with self.assertRaises(m.DiagnosticRunError) as e: self.run_it()
        self.assertEqual(e.exception.result['failure_stage'], 'baseline'); self.assertFalse(self.c.starts)
        self.assertEqual(self.c.cleanup_calls, 2); self.assertIn('restored', self.c.gui_calls)
    def test_provider_failure_cleans(self):
        self.c.fail = 'provider'
        with self.assertRaises(m.DiagnosticRunError) as e: self.run_it()
        self.assertEqual(e.exception.result['failure_stage'], 'provider_start'); self.assertFalse(self.c.process.alive)
        self.assertEqual(self.c.cleanup_calls, 2)
    def test_user_cancel_before_start(self):
        self.answers = iter(['cancel'])
        with self.assertRaises(m.DiagnosticCancelled) as e: self.run_it()
        self.assertEqual(e.exception.result['run_state'], 'cancelled'); self.assertFalse(self.c.starts)
        self.assertEqual(self.c.cleanup_calls, 2)
    def test_user_cancel_during_observation(self):
        self.answers = iter(['', 'cancel'])
        with self.assertRaises(m.DiagnosticCancelled) as e: self.run_it()
        self.assertFalse(e.exception.result['settings_diagnostic_observed']); self.assertFalse(self.c.process.alive)
    def test_keyboard_interrupt(self):
        def interrupted(_): raise KeyboardInterrupt()
        with self.assertRaises(m.DiagnosticCancelled):
            m.run_diagnostic(self.c, input_fn=interrupted, popen_factory=self.c.popen)
        self.assertEqual(self.c.cleanup_calls, 2)
    def test_cleanup_failure_is_not_hidden(self):
        self.c.fail = 'cleanup'
        with self.assertRaises(m.DiagnosticRunError) as e: self.run_it()
        self.assertEqual(e.exception.result['run_state'], 'cleanup_failed')
        self.assertIn('controller_cleanup', e.exception.result['cleanup_failures'])
        self.assertEqual(e.exception.result['summary']['state'], 'cleanup_failed')
    def test_study_close_failure_still_runs_controller_cleanup(self):
        self.c.fail = 'study_close'
        with self.assertRaises(m.DiagnosticRunError) as e: self.run_it()
        self.assertEqual(self.c.cleanup_calls, 2); self.assertFalse(self.c.process.alive)
        self.assertIn('study_close', e.exception.result['cleanup_failures'])
    def test_unregistered_broker_is_terminated(self):
        self.c.fail = 'identity'
        with self.assertRaises(m.DiagnosticRunError): self.run_it()
        self.assertTrue(self.c.process.terminated)
    def test_broker_wait_failure_keeps_cleanup_evidence(self):
        self.c.fail = 'wait'
        with self.assertRaises(m.DiagnosticRunError) as e: self.run_it()
        self.assertIn('broker_wait', e.exception.result['cleanup_failures'])
    def test_missing_capability_evidence(self):
        self.c.capabilities['capability'] = 'unknown'
        with self.assertRaises(m.DiagnosticRunError) as e: self.run_it()
        self.assertIsNone(e.exception.result['capability_available']); self.assertTrue(e.exception.result['restored'])
    def test_contradictory_baseline_evidence(self):
        self.c.capabilities['baseline'] = 'SYSTEM_BIOMETRY available=0\nSYSTEM_BIOMETRY available=1'
        with self.assertRaises(m.DiagnosticRunError): self.run_it()
        self.assertFalse(self.c.starts)
    def test_restore_capability_failure(self):
        self.c.capabilities['restored'] = 'SYSTEM_BIOMETRY available=1'
        with self.assertRaises(m.DiagnosticRunError) as e: self.run_it()
        self.assertFalse(e.exception.result['restored']); self.assertIn('restored_capability', e.exception.result['cleanup_failures'])
    def test_result_save_failure_not_success(self):
        self.c.fail = 'result_save'
        with self.assertRaises(m.DiagnosticRunError) as e: self.run_it()
        self.assertIn('result_save', e.exception.result['cleanup_failures'])
    def test_version_mismatch_does_not_start_lifecycle(self):
        self.c.loaded = 'wrong'
        with self.assertRaises(m.DiagnosticRunError): self.run_it()
        self.assertEqual(self.c.cleanup_calls, 0); self.assertFalse(self.c.starts)
    def test_initial_cleanup_failure_is_retried(self):
        self.c.fail = 'initial_cleanup'
        with self.assertRaises(m.DiagnosticRunError): self.run_it()
        self.assertEqual(self.c.cleanup_calls, 2)
    def test_prepare_failure(self):
        self.c.fail = 'prepare'
        with self.assertRaises(m.DiagnosticRunError): self.run_it()
        self.assertFalse(self.c.starts); self.assertEqual(self.c.cleanup_calls, 2)
    def test_lock_failure_never_cleans_other_session(self):
        self.c.fail = 'lock'
        with self.assertRaises(m.DiagnosticRunError) as e: self.run_it()
        self.assertEqual(e.exception.result['failure_stage'], 'lock'); self.assertEqual(self.c.cleanup_calls, 0)
    def test_no_live_cli(self):
        self.assertFalse(hasattr(m, 'main'))

if __name__ == '__main__': unittest.main()
