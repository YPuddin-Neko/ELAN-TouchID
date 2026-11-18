import importlib.util
import io
import json
import os
import plistlib
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('deployment', Path(__file__).with_name('native-provider-deployment.py'))
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)


class BackgroundServiceTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.install = self.root / 'installed'; (self.install / 'state').mkdir(parents=True)
        self.plist = self.root / 'daemon.plist'
        for name, value in [('INSTALL', self.install), ('PACKAGE', self.install), ('BACKGROUND_PLIST', self.plist)]:
            self.stack.enter_context(patch.object(d, name, value))
        for name in ['require_root', 'verify_signatures', 'environment', 'require_kernel_identity']:
            self.stack.enter_context(patch.object(d, name))
        self.stack.enter_context(patch.object(d, 'loaded_version', return_value=d.VERSION))
        self.cleanup = self.stack.enter_context(patch.object(d, 'cleanup'))
        self.stack.enter_context(patch.object(d.os, 'chown'))
        self.stack.enter_context(patch.object(d.os, 'fchown'))
        self.stack.enter_context(redirect_stdout(io.StringIO()))
        self.stack.enter_context(redirect_stderr(io.StringIO()))
        original_stat = Path.stat
        def root_owned(path, *args, **kwargs):
            actual = original_stat(path, *args, **kwargs)
            if path == self.plist:
                fields = list(actual); fields[4] = 0
                return os.stat_result(fields)
            return actual
        self.stack.enter_context(patch.object(Path, 'stat', root_owned))

    def existing(self, changes=None):
        value = d.background_plist(); value.update(changes or {})
        self.plist.write_bytes(plistlib.dumps(value)); self.plist.chmod(0o644)

    def test_enable_publishes_plist_and_waits_for_active_session(self):
        with patch.object(d, 'background_job', return_value=None), patch.object(d, 'command') as command, \
                patch.object(d, 'background_status', side_effect=[{'running': True, 'session': {'status': 'starting'}},
                    {'running': True, 'session': {'status': 'active'}}]), patch.object(d.time, 'sleep') as sleep:
            d.enable_background()
        self.assertEqual(plistlib.loads(self.plist.read_bytes()), d.background_plist())
        self.assertEqual(command.call_args.args[0][:3], ['/bin/launchctl', 'bootstrap', 'system'])
        self.assertEqual(sleep.call_count, 1)
        self.cleanup.assert_called_once()

    def test_bootstrap_failure_removes_automatic_start_and_recovers(self):
        with patch.object(d, 'background_job', return_value=None), patch.object(d, 'command', side_effect=RuntimeError('bootstrap failed')):
            with self.assertRaisesRegex(RuntimeError, 'bootstrap failed'): d.enable_background()
        self.assertFalse(self.plist.exists())
        self.assertEqual(self.cleanup.call_count, 2)

    def test_failed_publication_removes_only_own_temporary_file(self):
        with patch.object(d, 'background_job', return_value=None), patch.object(d.os, 'replace', side_effect=OSError('rename failed')):
            with self.assertRaisesRegex(OSError, 'rename failed'): d.enable_background()
        self.assertFalse(self.plist.exists())
        self.assertFalse(self.plist.with_suffix('.plist.new').exists())

    def test_failure_after_publication_does_not_leave_boot_enabled(self):
        original_unlink = Path.unlink
        def unlink(path, *args, **kwargs):
            if path.name == 'background-status.json': raise OSError('stale status is locked')
            return original_unlink(path, *args, **kwargs)
        with patch.object(d, 'background_job', return_value=None), patch.object(Path, 'unlink', unlink):
            with self.assertRaisesRegex(OSError, 'stale status'): d.enable_background()
        self.assertFalse(self.plist.exists())
        self.assertEqual(self.cleanup.call_count, 2)

    def test_foreign_configuration_is_not_overwritten_or_stopped(self):
        self.existing({'ProgramArguments': ['/bin/other']})
        original = self.plist.read_bytes()
        with patch.object(d, 'background_job', return_value='state = running'), patch.object(d, 'unload_job') as unload:
            with self.assertRaisesRegex(RuntimeError, 'differs'): d.stop_background()
        self.assertEqual(self.plist.read_bytes(), original); unload.assert_not_called()

    def test_disable_removes_job_and_startup_before_recovery(self):
        self.existing(); events = []
        def unload(*args, **kwargs):
            self.assertTrue(self.plist.exists()); events.append('bootout')
        def recover():
            self.assertFalse(self.plist.exists()); events.append('recover')
        self.cleanup.side_effect = recover
        with patch.object(d, 'background_job', return_value='state = running'), patch.object(d, 'unload_job', side_effect=unload):
            d.disable_background()
        self.assertEqual(events, ['bootout', 'recover'])

    def test_bootout_failure_preserves_startup_and_does_not_overlap_cleanup(self):
        self.existing()
        with patch.object(d, 'background_job', return_value='state = running'), \
                patch.object(d, 'unload_job', side_effect=RuntimeError('still running')):
            with self.assertRaisesRegex(RuntimeError, 'still running'): d.disable_background()
        self.assertTrue(self.plist.exists()); self.cleanup.assert_not_called()

    def test_unexpected_registered_job_without_plist_is_preserved(self):
        with patch.object(d, 'background_job', return_value='state = running'), patch.object(d, 'unload_job') as unload:
            with self.assertRaisesRegex(RuntimeError, 'no matching plist'): d.stop_background()
        unload.assert_not_called()

    def test_runtime_lock_contention_does_not_enable_boot_start(self):
        with d.runtime_lock(), patch.object(d, 'background_job', return_value=None):
            with self.assertRaisesRegex(RuntimeError, '另一个'): d.enable_background()
        self.assertFalse(self.plist.exists()); self.cleanup.assert_not_called()

    def test_daemon_planned_failure_returns_without_restart_exit(self):
        with patch.object(d, 'loaded_version', return_value='0.3.0'), patch.object(d, 'ManagedProviderRuntime') as runtime:
            self.assertIsNone(d.serve_background())
        runtime.assert_not_called(); self.cleanup.assert_not_called()

    def test_stale_report_does_not_make_new_process_ready(self):
        self.existing()
        (self.install / 'state/background-status.json').write_text(json.dumps({'pid': 31, 'status': 'active'}))
        with patch.object(d, 'background_job', return_value='\tstate = running\n\tpid = 32\n'):
            status = d.background_status()
        self.assertTrue(status['running']); self.assertNotIn('session', status)
        self.assertEqual(status['last_session']['pid'], 31)

    def test_rollback_dispatch_stops_background_before_locking_runtime(self):
        events = []
        @contextmanager
        def lock():
            events.append('lock'); yield; events.append('unlock')
        with patch.object(d.sys, 'argv', ['deployment', 'rollback']), patch.object(d.signal, 'signal'), \
                patch.object(d, 'stop_background', side_effect=lambda: events.append('stop')), \
                patch.object(d, 'runtime_lock', lock), patch.object(d, 'rollback', side_effect=lambda: events.append('rollback')):
            d.main()
        self.assertEqual(events, ['stop', 'lock', 'rollback', 'unlock'])


if __name__ == '__main__': unittest.main()
