import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lifecycle = load('lifecycle', 'native-session-lifecycle.py')
deployment = load('deployment', 'native-provider-deployment.py')


class Runtime:
    def __init__(self):
        self.time = 0
        self.active = False
        self.events = []
        self.console = lambda: True
        self.state = lambda: 'running'
        self.power = lambda: (True, 0)
        self.start_error = False
        self.stop_error = False

    def clock(self):
        return self.time

    def sleep(self, seconds):
        self.time += seconds

    def recover(self):
        self.events.append(('recover', self.time))

    def console_active(self):
        return self.console()

    def power_state(self):
        return self.power()

    def close(self):
        pass

    def start(self):
        if self.active:
            raise AssertionError('Previous generation has not stopped')
        self.active = True
        self.events.append(('start', self.time))
        if self.start_error:
            raise OSError('partial start')

    def stop(self):
        self.events.append(('stop', self.time))
        if self.stop_error:
            raise OSError('restore failed')
        self.active = False

    def poll(self):
        return self.state()

    def run(self, seconds):
        return lifecycle.supervise(self, seconds, self.clock, self.sleep)


class LifecycleTests(unittest.TestCase):
    def test_idle_console_does_not_start_provider(self):
        runtime = Runtime()
        runtime.console = lambda: False
        result = runtime.run(5)
        self.assertEqual(result['generations'], 0)
        self.assertEqual(runtime.events, [('recover', 0), ('stop', 5)])

    def test_running_session_is_stopped_at_deadline(self):
        runtime = Runtime()
        self.assertTrue(runtime.run(10)['restored'])
        self.assertEqual(runtime.events, [('recover', 0), ('start', 0), ('stop', 10)])

    def test_console_loss_restores_before_new_generation(self):
        runtime = Runtime()
        runtime.console = lambda: runtime.time < 2 or runtime.time >= 5
        result = runtime.run(8)
        self.assertEqual(result['console_waits'], 1)
        self.assertEqual(runtime.events, [('recover', 0), ('start', 0), ('stop', 2), ('start', 5), ('stop', 8)])

    def test_worker_exit_has_cleanup_barrier_and_delayed_restart(self):
        runtime = Runtime()
        runtime.state = lambda: 'exited' if runtime.time == 1 else 'running'
        self.assertEqual(runtime.run(10)['restarts'], 1)
        self.assertEqual(runtime.events[:5], [('recover', 0), ('start', 0), ('stop', 1), ('start', 6), ('stop', 10)])

    def test_starting_timeout_uses_same_cleanup_barrier(self):
        runtime = Runtime()
        runtime.state = lambda: 'starting'
        result = runtime.run(52)
        self.assertEqual(result['restarts'], 1)
        self.assertIn(('stop', 45), runtime.events)
        self.assertIn(('start', 50), runtime.events)

    def test_partial_start_failures_are_bounded(self):
        runtime = Runtime()
        runtime.start_error = True
        with self.assertRaisesRegex(RuntimeError, '三次'):
            runtime.run(100)
        self.assertEqual([time for action, time in runtime.events if action == 'start'], [0, 5, 15])
        self.assertFalse(runtime.active)

    def test_repeated_worker_crash_is_bounded(self):
        runtime = Runtime()
        runtime.state = lambda: 'exited'
        with self.assertRaisesRegex(RuntimeError, '三次'):
            runtime.run(100)
        self.assertEqual([time for action, time in runtime.events if action == 'start'], [0, 6, 17])
        self.assertFalse(runtime.active)

    def test_storage_failure_is_not_automatically_retried(self):
        runtime = Runtime()
        runtime.state = lambda: 'storage'
        with self.assertRaisesRegex(RuntimeError, '读取失败'):
            runtime.run(100)
        self.assertEqual(sum(action == 'start' for action, _ in runtime.events), 1)
        self.assertFalse(runtime.active)

    def test_recovery_failure_never_starts_new_worker(self):
        runtime = Runtime()
        runtime.state = lambda: 'exited'
        runtime.stop_error = True
        with self.assertRaisesRegex(OSError, 'restore failed'):
            runtime.run(100)
        self.assertEqual(sum(action == 'start' for action, _ in runtime.events), 1)

    def test_interrupt_drains_active_generation(self):
        runtime = Runtime()
        runtime.state = Mock(side_effect=KeyboardInterrupt)
        with self.assertRaises(KeyboardInterrupt):
            runtime.run(100)
        self.assertFalse(runtime.active)
        self.assertEqual(runtime.events[-1], ('stop', 1))

    def test_healthy_generation_resets_quick_failure_count(self):
        runtime = Runtime()
        runtime.state = lambda: 'exited' if runtime.time in (1, 7, 50) else 'running'
        result = runtime.run(57)
        self.assertEqual(result['generations'], 4)
        self.assertIn(('start', 55), runtime.events)

    def test_slow_initialization_does_not_count_as_healthy_uptime(self):
        runtime = Runtime()
        def state():
            age = runtime.time - [time for action, time in runtime.events if action == 'start'][-1]
            return 'starting' if age < 40 else 'running' if age == 40 else 'exited'
        runtime.state = state
        with self.assertRaisesRegex(RuntimeError, '三次'):
            runtime.run(200)
        self.assertEqual(sum(action == 'start' for action, _ in runtime.events), 3)

    def test_duration_cannot_create_unbounded_service(self):
        for duration in (0, -1, 901):
            runtime = Runtime()
            with self.assertRaises(ValueError):
                runtime.run(duration)
            self.assertEqual(runtime.events, [])

    def test_sleep_waits_for_full_wake_before_starting_fresh_generation(self):
        runtime = Runtime()
        runtime.power = lambda: (runtime.time < 2 or runtime.time >= 7, 0 if runtime.time < 2 else 1 if runtime.time < 7 else 3)
        result = runtime.run(10)
        self.assertEqual(result['power_stops'], 1)
        self.assertEqual(runtime.events, [('recover', 0), ('start', 0), ('stop', 2), ('start', 8), ('stop', 10)])

    def test_fast_sleep_wake_between_polls_still_retires_old_generation(self):
        runtime = Runtime()
        runtime.power = lambda: (True, 0 if runtime.time < 2 else 3)
        result = runtime.run(5)
        self.assertEqual(result['power_stops'], 1)
        self.assertIn(('stop', 2), runtime.events)
        self.assertIn(('start', 3), runtime.events)

    def test_unknown_power_or_dark_wake_does_not_open_sensor(self):
        runtime = Runtime()
        runtime.power = lambda: (False, 0)
        self.assertEqual(runtime.run(5)['generations'], 0)

    def test_lost_power_observer_stops_and_does_not_restart(self):
        runtime = Runtime()
        def power():
            if runtime.time >= 2: raise RuntimeError('observer exited')
            return True, 0
        runtime.power = power
        with self.assertRaisesRegex(RuntimeError, 'observer exited'):
            runtime.run(10)
        self.assertEqual(runtime.events, [('recover', 0), ('start', 0), ('stop', 2)])

    def test_persistent_session_does_not_restart_at_test_deadline(self):
        runtime = Runtime()
        def state():
            if runtime.time >= 2000: raise KeyboardInterrupt
            return 'running'
        runtime.state = state
        with self.assertRaises(KeyboardInterrupt):
            lifecycle.supervise(runtime, duration=None, persistent=True, clock=runtime.clock, sleep=runtime.sleep)
        self.assertEqual(runtime.events, [('recover', 0), ('start', 0), ('stop', 2000)])

    def test_inactive_gui_is_waited_for_without_crash_retry_limit(self):
        runtime = Runtime()
        runtime.state = lambda: 'inactive-session' if runtime.time < 30 else 'running'
        result = runtime.run(40)
        self.assertGreater(result['generations'], 3)
        self.assertEqual(result['restarts'], 0)
        self.assertTrue(result['restored'])

    def test_unbounded_duration_requires_explicit_persistent_mode(self):
        runtime = Runtime()
        with self.assertRaises(ValueError):
            lifecycle.supervise(runtime, duration=None)
        with self.assertRaises(ValueError):
            lifecycle.supervise(runtime, persistent=True)


class RuntimeAdapterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        identity = patch.object(deployment, 'require_kernel_identity')
        identity.start()
        self.addCleanup(identity.stop)
        self.runtime = deployment.ManagedProviderRuntime()
        self.runtime.worker_output = self.root / 'provider.out'
        self.runtime.worker_output.write_text('ELAN_PROVIDER ready=1\n')
        self.runtime.worker_target = 'gui/501/fixture'
        self.runtime.broker = Mock()
        self.runtime.broker.poll.return_value = None

    def test_crashed_launchd_job_is_not_running_because_old_ready_log_remains(self):
        with patch.object(deployment, 'command', return_value={'status': 0, 'stdout': 'state = not running'}):
            self.assertEqual(self.runtime.poll(), 'exited')

    def test_running_job_requires_ready_marker(self):
        with patch.object(deployment, 'command', return_value={'status': 0, 'stdout': '\tstate = running\n'}):
            self.assertEqual(self.runtime.poll(), 'running')
            self.runtime.worker_output.write_text('ELAN_PROVIDER begin=0\n')
            self.assertEqual(self.runtime.poll(), 'starting')

    def test_storage_failure_is_returned_before_ready_or_process_state(self):
        self.runtime.worker_output.write_text('ELAN_PROVIDER catalog_load_error=NSOSStatusErrorDomain:-25308\n')
        with patch.object(deployment, 'command') as command:
            self.assertEqual(self.runtime.poll(), 'storage')
        command.assert_not_called()

    def test_child_exit_overrides_ready_log(self):
        self.runtime.broker.poll.return_value = 1
        self.assertEqual(self.runtime.poll(), 'exited')

    def test_missing_gui_domain_waits_before_starting_provider(self):
        self.runtime.power.console = True; self.runtime.worker_target = None
        with patch.object(deployment, 'command', return_value={'status': 3, 'stderr': 'Could not find domain for user gui/501'}):
            self.assertFalse(self.runtime.console_active())

    def test_active_generation_reuses_observed_console_without_spawning_queries(self):
        self.runtime.power.console = True
        with patch.object(deployment, 'command') as command:
            self.assertTrue(self.runtime.console_active())
            self.runtime.power.console = False
            self.assertFalse(self.runtime.console_active())
        command.assert_not_called()

    def test_gui_query_permission_failure_is_reported(self):
        self.runtime.power.console = True; self.runtime.worker_target = None
        with patch.object(deployment, 'command', return_value={'status': 1, 'stderr': 'Operation not permitted'}):
            with self.assertRaisesRegex(RuntimeError, 'inspect GUI domain'): self.runtime.console_active()

    def test_launchd_failure_still_recovers_broker(self):
        self.runtime.study = Mock()
        self.runtime.study.close.side_effect = RuntimeError('job unload failed')
        with patch.object(deployment, 'INSTALL', self.root), patch.object(deployment, 'cleanup') as cleanup:
            with self.assertRaisesRegex(RuntimeError, 'job unload failed'):
                self.runtime.stop()
        cleanup.assert_called_once()
        self.runtime.broker.terminate.assert_called_once()

    def test_real_file_lock_prevents_two_controllers_and_releases(self):
        with patch.object(deployment, 'INSTALL', self.root):
            with deployment.runtime_lock():
                with self.assertRaisesRegex(RuntimeError, '另一个'):
                    with deployment.runtime_lock():
                        self.fail('Second controller acquired lock')
            with deployment.runtime_lock():
                pass


class PowerObserverStreamTests(unittest.TestCase):
    def setUp(self):
        self.reader, self.writer = os.pipe()
        self.addCleanup(os.close, self.reader)
        self.addCleanup(lambda: os.close(self.writer) if self.writer is not None else None)
        os.set_blocking(self.reader, False)
        self.observer = deployment.PowerObserver()
        self.observer.process = Mock()
        self.observer.process.stdout.fileno.return_value = self.reader
        self.observer.process.poll.return_value = None
        self.observer.log = io.BytesIO()

    def send(self, ready, epoch):
        os.write(self.writer, b'POWER_STATE ' + json.dumps({'ready': ready, 'epoch': epoch, 'console_known': True, 'console_user': 501}).encode() + b'\n')

    def test_partial_pipe_record_is_not_a_ready_state(self):
        os.write(self.writer, b'POWER_STA')
        self.assertIsNone(self.observer.read())
        os.write(self.writer, b'TE {"ready":true,"epoch":0,"console_known":true,"console_user":501}\n')
        self.assertEqual(self.observer.read(), (True, 0))
        self.assertIs(self.observer.console, True)

    def test_accumulated_sleep_wake_preserves_changed_generation(self):
        self.send(True, 0); self.observer.read()
        self.send(False, 1); self.send(False, 2); self.send(True, 3)
        self.assertEqual(self.observer.read(), (True, 3))

    def test_monitor_eof_is_not_cached_awake_state(self):
        self.send(True, 0); self.observer.read()
        os.close(self.writer); self.writer = None
        with self.assertRaisesRegex(RuntimeError, 'observer exited'):
            self.observer.read()

    def test_invalid_and_rewound_monitor_records_stop_control(self):
        self.send(True, 3); self.observer.read()
        self.send(True, 2)
        with self.assertRaisesRegex(RuntimeError, 'backwards'):
            self.observer.read()
        self.send(1, 4)
        with self.assertRaisesRegex(RuntimeError, 'invalid'):
            self.observer.read()


if __name__ == '__main__':
    unittest.main()
