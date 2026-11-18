"""Injected short diagnostic runner. Importing this module performs no system action."""
import importlib.util
import os
from pathlib import Path

_spec = importlib.util.spec_from_file_location('native_settings_result', Path(__file__).with_name('native-settings-result.py'))
_summary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_summary)


class DiagnosticRunError(RuntimeError):
    def __init__(self, result):
        super().__init__('Settings diagnostic failed; inspect the sanitized result')
        self.result = result


class DiagnosticCancelled(KeyboardInterrupt):
    def __init__(self, result):
        super().__init__('Settings diagnostic cancelled; cleanup attempted')
        self.result = result


def run_diagnostic(controller, *, input_fn, popen_factory, allow_connection_recovery=False):
    """Use an already verified controller; caller owns authorization and dependency selection.

    No four-step authentication regression or enrollment operation is performed.
    True recovery is an explicit caller choice, never inferred from observed cache state.
    """
    if type(allow_connection_recovery) is not bool:
        raise TypeError('allow_connection_recovery must be a boolean')
    if not callable(input_fn) or not callable(popen_factory):
        raise TypeError('Explicit input and process factories are required')
    result = {'schema_version': 1, 'run_state': 'not_run', 'auth_regression_ran': False,
              'native_success': None, 'settings_diagnostic_observed': False,
              'connection_recovery_authorized': allow_connection_recovery,
              'prepared_phases': [], 'baseline_available': None, 'capability_available': None,
              'restored': None, 'cleanup_failures': []}
    study = broker = broker_output = worker_output = None
    stage = 'lock'
    failed = cancelled = False
    lifecycle_started = False
    lease_write = None

    def failure(name):
        if name not in result['cleanup_failures']:
            result['cleanup_failures'].append(name)

    def prompt(message):
        answer = input_fn(message)
        if not isinstance(answer, str) or answer.strip().lower() in ('q', 'quit', 'cancel', '取消'):
            raise KeyboardInterrupt()

    def read_log(path):
        if path is None:
            return ''
        try:
            return path.read_text(errors='replace')
        except (OSError, UnicodeError):
            failure('summary_log_read')
            return ''

    try:
        with controller.runtime_lock():
            try:
                stage = 'preflight'
                controller.require_root(installed=True)
                controller.verify_signatures(controller.INSTALL)
                controller.environment()
                if controller.loaded_version() != controller.VERSION:
                    raise RuntimeError('Driver version mismatch')
                # Once initial cleanup starts, every later exit retries cleanup before returning.
                lifecycle_started = True
                stage = 'initial_cleanup'
                controller.cleanup()
                stage = 'study_create'
                study = controller.Study('settings-diagnostic')
                stage = 'prepare'
                client = controller.INSTALL / 'payload' / controller.KERNEL_PACKAGE / 'elan-native-probe'
                for phase in ['status', 'context-lifecycle', 'credential-study', 'policy-study', 'restore-study-availability']:
                    controller.command([client, '--' + phase])
                    result['prepared_phases'].append(phase)
                stage = 'baseline'
                baseline = controller.gui_auth(study, 'baseline')
                result['baseline_available'] = _capability(baseline)
                if result['baseline_available'] is not False:
                    raise RuntimeError('Baseline not confirmed unavailable')
                stage = 'ready_prompt'
                prompt('请先完全退出系统设置。此轮只观察设置，不重复四项指纹认证；若钥匙串询问配套程序读取指纹项，请按已批准流程操作。准备后按回车，取消请输入 cancel：')
                stage = 'broker_start'
                broker_output = study.directory / 'broker.out'
                mode = '--serve-managed-settings-recovery' if allow_connection_recovery else '--serve-managed'
                lease_read, lease_write = os.pipe()
                try:
                    with broker_output.open('w') as log:
                        broker = popen_factory([str(controller.INSTALL / 'ELANNativeBroker'), mode],
                                               stdin=lease_read, close_fds=True, stdout=log, stderr=-2)
                finally:
                    os.close(lease_read)
                controller.wait_output(broker_output, 'PROVIDER_BROKER ready=1')
                stage = 'broker_identity'
                identity = controller.broker_identity(broker.pid)
                if not identity:
                    raise RuntimeError('Broker identity unavailable')
                controller.save(controller.INSTALL / 'state/broker.json', {'pid': broker.pid, 'identity': identity})
                stage = 'provider_start'
                _, worker_output = study.job('gui/501', 'provider',
                    [controller.INSTALL / 'ELANNativeProvider.app/Contents/MacOS/ELANNativeProvider', '--serve'],
                    'com.apple.biometrickitd')
                controller.wait_output(worker_output, 'ELAN_PROVIDER ready=1', 90)
                stage = 'capability'
                result['capability_available'] = _capability(controller.gui_auth(study, 'capability'))
                if result['capability_available'] is not True:
                    raise RuntimeError('Capability not confirmed available')
                stage = 'observation'
                prompt('打开系统设置的“登录密码”，只观察，不录入、删除指纹或更改开关。观察后回这里按回车；取消请输入 cancel：')
                result['settings_diagnostic_observed'] = True
                result['run_state'] = 'observed'
            except KeyboardInterrupt:
                cancelled = True
                result['run_state'] = 'cancelled'
                result['failure_stage'] = stage
            except BaseException:
                failed = True
                result['run_state'] = 'failed'
                result['failure_stage'] = stage
            finally:
                if lease_write is not None:
                    try:
                        os.close(lease_write)
                    except OSError:
                        failure('lease_close')
                    lease_write = None
                if lifecycle_started:
                    if study is not None:
                        try:
                            study.close()
                        except BaseException:
                            failure('study_close')
                    if broker is not None:
                        try:
                            if broker.poll() is None and not (controller.INSTALL / 'state/broker.json').exists():
                                broker.terminate()
                                broker.wait(timeout=15)
                        except BaseException:
                            failure('unregistered_broker_stop')
                    try:
                        controller.cleanup()
                    except BaseException:
                        failure('controller_cleanup')
                    if broker is not None:
                        try:
                            if broker.wait(timeout=10) != 0:
                                failure('broker_exit')
                        except BaseException:
                            failure('broker_wait')
                    if study is not None:
                        try:
                            result['restored'] = _capability(controller.gui_auth(study, 'restored')) is False
                            if not result['restored']:
                                failure('restored_capability')
                        except BaseException:
                            result['restored'] = False
                            failure('restored_capability')
                broker_text, worker_text = read_log(broker_output), read_log(worker_output)
                result['cleanup_error'] = bool(result['cleanup_failures'])
                result['summary'] = _summary.summarize(broker_text, worker_text, result)
                if result['cleanup_failures']:
                    failed = True
                    result['run_state'] = 'cleanup_failed'
                if study is not None:
                    try:
                        controller.save(study.directory / 'result.json', result)
                    except BaseException:
                        failure('result_save')
                        failed = True
                        result['run_state'] = 'cleanup_failed'
                        result['cleanup_error'] = True
                        result['summary'] = _summary.summarize(broker_text, worker_text, result)
    except (KeyboardInterrupt, SystemExit):
        if not cancelled and not failed:
            cancelled = True
            result['run_state'] = 'cancelled'
            result['failure_stage'] = stage
    except BaseException:
        if not failed:
            failed = True
            result['run_state'] = 'failed'
            result['failure_stage'] = stage
    if 'summary' not in result:
        result['cleanup_error'] = bool(result['cleanup_failures'])
        result['summary'] = _summary.summarize('', '', result)
    if failed:
        raise DiagnosticRunError(result) from None
    if cancelled:
        raise DiagnosticCancelled(result) from None
    return result


def _capability(text):
    """Reject absent or contradictory capability evidence instead of coercing it."""
    if not isinstance(text, str):
        return None
    import re
    values = re.findall(r'SYSTEM_BIOMETRY available=([01])(?=\s|$)', text)
    if not values or len(set(values)) != 1:
        return None
    return values[0] == '1'
