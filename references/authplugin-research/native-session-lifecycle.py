"""Supervise native-provider generations, recovering before every restart."""
import time


def supervise(runtime, duration=900, clock=time.monotonic, sleep=time.sleep, persistent=False):
    if persistent and duration is not None:
        raise ValueError('Persistent supervision requires an explicit unbounded duration')
    if not persistent and (duration is None or not 0 < duration <= 900):
        raise ValueError('Session duration must be between 0 and 900 seconds')
    deadline = None if persistent else clock() + duration
    active = False
    started = None
    ready_since = None
    retry_at = 0
    failures = 0
    power_epoch = None
    result = {'generations': 0, 'restarts': 0, 'console_waits': 0, 'power_stops': 0, 'startup_errors': [], 'restored': False}

    def retry(state):
        nonlocal active, failures, retry_at
        runtime.stop()
        active = False
        if state == 'inactive-session':
            failures = 0
            retry_at = clock() + 5
            return
        if state == 'storage':
            raise RuntimeError('指纹数据读取失败，已停止后台重试。请运行原生认证测试查看钥匙串错误。')
        failures += 1
        if failures >= 3:
            raise RuntimeError('指纹服务连续三次启动或运行失败，已停止重试。')
        result['restarts'] += 1
        retry_at = clock() + 5 * (2 ** (failures - 1))
    try:
        runtime.recover()
        while deadline is None or clock() < deadline:
            power_ready, epoch = runtime.power_state()
            power_changed = power_epoch is not None and epoch != power_epoch
            power_epoch = epoch
            if not power_ready or power_changed:
                if active:
                    runtime.stop()
                    active = False
                    result['power_stops'] += 1
                failures = 0
                retry_at = 0
            elif not runtime.console_active():
                if active:
                    runtime.stop()
                    active = False
                    result['console_waits'] += 1
                failures = 0
                retry_at = 0
            elif not active and clock() >= retry_at:
                # start() can leave a partially bootstrapped job or broker.
                active = True
                started = clock()
                ready_since = None
                result['generations'] += 1
                try:
                    runtime.start()
                except Exception as error:
                    result['startup_errors'].append(str(error))
                    retry('startup')
            elif active:
                state = runtime.poll()
                if state == 'running':
                    if ready_since is None:
                        ready_since = clock()
                    if clock() - ready_since >= 30:
                        failures = 0
                elif state == 'starting' and clock() - started < 45:
                    ready_since = None
                    pass
                else:
                    retry(state)
            sleep(1 if deadline is None else min(1, max(0, deadline - clock())))
    finally:
        # stop() also handles an unfinished start and verifies system recovery.
        try:
            runtime.stop()
            result['restored'] = True
        finally:
            runtime.close()
    return result
