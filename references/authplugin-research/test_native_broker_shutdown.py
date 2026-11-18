"""Run the production broker loop with anonymous-pipe leases and mocked kernel/peer IO."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent


def production_blocks():
    source = (ROOT / 'native-provider-broker.mm').read_text()
    state = source[source.index('static volatile sig_atomic_t stopping;'):
                   source.index('static NSData *expectedWorkerIdentity')]
    transfer = source[source.index('enum class NativeBrokerTransfer'):
                      source.index('static bool removeStaleSocket')]
    stop = source[source.index('static NativeBrokerStop brokerStop('):
                  source.index('int main(int argc, char **argv)')]
    start = source.index('        int result = 1, peer = -1;')
    end = source.index('        return result;', start) + len('        return result;')
    loop = source[start:end]
    # Keep the dispatch and cleanup in the extracted body; only its dependencies are mocked.
    assert 'IOConnectCallStructMethod' in loop
    assert 'if (recoverProvider(connection)) result = 1;' in loop
    return state, transfer + stop + '''
static int runProductionServe(bool managed) {
    int listener = Listener, connection = Kernel, expected = Expected;
    bool connectionRecoveryEnabled = false;
''' + loop + '\n}\n'


class BrokerShutdownTests(unittest.TestCase):
    def test_production_serve_loop_with_host_sanitizers(self):
        compiler = shutil.which(os.environ.get('CXX', 'clang++'))
        self.assertIsNotNone(compiler, 'A host C++ compiler is required')
        state, implementation = production_blocks()
        with tempfile.TemporaryDirectory(prefix='native-broker-stop-') as temporary:
            directory = Path(temporary)
            (directory / 'native-broker-production-state.inc').write_text(state)
            (directory / 'native-broker-production.inc').write_text(implementation)
            executable = directory / 'test-native-broker-stop'
            command = [compiler, '-std=c++14', '-Wall', '-Wextra', '-Werror',
                       '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                       '-fno-omit-frame-pointer', '-g',
                       '-I', str(ROOT), '-I', str(directory),
                       str(ROOT / 'test-native-broker-stop.cpp'), '-o', str(executable)]
            compiled = subprocess.run(command, text=True, capture_output=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            environment = dict(os.environ, ASAN_OPTIONS='abort_on_error=1',
                               UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
            ran = subprocess.run([str(executable)], text=True, capture_output=True,
                                 env=environment, timeout=30)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            self.assertIn('BROKER_STOP production_loop=1 real_pipe_lease=1', ran.stdout)
            print(ran.stdout.splitlines()[-1])


if __name__ == '__main__':
    unittest.main()
