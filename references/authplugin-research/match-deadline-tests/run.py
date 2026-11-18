#!/usr/bin/env python3
"""Build source-extracted deadline regressions without opening hardware."""
import argparse
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

def extract(text, start, end):
    if text.count(start) != 1:
        raise ValueError(f'Expected one source anchor: {start!r}')
    begin = text.index(start)
    return text[begin:text.index(end, begin)]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['all', 'native', 'x86', 'sanitizer'], default='all')
    args = parser.parse_args()
    capture = (ROOT / 'src/elan_match_test.c').read_text()
    provider = (HERE.parent / 'native-elan-provider.m').read_text()
    bodies = {
        'capture': extract(capture, 'static ElanpressFeatures *captureWithReaderOptionsUntil(', 'static unsigned match('),
        'provider': extract(provider, '            const double captureDeadline =', '                unsigned score = 0;'),
        'post-match': extract(provider, '                    if (capture_milliseconds() >= captureDeadline)', '                    if (!record'),
    }
    if 'time(NULL)' in bodies['capture']:
        raise AssertionError('Capture deadline must use the monotonic clock')
    sources = [('capture', 'c', '/* CAPTURE_BODY */', 13),
               ('provider', 'm', '/* PROVIDER_LOOP */', 9),
               ('post-match', 'm', '/* POST_MATCH_GUARD */', 5)]
    modes = {'native': [], 'x86': ['-arch', 'x86_64'],
             'sanitizer': ['-fsanitize=address,undefined']}
    selected = modes if args.mode == 'all' else {args.mode: modes[args.mode]}
    with tempfile.TemporaryDirectory(prefix='elan-match-deadline-') as directory:
        work = Path(directory)
        for name, extension, marker, expected in sources:
            template = (HERE / f'{name}.{extension}.in').read_text()
            assert template.count(marker) == 1
            source = work / f'{name}.{extension}'
            source.write_text(template.replace(marker, bodies[name]))
            for mode, flags in selected.items():
                binary = work / f'{name}-{mode}'
                cmd = ['xcrun', 'clang', '-O1', *flags, '-I' + str(ROOT / 'src')]
                if extension == 'm':
                    cmd += ['-fobjc-arc', '-framework', 'Foundation']
                subprocess.run([*cmd, str(source), '-o', str(binary)], check=True, timeout=60)
                result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
                if result.returncode:
                    raise RuntimeError(result.stdout + result.stderr)
                passed = sum(line.startswith('PASS ') for line in result.stdout.splitlines())
                if passed != expected:
                    raise AssertionError(f'{name}/{mode}: expected {expected}, got {passed}')
                print(f'{name}/{mode}: {passed} passed')
    print('All requested source-extracted regression tests passed.')

if __name__ == '__main__':
    main()
