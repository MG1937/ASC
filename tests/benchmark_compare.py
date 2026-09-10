"""Compare module and CLI performance against a base checkout on one runner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import zipfile

from performance_compare import compare_pairs

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests' / 'fixtures'


def revision(root):
    return subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()


def measure(root, directory, case, output, sample):
    env = dict(os.environ, PYTHONPATH=str(root / 'src' / 'asc_core'))
    if case in ('unit', 'core'):
        command = [sys.executable, 'test_findrefs.py' if case == 'unit' else 'test.py']
    else:
        command = [sys.executable, str(root / 'main.py')]
        if case == 'cli_getclass':
            command += ['getclass', 'fixture.apk', 'com.google.android.material.timepicker.ClockFaceView', '--threads', '1', '--debug']
        else:
            command += ['findrefs', 'fixture.apk', '--threads', '1', '--debug', 'string', 'create']
    result = subprocess.run(command, cwd=directory, env=env, capture_output=True, text=True, timeout=30)
    (output / f'{case}-{sample}.stdout.log').write_text(result.stdout, encoding='utf-8')
    (output / f'{case}-{sample}.stderr.log').write_text(result.stderr, encoding='utf-8')
    if result.returncode:
        raise ValueError(f'{case} exited {result.returncode}; see {output}')
    if case == 'unit':
        times = {key: float(value) for key, value in re.findall(r'\[DEBUG\] (\w+) Time: ([\d.]+) us', result.stdout)}
        answer = {key: int(value) for key, value in re.findall(r'\[DEBUG\] ([\w ]+): (\d+)\s*$', result.stdout, re.M)}
    elif case == 'core':
        match = re.search(r'Total Execution Time in test.py: ([\d.]+) s', result.stdout)
        if match is None:
            raise ValueError('missing core timing')
        times = {'decompile': float(match[1]) * 1e6}
        answer = result.stdout.split('[INFO]')[0].strip()
    else:
        match = re.search(r'\[DEBUG\] Total Execution Time: ([\d.]+) us', result.stdout)
        if match is None:
            raise ValueError('missing CLI timing')
        times = {case: float(match[1])}
        answer = (result.stdout.split('-' * 50)[-1].strip() if case == 'cli_getclass' else
                  sorted(line for line in result.stdout.splitlines() if ' | ' in line))
    if not answer or (case in ('core', 'cli_getclass') and 'class ClockFaceView' not in answer):
        raise ValueError(f'{case}: missing result')
    return times, answer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, default=ROOT)
    parser.add_argument('--samples', type=int, default=31)
    parser.add_argument('--cases', nargs='+', choices=('unit', 'core', 'cli_getclass', 'cli_findrefs'),
                        default=['unit', 'core', 'cli_getclass', 'cli_findrefs'])
    parser.add_argument('--output', type=Path, default=Path('artifacts/comparison'))
    args = parser.parse_args()
    if args.samples < 15:
        parser.error('at least 15 paired samples are required')
    roots = {'base': args.baseline.resolve(), 'candidate': args.candidate.resolve()}
    report = {'python': sys.version, 'platform': platform.platform(), 'samples': {}, 'errors': []}
    args.output.mkdir(parents=True, exist_ok=True)
    for side in roots:
        (args.output / side).mkdir(exist_ok=True)
    try:
        report['revisions'] = {side: revision(root) for side, root in roots.items()}
        contract = json.loads((FIXTURES / 'reference-baseline.json').read_text())
        archive = FIXTURES / 'reference-workload.zip'
        if hashlib.sha256(archive.read_bytes()).hexdigest() != contract['archive_sha256']:
            raise ValueError('reference archive identity mismatch')
        with tempfile.TemporaryDirectory() as directory:
            with zipfile.ZipFile(archive) as source:
                if set(source.namelist()) != {'classes.dex', 'test.py', 'test_findrefs.py'}:
                    raise ValueError('unexpected archive members')
                source.extractall(directory)
            with zipfile.ZipFile(Path(directory) / 'fixture.apk', 'w', compression=zipfile.ZIP_DEFLATED) as apk:
                apk.write(Path(directory) / 'classes.dex', 'classes.dex')
            for case in args.cases:
                expected_keys = set(contract['findrefs_times_us']) if case == 'unit' else {'decompile' if case == 'core' else case}
                samples = {key: {'base': [], 'candidate': []} for key in expected_keys}
                report['samples'][case] = samples
                for index in range(-1, args.samples):
                    answers = {}
                    order = ('base', 'candidate') if index % 2 == 0 else ('candidate', 'base')
                    for side in order:
                        times, answers[side] = measure(roots[side], directory, case, args.output / side, index)
                        if times.keys() != expected_keys:
                            raise ValueError(f'{case}: missing or unexpected timing metrics')
                        if case == 'unit' and answers[side] != contract['findrefs_counts']:
                            raise ValueError(f'{side}: reference count mismatch')
                        if index >= 0:
                            for key, value in times.items():
                                samples[key][side].append(value)
                    if answers['base'] != answers['candidate']:
                        raise ValueError(f'{case}: base/candidate outputs differ')
        metric_count = sum(len(metrics) for metrics in report['samples'].values())
        report['comparisons'] = {}
        for case, metrics in report['samples'].items():
            for key, values in metrics.items():
                result = compare_pairs(values['base'], values['candidate'], metric_count)
                report['comparisons'][f'{case}/{key}'] = result
                if result['regression']:
                    report['errors'].append(f'{case}/{key}: significant slowdown ({result["paired_median_change_percent"]:+.2f}%)')
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        report['errors'].append(str(error))
    (args.output / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items() if key != 'samples'}, indent=2))
    return 1 if report['errors'] else 0


if __name__ == '__main__':
    sys.exit(main())
