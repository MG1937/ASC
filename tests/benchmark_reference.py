"""Run the supplied DEX benchmarks unchanged in fresh Python processes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / 'fixtures'


def run_script(script, directory, output, index):
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src' / 'asc_core'))
    start = time.perf_counter()
    result = subprocess.run([sys.executable, script], cwd=directory, env=env,
                            capture_output=True, text=True, timeout=30)
    wall_ms = (time.perf_counter() - start) * 1000
    stem = output / f'{Path(script).stem}-{index:02d}'
    stem.with_suffix('.stdout.log').write_text(result.stdout, encoding='utf-8')
    stem.with_suffix('.stderr.log').write_text(result.stderr, encoding='utf-8')
    if result.returncode:
        raise ValueError(f'{script} sample {index}: exit {result.returncode}; see logs')
    return result.stdout, wall_ms


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=int, default=9)
    parser.add_argument('--output', type=Path, default=Path('artifacts/reference'))
    args = parser.parse_args()
    if args.samples < 3:
        parser.error('use at least 3 samples')
    args.output.mkdir(parents=True, exist_ok=True)
    baseline = json.loads((FIXTURES / 'reference-baseline.json').read_text())
    archive = FIXTURES / 'reference-workload.zip'
    report = {'python': sys.version, 'platform': platform.platform(),
              'requested_samples': args.samples, 'baseline': baseline,
              'decompile': [], 'findrefs': [], 'errors': []}
    try:
        if hashlib.sha256(archive.read_bytes()).hexdigest() != baseline['archive_sha256']:
            raise ValueError('Reference archive does not match the supplied sample')
        with tempfile.TemporaryDirectory() as directory:
            with zipfile.ZipFile(archive) as source:
                if set(source.namelist()) != {'classes.dex', 'test.py', 'test_findrefs.py'}:
                    raise ValueError('Unexpected reference archive members')
                source.extractall(directory)
            for index in range(args.samples):
                text, wall_ms = run_script('test.py', directory, args.output, index)
                match = re.search(r'Total Execution Time in test.py: ([\d.]+) s', text)
                if match is None or 'class ClockFaceView' not in text:
                    raise ValueError(f'test.py sample {index}: missing source or timing')
                report['decompile'].append({'seconds': float(match[1]), 'wall_ms': wall_ms})
                text, wall_ms = run_script('test_findrefs.py', directory, args.output, index)
                times = {key: float(value) for key, value in
                         re.findall(r'\[DEBUG\] (\w+) Time: ([\d.]+) us', text)}
                counts = {key: int(value) for key, value in
                          re.findall(r'\[DEBUG\] ([\w ]+): (\d+)\s*$', text, re.M)}
                report['findrefs'].append({'times_us': times, 'counts': counts, 'wall_ms': wall_ms})
                if counts != baseline['findrefs_counts']:
                    raise ValueError(f'test_findrefs.py sample {index}: count mismatch: {counts}')
                if times.keys() != baseline['findrefs_times_us'].keys():
                    raise ValueError(f'test_findrefs.py sample {index}: timing metrics changed')
        median = statistics.median(row['seconds'] for row in report['decompile'])
        report['decompile_median_seconds'] = median
        report['decompile_max_seconds'] = max(row['seconds'] for row in report['decompile'])
        if median > baseline['decompile_limit_seconds']:
            report['errors'].append(f'Decompilation median {median:.4f} s exceeds 0.0880 s')
        report['findrefs_comparison'] = []
        for metric, reference in baseline['findrefs_times_us'].items():
            measured = statistics.median(row['times_us'][metric] for row in report['findrefs'])
            report['findrefs_comparison'].append({
                'metric': metric, 'baseline_us': reference, 'median_us': measured,
                'change_percent': (measured / reference - 1) * 100})
    except (ValueError, OSError, subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
        report['errors'].append(str(error))
    (args.output / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items()
                      if key not in ('decompile', 'findrefs', 'baseline')}, indent=2))
    return 1 if report['errors'] else 0


if __name__ == '__main__':
    sys.exit(main())
