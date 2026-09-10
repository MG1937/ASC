"""Measure cold interpreter startup with a generated APK and the real CLI."""
import argparse
import json
from pathlib import Path
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time
import zipfile

from dex_fixture import make_dex

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=int, default=9)
    parser.add_argument('--max-total-ms', type=float, default=100)
    parser.add_argument('--max-wall-ms', type=float, default=250)
    parser.add_argument('--output', type=Path, default=Path('artifacts/startup'))
    args = parser.parse_args()
    if args.samples < 3 or args.max_total_ms <= 0 or args.max_wall_ms <= 0:
        parser.error('use at least 3 samples and positive time budgets')
    args.output.mkdir(parents=True, exist_ok=True)
    records = []
    errors = []
    with tempfile.TemporaryDirectory() as directory:
        apk = Path(directory) / 'fixture.apk'
        with zipfile.ZipFile(apk, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('classes.dex', make_dex())
        command = [sys.executable, str(ROOT / 'main.py'), 'getclass', str(apk),
                   'example.Test', '--threads', '1', '--debug']
        for index in range(args.samples):
            start = time.perf_counter()
            try:
                result = subprocess.run(command, cwd=ROOT, capture_output=True,
                                        text=True, timeout=30)
            except subprocess.TimeoutExpired:
                errors.append(f'sample {index}: CLI exceeded 30 seconds')
                break
            wall_ms = (time.perf_counter() - start) * 1000
            (args.output / f'{index:02d}.stdout.log').write_text(result.stdout, encoding='utf-8')
            (args.output / f'{index:02d}.stderr.log').write_text(result.stderr, encoding='utf-8')
            if result.returncode or any(text not in result.stdout for text in
                                       ('class Test', 'void first()', 'void second()')):
                errors.append(f'sample {index}: decompilation failed; see logs')
                break
            record = {'wall_ms': wall_ms}
            for key, label in (('total_ms', 'Total Execution Time'),
                               ('extraction_ms', 'Total Extraction Time'),
                               ('apk_ms', 'APK Scan Time')):
                match = re.search(r'\[DEBUG\] ' + label + r': ([\d.]+) us', result.stdout)
                if match is None:
                    errors.append(f'sample {index}: missing debug metric {label}')
                    break
                record[key] = float(match[1]) / 1000
            if errors:
                break
            records.append(record)
    medians = {key: statistics.median(row[key] for row in records)
               for key in records[0]} if records else {}
    for metric, budget in (('total_ms', args.max_total_ms), ('wall_ms', args.max_wall_ms)):
        if medians.get(metric, 0) > budget:
            errors.append(f'{metric} median {medians[metric]:.2f} ms exceeds {budget:.2f} ms')
    report = {'python': sys.version, 'platform': platform.platform(),
              'command': command, 'requested_samples': args.samples,
              'budgets_ms': {'total_ms': args.max_total_ms, 'wall_ms': args.max_wall_ms},
              'samples': records, 'median_ms': medians, 'errors': errors}
    (args.output / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
