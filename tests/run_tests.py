"""Run self-contained regression tests without an external APK."""
import argparse
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-decompiler', action='store_true')
    parser.add_argument('--suite', choices=('all', 'unit', 'integration'), default='all')
    args = parser.parse_args()
    if args.require_decompiler and importlib.util.find_spec('androguard') is None:
        parser.error('Androguard is required; install requirements.txt')
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_*.py')
    if args.suite != 'all':
        def tests(items):
            for item in items:
                if isinstance(item, unittest.TestSuite):
                    yield from tests(item)
                else:
                    yield item
        suite = unittest.TestSuite(test for test in tests(suite)
                                   if ('test_decompiler.DecompilerTests.' in test.id()
                                       or test.id().endswith('test_archive_is_reproducible_and_runs_outside_checkout'))
                                   == (args.suite == 'integration'))
    if suite.countTestCases() == 0:
        parser.error('selected suite contains no tests')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() and not (args.require_decompiler and result.skipped) else 1)
