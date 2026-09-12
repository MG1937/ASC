import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from dex_fixture import make_dex

ROOT = Path(__file__).resolve().parents[1]


class JsonCliTests(unittest.TestCase):
    def test_findrefs_json_on_fixture_apk(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('classes.dex', make_dex())
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / 'main.py'),
                    'findrefs',
                    str(apk),
                    '--threads',
                    '2',
                    'string',
                    'token',
                    '--json',
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload['ok'])
            self.assertEqual(payload['command'], 'findrefs')
            self.assertEqual(
                payload['hits'],
                [
                    {
                        'dex_name': 'classes.dex',
                        'caller_class': 'Lexample/Test;',
                        'caller_method': 'first',
                        'matched': ['token'],
                    },
                    {
                        'dex_name': 'classes.dex',
                        'caller_class': 'Lexample/Test;',
                        'caller_method': 'second',
                        'matched': ['token'],
                    },
                ],
            )

    def test_getclass_json_missing_class(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('classes.dex', make_dex())
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / 'main.py'),
                    'getclass',
                    str(apk),
                    'example.Missing',
                    '--json',
                    '--threads',
                    '2',
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            payload = json.loads(result.stdout)
            self.assertFalse(payload['ok'])
            self.assertIn('not found', payload['error'])


if __name__ == '__main__':
    unittest.main()
