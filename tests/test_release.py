import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from dex_fixture import make_dex
from scripts.build_release import build


class ReleaseTests(unittest.TestCase):
    def test_invalid_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for version in ('0.1.0', '../v0.1.0', 'v01.0.0', 'v0.1.0-rc.0'):
                with self.subTest(version=version), self.assertRaises(ValueError):
                    build(version, Path(directory))

    def test_archive_is_reproducible_and_runs_outside_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = build('v0.1.0-rc.1', root)
            original = archive.read_bytes()
            self.assertEqual(build('v0.1.0-rc.1', root).read_bytes(), original)
            self.assertEqual((root / 'SHA256SUMS').read_text().split()[0],
                             hashlib.sha256(original).hexdigest())
            with zipfile.ZipFile(archive) as package:
                names = package.namelist()
                self.assertTrue(any(name.endswith('/requirements.txt') for name in names))
                self.assertFalse(any(name.endswith(('.dex', '.apk', '/test.py', '/test_findrefs.py'))
                                     or '/tests/' in name or '/.git/' in name for name in names))
                package.extractall(root)
            app = root / 'ASC-v0.1.0-rc.1'
            apk = root / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w', compression=zipfile.ZIP_DEFLATED) as package:
                package.writestr('classes.dex', make_dex())
            for args, expected in ((['findrefs', str(apk), 'string', 'token'], 'token'),
                                   (['getclass', str(apk), 'example.Test'], 'class Test')):
                result = subprocess.run([sys.executable, str(app / 'main.py'), *args],
                                        cwd=root, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout)
