import hashlib
import importlib
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib

from dex_fixture import make_dex
from src.asc_core.core.dex.dex_manager import DexManager

ROOT = Path(__file__).resolve().parents[1]


class RebuildTests(unittest.TestCase):
    def test_rebuilt_dex_has_valid_signature_and_checksum(self):
        data = DexManager(make_dex()).extract_and_rebuild('Lexample/Test;')
        self.assertEqual(data[12:32], hashlib.sha1(data[32:]).digest())
        self.assertEqual(struct.unpack_from('<I', data, 8)[0], zlib.adler32(data[12:]) & 0xffffffff)


@unittest.skipUnless(importlib.util.find_spec('androguard'), 'install requirements.txt for decompiler tests')
class DecompilerTests(unittest.TestCase):
    def test_decompile_preserves_modules_and_class_zero(self):
        names = ('json', 'math', 'bisect', 'multiprocessing', 'tempfile', 'urllib.request', 'networkx')
        before = {name: importlib.import_module(name) for name in names}
        from src.asc_client.asc_handler import AscHandler
        from src.asc_core.utils.decompiler_simple import decompile_dex_bytes
        from loguru import logger
        logger.disable('androguard')
        source = AscHandler().getclass(make_dex(), 'Lexample/Test;')
        self.assertIn('class Test', source)
        self.assertIn('void first()', source)
        self.assertIn('void second()', source)
        self.assertIn('class Test', decompile_dex_bytes(make_dex(), 'Lexample/Test;'))
        for name, module in before.items():
            self.assertIs(sys.modules[name], module, name)
        self.assertEqual(before['json'].loads('{"ok": true}'), {'ok': True})
        self.assertEqual(before['math'].sqrt(4), 2)

    def test_cli_on_stored_and_compressed_multidex_apk(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                with self.subTest(compression=compression):
                    with zipfile.ZipFile(apk, 'w', compression=compression) as archive:
                        archive.writestr('classes.dex', make_dex())
                        archive.writestr('classes2.dex', make_dex())
                    search = subprocess.run(
                        [sys.executable, str(ROOT / 'main.py'), 'findrefs', str(apk), '--threads', '2', 'string', 'token'],
                        cwd=ROOT, capture_output=True, text=True, timeout=30)
                    self.assertEqual(search.returncode, 0, search.stderr)
                    self.assertEqual(len(search.stdout.splitlines()), 4, search.stdout)
                    source = subprocess.run(
                        [sys.executable, str(ROOT / 'main.py'), 'getclass', str(apk), 'example.Test', '--threads', '2'],
                        cwd=ROOT, capture_output=True, text=True, timeout=30)
                    self.assertEqual(source.returncode, 0, source.stderr)
                    self.assertIn('class Test', source.stdout)

    def test_gui_store_can_decompile_twice_and_then_search(self):
        from src.asc_client.gui.runtime import GuiDexStore
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            with zipfile.ZipFile(apk, 'w') as archive:
                archive.writestr('classes.dex', make_dex())
            store = GuiDexStore(str(apk), max_workers=1)
            store.load()
            first = store.get_source('Lexample/Test;')
            store.source_cache.clear()
            self.assertEqual(store.get_source('Lexample/Test;'), first)
            self.assertIn('class Test', first[1])
            self.assertTrue(store.search_members('method', 'first'))
