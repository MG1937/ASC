import importlib
import importlib.util
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest
import zipfile

from dex_fixture import make_dex, make_static_field_dex
from src.asc_core.core.dex.dex_manager import DexManager
from src.asc_core.utils.dex_parser import parse_encoded_array
from src.asc_core.utils.tinydex import DEX

ROOT = Path(__file__).resolve().parents[1]


class RebuildTests(unittest.TestCase):
    def test_rebuilt_dex_keeps_signature_and_checksum_zero(self):
        data = DexManager(make_dex()).extract_and_rebuild('Lexample/Test;')
        self.assertEqual(data[8:32], bytes(24))

    def test_rebuild_keeps_static_values_and_field_operands_aligned(self):
        data = DexManager(make_static_field_dex()).extract_and_rebuild('Lexample/Statics;')
        dex = DEX.parse(memoryview(data), 'rebuilt.dex')
        clazz = dex.classes[0]
        static_fields = [field for field in clazz.fields if field.is_static]
        static_values_off = struct.unpack_from('<I', data, clazz._class_def_off + 28)[0]
        values = parse_encoded_array(memoryview(data), static_values_off, set(), set(), set(), set())

        self.assertEqual([field.name for field in static_fields], ['FIRST', 'SECOND'])
        self.assertEqual([int.from_bytes(value[1], 'little', signed=True) for value in values], [11, 22])

        method = next(method for method in clazz.methods if method.name == 'getSecond')
        field_idx = method.bytecode[2] | (method.bytecode[3] << 8)
        self.assertEqual(dex.fields[field_idx].name, 'SECOND')


@unittest.skipUnless(importlib.util.find_spec('androguard'), 'install requirements.txt for decompiler tests')
class DecompilerTests(unittest.TestCase):
    def test_decompile_keeps_dummy_fast_path_and_class_zero(self):
        script = """
import sys
sys.path.insert(0, 'tests')
from dex_fixture import make_dex
loaded = []
sys.addaudithook(lambda event, args: loaded.append(args[0]) if event == 'import' else None)
from src.asc_client.asc_handler import AscHandler
for _ in range(2):
    source = AscHandler().getclass(make_dex(), 'Lexample/Test;')
    assert 'class Test' in source
    assert 'void first()' in source
    assert 'void second()' in source
for name in ('email', 'xml.sax.saxutils', 'networkx', 'loguru'):
    assert type(sys.modules[name]).__name__ == 'DummyModule', name
    assert not any(module == name or module.startswith(name + '.') for module in loaded), name
assert sys.modules['mutf8.cmutf8'].decode_modified_utf8.__module__ == '_asc_client_mutf8_py'
"""
        result = subprocess.run([sys.executable, '-c', script], cwd=ROOT,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

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

                    json_source = subprocess.run(
                        [sys.executable, str(ROOT / 'main.py'), 'getclass', str(apk), 'example.Test',
                         '--threads', '2', '--json'],
                        cwd=ROOT, capture_output=True, text=True, timeout=30)
                    self.assertEqual(json_source.returncode, 0, json_source.stderr)
                    import json
                    payload = json.loads(json_source.stdout)
                    self.assertTrue(payload['ok'])
                    self.assertEqual(payload['command'], 'getclass')
                    self.assertEqual(payload['class_name'], 'Lexample/Test;')
                    self.assertEqual(payload['dex_name'], 'classes.dex')
                    self.assertIn('class Test', payload['source'])

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
