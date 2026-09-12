import struct
import sys
import unittest
from unittest.mock import patch

from dex_fixture import make_dex
from src.asc_client.asc_handler import AscHandler
from src.asc_core.findrefs.locator.insn_locator import InsnLocator
from src.asc_core.findrefs.scan.code_item_scan import CodeItemScanner
from src.asc_core.utils.tinydex import DEX


class ReferenceTests(unittest.TestCase):
    def search(self, data):
        dex = DEX.parse(memoryview(data), 'fixture.dex')
        locator = InsnLocator(dex)
        locator.parse()
        query = {'string': {5}}
        CodeItemScanner(locator).scan(query)
        return query['string']

    def test_shared_code_keeps_method_zero(self):
        results = self.search(make_dex())
        self.assertEqual(len(results), 1)
        self.assertEqual(set(results[0]), {0, 1})

    def test_repeated_scans_preserve_method_bounds(self):
        locator = InsnLocator(DEX.parse(memoryview(make_dex()), 'fixture.dex'))
        locator.parse()
        original_bounds = dict(locator.method_bounds)
        scanner = CodeItemScanner(locator)
        for _ in range(2):
            query = {'string': {5}}
            scanner.scan(query)
            self.assertEqual(set(query['string'][0]), {0, 1})
            self.assertEqual(locator.method_bounds, original_bounds)

    def test_fallback_without_class_data_map_entry(self):
        data = bytearray(make_dex())
        map_off = struct.unpack_from('<I', data, 52)[0]
        count = struct.unpack_from('<I', data, map_off)[0]
        for off in range(map_off + 4, map_off + 4 + count * 12, 12):
            if struct.unpack_from('<H', data, off)[0] == 0x2000:
                struct.pack_into('<H', data, off, 0xffff)
        self.assertEqual(set(self.search(data)[0]), {0, 1})

    def test_empty_or_absent_map_uses_class_definitions(self):
        for empty in (True, False):
            with self.subTest(empty=empty):
                data = bytearray(make_dex())
                map_off = struct.unpack_from('<I', data, 52)[0]
                struct.pack_into('<I', data, map_off if empty else 52, 0)
                self.assertEqual(set(self.search(data)[0]), {0, 1})

    def test_class_without_method_bodies_has_no_references(self):
        data = bytearray(make_dex())
        class_off = struct.unpack_from('<I', data, 100)[0]
        class_data = struct.unpack_from('<I', data, class_off + 24)[0]
        data[class_data:class_data + 10] = b'\0\0\x02\0\0\x09\0\x01\x09\0'
        self.assertEqual(self.search(data), [])

    def test_search_does_not_require_androguard(self):
        with patch.dict(sys.modules, {'androguard': None}):
            lines = AscHandler().findrefs('fixture.dex', make_dex(), 'string', {'string': 'token'})
        self.assertEqual(len(lines), 2)
        self.assertTrue(any('->first' in line for line in lines))
        self.assertTrue(any('->second' in line for line in lines))


class StringTests(unittest.TestCase):
    def locate(self, data, query):
        from src.asc_core.findrefs.locator.string_locator import StringLocator
        return StringLocator(DEX.parse(memoryview(data), 'fixture.dex')).locate(query)

    def test_last_string_is_searchable(self):
        self.assertEqual(self.locate(make_dex(), 'token'), {5})

    def test_physical_string_order_does_not_change_ids(self):
        from dex_fixture import uleb
        data = bytearray(make_dex())
        ids_off = struct.unpack_from('<I', data, 60)[0]
        for idx, value in reversed(list(enumerate((b'Lexample/Test;', b'Ljava/lang/Object;', b'V', b'first', b'second', b'token')))):
            struct.pack_into('<I', data, ids_off + 4 * idx, len(data))
            data.extend(uleb(len(value)) + value + b'\0')
        self.assertEqual(self.locate(data, 'token'), {5})
        self.assertEqual(self.locate(data, 'first'), {3})
        self.assertEqual(self.locate(data, 'Lexample/Test;'), {0})

    def make_strings(self, values, gap=b''):
        from dex_fixture import uleb
        data = bytearray(make_dex())
        ids_off = struct.unpack_from('<I', data, 60)[0]
        struct.pack_into('<I', data, 56, len(values))
        for idx, value in enumerate(values):
            data.extend(gap)
            struct.pack_into('<I', data, ids_off + 4 * idx, len(data))
            data.extend(uleb(len(value)) + value + b'\0')
        return data

    def test_literal_header_hit_does_not_hide_content_hit(self):
        self.assertEqual(self.locate(self.make_strings([b'A' * 65]), 'A'), {0})
        self.assertEqual(self.locate(self.make_strings([b'B' * 65]), 'A'), set())

    def test_regex_header_hit_does_not_hide_content_hit(self):
        self.assertEqual(self.locate(self.make_strings([b'A' * 65]), 'A+'), {0})
        self.assertEqual(self.locate(self.make_strings([b'B' * 65]), 'A+'), set())

    def test_multibyte_length_and_repeated_hits(self):
        data = self.make_strings([b'A' * 200 + b'View', b'ViewView'])
        self.assertEqual(self.locate(data, 'View'), {0, 1})
        self.assertEqual(self.locate(data, 'V.ew'), {0, 1})
        self.assertEqual(self.locate(self.make_strings([b'A' * 128]), '\x01'), set())

    def test_bytes_between_strings_are_not_search_results(self):
        data = self.make_strings([b'first', b'second', b'third'], gap=b'View\0')
        self.assertEqual(self.locate(data, 'View'), set())
        self.assertEqual(self.locate(data, 'second'), {1})

    def test_regex_cannot_cross_string_terminators(self):
        data = self.make_strings([b'AAA', b'BBB'])
        self.assertEqual(self.locate(data, 'A.*B'), set())
        self.assertEqual(self.locate(data, 'A\x00\x03B'), set())

    def test_empty_string_table(self):
        data = bytearray(make_dex())
        struct.pack_into('<II', data, 56, 0, 0)
        self.assertEqual(self.locate(data, 'token'), set())


class DependencyTests(unittest.TestCase):
    def test_reference_search_without_site_packages(self):
        import subprocess
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        script = """
import sys
sys.path.insert(0, 'tests')
from dex_fixture import make_dex
from src.asc_client.asc_handler import AscHandler
lines = AscHandler().findrefs('fixture.dex', make_dex(), 'string', {'string': 'token'})
assert len(lines) == 2, lines
assert 'androguard' not in sys.modules
assert 'src.asc_core.utils.decompiler' not in sys.modules
"""
        result = subprocess.run([sys.executable, '-S', '-c', script], cwd=root,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
