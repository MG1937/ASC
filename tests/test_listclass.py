from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

from dex_fixture import make_dex, make_static_field_dex


ROOT = Path(__file__).resolve().parents[1]


def make_class_only_dex(descriptors, base=0, version=b"035"):
    header_size = 0x78 if version == b"041" else 0x70
    encoded = [name.encode("utf-8") for name in descriptors]
    buf = bytearray(header_size)

    string_ids = len(buf)
    buf.extend(bytes(4 * len(encoded)))
    type_ids = len(buf)
    buf.extend(bytes(4 * len(encoded)))
    class_defs = len(buf)
    buf.extend(bytes(32 * len(encoded)))
    data_off = len(buf)

    for index, value in enumerate(encoded):
        string_off = base + len(buf)
        struct.pack_into("<I", buf, string_ids + index * 4, string_off)
        struct.pack_into("<I", buf, type_ids + index * 4, index)
        struct.pack_into("<IIIIIIII", buf, class_defs + index * 32,
                         index, 1, 0xffffffff, 0, 0xffffffff, 0, 0, 0)
        buf.append(len(value))
        buf.extend(value)
        buf.append(0)

    buf[:8] = b"dex\n" + version + b"\0"
    struct.pack_into("<IIIIII", buf, 0x20, len(buf), header_size, 0x12345678, 0, 0, 0)
    struct.pack_into(
        "<IIIIIIIIIIIIII",
        buf,
        0x38,
        len(encoded),
        base + string_ids,
        len(encoded),
        base + type_ids,
        0,
        0,
        0,
        0,
        0,
        0,
        len(encoded),
        base + class_defs,
        len(buf) - data_off,
        base + data_off,
    )
    if version == b"041":
        struct.pack_into("<I", buf, 0x74, base)
    return buf


def make_dex041_container():
    first = make_class_only_dex(["Lalpha/First;", "Lshared/Duplicate;"], version=b"041")
    second = make_class_only_dex(
        ["Lbeta/Second;", "Lshared/Duplicate;"],
        base=len(first),
        version=b"041",
    )
    data = first + second
    for header_off in (0, len(first)):
        struct.pack_into("<I", data, header_off + 0x70, len(data))
    return bytes(data)


class ListClassTests(unittest.TestCase):
    def run_cli(self, apk, *args, no_site=False):
        command = [sys.executable]
        if no_site:
            command.append("-S")
        command.extend([str(ROOT / "main.py"), "listclass", str(apk), *args])
        return subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_cli_filters_normalized_prefix_for_stored_and_deflated_dex(self):
        data = make_class_only_dex([
            "Lcom/xxx/First;",
            "Lcom/xxx/internal/Second;",
            "Lorg/example/Other;",
        ])
        expected = "Lcom/xxx/First;\nLcom/xxx/internal/Second;\n"
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                for prefix in ("com.xxx", "com/xxx", "Lcom/xxx"):
                    with self.subTest(compression=compression, prefix=prefix):
                        with zipfile.ZipFile(apk, "w", compression=compression) as archive:
                            archive.writestr("classes.dex", data)
                        result = self.run_cli(apk, "--prefix", prefix)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout, expected)

    def test_cli_preserves_dex_order_for_stored_and_deflated_multidex(self):
        expected = "Lexample/Test;\nLexample/Statics;\nLexample/Test;\n"
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            output = Path(directory) / "classes.txt"
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                with self.subTest(compression=compression):
                    with zipfile.ZipFile(apk, "w", compression=compression) as archive:
                        archive.writestr("classes.dex", make_dex())
                        archive.writestr("classes2.dex", make_static_field_dex())
                        archive.writestr("classes3.dex", make_dex())
                    result = self.run_cli(apk, "--threads", "2", "-o", str(output))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(output.read_text(encoding="utf-8"), expected)

    def test_cli_does_not_require_site_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("classes.dex", make_dex())
            result = self.run_cli(apk, no_site=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "Lexample/Test;\n")

    def test_deflate_path_lists_large_dex(self):
        data = bytearray(make_dex())
        data.extend(random.Random(0).randbytes(1024 * 1024))
        struct.pack_into("<I", data, 0x20, len(data))

        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("classes.dex", data)
            result = self.run_cli(apk)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "Lexample/Test;\n")

    def test_dex041_container_lists_every_logical_member(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                with self.subTest(compression=compression):
                    with zipfile.ZipFile(apk, "w", compression=compression) as archive:
                        archive.writestr("classes.dex", make_dex041_container())
                    result = self.run_cli(apk, "--threads", "1")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(
                        result.stdout,
                        "Lalpha/First;\nLshared/Duplicate;\n"
                        "Lbeta/Second;\nLshared/Duplicate;\n",
                    )

    def test_bad_class_type_index_is_a_clean_error(self):
        data = bytearray(make_dex())
        class_defs_off = struct.unpack_from("<I", data, 0x64)[0]
        struct.pack_into("<I", data, class_defs_off, 0xffffffff)

        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("classes.dex", data)
            result = self.run_cli(apk)
            self.assertEqual(result.returncode, 1)
            self.assertIn("Error: bad class_def->type_idx", result.stderr)

    def test_worker_count_must_be_positive(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", make_dex())
            result = self.run_cli(apk, "--threads", "0")
            self.assertEqual(result.returncode, 1)
            self.assertIn("Worker count must be greater than zero", result.stderr)

    def test_empty_prefix_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", make_dex())
            result = self.run_cli(apk, "--prefix", " ")
            self.assertEqual(result.returncode, 1)
            self.assertIn("Class prefix cannot be empty", result.stderr)


if __name__ == "__main__":
    unittest.main()
