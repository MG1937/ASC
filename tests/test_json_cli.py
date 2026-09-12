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
    def make_apk(self, directory):
        apk = Path(directory) / "fixture.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("classes.dex", make_dex())
        return apk

    def test_findrefs_emits_structured_json_and_output_file(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = self.make_apk(directory)
            output = Path(directory) / "results.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "main.py"),
                    "findrefs",
                    str(apk),
                    "--threads",
                    "2",
                    "string",
                    "token",
                    "--json",
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), payload)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["command"], "findrefs")
            self.assertEqual(payload["find_type"], "string")
            self.assertEqual(payload["query"], {"string": "token"})
            self.assertEqual(payload["count"], 2)
            self.assertEqual(
                payload["hits"],
                [
                    {
                        "dex_name": "classes.dex",
                        "caller_class": "Lexample/Test;",
                        "caller_method": "first",
                        "matched": ["token"],
                    },
                    {
                        "dex_name": "classes.dex",
                        "caller_class": "Lexample/Test;",
                        "caller_method": "second",
                        "matched": ["token"],
                    },
                ],
            )

    def test_json_debug_logs_stay_on_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = self.make_apk(directory)
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "main.py"),
                    "findrefs",
                    str(apk),
                    "--threads",
                    "2",
                    "--debug",
                    "string",
                    "token",
                    "--json",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["count"], 2)
            self.assertIn("[DEBUG]", result.stderr)

    def test_json_error_is_emitted_on_stdout(self):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "main.py"),
                "findrefs",
                "missing.apk",
                "string",
                "token",
                "--json",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["command"], "findrefs")
        self.assertIn("missing.apk", payload["error"])


if __name__ == "__main__":
    unittest.main()
