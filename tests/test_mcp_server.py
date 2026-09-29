import asyncio
import tempfile
import unittest
import zipfile
from pathlib import Path

from mcp.client import Client
from mcp.client._memory import InMemoryTransport

from dex_fixture import make_dex
from droidasc.mcp_server import server


class McpServerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.apk = Path(self.directory.name) / "fixture.apk"
        with zipfile.ZipFile(self.apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("classes.dex", make_dex())

    def tearDown(self):
        self.directory.cleanup()

    def run_async(self, coro):
        return asyncio.run(coro)

    async def _list_tools(self):
        async with Client(InMemoryTransport(server)) as client:
            return await client.list_tools()

    async def _call(self, tool, arguments):
        async with Client(InMemoryTransport(server)) as client:
            return await client.call_tool(tool, arguments)

    def test_exposes_read_only_tools(self):
        result = self.run_async(self._list_tools())
        names = {tool.name for tool in result.tools}
        self.assertEqual(
            names,
            {"decompile_class", "list_classes", "decode_manifest", "find_references"},
        )
        self.assertTrue(all(tool.annotations.read_only_hint for tool in result.tools))

    def test_list_classes_returns_structured_result(self):
        result = self.run_async(
            self._call(
                "list_classes",
                {"apk_path": str(self.apk), "prefix": "example", "limit": 1},
            )
        )
        self.assertFalse(result.is_error)
        self.assertEqual(result.structured_content["classes"], ["Lexample/Test;"])
        self.assertEqual(result.structured_content["total"], 1)
        self.assertFalse(result.structured_content["truncated"])

    def test_decompile_and_findrefs_work_through_mcp(self):
        decompiled = self.run_async(
            self._call(
                "decompile_class",
                {"apk_path": str(self.apk), "class_name": "example.Test", "threads": 1},
            )
        )
        self.assertFalse(decompiled.is_error)
        self.assertIn("class Test", decompiled.structured_content["source"])
        self.assertEqual(decompiled.structured_content["class_name"], "Lexample/Test;")

        refs = self.run_async(
            self._call(
                "find_references",
                {
                    "apk_path": str(self.apk),
                    "find_type": "string",
                    "value": "token",
                    "threads": 1,
                    "max_results": 1,
                },
            )
        )
        self.assertFalse(refs.is_error)
        self.assertEqual(refs.structured_content["returned"], 1)
        self.assertEqual(refs.structured_content["total"], 2)
        self.assertTrue(refs.structured_content["truncated"])
        self.assertTrue(any("->first" in line for line in refs.structured_content["matches"]))

    def test_invalid_input_is_reported_as_tool_error(self):
        result = self.run_async(
            self._call(
                "list_classes",
                {"apk_path": str(Path(self.directory.name) / "missing.apk")},
            )
        )
        self.assertTrue(result.is_error)
        self.assertIn("Cannot access APK", result.content[0].text)


if __name__ == "__main__":
    unittest.main()
