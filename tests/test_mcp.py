import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from dex_fixture import make_dex
from src.asc_client.mcp_server import McpServer

ROOT = Path(__file__).resolve().parents[1]


def _frame(message):
    raw = json.dumps(message).encode('utf-8')
    return f'Content-Length: {len(raw)}\r\n\r\n'.encode('ascii') + raw


class McpTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.apk = Path(self._tmpdir.name) / 'fixture.apk'
        with zipfile.ZipFile(self.apk, 'w') as archive:
            archive.writestr('classes.dex', make_dex())
        self.server = McpServer(default_apk=str(self.apk), threads=2)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_initialize_and_tools_list(self):
        init = self.server.handle_message(
            {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'initialize',
                'params': {
                    'protocolVersion': '2024-11-05',
                    'capabilities': {},
                    'clientInfo': {'name': 'test', 'version': '0'},
                },
            }
        )
        self.assertEqual(init['result']['serverInfo']['name'], 'droid-asc')
        listed = self.server.handle_message(
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}}
        )
        names = {tool['name'] for tool in listed['result']['tools']}
        self.assertEqual(names, {'get_class', 'find_refs'})

    def test_find_refs_tool(self):
        response = self.server.handle_message(
            {
                'jsonrpc': '2.0',
                'id': 3,
                'method': 'tools/call',
                'params': {
                    'name': 'find_refs',
                    'arguments': {
                        'find_type': 'string',
                        'value': 'token',
                        'threads': 2,
                    },
                },
            }
        )
        body = response['result']['structuredContent']
        self.assertTrue(body['ok'])
        self.assertEqual(
            body['hits'],
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
        self.assertFalse(response['result']['isError'])

    def test_missing_apk_and_unknown_tool(self):
        bare = McpServer(threads=2)
        missing = bare.handle_message(
            {
                'jsonrpc': '2.0',
                'id': 4,
                'method': 'tools/call',
                'params': {
                    'name': 'find_refs',
                    'arguments': {'find_type': 'string', 'value': 'token'},
                },
            }
        )
        self.assertTrue(missing['result']['isError'])
        self.assertIn('apk_path', missing['result']['structuredContent']['error'])

        unknown = self.server.handle_message(
            {
                'jsonrpc': '2.0',
                'id': 5,
                'method': 'tools/call',
                'params': {'name': 'nope', 'arguments': {}},
            }
        )
        self.assertTrue(unknown['result']['isError'])
        self.assertIn('unknown tool', unknown['result']['structuredContent']['error'])

    def test_stdio_subprocess_session(self):
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / 'main.py'), 'mcp', '--apk', str(self.apk), '--threads', '2'],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            requests = (
                _frame(
                    {
                        'jsonrpc': '2.0',
                        'id': 1,
                        'method': 'initialize',
                        'params': {
                            'protocolVersion': '2024-11-05',
                            'capabilities': {},
                            'clientInfo': {'name': 'test', 'version': '0'},
                        },
                    }
                )
                + _frame({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
                + _frame({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})
                + _frame(
                    {
                        'jsonrpc': '2.0',
                        'id': 3,
                        'method': 'tools/call',
                        'params': {
                            'name': 'find_refs',
                            'arguments': {'find_type': 'string', 'value': 'token'},
                        },
                    }
                )
            )
            stdout, stderr = proc.communicate(requests, timeout=30)
            self.assertEqual(proc.returncode, 0, stderr.decode('utf-8', errors='replace'))
            messages = []
            buf = stdout
            while buf:
                header_end = buf.find(b'\r\n\r\n')
                self.assertNotEqual(header_end, -1, buf[:200])
                headers = buf[:header_end].decode('ascii')
                length = int(
                    next(
                        line.split(':', 1)[1].strip()
                        for line in headers.split('\r\n')
                        if line.lower().startswith('content-length:')
                    )
                )
                start = header_end + 4
                end = start + length
                messages.append(json.loads(buf[start:end]))
                buf = buf[end:]
            self.assertEqual(len(messages), 3)
            names = {tool['name'] for tool in messages[1]['result']['tools']}
            self.assertEqual(names, {'get_class', 'find_refs'})
            self.assertEqual(len(messages[2]['result']['structuredContent']['hits']), 2)
        finally:
            if proc.poll() is None:
                proc.kill()

    @unittest.skipUnless(importlib.util.find_spec('androguard'), 'install requirements.txt for decompiler tests')
    def test_json_survives_get_class(self):
        import json as json_mod

        response = self.server.handle_message(
            {
                'jsonrpc': '2.0',
                'id': 6,
                'method': 'tools/call',
                'params': {
                    'name': 'get_class',
                    'arguments': {'class_name': 'example.Test', 'threads': 2},
                },
            }
        )
        self.assertFalse(response['result']['isError'], response)
        self.assertIn('class Test', response['result']['structuredContent']['source'])
        self.assertEqual(json_mod.dumps({'ok': True}), '{"ok": true}')
        self.assertNotEqual(type(sys.modules['json']).__name__, 'DummyModule')


if __name__ == '__main__':
    unittest.main()
