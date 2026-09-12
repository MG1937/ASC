import json
import sys

from src.asc_client.results import findref_hit_to_dict, getclass_result_to_dict


PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "droid-asc", "version": "0.1.0"}

TOOLS = [
    {
        "name": "get_class",
        "description": "Locate a class in an APK, extract one DEX in memory, then decompile to Java source.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {
                    "type": "string",
                    "description": "Path to the APK. Optional when the server was started with --apk.",
                },
                "class_name": {
                    "type": "string",
                    "description": "Dalvik or dotted class name, e.g. Lcom/poc/Main; or com.poc.Main.",
                },
                "threads": {
                    "type": "integer",
                    "description": "Worker thread count.",
                    "default": 8,
                },
            },
            "required": ["class_name"],
        },
    },
    {
        "name": "find_refs",
        "description": "Find code references for a string, type, method, or field across all DEX entries in an APK.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {
                    "type": "string",
                    "description": "Path to the APK. Optional when the server was started with --apk.",
                },
                "find_type": {
                    "type": "string",
                    "enum": ["string", "type", "method", "field"],
                    "description": "Reference search kind.",
                },
                "value": {
                    "type": "string",
                    "description": "Fuzzy string/type pattern, or method/field name.",
                },
                "class_name": {
                    "type": "string",
                    "description": "Optional class constraint for method/field searches.",
                },
                "fuzzy_class": {
                    "type": "boolean",
                    "description": "Treat class_name as a fuzzy match.",
                    "default": False,
                },
                "threads": {
                    "type": "integer",
                    "description": "Worker process count.",
                    "default": 8,
                },
            },
            "required": ["find_type"],
        },
    },
]

_TOOL_BY_NAME = {tool["name"]: tool for tool in TOOLS}


def _format_class_name(name: str) -> str:
    if not name:
        raise ValueError("Class name cannot be empty")
    if name.startswith("L") and name.endswith(";") and "/" in name:
        return name
    name = name.replace(".", "/")
    if not name.startswith("L"):
        name = f"L{name}"
    if not name.endswith(";"):
        name = f"{name};"
    return name


def _normalize_class_query(name, fuzzy: bool):
    if name is None:
        return None
    if fuzzy:
        if "." in name and "/" not in name:
            return name.replace(".", "/")
        return name
    return _format_class_name(name)


def _build_member_find(key: str, clz, clz_fuzzy: bool, name):
    if clz == "":
        clz = None
    if name == "":
        name = None
    if clz is None and name is None:
        raise ValueError(f"{key} query needs at least one of class or {key} name")
    if clz is None:
        return {key: {"class": None, key: name}}
    clz = _normalize_class_query(clz, clz_fuzzy)
    return {key: {"class": [clz, not clz_fuzzy], key: name}}


def run_getclass(apk_path: str, class_name: str, threads: int = 8, debug: bool = False) -> dict:
    from src.asc_client.apk_handler import ApkHandler
    from src.asc_client.asc_handler import AscHandler
    from src.asc_client.results import GetClassResult

    dalvik_class = _format_class_name(class_name)
    apk_handler = ApkHandler(apk_path, debug=debug, max_workers=threads)
    hit = apk_handler.get_class_dex(dalvik_class)
    if hit is None:
        raise ValueError(f"Class {dalvik_class} not found in APK.")
    dex_name, dex_buf = hit
    source = AscHandler(debug).getclass(dex_buf, dalvik_class)
    result = GetClassResult(dex_name=dex_name, class_name=dalvik_class, source=source)
    body = {
        "ok": True,
        "command": "getclass",
        "apk_path": apk_path,
        **getclass_result_to_dict(result),
    }
    return body


def run_findrefs(
    apk_path: str,
    find_type: str,
    value=None,
    class_name=None,
    fuzzy_class: bool = False,
    threads: int = 8,
    debug: bool = False,
) -> dict:
    from src.asc_client.apk_handler import ApkHandler

    if find_type == "string":
        if value is None:
            raise ValueError("string query needs a value")
        find = {"string": value}
        query = {"find_type": "string", "value": value}
    elif find_type == "type":
        if value is None:
            raise ValueError("type query needs a value")
        find = {"type": value}
        query = {"find_type": "type", "value": value}
    elif find_type == "method":
        find = _build_member_find("method", class_name, fuzzy_class, value)
        query = {
            "find_type": "method",
            "value": value,
            "class_name": class_name,
            "fuzzy_class": fuzzy_class,
        }
    elif find_type == "field":
        find = _build_member_find("field", class_name, fuzzy_class, value)
        query = {
            "find_type": "field",
            "value": value,
            "class_name": class_name,
            "fuzzy_class": fuzzy_class,
        }
    else:
        raise ValueError(f"unsupported find_type: {find_type}")

    apk_handler = ApkHandler(apk_path, debug=debug, max_workers=threads)
    hits = []
    for _dex_name, batch in apk_handler.for_each_findrefs_hits(find_type, find):
        hits.extend(batch)
    hits.sort(key=lambda h: (h.dex_name, h.caller_class, h.caller_method, h.matched))
    return {
        "ok": True,
        "command": "findrefs",
        "apk_path": apk_path,
        "query": query,
        "hits": [findref_hit_to_dict(hit) for hit in hits],
    }


class McpServer:
    def __init__(self, default_apk=None, threads: int = 8, debug: bool = False):
        self.default_apk = default_apk
        self.threads = threads
        self.debug = debug

    def _resolve_apk(self, arguments: dict) -> str:
        apk_path = arguments.get("apk_path") or self.default_apk
        if not apk_path:
            raise ValueError("apk_path is required (pass it in the tool args or start with --apk)")
        return apk_path

    def call_tool(self, name: str, arguments: dict) -> dict:
        if name not in _TOOL_BY_NAME:
            raise ValueError(f"unknown tool: {name}")
        arguments = arguments or {}
        threads = int(arguments.get("threads") or self.threads)
        if name == "get_class":
            class_name = arguments.get("class_name")
            if not class_name:
                raise ValueError("class_name is required")
            return run_getclass(
                self._resolve_apk(arguments),
                class_name,
                threads=threads,
                debug=self.debug,
            )
        return run_findrefs(
            self._resolve_apk(arguments),
            arguments.get("find_type"),
            value=arguments.get("value"),
            class_name=arguments.get("class_name"),
            fuzzy_class=bool(arguments.get("fuzzy_class", False)),
            threads=threads,
            debug=self.debug,
        )

    def handle_message(self, message: dict):
        if "method" not in message:
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32600, "message": "Invalid Request"},
            }

        method = message["method"]
        msg_id = message.get("id")
        params = message.get("params") or {}

        if method.startswith("notifications/") or msg_id is None:
            return None

        try:
            if method == "initialize":
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO,
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                name = params.get("name")
                arguments = params.get("arguments") or {}
                try:
                    body = self.call_tool(name, arguments)
                    result = {
                        "content": [{"type": "text", "text": json.dumps(body)}],
                        "structuredContent": body,
                        "isError": False,
                    }
                except Exception as exc:
                    err_body = {"ok": False, "error": str(exc)}
                    result = {
                        "content": [{"type": "text", "text": json.dumps(err_body)}],
                        "structuredContent": err_body,
                        "isError": True,
                    }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }
            return {"jsonrpc": "2.0", "id": msg_id, "result": result}
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32603, "message": str(exc)},
            }


def _read_message(stdin):
    headers = {}
    while True:
        line = stdin.readline()
        if not line:
            return None
        line = line.decode("utf-8") if isinstance(line, bytes) else line
        if line in ("\r\n", "\n"):
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    body = stdin.read(length)
    if not body:
        return None
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    return json.loads(body)


def _write_message(stdout, message: dict):
    raw = json.dumps(message, ensure_ascii=False).encode("utf-8")
    header = f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii")
    stdout.buffer.write(header)
    stdout.buffer.write(raw)
    stdout.buffer.flush()


def serve_stdio(default_apk=None, threads: int = 8, debug: bool = False):
    server = McpServer(default_apk=default_apk, threads=threads, debug=debug)
    stdin = sys.stdin.buffer
    while True:
        message = _read_message(stdin)
        if message is None:
            break
        response = server.handle_message(message)
        if response is not None:
            _write_message(sys.stdout, response)


if __name__ == "__main__":
    serve_stdio()
