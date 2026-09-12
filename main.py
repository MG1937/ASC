import argparse
import json
import os
import subprocess
import sys
import time

t_start = time.perf_counter()


def _format_class_name(name : str) -> str:
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


def _normalize_class_query(name : str, fuzzy : bool) -> str:
    if name is None:
        return None
    if fuzzy:
        if "." in name and "/" not in name:
            return name.replace(".", "/")
        return name
    return _format_class_name(name)


def _build_member_find(key : str, clz : str, clz_fuzzy : bool, name : str) -> dict:
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


def _get_find_query(args) -> tuple:
    if args.find_type == "string":
        return "string", {"string": args.value}
    if args.find_type == "type":
        return "type", {"type": args.value}
    if args.find_type == "method":
        return "method", _build_member_find("method", args.class_name, args.fuzzy_class, args.name)
    return "field", _build_member_find("field", args.class_name, args.fuzzy_class, args.name)


def _emit_json(payload : dict, output_path=None):
    text = json.dumps(payload, ensure_ascii=False) + "\n"
    sys.stdout.write(text)
    if output_path:
        with open(output_path, "w", encoding="utf-8", errors="replace", newline="\n") as fp:
            fp.write(text)


def _handle_getclass(args):
    from src.asc_client.mcp_server import run_getclass

    if getattr(args, "json", False):
        body = run_getclass(args.apk_path, args.dalvik_class, threads=args.threads, debug=args.debug)
        if args.debug:
            t_end = time.perf_counter()
            print(f"[DEBUG] Hit DEX: {body['dex_name']}", file=sys.stderr)
            print(f"[DEBUG] Total Execution Time: {(t_end - t_start) * 1000000:.2f} us", file=sys.stderr)
        _emit_json(body, args.output)
        return

    from src.asc_client.apk_handler import ApkHandler

    dalvik_class = _format_class_name(args.dalvik_class)
    apk_handler = ApkHandler(args.apk_path, debug=args.debug, max_workers=args.threads)
    hit = apk_handler.get_class_dex(dalvik_class)
    if hit is None:
        raise ValueError(f"Class {dalvik_class} not found in APK.")

    dex_name, dex_buf = hit
    if args.debug:
        t_hit_end = time.perf_counter()

    from src.asc_client.asc_handler import AscHandler
    source_code = AscHandler(args.debug).getclass(dex_buf, dalvik_class)
    t_end = time.perf_counter()

    if args.debug:
        print(f"[DEBUG] Hit DEX: {dex_name}")
        print(f"[DEBUG] APK Scan Time: {(t_hit_end - t_start) * 1000000:.2f} us")
        print(f"[DEBUG] Total Execution Time: {(t_end - t_start) * 1000000:.2f} us")
        print("-" * 50)

    if args.output:
        with open(args.output, "w", encoding="utf-8", errors="replace", newline="\n") as fp:
            fp.write(source_code)
            if not source_code.endswith("\n"):
                fp.write("\n")
    print(source_code)


def _handle_findrefs(args):
    find_type, find = _get_find_query(args)

    if getattr(args, "json", False):
        from src.asc_client.mcp_server import run_findrefs

        value = getattr(args, "value", None)
        if value is None:
            value = getattr(args, "name", None)
        body = run_findrefs(
            args.apk_path,
            find_type,
            value=value,
            class_name=getattr(args, "class_name", None),
            fuzzy_class=bool(getattr(args, "fuzzy_class", False)),
            threads=args.threads,
            debug=args.debug,
        )
        if args.debug:
            t_end = time.perf_counter()
            print(f"[DEBUG] Total Execution Time: {(t_end - t_start) * 1000000:.2f} us", file=sys.stderr)
        _emit_json(body, args.output)
        return

    from src.asc_client.apk_handler import ApkHandler

    apk_handler = ApkHandler(args.apk_path, debug=args.debug, max_workers=args.threads)

    output_fp = None
    if args.output:
        output_fp = open(args.output, "w", encoding="utf-8", errors="replace", newline="\n")

    out = sys.stdout
    for _dex_name, lines in apk_handler.for_each_findrefs(find_type, find):
        if not lines:
            continue
        text = "\n".join(lines) + "\n"
        out.write(text)
        if output_fp is not None:
            output_fp.write(text)

    if output_fp is not None:
        output_fp.close()

    if args.debug:
        t_end = time.perf_counter()
        print(f"[DEBUG] Total Execution Time: {(t_end - t_start) * 1000000:.2f} us")


def _handle_mcp(args):
    from src.asc_client.mcp_server import serve_stdio

    serve_stdio(default_apk=args.apk, threads=args.threads, debug=args.debug)


def _run_gui(argv):
    parser = argparse.ArgumentParser(
        description="ASC GUI entry.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python main.py app.apk --gui
  python main.py app.apk --gui --debug
  python main.py app.apk --gui --threads 16
""",
    )
    parser.add_argument("apk_path", help="Path to the input APK file.")
    parser.add_argument("--gui", action="store_true", help="Launch GUI.")
    parser.add_argument("--threads", "--thread", type=int, default=8, help="Worker count.")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode.")
    parser.add_argument("--gui-foreground", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if not args.debug and not args.gui_foreground:
        cmd = [
            sys.executable,
            os.path.abspath(__file__),
            args.apk_path,
            "--gui",
            "--gui-foreground",
            "--threads",
            str(args.threads),
        ]
        creationflags = 0
        start_new_session = False
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            start_new_session = True
        subprocess.Popen(
            cmd,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=creationflags,
            start_new_session=start_new_session,
        )
        return

    from src.asc_client.gui.app import launch_gui
    launch_gui(args.apk_path, max_workers=args.threads, debug=args.debug)


def main():
    if len(sys.argv) == 1:
        _build_main_parser().print_help()
        return
    if "--gui" in sys.argv[1:]:
        _run_gui(sys.argv[1:])
        return

    parser = _build_main_parser()
    args = parser.parse_args()

    try:
        if args.command == "mcp":
            _handle_mcp(args)
        elif args.command == "getclass":
            _handle_getclass(args)
        else:
            _handle_findrefs(args)
    except Exception as e:
        if getattr(args, "json", False):
            _emit_json({"ok": False, "error": str(e)}, getattr(args, "output", None))
        else:
            print(f"Error: {e}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _add_json_flag(parser):
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON envelope on stdout instead of text.",
    )


def _build_main_parser():
    parser = argparse.ArgumentParser(
        description="ASC tooling entry.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python main.py app.apk --gui
  python main.py getclass app.apk Lcom/poc/Main; -o Main.java
  python main.py getclass app.apk com.poc.Main --json
  python main.py findrefs app.apk string token --json
  python main.py mcp --apk app.apk
  python main.py findrefs app.apk type com.poc.Main
  python main.py findrefs app.apk method onCreate --class com.poc.Main
  python main.py findrefs app.apk method notify --class openclaw --fuzzy-class -o method_refs.txt
  python main.py findrefs app.apk field changeQuickRedirect -o field_refs.txt
""",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    getclass_parser = subparsers.add_parser(
        "getclass",
        help="Locate the target class in APK, extract one DEX in memory, then decompile.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python main.py getclass app.apk Lcom/poc/Main;
  python main.py getclass app.apk com.poc.Main -o Main.java
  python main.py getclass app.apk com.poc.Main --json
  python main.py getclass app.apk com.poc.Main --threads 16 --debug
""",
    )
    getclass_parser.add_argument("--debug", action="store_true", help="Enable debug profiling output.")
    getclass_parser.add_argument("--threads", "--thread", type=int, default=8, help="Worker thread count.")
    _add_json_flag(getclass_parser)
    getclass_parser.add_argument("-o", "--output", help="Also write decompiled output to this file.")
    getclass_parser.add_argument("apk_path", help="Path to the input APK file.")
    getclass_parser.add_argument("dalvik_class", help="The Dalvik format class name to extract (e.g., Lcom/poc/Main;).")

    findrefs_parser = subparsers.add_parser(
        "findrefs",
        help="Find code references for string/type/method/field across all DEX entries in APK.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python main.py findrefs app.apk string token -o string_refs.txt
  python main.py findrefs app.apk string token --json
  python main.py findrefs app.apk type com.poc.Main
  python main.py findrefs app.apk method onCreate --class com.poc.Main
  python main.py findrefs app.apk method notify --class openclaw --fuzzy-class -o method_refs.txt
  python main.py findrefs app.apk field changeQuickRedirect -o field_refs.txt
""",
    )
    findrefs_parser.add_argument("--debug", action="store_true", help="Enable debug profiling output.")
    findrefs_parser.add_argument("--threads", "--thread", type=int, default=8, help="Worker thread count.")
    findrefs_parser.add_argument("apk_path", help="Path to the input APK file.")
    find_subparsers = findrefs_parser.add_subparsers(dest="find_type", required=True)

    string_parser = find_subparsers.add_parser(
        "string",
        help="Find references to a fuzzy string.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python main.py findrefs app.apk string token
  python main.py findrefs app.apk string Authorization -o string_refs.txt
""",
    )
    _add_json_flag(string_parser)
    string_parser.add_argument("-o", "--output", help="Also write reference search output to this file.")
    string_parser.add_argument("value", help="Fuzzy string pattern.")

    type_parser = find_subparsers.add_parser(
        "type",
        help="Find references to a fuzzy type descriptor/name.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python main.py findrefs app.apk type com.poc.Main
  python main.py findrefs app.apk type Lcom/poc/Main; -o type_refs.txt
""",
    )
    _add_json_flag(type_parser)
    type_parser.add_argument("-o", "--output", help="Also write reference search output to this file.")
    type_parser.add_argument("value", help="Fuzzy type pattern.")

    method_parser = find_subparsers.add_parser(
        "method",
        help="Find references to methods.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python main.py findrefs app.apk method onCreate
  python main.py findrefs app.apk method notify --class com.poc.Main
  python main.py findrefs app.apk method notify --class poc --fuzzy-class -o method_refs.txt
""",
    )
    _add_json_flag(method_parser)
    method_parser.add_argument("-o", "--output", help="Also write reference search output to this file.")
    method_parser.add_argument("name", nargs="?", default=None, help="Fuzzy method name.")
    method_parser.add_argument("--class", dest="class_name", default=None, help="Dalvik class or fuzzy class pattern.")
    method_parser.add_argument("--fuzzy-class", action="store_true", help="Treat --class as fuzzy match.")

    field_parser = find_subparsers.add_parser(
        "field",
        help="Find references to fields.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python main.py findrefs app.apk field changeQuickRedirect
  python main.py findrefs app.apk field token --class com.poc.Main
  python main.py findrefs app.apk field token --class poc --fuzzy-class -o field_refs.txt
""",
    )
    _add_json_flag(field_parser)
    field_parser.add_argument("-o", "--output", help="Also write reference search output to this file.")
    field_parser.add_argument("name", nargs="?", default=None, help="Fuzzy field name.")
    field_parser.add_argument("--class", dest="class_name", default=None, help="Dalvik class or fuzzy class pattern.")
    field_parser.add_argument("--fuzzy-class", action="store_true", help="Treat --class as fuzzy match.")

    mcp_parser = subparsers.add_parser(
        "mcp",
        help="Serve get_class and find_refs over MCP stdio (JSON-RPC with Content-Length framing).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python main.py mcp
  python main.py mcp --apk app.apk --threads 8
""",
    )
    mcp_parser.add_argument("--apk", default=None, help="Default APK path for tools that omit apk_path.")
    mcp_parser.add_argument("--threads", "--thread", type=int, default=8, help="Default worker count.")
    mcp_parser.add_argument("--debug", action="store_true", help="Enable debug profiling output on stderr.")
    return parser


if __name__ == "__main__":
    main()
