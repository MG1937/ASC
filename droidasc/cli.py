import argparse
import os
import subprocess
import sys
import time

t_start = time.perf_counter()

def _version():
    from importlib import metadata as _pkg_metadata

    try:
        return _pkg_metadata.version("droidasc")
    except _pkg_metadata.PackageNotFoundError:
        return "unknown"


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
    if args.find_type in ("extends", "impl"):
        # scan_extends/scan_implements need the precise dalvik class form
        return args.find_type, {args.find_type: _format_class_name(args.value)}
    if args.find_type == "method":
        return "method", _build_member_find("method", args.class_name, args.fuzzy_class, args.name)
    return "field", _build_member_find("field", args.class_name, args.fuzzy_class, args.name)


def _handle_getclass(args):
    from droidasc.asc_client.apk_handler import ApkHandler

    dalvik_class = _format_class_name(args.dalvik_class)
    apk_handler = ApkHandler(args.apk_path, debug=args.debug, max_workers=args.threads)
    hit = apk_handler.get_class_dex(dalvik_class)
    if hit is None:
        raise ValueError(f"Class {dalvik_class} not found in APK.")

    dex_name, dex_buf = hit
    if args.debug:
        t_hit_end = time.perf_counter()

    from droidasc.asc_client.asc_handler import AscHandler
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


def _handle_disassemble(args):
    from droidasc.asc_client.apk_handler import ApkHandler
    from droidasc.asc_core.core.dex.dex_manager import DexManager
    from dadguard.disassembler import disassemble_dex_bytes

    t_start = time.perf_counter()
    dalvik_class = _format_class_name(args.dalvik_class)
    apk_handler = ApkHandler(args.apk_path, debug=args.debug, max_workers=args.threads)
    hit = apk_handler.get_class_dex(dalvik_class)
    if hit is None:
        raise ValueError(f"Class {dalvik_class} not found in APK.")
    t_lookup_end = time.perf_counter()

    _dex_name, dex_buf = hit
    rebuilt_dex = DexManager(memoryview(dex_buf), debug=args.debug).extract_and_rebuild(
        dalvik_class
    )
    t_rebuild_end = time.perf_counter()
    disassembly = disassemble_dex_bytes(
        rebuilt_dex,
        verify_checksum=False,
        debug=args.debug,
        debuginfo=args.debuginfo,
        method_signature=args.method_signature,
    )
    t_format_end = time.perf_counter()
    if args.debug:
        print(
            "[DEBUG] Disassemble APK lookup: {:.3f} ms".format(
                (t_lookup_end - t_start) * 1000
            ),
            file=sys.stderr,
        )
        print(
            "[DEBUG] Disassemble DEX rebuild: {:.3f} ms".format(
                (t_rebuild_end - t_lookup_end) * 1000
            ),
            file=sys.stderr,
        )
        print(
            "[DEBUG] Disassemble smali format: {:.3f} ms".format(
                (t_format_end - t_rebuild_end) * 1000
            ),
            file=sys.stderr,
        )
        print(
            "[DEBUG] Disassemble total: {:.3f} ms".format(
                (t_format_end - t_start) * 1000
            ),
            file=sys.stderr,
        )
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="\n") as fp:
            fp.write(disassembly)
            if disassembly and not disassembly.endswith("\n"):
                fp.write("\n")
    else:
        sys.stdout.write(disassembly)
        if disassembly and not disassembly.endswith("\n"):
            sys.stdout.write("\n")


def _handle_listclass(args):
    from droidasc.asc_client.apk_handler import ApkHandler

    names = ApkHandler(args.apk_path, debug=args.debug, max_workers=args.threads).list_classes(
        args.prefix
    )

    output_fp = (
        open(args.output, "w", encoding="utf-8", errors="replace", newline="\n")
        if args.output
        else None
    )
    out = output_fp if output_fp is not None else sys.stdout
    try:
        for start in range(0, len(names), 8192):
            text = "\n".join(names[start:start + 8192]) + "\n"
            out.write(text)
    finally:
        if output_fp is not None:
            output_fp.close()

    if args.debug:
        t_end = time.perf_counter()
        print(f"[DEBUG] Total Execution Time: {(t_end - t_start) * 1000000:.2f} us")


def _handle_batch(args):
    from droidasc.asc_client import batch

    log = print if args.debug else None
    index = batch.index_apk(args.apk_path, args.prefix, log)
    if not index:
        raise ValueError("No classes matched the requested selection.")

    if args.from_file:
        requested = batch.read_class_list(args.from_file)
        missing = [name for name in requested if name not in index]
        if missing:
            print(
                f"Warning: {len(missing)} class(es) not in APK, first: {missing[0]}",
                file=sys.stderr,
            )
        selected = [name for name in requested if name in index]
        if not selected:
            raise ValueError("None of the listed classes are present in the APK.")
    else:
        selected = sorted(index)

    if args.limit:
        selected = selected[: args.limit]

    t_batch = time.perf_counter()
    written = skipped = failed = 0
    for position, name in enumerate(selected, 1):
        dest = os.path.join(args.out_dir, batch.class_output_path(name))
        if args.resume and os.path.exists(dest):
            skipped += 1
        else:
            try:
                source = batch.decompile(index, name)
            except Exception as exc:  # one bad class must not abort the pass
                failed += 1
                print(f"[BATCH] failed: {name}: {exc}", file=sys.stderr)
            else:
                batch.write_source(dest, source)
                written += 1
        if position % 500 == 0 or position == len(selected):
            elapsed = time.perf_counter() - t_batch
            print(
                f"[BATCH] {position}/{len(selected)} written={written} "
                f"skipped={skipped} failed={failed} {position / elapsed:.1f} class/s",
                file=sys.stderr,
            )

    print(
        f"[BATCH] done written={written} skipped={skipped} failed={failed} "
        f"in {time.perf_counter() - t_batch:.2f}s",
        file=sys.stderr,
    )

    if args.debug:
        t_end = time.perf_counter()
        print(f"[DEBUG] Total Execution Time: {(t_end - t_start) * 1000000:.0f} us")

    if failed == len(selected):
        raise ValueError("Every selected class failed to decompile.")


def _handle_getmanifest(args):
    from droidasc.asc_client.manifest_handler import get_manifest_xml

    xml = get_manifest_xml(args.apk_path, pretty=True)
    if args.output:
        with open(args.output, "w", encoding="utf-8", errors="replace", newline="\n") as fp:
            fp.write(xml)
            if not xml.endswith("\n"):
                fp.write("\n")
    print(xml)

    if args.debug:
        t_end = time.perf_counter()
        print(f"[DEBUG] Total Execution Time: {(t_end - t_start) * 1000000:.2f} us")


def _handle_findrefs(args):
    from droidasc.asc_client.apk_handler import ApkHandler

    apk_handler = ApkHandler(args.apk_path, debug=args.debug, max_workers=args.threads)
    find_type, find = _get_find_query(args)

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


def _run_gui(argv):
    parser = argparse.ArgumentParser(
        description="ASC GUI entry.",
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
            "-m", "droidasc",
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
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=creationflags,
            start_new_session=start_new_session,
        )
        return

    from droidasc.asc_client.gui.app import launch_gui
    launch_gui(args.apk_path, max_workers=args.threads, debug=args.debug)


def main():
    argv = sys.argv[1:]
    if len(sys.argv) == 1:
        _build_main_parser(show_version=True).print_help()
        return
    if argv[0] in ("-v", "-V", "--version"):
        print(_version())
        return
    if "--gui" in argv:
        _run_gui(argv)
        return

    parser = _build_main_parser(show_version=("-h" in argv or "--help" in argv))
    args = parser.parse_args()

    try:
        if args.command == "getclass":
            _handle_getclass(args)
        elif args.command == "disassemble":
            _handle_disassemble(args)
        elif args.command == "listclass":
            _handle_listclass(args)
        elif args.command == "batch":
            _handle_batch(args)
        elif args.command == "getmanifest":
            _handle_getmanifest(args)
        elif args.command == "findrefs":
            _handle_findrefs(args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _build_main_parser(show_version=False):
    parser = argparse.ArgumentParser(
        prog="droidasc",
        description=(
            f"ASC tooling entry (v{_version()})."
            if show_version
            else "ASC tooling entry."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""common:
  Class names accept both com.poc.Main and Lcom/poc/Main;.
  Commands with -o/--output write to stdout when the option is omitted.
  --threads N controls parallel APK scanning; --debug enables timing output.

examples:
  droidasc app.apk --gui
  droidasc getclass app.apk Lcom/poc/Main; -o Main.java
  droidasc getclass app.apk com.poc.Main --threads 16
  droidasc disassemble app.apk Lcom/poc/Main; -o Main.smali
  droidasc disassemble app.apk com.poc.Main --debug
  droidasc disassemble app.apk com.poc.Main --debuginfo
  droidasc disassemble app.apk com.poc.Main --method 'run(I)V'
  droidasc listclass app.apk
  droidasc listclass app.apk -o classes.txt
  droidasc listclass app.apk --prefix com.poc
  droidasc batch app.apk --prefix com.poc -o out/
  droidasc batch app.apk --from-file classes.txt -o out/ --resume
  droidasc getmanifest app.apk
  droidasc getmanifest app.apk -o AndroidManifest.xml
  droidasc findrefs app.apk string token -o string_refs.txt
  droidasc findrefs app.apk type com.poc.Main
  droidasc findrefs app.apk method onCreate --class com.poc.Main
  droidasc findrefs app.apk method notify --class MainActivity --fuzzy-class -o method_refs.txt
  droidasc findrefs app.apk field apiKey -o field_refs.txt
  droidasc findrefs app.apk extends java.lang.Object
  droidasc findrefs app.apk extends android.app.Activity -o subclasses.txt
  droidasc findrefs app.apk impl android.os.IInterface -o impls.txt
""",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    getclass_parser = subparsers.add_parser(
        "getclass",
        help="Locate the target class in APK, extract one DEX in memory, then decompile.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  droidasc getclass app.apk Lcom/poc/Main;
  droidasc getclass app.apk com.poc.Main -o Main.java
  droidasc getclass app.apk com.poc.Main --threads 16 --debug
""",
    )
    getclass_parser.add_argument("--debug", action="store_true", help="Enable debug profiling output.")
    getclass_parser.add_argument("--threads", "--thread", type=int, default=8, help="Worker thread count.")
    getclass_parser.add_argument("-o", "--output", help="Also write decompiled output to this file.")
    getclass_parser.add_argument("apk_path", help="Path to the input APK file.")
    getclass_parser.add_argument(
        "dalvik_class",
        help="Class name in dotted or Dalvik form, e.g. com.poc.Main or Lcom/poc/Main;.",
    )

    disassemble_parser = subparsers.add_parser(
        "disassemble",
        help="Extract a class, rebuild a small DEX, then disassemble it with dadguard.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  droidasc disassemble app.apk Lcom/poc/Main;
  droidasc disassemble app.apk com.poc.Main -o Main.smali
  droidasc disassemble app.apk com.poc.Main --threads 16 --debug
  droidasc disassemble app.apk com.poc.Main --debuginfo
  droidasc disassemble app.apk com.poc.Main --method 'run(I)V'
""",
    )
    disassemble_parser.add_argument("--debug", action="store_true", help="Enable debug profiling output.")
    disassemble_parser.add_argument(
        "--debuginfo",
        action="store_true",
        help="Include DEX line and local-variable debug directives.",
    )
    disassemble_parser.add_argument(
        "--method",
        dest="method_signature",
        help="Render one exact method signature, e.g. run(I)V.",
    )
    disassemble_parser.add_argument("--threads", "--thread", type=int, default=8, help="Worker count.")
    disassemble_parser.add_argument(
        "-o",
        "--output",
        help="Write disassembly to this file; default is stdout.",
    )
    disassemble_parser.add_argument("apk_path", help="Path to the input APK file.")
    disassemble_parser.add_argument(
        "dalvik_class",
        help="Class name in dotted or Dalvik form, e.g. com.poc.Main or Lcom/poc/Main;.",
    )

    listclass_parser = subparsers.add_parser(
        "listclass",
        help="List classes across all DEX entries; use --prefix to filter by package/class prefix.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  droidasc listclass app.apk
  droidasc listclass app.apk --prefix com.poc
  droidasc listclass app.apk -o classes.txt
  droidasc listclass app.apk --threads 16 --debug
""",
    )
    listclass_parser.add_argument("--debug", action="store_true", help="Enable debug profiling output.")
    listclass_parser.add_argument("--threads", "--thread", type=int, default=8, help="Worker thread count.")
    listclass_parser.add_argument(
        "--prefix",
        help="Only list classes with this package/class prefix (e.g., com.poc or Lcom/poc).",
    )
    listclass_parser.add_argument("-o", "--output", help="Write class names to this file instead of stdout.")
    listclass_parser.add_argument("apk_path", help="Path to the input APK file.")

    batch_parser = subparsers.add_parser(
        "batch",
        help="Decompile many classes in one APK pass, inflating each DEX exactly once.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  droidasc batch app.apk --prefix com.poc -o out/
  droidasc batch app.apk --from-file classes.txt -o out/
  droidasc batch app.apk --from-file classes.txt -o out/ --resume
""",
    )
    batch_parser.add_argument("--debug", action="store_true", help="Enable debug profiling output.")
    selection = batch_parser.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--from-file",
        metavar="FILE",
        help="Class list file: one name per line, dotted or Dalvik, # comments allowed.",
    )
    selection.add_argument(
        "--prefix",
        help="Decompile every class whose name starts with this prefix.",
    )
    batch_parser.add_argument(
        "-o",
        "--out-dir",
        required=True,
        help="Output directory; files mirror the package tree (com/poc/Main.java).",
    )
    batch_parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip classes whose output file already exists.",
    )
    batch_parser.add_argument(
        "--limit",
        type=int,
        default=0,
        metavar="N",
        help="Decompile at most N classes (0 means no limit).",
    )
    batch_parser.add_argument("apk_path", help="Path to the input APK file.")

    getmanifest_parser = subparsers.add_parser(
        "getmanifest",
        help="Decode AndroidManifest.xml from APK and print it as XML.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  droidasc getmanifest app.apk
  droidasc getmanifest app.apk -o AndroidManifest.xml
""",
    )
    getmanifest_parser.add_argument("--debug", action="store_true", help="Enable debug profiling output.")
    getmanifest_parser.add_argument("-o", "--output", help="Also write decoded manifest to this file.")
    getmanifest_parser.add_argument("apk_path", help="Path to the input APK file.")

    findrefs_parser = subparsers.add_parser(
        "findrefs",
        help="Find code references for string/type/method/field across all DEX entries in APK.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  droidasc findrefs app.apk string token -o string_refs.txt
  droidasc findrefs app.apk type com.poc.Main
  droidasc findrefs app.apk method onCreate --class com.poc.Main
  droidasc findrefs app.apk method notify --class openclaw --fuzzy-class -o method_refs.txt
  droidasc findrefs app.apk field changeQuickRedirect -o field_refs.txt
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
  droidasc findrefs app.apk string token
  droidasc findrefs app.apk string Authorization -o string_refs.txt
""",
    )
    string_parser.add_argument("-o", "--output", help="Also write reference search output to this file.")
    string_parser.add_argument("value", help="Fuzzy string pattern.")

    type_parser = find_subparsers.add_parser(
        "type",
        help="Find references to a fuzzy type descriptor/name.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  droidasc findrefs app.apk type com.poc.Main
  droidasc findrefs app.apk type Lcom/poc/Main; -o type_refs.txt
""",
    )
    type_parser.add_argument("-o", "--output", help="Also write reference search output to this file.")
    type_parser.add_argument("value", help="Fuzzy type pattern.")

    extends_parser = find_subparsers.add_parser(
        "extends",
        help="Find classes that extend the target class.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  droidasc findrefs app.apk extends android.app.Activity
  droidasc findrefs app.apk extends com.poc.Base -o subclasses.txt
""",
    )
    extends_parser.add_argument("-o", "--output", help="Also write subclass output to this file.")
    # SUPPRESS so a flag given before the sub-command (handled by the parent
    # parser) is not reset by the child's own default.
    extends_parser.add_argument("--debug", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    extends_parser.add_argument("--threads", "--thread", type=int, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    extends_parser.add_argument(
        "value",
        help="Target class in dotted or Dalvik form.",
    )

    impl_parser = find_subparsers.add_parser(
        "impl",
        help="Find classes that implement the target interface.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  droidasc findrefs app.apk impl android.os.IInterface
  droidasc findrefs app.apk impl com.poc.Service -o impls.txt
""",
    )
    impl_parser.add_argument("-o", "--output", help="Also write implementor output to this file.")
    # SUPPRESS so a flag given before the sub-command (handled by the parent
    # parser) is not reset by the child's own default.
    impl_parser.add_argument("--debug", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    impl_parser.add_argument("--threads", "--thread", type=int, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    impl_parser.add_argument(
        "value",
        help="Target interface in dotted or Dalvik form.",
    )

    method_parser = find_subparsers.add_parser(
        "method",
        help="Find references to methods.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  droidasc findrefs app.apk method onCreate
  droidasc findrefs app.apk method notify --class com.poc.Main
  droidasc findrefs app.apk method notify --class poc --fuzzy-class -o method_refs.txt
""",
    )
    method_parser.add_argument("-o", "--output", help="Also write reference search output to this file.")
    method_parser.add_argument("name", nargs="?", default=None, help="Fuzzy method name.")
    method_parser.add_argument("--class", dest="class_name", default=None, help="Dalvik class or fuzzy class pattern.")
    method_parser.add_argument("--fuzzy-class", action="store_true", help="Treat --class as fuzzy match.")

    field_parser = find_subparsers.add_parser(
        "field",
        help="Find references to fields.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  droidasc findrefs app.apk field changeQuickRedirect
  droidasc findrefs app.apk field token --class com.poc.Main
  droidasc findrefs app.apk field token --class poc --fuzzy-class -o field_refs.txt
""",
    )
    field_parser.add_argument("-o", "--output", help="Also write reference search output to this file.")
    field_parser.add_argument("name", nargs="?", default=None, help="Fuzzy field name.")
    field_parser.add_argument("--class", dest="class_name", default=None, help="Dalvik class or fuzzy class pattern.")
    field_parser.add_argument("--fuzzy-class", action="store_true", help="Treat --class as fuzzy match.")
    return parser


if __name__ == "__main__":
    main()
