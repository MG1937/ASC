"""Scenario driver that exercises the original Python ASC through its real code paths.

The original project has no CLI for the manifest and class-index features (they are
GUI-only), so this driver calls the same functions the GUI calls, in a fresh process,
so they can be timed against the equivalent `rasc` subcommands.

Usage:
    REF_ROOT=/path/to/reference python reference_scenario.py manifest <apk>
    REF_ROOT=/path/to/reference python reference_scenario.py classes  <apk> [workers]
"""

import os
import sys
import time

ROOT = os.environ["REF_ROOT"]
sys.path.insert(0, ROOT)
os.chdir(ROOT)


def main() -> int:
    mode, apk = sys.argv[1], sys.argv[2]
    started = time.perf_counter()

    if mode == "manifest":
        from src.asc_client.manifest_handler import get_manifest_xml

        sys.stdout.write(get_manifest_xml(apk, pretty=True))
    elif mode == "classes":
        from src.asc_client.gui.runtime import GuiDexStore

        store = GuiDexStore(apk, max_workers=int(sys.argv[3]) if len(sys.argv) > 3 else 8)
        store.load()
        sys.stdout.write("\n".join(store.class_names))
        sys.stdout.write("\n")
    else:
        raise SystemExit(f"unknown mode {mode!r}")

    sys.stdout.flush()
    sys.stderr.write(f"[scenario] {mode} inner={(time.perf_counter() - started) * 1000:.0f}ms\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
