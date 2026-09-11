#!/usr/bin/env python3
"""Compare rasc's decompilation against JADX, which is the authority.

JADX is the reference for "what the source really is"; rasc is only judged where
JADX itself produced clean output. The comparison uses semantic anchors rather
than text: the set of string literals in each output (normalized for escapes and
for the short whitespace fragments formatters produce). A literal that JADX has
in a class it decompiled cleanly, and that rasc's output for the same class does
not, is a rasc bug: the decompiler lost code.

    python3 bench/jadx_parity.py app.apk [--sample N] [--class <dotted.name>]

Needs `jadx` on PATH (Homebrew's jadx is fine) and RASC_BIN.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

BAD_CODE = re.compile(
    r"Code decompiled incorrectly|Failed to decompile|JADX WARN|Method not decompiled|"
    r"Instruction doesn't exist|Inconsistent code",
    re.IGNORECASE,
)
LITERAL = re.compile(r'"((?:[^"\\]|\\.)*)"')


def run(command: list[str], timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def literals(source: str) -> set[str]:
    """String literals worth comparing: escapes resolved, formatter noise dropped."""
    out = set()
    for raw in LITERAL.findall(source):
        try:
            value = raw.encode().decode("unicode_escape")
        except Exception:
            value = raw
        if len(value) >= 4 and value.strip():
            out.add(value)
    return out


def classes_of(binary: str, archive: str) -> list[str]:
    out = run([binary, "classes", "--threads", "8", archive])
    if out.returncode != 0:
        raise SystemExit(f"classes failed: {out.stderr[:200]}")
    found = []
    for line in out.stdout.splitlines():
        parts = line.split(" | ")
        if len(parts) >= 2 and parts[1].startswith("L") and parts[1].endswith(";"):
            found.append(parts[1][1:-1].replace("/", "."))
    return found


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    archive = sys.argv[1]
    binary = os.environ.get("RASC_BIN", "target/release/rasc")
    wanted: list[str] = []
    sample = 12
    rest = sys.argv[2:]
    while rest:
        flag = rest.pop(0)
        if flag == "--sample":
            sample = int(rest.pop(0))
        elif flag == "--class":
            wanted.append(rest.pop(0))
        else:
            raise SystemExit(f"unknown option {flag}")

    if not wanted:
        found = classes_of(binary, archive)
        step = max(1, len(found) // sample)
        wanted = found[::step][:sample]

    judged = lost_total = 0
    for dotted in wanted:
        descriptor = "L" + dotted.replace(".", "/") + ";"
        ours = run([binary, "getclass", "--threads", "8", archive, descriptor])
        if ours.returncode != 0 or not ours.stdout.strip():
            print(f"{dotted}: rasc produced nothing (rc={ours.returncode}) — {ours.stderr.strip()[:80]}")
            continue
        out_dir = tempfile.mkdtemp(prefix="jadx-parity-")
        try:
            theirs = run(["jadx", "--no-res", "--single-class", dotted, "-d", out_dir, archive])
            produced = list(pathlib.Path(out_dir).rglob("*.java"))
            if not produced:
                print(f"{dotted}: JADX produced nothing (rc={theirs.returncode})")
                continue
            source = produced[0].read_text(errors="replace")
        finally:
            shutil.rmtree(out_dir, ignore_errors=True)

        # JADX's `--single-class` resolves an inner `$Name` request to the *outer*
        # class, which would compare two different classes; only judge when the
        # produced declaration is the one that was asked for.
        declaration = re.search(r"\b(?:class|interface|enum)\s+([A-Za-z0-9_$]+)", source)
        simple = dotted.rsplit(".", 1)[-1]
        if not declaration or declaration.group(1) != simple:
            produced_name = declaration.group(1) if declaration else "?"
            print(f"{dotted}: JADX emitted {produced_name!r} instead, not judging")
            continue
        if BAD_CODE.search(source):
            print(f"{dotted}: JADX flagged its own output, not judging rasc")
            continue
        judged += 1
        missing = sorted(literals(source) - literals(ours.stdout))
        lost_total += len(missing)
        verdict = "ok" if not missing else f"MISSING {len(missing)}"
        print(f"{dotted}: {verdict} (JADX {len(literals(source))} literals, rasc {len(literals(ours.stdout))})")
        for value in missing[:5]:
            print(f"    {value[:110]!r}")

    print(f"judged {judged} class(es) where JADX was clean; literals rasc lost: {lost_total}")
    return 1 if lost_total else 0


if __name__ == "__main__":
    sys.exit(main())
