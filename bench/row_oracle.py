#!/usr/bin/env python3
"""Arbitrate the rows the reference reports and rasc does not.

`rasc` decodes instructions by opcode width and only counts real instructions; the
reference locates references with single-byte regexes over the code item, without an
instruction-boundary check, so it also "finds" reference bytes inside operands and
switch payloads. That claim has so far rested on a handful of spot checks.

This script checks it row by row with an independent decoder: Androguard parses the
code item and yields real instructions, and a row is a *real* reference only if the
named method contains an instruction of the right kind whose operand mentions the
query. Any row the oracle calls real is a rasc miss and is printed for inspection.

    RASC_BIN=target/release/rasc REF_ROOT=... REF_PY=... \
      python3 bench/row_oracle.py app.apk <string|type|field|method> <query> [max rows]
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import zipfile

logging.disable(logging.CRITICAL)

# The operand that the query is compared against, per kind: the string literal, the
# type descriptor, `Lclass;->field`, or `Lclass;->method(params)ret`. Comparing the
# whole instruction output instead would let a short query match the class name.
OPERAND = {
    "string": re.compile(r"'([^']*)'"),
    "type": re.compile(r"(L[^;]*;)"),
    "field": re.compile(r"(L[^;]*;->[^ ]+)"),
    "method": re.compile(r"(L[^;]*;->[^()]*\([^)]*\)[^ ]*)"),
}

PREFIXES = {
    "string": ("const-string",),
    "type": (
        "const-class",
        "check-cast",
        "instance-of",
        "new-instance",
        "new-array",
        "filled-new-array",
    ),
    "field": ("iget", "iput", "sget", "sput"),
    "method": ("invoke",),
}


def rows(command: list[str], cwd: str | None = None) -> set[str]:
    out = subprocess.run(command, capture_output=True, text=True, cwd=cwd)
    if out.returncode != 0:
        raise SystemExit(f"command failed ({out.returncode}): {' '.join(command)}\n{out.stderr[:300]}")
    return set(out.stdout.splitlines())


def identity(row: str) -> tuple[str, str, str] | None:
    """(dex entry, class descriptor, method name) of a row, or None for a fragment.

    A row reads `<dex> | <class>-><method> | matched=(<text>)`; the reference also
    emits fragments of multi-line matched text, which carry no identity.
    """
    head, marker, _ = row.partition(" | matched=(")
    if not marker or " | " not in head:
        return None
    dex_name, _, target = head.partition(" | ")
    if "->" not in target:
        return None
    class_name, _, method_name = target.partition("->")
    return dex_name, class_name.strip(), method_name.strip()


def main() -> int:
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    apk = sys.argv[1]
    # Accept both "<kind> <query>" as one argument and as two.
    kind, _, query = sys.argv[2].partition(" ")
    if not query:
        kind, query = sys.argv[2], sys.argv[3]
        rest = sys.argv[4:]
    else:
        rest = sys.argv[3:]
    if kind not in PREFIXES:
        raise SystemExit(f"unknown query kind {kind!r}; expected one of {sorted(PREFIXES)}")
    limit = int(rest[0]) if rest else 200
    prefixes = PREFIXES[kind]

    binary = os.environ.get("RASC_BIN", "target/release/rasc")
    ours = rows([binary, "findrefs", "--threads", "8", apk, kind, query])
    theirs = rows(
        [
            os.environ["REF_PY"],
            os.path.join(os.environ["REF_ROOT"], "main.py"),
            "findrefs",
            "--threads",
            "8",
            apk,
            kind,
            query,
        ],
        cwd=os.environ["REF_ROOT"],
    )
    ours_ids = {row for row in (identity(r) for r in ours) if row}
    asc_only = [identity(r) for r in theirs]
    asc_only = [i for i in asc_only if i and i not in ours_ids][:limit]
    print(f"{os.path.basename(apk)} {kind} {query!r}: rasc {len(ours_ids)} rows, asc-only {len(asc_only)} checked")

    from androguard.core.dex import DEX  # imported late: it is slow and noisy

    dexes: dict[str, DEX] = {}
    # Two different reasons the reference reports a row rasc does not:
    #   name  - a real instruction references it *and* the member name matches:
    #           that would be a rasc miss.
    #   class - a real instruction references it, but only its class part matches
    #           the query: the reference matches the whole `Lclass;->member` string
    #           while rasc matches the member name (deliberately: a `field`/`method`
    #           query is a name query).
    #   none  - no real instruction references it at all: the reference's byte-regex
    #           locator "found" reference bytes inside operands or payload data.
    real, class_only, fake, missing = [], [], 0, 0
    for dex_name, class_name, method_name in asc_only:
        if dex_name not in dexes:
            with zipfile.ZipFile(apk) as archive:
                dexes[dex_name] = DEX(archive.read(dex_name))
        dex = dexes[dex_name]
        method = None
        for cls in dex.get_classes():
            if cls.get_name() != class_name:
                continue
            method = next((m for m in cls.get_methods() if m.get_name() == method_name), None)
            break
        if method is None:
            missing += 1
            continue
        name_hit = class_hit = None
        for instruction in method.get_instructions():
            if not instruction.get_name().startswith(prefixes):
                continue
            output = instruction.get_output()
            for operand in OPERAND[kind].findall(output):
                if query not in operand:
                    continue
                member = operand.rsplit("->", 1)[-1]
                if query in member:
                    name_hit = f"{instruction.get_name()} {output}"
                    break
                class_hit = f"{instruction.get_name()} {output}"
            if name_hit:
                break
        if name_hit:
            real.append((class_name, method_name, name_hit))
        elif class_hit:
            class_only.append((class_name, method_name, class_hit))
        else:
            fake += 1

    print(f"  member-name hits (would be rasc misses): {len(real)}")
    for class_name, method_name, hit in real[:5]:
        print(f"    {class_name}->{method_name}: {hit[:120]}")
    print(f"  class-part-only hits (reference matches `class->member`, rasc the name): {len(class_only)}")
    print(f"  no real instruction references it (reference's byte-regex false positive): {fake}")
    if missing:
        print(f"  rows whose method the decoder could not locate: {missing}")
    return 1 if real else 0


if __name__ == "__main__":
    sys.exit(main())
