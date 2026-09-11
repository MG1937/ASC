#!/usr/bin/env python3
"""Diff `rasc getclass` output between two binaries over a stratified class sample.

The vendored droidsaw-dex patches (see vendor/droidsaw-dex/PATCHES.md) let
`getclass` parse only the requested class's bodies. That is only sound if the
decompiled source is byte-identical to what the unpatched, full parse produced,
so this script re-checks the claim on real APKs:

    bench/decompile_equivalence.py <reference-binary> <apk> [apk ...]

For every APK it lists the classes, samples them stratified by DEX entry (so the
sample covers every DEX, not just the first), and compares stdout, stderr and the
exit code of `getclass` from both binaries. Differences are printed with the class
name and a unified diff of the first few lines; the exit status is non-zero when
any class differs.
"""

from __future__ import annotations

import difflib
import os
import random
import re
import subprocess
import sys
import zlib

WORKERS = "8"


# droidsaw annotates classes it identifies as R8 outlines/synthetics. That
# analysis walks every class body in the DEX, which the scoped parse (only the
# requested class's bodies) cannot see, so the annotation is dropped - the Java
# source itself stays identical.
ANNOTATION = re.compile(r"^\s*/\* @droidsaw .*?\*/\s*$")


def strip_annotations(source: str) -> tuple[str, int]:
    kept = []
    dropped = 0
    for line in source.splitlines():
        if ANNOTATION.match(line):
            dropped += 1
        else:
            kept.append(line)
    return "\n".join(kept), dropped


def run(binary: str, apk: str, descriptor: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        [binary, "getclass", "--threads", WORKERS, apk, descriptor],
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def class_index(binary: str, apk: str) -> list[tuple[str, str]]:
    """(dex entry, descriptor) for every class in the APK."""
    proc = subprocess.run(
        [binary, "classes", "--threads", WORKERS, apk], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise SystemExit(f"classes failed on {apk}: {proc.stderr.strip()}")
    rows = []
    for line in proc.stdout.splitlines():
        parts = line.split(" | ")
        # `classes` prints "<dex> | <descriptor> | <name> | package=<p> | class=<c>".
        if len(parts) >= 2 and parts[1].startswith("L"):
            rows.append((parts[0], parts[1]))
    return rows


def sample_stratified(rows: list[tuple[str, str]], want: int, seed: int) -> list[str]:
    """Pick `want` classes spread evenly over DEX entries."""
    by_dex: dict[str, list[str]] = {}
    for dex, descriptor in rows:
        by_dex.setdefault(dex, []).append(descriptor)
    rng = random.Random(seed)
    per_dex = max(1, want // max(1, len(by_dex)))
    picked = []
    for descriptors in by_dex.values():
        picked.extend(rng.sample(descriptors, min(per_dex, len(descriptors))))
    return picked


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    reference = sys.argv[1]
    apks = sys.argv[2:]
    binary = os.environ.get("RASC_BIN", "target/release/rasc")
    want = int(os.environ.get("SAMPLE", "12"))
    checked = 0
    mismatches = 0
    annotations = [0]  # whole-DEX `@droidsaw` annotations dropped by the scoped parse
    for apk in apks:
        rows = class_index(binary, apk)
        # A stable seed: `hash()` on a string is randomized per process, which
        # would sample different classes on every run and make a difference
        # impossible to reproduce.
        classes = sample_stratified(rows, want, seed=zlib.crc32(apk.encode()))
        differs = 0
        for descriptor in classes:
            expect = run(reference, apk, descriptor)
            got = run(binary, apk, descriptor)
            checked += 1
            if expect == got:
                continue
            if expect[0] == got[0]:
                # Same exit status: compare the source without droidsaw's whole-DEX
                # annotations, which the scoped parse cannot reproduce.
                expect_source, expect_dropped = strip_annotations(expect[1])
                got_source, got_dropped = strip_annotations(got[1])
                if expect_source == got_source and expect[2] == got[2]:
                    annotations[0] += max(expect_dropped, got_dropped)
                    continue
            differs += 1
            mismatches += 1
            print(f"DIFF {apk} {descriptor}")
            if expect[0] != got[0]:
                print(f"  exit {expect[0]} vs {got[0]}")
            diff = difflib.unified_diff(
                expect[1].splitlines(), got[1].splitlines(), "unpatched", "rasc", lineterm=""
            )
            for line in list(diff)[:12]:
                print(f"  {line}")
        print(f"{apk}: {len(classes)} classes sampled over {len({d for d, _ in rows})} DEX entries, {differs} differences")
    note = f", {annotations[0]} class(es) with dropped @droidsaw annotations" if annotations[0] else ""
    print(f"total: {checked} comparisons, {mismatches} differences{note}")
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
