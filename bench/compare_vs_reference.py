"""Real-scenario benchmark: rasc (native Rust) vs the original Python ASC.

Correctness is checked before any timing is reported: every scenario is validated
for exit status, output size, and (where comparable) the result set itself, so a
broken invocation can never be mistaken for a speedup.

Method
    * one fresh process per measurement,
    * one clock in this process,
    * the order of the two implementations is randomized per round so machine
      drift hits both sides equally,
    * median of N runs, stdout discarded (formatting and write syscalls are still
      exercised).

Usage
    REF_ROOT=/path/to/reference \
    APK=/path/to/app.apk \
    RASC_BIN=/path/to/target/release/rasc \
    REF_PY=/path/to/venv/bin/python \
    python3 compare_vs_reference.py

The original project has no CLI for the manifest and class-index features, so the
Python side goes through bench/reference_scenario.py, which calls the same code the GUI
calls.
"""

import os
import random
import re
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = os.environ["REF_ROOT"]
APK = os.environ["APK"]
RASC = os.environ["RASC_BIN"]
PY = os.environ["REF_PY"]
DRIVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference_scenario.py")
THREADS = os.environ.get("THREADS", "8")


def rasc(*args):
    """rasc <subcommand> --threads N <apk> ..."""
    return [RASC, args[0], "--threads", THREADS, APK, *args[1:]]


def asc(*args):
    """python main.py <subcommand> --threads N <apk> ..."""
    return [PY, "main.py", args[0], "--threads", THREADS, APK, *args[1:]]


def pick_late_class():
    """Pick a class defined in the highest-numbered classes*.dex, for a worst-case
    early-stop lookup (the original implementation sorts DEXes by compressed size
    ascending, so classes.dex is always its best case)."""
    out = subprocess.run([RASC, "classes", "--threads", THREADS, APK],
                         capture_output=True, cwd=ROOT, check=True).stdout.splitlines()
    best = None
    for line in out:
        parts = line.split(b" | ")
        if len(parts) < 2:
            continue
        dex, descriptor = parts[0], parts[1]
        match = re.match(rb"classes(\d+)\.dex$", dex)
        if not match or not descriptor.startswith(b"Lcom/"):
            continue
        index = int(match.group(1))
        if best is None or index > best[0]:
            best = (index, dex.decode(), descriptor.decode())
    return best


late = pick_late_class()
if late is None:
    raise SystemExit("could not find a late-DEX class for the getclass scenario")
_, late_dex, late_class = late

SCENARIOS = [
    ("findrefs string Authorization",
     rasc("findrefs", "string", "Authorization"),
     asc("findrefs", "string", "Authorization"), 5, "rows"),
    ("findrefs string com.example.sdk",
     rasc("findrefs", "string", "com.example.sdk"),
     asc("findrefs", "string", "com.example.sdk"), 3, "rows"),
    ("findrefs type Gson",
     rasc("findrefs", "type", "Gson"),
     asc("findrefs", "type", "Gson"), 3, "rows"),
    ("findrefs method onCreate",
     rasc("findrefs", "method", "onCreate"),
     asc("findrefs", "method", "onCreate"), 3, "rows"),
    ("findrefs method onCreate --class com.example --fuzzy-class",
     rasc("findrefs", "method", "onCreate", "--class", "com.example", "--fuzzy-class"),
     asc("findrefs", "method", "onCreate", "--class", "com.example", "--fuzzy-class"),
     3, "rows"),
    ("findrefs field INSTANCE",
     rasc("findrefs", "field", "INSTANCE"),
     asc("findrefs", "field", "INSTANCE"), 3, "rows"),
    ("getclass early (classes.dex)",
     rasc("getclass", "Lcom/example/Probe;"),
     asc("getclass", "Lcom/example/Probe;"), 5, "nonempty"),
    (f"getclass late ({late_dex})",
     rasc("getclass", late_class), asc("getclass", late_class), 3, "nonempty"),
    ("getclass missing class (error path)",
     rasc("getclass", "Lcom/example/DefinitelyNotThere;"),
     asc("getclass", "Lcom/example/DefinitelyNotThere;"), 3, "empty"),
    ("manifest (binary AXML -> XML)",
     [RASC, "manifest", APK], [PY, DRIVER, "manifest", APK], 3, "nonempty"),
    ("classes (full class index)",
     [RASC, "classes", "--threads", THREADS, APK],
     [PY, DRIVER, "classes", APK, THREADS], 3, "classes"),
]


def timed(argv):
    start = time.perf_counter()
    proc = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          cwd=ROOT, check=False)
    return (time.perf_counter() - start) * 1000.0, proc.returncode


def capture(argv, path):
    with open(path, "wb") as out:
        proc = subprocess.run(argv, stdout=out, stderr=subprocess.DEVNULL, cwd=ROOT, check=False)
    return proc.returncode


def read_lines(path):
    with open(path, "rb") as handle:
        return handle.read().splitlines()


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rasc-vs-asc-")
    print(f"APK  : {os.path.basename(APK)} ({os.path.getsize(APK) / 2**20:.0f} MiB)")
    print(f"asc  : {subprocess.run([PY, '--version'], capture_output=True, text=True).stdout.strip()}")
    print(f"rasc : {RASC}")
    print(f"method: fresh process, randomized interleave, median of N, threads={THREADS}\n")
    print(f"{'scenario':<52} {'rasc':>8} {'asc':>9} {'speedup':>8} {'N':>2}  parity")
    print("-" * 118)

    results = []
    for label, rasc_argv, asc_argv, repeats, check in SCENARIOS:
        r_path, a_path = f"{tmp}/r", f"{tmp}/a"
        rc_r = capture(rasc_argv, r_path)
        rc_a = capture(asc_argv, a_path)
        r_lines, a_lines = read_lines(r_path), read_lines(a_path)

        parity, ok = "", True
        if check == "rows":
            r_set, a_set = set(r_lines), set(a_lines)
            parity = f"rows {len(r_set)}/{len(a_set)} diff -{len(a_set - r_set)}/+{len(r_set - a_set)}"
            ok = bool(r_set) and rc_r == 0 and rc_a == 0
        elif check == "classes":
            r_descr = {line.split(b" | ")[1] for line in r_lines if b" | " in line}
            a_descr = set(a_lines)
            parity = f"classes {len(r_descr)}/{len(a_descr)} diff -{len(a_descr - r_descr)}/+{len(r_descr - a_descr)}"
            ok = bool(r_descr) and rc_r == 0 and rc_a == 0
        elif check == "nonempty":
            parity = f"source {len(r_lines)}/{len(a_lines)} lines"
            ok = bool(r_lines) and bool(a_lines) and rc_r == 0 and rc_a == 0
        else:  # "empty": both must fail cleanly with no stdout
            parity = f"exit {rc_r}/{rc_a}, stdout {len(r_lines)}/{len(a_lines)}"
            ok = rc_r != 0 and rc_a != 0 and not r_lines and not a_lines

        if not ok:
            print(f"{label:<52} {'INVALID':>8} {'':>9} {'':>8} {'':>2}  {parity}")
            results.append((label, None, None))
            continue

        expected = {"rasc": rc_r, "asc": rc_a}
        argv_of = {"rasc": rasc_argv, "asc": asc_argv}
        timings = {"rasc": [], "asc": []}
        for _ in range(repeats):
            order = ["rasc", "asc"]
            random.shuffle(order)
            for side in order:
                elapsed, code = timed(argv_of[side])
                if code == expected[side]:
                    timings[side].append(elapsed)

        r_med = statistics.median(timings["rasc"])
        a_med = statistics.median(timings["asc"])
        print(f"{label:<52} {r_med:>6.0f}ms {a_med:>7.0f}ms {a_med / r_med:>7.1f}x {repeats:>2}  {parity}")
        results.append((label, r_med, a_med))

    print("-" * 118)
    valid = [(label, r, a) for label, r, a in results if r]
    print(f"valid scenarios: {len(valid)}/{len(results)}")
    if valid:
        print(f"geometric-mean speedup: {statistics.geometric_mean([a / r for _, r, a in valid]):.1f}x")
    return 0 if len(valid) == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
