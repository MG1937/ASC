"""Robustness check: corrupt an APK in deterministic ways and require that rasc fails
cleanly instead of panicking.

`rasc` validates the ZIP structures, DEX tables and the binary manifest before and
while decoding them; this script is how that property is checked against real
archives. Every mutation is seeded, so a failure is reproducible by re-running with
the same seed and mutation count.

Usage:
    RASC_BIN=target/release/rasc python3 bench/mutation_check.py app.apk [count]

Mutations cover truncation, byte flips, zero runs, damaged DEX headers, damaged
central-directory fields and a rewritten (corrupted) AndroidManifest.xml. A failure
is any run that panics, aborts or exits with a code above 2.
"""

import os
import random
import subprocess
import sys
import tempfile
import zipfile

RASC = os.environ.get("RASC_BIN", "target/release/rasc")
SEED = 20260912
# `rasc findrefs [OPTIONS] <APK> <QUERY>`: the archive comes before the query.
COMMANDS = [
    ["manifest", "{apk}"],
    ["classes", "--threads", "4", "{apk}"],
    ["findrefs", "--threads", "4", "{apk}", "string", "androidx"],
    ["findrefs", "--threads", "4", "{apk}", "type", "Ljava/lang/String;"],
    ["getclass", "--threads", "4", "{apk}", "Landroid/app/Activity;"],
]


def corrupt(data: bytes, rng: random.Random) -> tuple[str, bytes]:
    """One mutation; the label is printed only when it causes a problem."""
    buf = bytearray(data)
    kind = rng.choice(["truncate", "flip", "zero-run", "dex-header", "central-dir"])
    if kind == "truncate":
        return "truncate", bytes(buf[: rng.randrange(1, len(buf))])
    if kind == "flip":
        for _ in range(rng.randrange(1, 8)):
            buf[rng.randrange(len(buf))] ^= 1 << rng.randrange(8)
        return "flip", bytes(buf)
    if kind == "zero-run":
        start = rng.randrange(len(buf))
        length = min(rng.randrange(1, 4096), len(buf) - start)
        buf[start : start + length] = b"\x00" * length
        return "zero-run", bytes(buf)
    if kind == "dex-header":
        magic = data.find(b"dex\n03")
        if magic < 0:
            return "dex-header", bytes(buf)
        for _ in range(rng.randrange(1, 6)):
            buf[magic + rng.randrange(8, 0x70)] ^= 0xFF
        return "dex-header", bytes(buf)
    signature = data.rfind(b"PK\x01\x02")
    if signature < 0:
        return "central-dir", bytes(buf)
    for _ in range(rng.randrange(1, 5)):
        buf[signature + rng.randrange(0, 46)] = rng.randrange(256)
    return "central-dir", bytes(buf)


def rewrite_manifest(source: zipfile.ZipFile, target: str, payload: bytes) -> None:
    """Writes an archive with `payload` as its (uncompressed) AndroidManifest.xml."""
    with zipfile.ZipFile(target, "w", zipfile.ZIP_STORED) as out:
        out.writestr("AndroidManifest.xml", payload)
        for name in source.namelist():
            if name != "AndroidManifest.xml":
                out.writestr(name, source.read(name))


def corrupt_manifest(axml: bytes, rng: random.Random) -> bytes:
    buf = bytearray(axml)
    kind = rng.choice(["flip", "zero-run", "truncate", "chunk-type"])
    if kind == "truncate":
        return bytes(buf[: rng.randrange(1, len(buf))])
    if kind == "chunk-type":
        # Aim at the node chunks, where a structurally valid but nonsensical type is
        # the interesting case; random offsets almost never produce one.
        offset = rng.randrange(max(1, len(buf) // 2), len(buf))
        buf[offset] = rng.choice([0x00, 0x01, 0x03, 0x04, 0x80, 0x02, 0xFF])
        return bytes(buf)
    if kind == "zero-run":
        start = rng.randrange(len(buf))
        length = min(rng.randrange(1, 256), len(buf) - start)
        buf[start : start + length] = b"\x00" * length
        return bytes(buf)
    for _ in range(rng.randrange(1, 6)):
        buf[rng.randrange(len(buf))] ^= 1 << rng.randrange(8)
    return bytes(buf)


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    seed_apk = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    data = open(seed_apk, "rb").read()
    rng = random.Random(SEED)
    problems = 0

    with tempfile.TemporaryDirectory(prefix="rasc-mutation-") as tmp:
        path = os.path.join(tmp, "mutated.apk")
        source = zipfile.ZipFile(seed_apk)
        has_manifest = "AndroidManifest.xml" in source.namelist()
        for index in range(count):
            if has_manifest:
                # Alternate between whole-archive corruption and manifest-only damage.
                payload = corrupt_manifest(source.read("AndroidManifest.xml"), rng)
                rewrite_manifest(source, path, payload)
                label = "manifest"
            else:
                label, payload = corrupt(data, rng)
                with open(path, "wb") as handle:
                    handle.write(payload)
            for command in COMMANDS:
                argv = [part.replace("{apk}", path) for part in command]
                proc = subprocess.run([RASC, *argv], capture_output=True, text=True, timeout=120)
                if "panicked at" in proc.stderr or proc.returncode < 0 or proc.returncode > 2:
                    problems += 1
                    print(
                        f"  #{index} {label} {command[0]} exit={proc.returncode} "
                        f"{proc.stderr.strip().splitlines()[:1]}"
                    )
        source.close()

    print(f"mutations={count} problems={problems}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
