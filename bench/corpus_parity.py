"""Parity check of rasc against the original Python ASC for any APK.

Compares, per APK:
  * the class-definition set (`rasc classes` vs the reference's GuiDexStore list),
  * the row set of literal string queries (`rasc findrefs string <q>` vs `main.py findrefs`),
  * the decoded manifest as a tree (tag names, attributes and text), so formatting
    differences - we emit an XML declaration and four-space indentation, the
    reference does not - are reported as information rather than as failures.

Usage:
    RASC_BIN=target/release/rasc \
    REF_ROOT=/path/to/reference \
    REF_PY=/path/to/python \
    python3 bench/corpus_parity.py app.apk [more.apk ...]

Exits non-zero when a class set or a row set differs, so it doubles as a gate for
new corpus APKs. Needs the reference checkout and its Python environment.
"""

import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ElementTree

QUERIES = ["string androidx", "string Authorization"]
DRIVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference_scenario.py")
ROOT = os.path.dirname(os.path.dirname(DRIVER))


def run(command: list[str], cwd: str | None = None, env: dict[str, str] | None = None) -> str:
    proc = subprocess.run(command, capture_output=True, text=True, cwd=cwd, env=env)
    if proc.returncode != 0:
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(command)}\n{proc.stderr.strip()[:400]}")
    return proc.stdout


def asc_environment() -> dict[str, str]:
    return dict(os.environ, REF_ROOT=os.environ["REF_ROOT"])


def to_java_name(name: str) -> str:
    """Both sides hand out `Lpkg/Name;`; compare dotted names."""
    name = name.strip()
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def rasc_classes(binary: str, apk: str) -> set[str]:
    out = run([binary, "classes", "--threads", "8", apk])
    return {to_java_name(line.split(" | ")[1]) for line in out.splitlines() if line.strip()}


def asc_classes(apk: str) -> set[str]:
    out = run([os.environ["REF_PY"], DRIVER, "classes", apk, "8"], cwd=os.environ["REF_ROOT"], env=asc_environment())
    return {to_java_name(line) for line in out.splitlines() if line.strip()}


ROW_PREFIX = " | matched=("


def split_rows(lines: set[str]) -> tuple[dict[str, str], int]:
    """Map each row's identity to its matched text.

    A row reads `<dex> | <class>-><method> | matched=(<text>)`. The reference
    implementation prints the matched text verbatim, so a string constant that
    spans lines arrives as extra fragment lines and the text itself is cut short;
    those lines have no identity and are counted separately.
    """
    identities: dict[str, str] = {}
    fragments = 0
    for line in lines:
        head, marker, text = line.partition(ROW_PREFIX)
        if not marker or " | " not in head or "->" not in head:
            fragments += 1
            continue
        identities[head] = text[:-1] if text.endswith(")") else text
    return identities, fragments


def reference_truncation(theirs: str, ours: str) -> bool:
    """True when `theirs` looks like the reference's cut-short copy of `ours`."""
    if not theirs or len(theirs) >= len(ours):
        return False
    for length in range(1, len(theirs) + 1):
        if theirs[:length] not in ours:
            return False
    return True


# Broad sweep across all four modes. The reference locator is a byte regex with no
# instruction-boundary check, so it reports *extra* rows here.
# The sweep check is therefore one-directional: rasc must never
# report a row the reference misses, and the extras are only counted.
SWEEP_QUERIES = [
    "string http",
    "string android.permission",
    "string Lcom",
    "string key",
    "string value",
    "string UTF-8",
    "string config",
    "type Ljava/lang/String;",
    "type Activity",
    "type android",
    "method <init>",
    "method on",
    "method get",
    "field m",
    "field INSTANCE",
]


# A pattern the reference treats literally: it matches class names with `re`, so
# `.` is a wildcard and `$` an anchor there. Letters, digits, slashes and dots in a
# package prefix are safe.
SAFE_PATTERN = re.compile(r"^[A-Za-z0-9_./]+$")


def rasc_rows(binary: str, apk: str, query: str) -> set[str]:
    args = query.split()
    return set(run([binary, "findrefs", "--threads", "8", apk, *args]).splitlines())


def asc_rows(apk: str, query: str) -> set[str]:
    args = query.split()
    out = run(
        [os.environ["REF_PY"], os.path.join(os.environ["REF_ROOT"], "main.py"), "findrefs", "--threads", "8", apk, *args],
        cwd=os.environ["REF_ROOT"],
        env=asc_environment(),
    )
    return set(out.splitlines())


def tree_shape(text: str):
    """(tag, sorted attributes, children) recursively, ignoring formatting."""
    def value(text: str) -> str:
        # Hex values differ between the two renderers in case and zero padding;
        # compare them numerically.
        if text.startswith("0x"):
            try:
                return str(int(text, 16))
            except ValueError:
                return text
        return text

    def node(element):
        attributes = tuple(sorted((name, value(text)) for name, text in element.attrib.items()))
        return (element.tag, attributes, tuple(node(child) for child in element))

    return node(ElementTree.fromstring(text))


def manifest_differences(ours: str, theirs: str) -> list[str]:
    """First few structural differences, as `path: what differs` lines."""
    ours_tree = ElementTree.fromstring(ours)
    theirs_tree = ElementTree.fromstring(theirs)
    out: list[str] = []

    def walk(x, y, path):
        if len(out) >= 8:
            return
        if x.tag != y.tag:
            out.append(f"{path}: tag {x.tag!r} vs {y.tag!r}")
            return
        ours_attrs, theirs_attrs = dict(x.attrib), dict(y.attrib)
        for name in sorted(set(ours_attrs) | set(theirs_attrs)):
            if ours_attrs.get(name) != theirs_attrs.get(name):
                out.append(f"{path}/{x.tag}: {name}={ours_attrs.get(name)!r} vs {theirs_attrs.get(name)!r}")
        if len(x) != len(y):
            out.append(f"{path}/{x.tag}: {len(x)} children vs {len(y)}")
            return
        for index, (child_x, child_y) in enumerate(zip(x, y)):
            walk(child_x, child_y, f"{path}/{x.tag}[{index}]")

    walk(ours_tree, theirs_tree, "root")
    return out


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    binary = os.environ.get("RASC_BIN", os.path.join(ROOT, "target/release/rasc"))
    failures = 0
    for apk in sys.argv[1:]:
        print(f"=== {os.path.basename(apk)} ===")
        ours, theirs = rasc_classes(binary, apk), asc_classes(apk)
        if ours == theirs:
            print(f"  classes: {len(ours)} identical")
        else:
            failures += 1
            print(f"  classes: DIFFER rasc={len(ours)} asc={len(theirs)}")
            print(f"    only rasc: {sorted(ours - theirs)[:4]}")
            print(f"    only asc : {sorted(theirs - ours)[:4]}")

        for query in QUERIES:
            a, b = rasc_rows(binary, apk, query), asc_rows(apk, query)
            ours, _ = split_rows(a)
            theirs, fragments = split_rows(b)
            if ours.keys() != theirs.keys():
                failures += 1
                print(f"  findrefs {query}: DIFFER rasc={len(ours)} asc={len(theirs)}")
                print(f"    only rasc: {sorted(set(ours) - set(theirs))[:2]}")
                print(f"    only asc : {sorted(set(theirs) - set(ours))[:2]}")
                continue
            # Same references; the reference's matched text may still be cut short.
            cut = [key for key in ours if ours[key] != theirs[key]]
            unexpected = [key for key in cut if not reference_truncation(theirs[key], ours[key])]
            if unexpected:
                failures += 1
                print(f"  findrefs {query}: matched text differs in {len(unexpected)} row(s), not a truncation")
                for key in unexpected[:2]:
                    print(f"    rasc: {ours[key]!r}")
                    print(f"    asc : {theirs[key]!r}")
                continue
            note = ""
            if cut:
                note = f", matched text cut short in {len(cut)} (reference truncation)"
            if fragments:
                note += f", {fragments} reference fragment line(s)"
            print(f"  findrefs {query}: {len(ours)} row identities identical{note}")

        swept = 0
        for query in SWEEP_QUERIES:
            a, b = rasc_rows(binary, apk, query), asc_rows(apk, query)
            ours, _ = split_rows(a)
            theirs, fragments = split_rows(b)
            missing = sorted(set(ours) - set(theirs))
            extra = len(set(theirs) - set(ours))
            swept += 1
            if missing:
                failures += 1
                print(f"  sweep {query}: rasc reports {len(missing)} row(s) the reference misses")
                for row in missing[:3]:
                    print(f"    {row}")
            else:
                print(
                    f"  sweep {query}: {len(ours)} rows, {extra} reference-only, "
                    f"{fragments} fragment(s)"
                )

        # Filter sweep: the class filters are their own code path (exact, fuzzy and
        # the dotted-name normalization), and the reference matches them with `re`,
        # so only literal-safe package prefixes are compared. One-directional like
        # the query sweep: a row rasc reports and the reference does not is a bug.
        # The class pattern constrains the class the reference points at, so the
        # patterns are derived from the unfiltered rows themselves - a package that
        # really does define the queried member. Otherwise every combination would
        # trivially return nothing on both sides and check no rows at all.
        checked_rows = 0
        filtered = 0
        for member in ("onCreate", "on"):
            base_rows, _ = split_rows(rasc_rows(binary, apk, f"method {member}"))
            counts: dict[str, int] = {}
            for row in base_rows:
                parts = row.split(" | ")
                if len(parts) != 2 or "->" not in parts[1]:
                    continue
                name = to_java_name(parts[1].split("->", 1)[0])
                if "$" in name or "." not in name:
                    continue
                prefix = name.rsplit(".", 1)[0]
                if SAFE_PATTERN.match(prefix):
                    counts[prefix] = counts.get(prefix, 0) + 1
            for pattern in [p for p, _ in sorted(counts.items(), key=lambda kv: -kv[1])[:4]]:
                for extra in ([], ["--fuzzy-class"]):
                    args = f"method {member} --class {pattern}"
                    if extra:
                        args += " --fuzzy-class"
                    ours_rows, _ = split_rows(rasc_rows(binary, apk, args))
                    theirs_rows, _ = split_rows(asc_rows(apk, args))
                    missing = sorted(set(ours_rows) - set(theirs_rows))
                    filtered += 1
                    checked_rows += len(ours_rows)
                    if missing:
                        failures += 1
                        flag = " --fuzzy-class" if extra else ""
                        print(
                            f"  filter {member} --class {pattern}{flag}: rasc reports "
                            f"{len(missing)} of {len(ours_rows)} row(s) the reference misses"
                        )
                        for row in missing[:3]:
                            print(f"    {row}")
        print(f"  filters: {filtered} combination(s), {checked_rows} rows checked")

        ours_manifest = run([binary, "manifest", apk])
        theirs_manifest = run(
            [os.environ["REF_PY"], DRIVER, "manifest", apk], cwd=os.environ["REF_ROOT"], env=asc_environment()
        )
        if tree_shape(ours_manifest) == tree_shape(theirs_manifest):
            print(
                f"  manifest: content identical, formatting differs "
                f"(rasc {len(ours_manifest.splitlines())} lines vs asc {len(theirs_manifest.splitlines())})"
            )
        else:
            differences = manifest_differences(ours_manifest, theirs_manifest)
            print(f"  manifest: content differs in {len(differences)} place(s)")
            for line in differences[:4]:
                print(f"    {line}")
    print("parity check:", "ok" if failures == 0 else f"{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
