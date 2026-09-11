#!/bin/bash
# CLI contract checks: the exit-code, payload and diagnostic invariants that the
# benchmark harness relies on, expressed as a script so they travel with the
# project instead of living only in a gitignored session folder.
#
# Usage: bash bench/contracts.sh <path/to/app.apk> [path/to/rasc]
#
# Needs a real APK; unit tests cover everything that can be checked without one.
set -euo pipefail

APK="${1:?usage: contracts.sh <apk> [rasc]}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${2:-$ROOT/target/release/rasc}"
CLASS='Lcom/example/Probe;'
ABSENT='__RASC_ABSENT_7f32c9__'

[ -f "$APK" ] || { echo "contracts: missing APK $APK" >&2; exit 1; }
[ -x "$BIN" ] || { echo "contracts: missing binary $BIN" >&2; exit 1; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/rasc-contracts.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "contract violated: $1" >&2; exit 1; }
same() { cmp -s "$1" "$2" || fail "$3"; }

# Every query mode returns rows for a query that exists in the APK, and nothing
# for one that does not.
"$BIN" findrefs --threads 4 "$APK" type Gson >"$TMP/type"
"$BIN" findrefs --threads 4 "$APK" method onCreate >"$TMP/method"
"$BIN" findrefs --threads 4 "$APK" field INSTANCE >"$TMP/field"
"$BIN" findrefs --threads 4 "$APK" string "$ABSENT" >"$TMP/absent"
[ -s "$TMP/type" ] || fail "type query returned nothing"
[ -s "$TMP/method" ] || fail "method query returned nothing"
[ -s "$TMP/field" ] || fail "field query returned nothing"
[ ! -s "$TMP/absent" ] || fail "absent query returned rows"

# The class index still contains a class known to be defined, and the manifest
# decodes to XML with the usual root and namespace.
"$BIN" classes --threads 4 --filter com.example.Probe "$APK" >"$TMP/classes"
grep -q 'Lcom/example/Probe;' "$TMP/classes" || fail "class index lost the probe class"
"$BIN" manifest "$APK" >"$TMP/manifest.xml"
grep -q '<manifest ' "$TMP/manifest.xml" || fail "manifest has no root element"
grep -q 'xmlns:android=' "$TMP/manifest.xml" || fail "manifest lost its namespace"
head -1 "$TMP/manifest.xml" | grep -qx '<?xml version="1.0" encoding="utf-8"?>' \
  || fail "manifest lost its XML declaration"
grep -q '^    <uses-sdk ' "$TMP/manifest.xml" || fail "manifest indentation is not four spaces per level"
grep -q '^        <package ' "$TMP/manifest.xml" || fail "manifest deeper indentation is wrong"
grep -q ' />$' "$TMP/manifest.xml" || fail "manifest no longer writes self-closing tags as ' />'"
grep -q '[^ ]/>' "$TMP/manifest.xml" && fail "manifest wrote a self-closing tag without the space"
[ "$(tail -1 "$TMP/manifest.xml")" = "</manifest>" ] || fail "manifest does not end with its root close tag"
grep -q 'ResourceValueType::' "$TMP/manifest.xml" && fail "manifest leaks decoder placeholder values"

# An -o file receives exactly the bytes stdout received, for every subcommand.
"$BIN" findrefs --threads 4 "$APK" string Authorization -o "$TMP/findrefs.file" >"$TMP/findrefs.stdout"
same "$TMP/findrefs.file" "$TMP/findrefs.stdout" "findrefs -o differs from stdout"
"$BIN" classes --threads 4 --filter com.example.Probe -o "$TMP/classes.file" "$APK" >"$TMP/classes.stdout"
same "$TMP/classes.file" "$TMP/classes.stdout" "classes -o differs from stdout"
"$BIN" manifest -o "$TMP/manifest.file" "$APK" >"$TMP/manifest.stdout"
same "$TMP/manifest.file" "$TMP/manifest.stdout" "manifest -o differs from stdout"
"$BIN" getclass --threads 4 -o "$TMP/class.file" "$APK" "$CLASS" >"$TMP/class.stdout"
same "$TMP/class.file" "$TMP/class.stdout" "getclass -o differs from stdout"

# --debug diagnostics go to stderr and leave stdout byte-identical.
"$BIN" findrefs --debug --threads 4 "$APK" string Authorization >"$TMP/debug.stdout" 2>"$TMP/debug.stderr"
same "$TMP/debug.stdout" "$TMP/findrefs.stdout" "findrefs --debug changed stdout"
grep -q '^\[DEBUG\]' "$TMP/debug.stderr" || fail "findrefs --debug printed no diagnostics on stderr"
"$BIN" getclass --debug --threads 4 "$APK" "$CLASS" >"$TMP/debug-class.stdout" 2>"$TMP/debug-class.stderr"
same "$TMP/debug-class.stdout" "$TMP/class.stdout" "getclass --debug changed stdout"
grep -q '^\[DEBUG\]' "$TMP/debug-class.stderr" || fail "getclass --debug printed no diagnostics on stderr"

# A missing class is an error with a message and exit status 1, not a panic.
if "$BIN" getclass --threads 4 "$APK" com.example.NoSuchClass7f32c9 >"$TMP/missing.stdout" 2>"$TMP/missing.stderr"; then
  fail "getclass succeeded for a class that does not exist"
fi
grep -q 'not found' "$TMP/missing.stderr" || fail "missing class did not report 'not found'"

echo "contracts ok"
