# Upstream request (ready to file)

Two changes we currently carry as a vendor patch, with the measurements that
motivated them. Both come from a Rust APK-analysis CLI (`rasc`) that uses
`droidsaw-dex` only to decompile one class per process; it never re-emits DEX
bytes. Deleting this directory is the goal.

## 1. A parse scope: "this class only, no emit support"

`DexFile::parse(data, budget)` currently does two kinds of work a decompile-only
caller cannot use, measured on a 9.8 MiB DEX (24,436 class_def rows):

| stage | cost |
|---|---:|
| whole-input SHA-1 feeding `input_checksums_canonical` (read only by `emit_dex.rs`) | ~5 ms |
| `parse_map_driven_sections` (method handles, call-site ids, section-walk diagnostics) | ~3 ms |
| per-class `class_data` / `code_item` / static-value tables for every class | ~65 ms |
| strings + id sections + tail (needed) | ~25 ms |

Parsing only the requested class and skipping the emit-only stages takes the same
DEX from **120.7 ms to 23.7 ms**, and the decompiled source for that class is
byte-identical (verified over 1176 classes spread across all 56 DEXes of a 343 MiB
APK, plus 4 other APKs). Suggested shape:

```rust
impl DexFile {
    /// Parse everything a decompiler needs; skip emit-only tables.
    pub fn parse_for_decompilation(data: &[u8]) -> Result<Self>;
    /// Additionally parse only `descriptor`'s class bodies. Falls back to the
    /// full parse when the descriptor matches no class.
    pub fn parse_for_class(data: &[u8], descriptor: &str) -> Result<Self>;
}
```

A generic options struct would be fine too; the two entry points are simply what a
one-class CLI needs.

One caveat we discovered while validating this: the whole-DEX analyses behind the
`@droidsaw R8Origin(...)` annotations need every class body, so a class-scoped parse
drops those comments (the Java source is byte-identical; only the annotations go).
A scope that keeps the emit tables out of the way but still feeds the R8 inversion,
or a documented note that the annotations require the full parse, would be ideal.

## 2. DEX 041 headers (0x78 bytes)

`standard_dex_file.cc`-style containers are rejected today with
`invalid DEX header_size: 120 (spec mandates 0x70)`, so a 041 member cannot be
decompiled at all. The field semantics we had to establish while working around
it (verified against another implementation, which enumerates members the same
way):

- `file_size` (0x20) is the **member's** own size: it is what enumerates members
  (`offset += file_size`) and what bounds the member's own header/section block.
- Section offsets in a 041 header are **container-relative**, so they point past
  `file_size`.
- `container_size` (0x70) is the whole container, `header_offset` (0x74) the
  member's start.
- Because `verify_checksum` hashes `data[12..file_size]`, a caller that hands over
  a container view must also present a `file_size` covering the region the section
  offsets reach, otherwise the bounds checks reject them.

Accepting `header_size == 0x78` (and documenting which `file_size` semantics the
parser expects for such input) would remove our workaround.

## What we do meanwhile

`vendor/droidsaw-dex` carries both changes as a patch (`PATCHES.md` documents each
one, and the patched lines are marked `PATCHED (rasc)`), plus `parse_for_class`'s
fallback for unmatched descriptors. The repository's tests and
`bench/decompile_equivalence.py` pin the behaviour, so we can drop the directory as
soon as upstream supports either entry point.
