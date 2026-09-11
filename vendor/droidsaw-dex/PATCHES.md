# Patched: droidsaw-dex 2.0.0

Vendored copy of [`droidsaw-dex`](https://github.com/droidsaw/droidsaw-dex) 2.0.0
(BSD-3-Clause, `LICENSE` kept as shipped) with two additions, both in
`src/parser/mod.rs` and both used only by `rasc getclass`. Everything else is
byte-identical to the published crate; the patched lines are marked
`PATCHED (rasc)`.

Why: `DexFile::parse` does work that only the emit path consumes, and it decodes
the class bodies of every class in the DEX. `getclass` asks for one class and
never re-emits DEX bytes, so most of that parse is dead weight. Measured on the
9.8 MiB `classes.dex` of the benchmark APK (24,436 class_def rows): full parse
120.7 ms, scoped parse 23.7 ms.

## 1. `DexFile::parse_for_decompilation`

Skips two emit-only stages:

- the whole-input SHA-1 that only feeds `input_checksums_canonical`, read solely by
  `emit_dex.rs`;
- `parse_map_driven_sections`, whose outputs are method handles, call-site ids and
  the section-walk parse-error side channel. All three are consumed by emit; rasc
  reads none of them.

Measured effect on its own: ~6 ms of a ~100 ms parse, so it exists mainly to make
the scoped parse below expressible without changing the full parse's behaviour.

## 2. `DexFile::parse_for_class`

Parses the per-class `class_data`, `code_item` and static-value tables for the
requested descriptor only; every other class keeps its `class_def` row but no
bodies. Also falls back to the full parse when the descriptor matches no class, so
a non-canonical spelling can never yield a DEX whose classes have no code.

Measured effect: 120.7 ms -> 23.7 ms on the DEX above; the per-class decompile
cost (~21 ms) is unchanged, because it already only walks the requested class.

## Safety

`rasc` never re-emits DEX bytes, so none of the skipped structures are observable
in its output. Three layers guard the claim:

1. `src/apk.rs` unit tests against a synthetic APK (the DEX fixture carries a valid
   Adler-32 checksum and a `proto_ids` section so `droidsaw-dex` accepts it): the
   scoped parse keeps fewer class bodies yet decompiles the requested class to the
   same source, an unmatched descriptor falls back to the full parse, and
   `decompile_class` works end to end.
   One qualification, found by the corpus sweep: droidsaw's `@droidsaw R8Origin(...)`
   comments come from an analysis that walks *every* class body, so they are dropped
   by a scoped parse. The Java source is unaffected (verified by stripping those
   comment lines), and `bench/decompile_equivalence.py` reports them separately
   instead of treating them as a difference.
2. `bench/decompile_equivalence.py` diffs `rasc getclass` against an unpatched
   binary over a stratified sample of classes on real APKs.
3. `bench/contracts.sh` decompiles the same packaged class through its dotted and
   slashed spellings and requires identical sources.

`UPSTREAM.md` in this directory is the ready-to-file request for both changes
(measurements included). Once upstream grows a public parse scope — or accepts the
0x78-byte DEX 041 header — this vendor directory should be dropped in favour of it.

## 3. `parse_string_pool` decodes the pool in parallel

The entries are independent, and rayon's ordered collect keeps the first error
(lowest index) winning, so behaviour is unchanged while the pool decodes on every
core. Measured on a 9.8 MiB DEX: 9.4 ms -> sub-millisecond for a class-scoped parse,
which is most of what a `getclass` scoped parse still spent.
