# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-06-11

### Added

- SPR encoder — obfuscation-invariant structural tokenization of parser
  output (NR / BC / AR rungs: Android-API supertype name erasure,
  bytecode-shape and arity tokenization).
- DEX spec-invariant findings now surface to audit: index-keyed ID-pool
  ordering (`OutOfOrder`), `class_def` topological-order violations and a
  typed super-chain terminator, unsorted/overlapping `try_items`, non-zero
  MBZ reserved fields (`map_item` / `method_handle`), and header/map offset
  disagreement on aliased id-section offsets.
- Obfuscation features: main-package class-retention count, declared-package
  threading; Kotlin-rendering-`Indeterminate` class bannering.
- DEX version `"040"` accepted by the parser oracle.
- Negative-property proptests for `DexFile::parse` header fields; SPR-encoder
  fuzz coverage over parser output.

### Fixed

- `desugar()` fixpoint loop bounded to guarantee termination on adversarial
  input.
- `string_ids` pool ordering keyed on ART's MUTF-8 collation (UTF-16
  code-unit order), not raw byte order.
- R8 outline recogniser rejects single-bare-return synthetic helpers;
  trampoline census memoizes canonical `class_def` resolution.
- Emit gated on completeness failures only, not conformance anomalies;
  parsed `utf16_size` preserved on string-pool emit; `had_terminator`
  excluded from string-pool round-trip equivalence.

## [1.0.0] - 2026-05-25

### Added

- DEX parser: zero-copy `DexFile` view over caller-owned `&[u8]`; MUTF-8 codec (`src/mutf8.rs`); headers and id pools validated at parse time; class data, code items, and string pools decoded on demand
- Typed `Opcode` enum: 224 variants, AOSP `bytecode.txt` v035–v041
- CFG with typed exception edges: `EdgeKind::ExceptionHandler(TypeIdx)` and `EdgeKind::ExceptionCatchAll`; exception regions tracked separately from normal control flow
- SSA via Braun algorithm, parameterized over `droidsaw-common::ssa`
- `DexType` lattice: Bottom → primitives / references → Top
- Optimizer: copy propagation, constant folding (DEX semantics), DCE; `FxHashMap<VarId, _>` for intra-function passes
- Structurer: `if/else`, `while`, `for`, `try/catch`, `switch` via `droidsaw-common::region`
- Sugar: enhanced-for recovery, short-circuit `||/&&` reconstruction
- Java emitter: `classes::decompile_class` produces Java source per class; `BTreeMap` throughout for deterministic output
- `emit_dex`: `DexFile` → DEX bytes; `NonDecreasing<T>` / `StrictlyAscending<T>` newtypes enforce spec's lexicographic-sort requirement on id pools as a type-system theorem; parse domain ⊋ emit domain by design
- `ContentEquiv<DexFile>`: roundtrip equivalence relation with independently proptested quotient laws (reflexivity, symmetry, transitivity); proptested at 256 cases default
- 100% byte-identical roundtrip on F-Droid corpus (5,767 DEX files) under preservation mode; 309 files (5.4%) differ in 24 header bytes only — legacy-`dx` non-canonical SHA-1 inputs, attributed via `CanonicalTransform::InputChecksumNormalized`
- `dexdump` differential oracle: every class descriptor and method `(class, name, proto)` triple `dexdump -d` enumerates must appear in droidsaw-dex output; missed class or method is a build break
- 13 libFuzzer targets: `fuzz_parser`, `fuzz_opcode_decode`, `fuzz_cfg`, `fuzz_ssa`, `fuzz_emit_roundtrip`, `fuzz_enum_cross_class`, `fuzz_protector_recognizer`, `fuzz_emulator`, `fuzz_decode_debug_info`, `fuzz_diag_collectors`, `fuzz_proguard_mapping`, `parser_differential`, `cfg_differential`
- 40 Kani harnesses across 9 files: header size, access flags (3 scopes × 6 cases), register narrowing bounds, class-def offset bounds, encoded-value `value_arg` narrowing, annotation directory capacity, endian-tag roundtrip, 4-bit sign-extension, try-item range
- 40 fixtures: 39 compile-pass, 1 compile-fail, 0 semantic-fail; `UNRECOGNIZED_REGION` ratchet per-fixture with per-file SHA-256 baselines
- Smali disassembly (`src/smali.rs`)
- ProGuard/R8 mapping parser (`src/mapping.rs`)
- Protector signature recognizers: `fragmented_string_literal`, `reflective_invoke_stub`; compiler signatures: `javac21`, `kotlinc19`
- Cross-DEX xref index keyed on stable descriptor triples (class, name, proto) — `Xrefs::merge` well-defined across multidex APKs
- SDK version detector with fallback heuristics (`src/sdk_inventory.rs`)
- Adversarial fixture corpus: opcode-invariant, OOM, header/map disagreement, try-item range, string-length disagreement

[1.0.0]: https://github.com/droidsaw/droidsaw-dex/releases/tag/v1.0.0
