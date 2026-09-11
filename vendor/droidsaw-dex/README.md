# droidsaw-dex

DEX (Dalvik Executable) bytecode parser and decompiler. Parses `classes*.dex` bytes, builds a CFG, builds SSA via Braun's algorithm, structures regions, and emits Java source. Inverse path `emit_dex` reserializes a parsed `DexFile` back to DEX bytes; `parse ∘ emit_dex ∘ parse ≡ parse` at the IR level.

Sits below the `droidsaw` binary in the workspace. Depends on `droidsaw-common` for generic graph / SSA / region / dominator algorithms (the bundle is generic over `I: Instr`); DEX opcode tables, the `Opcode` enum (224 variants in `src/opcodes.rs`), and DEX format specifics stay here. Nothing format-specific leaks into `droidsaw-common`.

## Architecture

DEX and Hermes share the same decompiler pipeline. The middle stages are generic in `droidsaw-common`; this crate supplies its own `Insn` type and DEX-specific sugar.

| Stage | Module | Input → Output |
|---|---|---|
| parse | `src/parser/mod.rs`, `src/header.rs`, `src/annotation.rs`, `src/access_flags.rs`, `src/ids.rs` | `&[u8]` → `DexFile` |
| decode | `src/decode.rs`, `src/opcodes.rs` | code-item bytes → `Vec<Insn>` |
| CFG | `src/cfg.rs` | `Vec<Insn>` → basic blocks + typed edges |
| dominators | `droidsaw-common::graph::dominators` | basic blocks → idom map |
| SSA (Braun) | `src/ssa.rs`, `droidsaw-common::ssa` | basic blocks → `SsaBody` |
| types | `src/types.rs` | `DexType` lattice; `Bottom` → primitives / references → `Top` |
| optimize | `src/optimize.rs` | copy propagation, const folding (DEX semantics), DCE |
| structure | `src/structure.rs`, `droidsaw-common::region` | CFG → `RegionTree` (`if`/`else`, `while`, `for`, `try`/`catch`, `switch`) |
| sugar | `src/sugar.rs` | enhanced-for recovery, short-circuit `||` / `&&` reconstruction |
| emit (Java) | `src/emit.rs`, `src/classes.rs` | `RegionTree` → Java source |
| emit (DEX) | `src/emit_dex.rs` | `DexFile` → DEX bytes |
| validate | `tests/byte_identity_smoke.rs`, `tests/roundtrip_proptest.rs` | source bytes / IR ≡ input |

Exception edges are typed (`EdgeKind::ExceptionHandler(TypeIdx)` and `EdgeKind::ExceptionCatchAll`) and tracked separately in `exception_regions` so downstream passes can distinguish exception flow from normal control flow.

Canonical id-pool ordering in `emit_dex` is encoded structurally via the `NonDecreasing<T>` and `StrictlyAscending<T>` newtypes — emit code can only obtain them through `from_sorted` / `from_verified`, so the spec's lexicographic-sort requirement on `string_ids` / `type_ids` / `proto_ids` / `field_ids` / `method_ids` is a type-system theorem, not a test result. The asymmetry **emit domain ⊊ parse domain** is intentional: parse tolerates anomalies so analysis can proceed on adversarial input; emit rejects them so no ill-formed shape ever round-trips onward.

Cross-references (`src/xrefs.rs`) are keyed on stable descriptor triples (class, name, proto), not per-DEX pool indices, so `Xrefs::merge` is well-defined across multidex APKs. Signatures and protector recognizers (`src/signatures/`) include `javac21`, `kotlinc19`, and two protector shapes (`fragmented_string_literal`, `reflective_invoke_stub`).

Deterministic IR. `BTreeMap` only, no `HashMap`. Typed `Opcode` enum (224 variants, AOSP `bytecode.txt` v035–v041). Structural try-catch (partition before recurse). Sugar separated from core structuring.

## Inputs

`&[u8]` of `classes*.dex` content. Multi-dex APKs produce one `DexFile` per `classes<N>.dex`; `droidsaw-apk` extracts them. Headers and id pools are validated at parse time; class data, code items, and string pools are decoded on demand.

`DexFile` is a zero-copy view borrowing from a caller-owned byte slice. String encoding is MUTF-8; the codec lives in `src/mutf8.rs` and is never bypassed by callers.

## Output

- `DexFile` IR (`src/parser/mod.rs`) — classes, methods, code items, debug info, annotations, call sites, method handles.
- `classes::decompile_class` — Java source for a single class.
- `smali::*` — Smali disassembly (`src/smali.rs`).
- `emit_dex::emit_dex` — DEX bytes for a parsed `DexFile` (`src/emit_dex.rs`).

## Correctness

Five gates. Each catches what the layer above it can't.

### 1. Round-trip disassembly

`emit_dex` is the inverse of `DexFile::parse`. The equivalence specification *is* the round-trip contract:

```
parse ∘ emit_dex ∘ parse ≡ parse
```

`ContentEquiv<DexFile>` in `src/parser/content_equiv.rs` is the equivalence relation: pool sizes and contents must match; layout-dependent fields (per-section offsets, header checksum/signature, BTreeMap keys that are original-file offsets) are excluded — these are deterministic-emit consequences, not IR content.

Proptested at 256 cases default in `tests/roundtrip_proptest.rs` (`parse_emit_parse_structural_equivalence`). The quotient laws on `ContentEquiv` — reflexivity, symmetry, transitivity — are independently proptested in `tests/quotient_laws_proptest.rs` so the relation is a real equivalence, not a leaky `PartialEq`.

Byte-identity is a stricter gate measured at `tests/byte_identity_smoke.rs`: byte-identical output ⇒ empty `applied_transformations` (the attribution contract — emit may never report a transform it did not actually perform). Measured on the F-Droid corpus (`tests/corpus_byte_identity_fdroid_sweep.rs`): **100% byte-identical round-trip on 5767 of 5767 DEX files under preservation mode** (2026-05-23). 309 files (5.4%) differ only in 24 header bytes — exclusively legacy-`dx`-toolchain non-canonical SHA-1 inputs, typed-attributed via `CanonicalTransform::InputChecksumNormalized`.

Verify locally:

```sh
cargo test -p droidsaw-dex --test roundtrip_proptest
cargo test -p droidsaw-dex --test quotient_laws_proptest
cargo test -p droidsaw-dex --test byte_identity_smoke -- --nocapture
```

### 2. Fixture ratchet

40 fixtures in `tests/fixtures/java/`, driven by `tests/fixtures/manifest.toml` and run by `tests/fixture_ratchet.rs`. The full pipeline per fixture is `javac → d8 → decompile → javac → java`. Fixtures with an `expected_stdout` entry compare the recompiled run's stdout against that golden file; fixtures without one use the original `java` run's output as the golden.

Current state: 39 `compile_pass`, 1 `compile_fail`, 0 `semantic_fail`.

Fixture statuses are a ratchet. `semantic_fail` stays at 0. `compile_fail` decreases monotonically. A `compile_pass → compile_fail` flip blocks merge.

`UNRECOGNIZED_REGION` ratchet is per-APK in `tests/unrecognized_ratchet.rs` with per-file SHA-256 baselines in `tests/baselines/unrecognized.toml`. Per-APK monotone (not global): each APK is gated against its own baseline; rotated APKs fail loud rather than silently re-baseline.

### 3. Adversarial fuzz

libFuzzer targets in `fuzz/fuzz_targets/`:

| Target | Invariant |
|---|---|
| `fuzz_parser` | `DexFile::parse(bytes)` never panics. |
| `fuzz_opcode_decode` | `decode::decode_insns` never panics. |
| `fuzz_cfg` | `Cfg::build` never panics on any parser-accepted code item. |
| `fuzz_ssa` | `SsaBody::build` never panics on any parser-accepted body. |
| `fuzz_emit_roundtrip` | `parse(emit_dex(parse(bytes)))` succeeds and is `ContentEquiv` to first parse on every accepted input. |
| `fuzz_enum_cross_class` | Cross-class enum recognizer no-panic. |
| `fuzz_protector_recognizer` | Protector-shape signatures no-panic on adversarial input. |
| `fuzz_emulator` | Bounded symbolic emulator no-panic. |
| `fuzz_decode_debug_info` | `decode_debug_info` never panics on adversarial input. |
| `fuzz_diag_collectors` | Diagnostic collectors no-panic on parsing errors. |
| `fuzz_proguard_mapping` | ProGuard mapping parser no-panic on malformed input. |
| `parser_differential` | `naive_parse_dex(data).to_shape() == DexFile::parse(data).to_shape()` on inputs both accept. Layered-oracle for silent-wrong-parse bugs. |
| `cfg_differential` | `naive_cfg(code).shape() == Cfg::build(code).to_shape()`. Layered-oracle for silent-wrong-CFG bugs (the class of bug that broke dominators without panicking). |

Tracked crash reproducers live under `fuzz/crashes/<target>/`; curated seeds under `fuzz/seeds/<target>/`. Run a target:

```sh
cd droidsaw-dex
RUSTUP_TOOLCHAIN=nightly-2025-11-21 cargo fuzz run fuzz_parser
RUSTUP_TOOLCHAIN=nightly-2025-11-21 cargo fuzz run fuzz_emit_roundtrip
```

Adversarial fixtures under `tests/fixtures/adversarial/` (opcode-invariant, OOM, header/map disagreement, try-item range, string-length disagreement) double as fuzz seeds and as deterministic regression tests in `tests/opcode_invariant_fixtures.rs`.

### 4. Cross-tool differential

`dexdump` (Android SDK build-tools) is a DEX disassembler used here as a code-unit coverage oracle. The check is not about comparing disassembly or decompiled Java output — it is about whether droidsaw-dex can see every class and method the disassembler sees. Differential runs from `droidsaw-bench` (`src/dexdump_runner.rs` + `src/cross_tool.rs`): every class descriptor and every method `(class, name, proto)` triple that `dexdump -d` enumerates must also appear in droidsaw-dex output. A missed class or method is a build break.

### 5. Formal proofs

Nine Kani harness files under `proofs/`, totaling 40 `#[kani::proof]` attributes:

| File | Subject | Sub-proofs |
|---|---|---|
| `proofs/header_size_gauge.rs` | `DexHeader::parse` rejects `header_size != 0x70` | 2 |
| `proofs/access_flags_spec_union.rs` | `access_flags::validate` rejects out-of-mask bits (3 scopes × 6 cases) | 6 |
| `proofs/debug_register_bound.rs` | `narrow_register` blocks the `register as u16` truncation smuggling path | 4 |
| `proofs/class_def_off_bound.rs` | 4 `class_def` offset fields bounds-check at parse time, not on first read | 4 |
| `proofs/encoded_value_value_arg_bound.rs` | `annotation::check_value_arg_size` blocks the 11 narrowing-cast arms that broke roundtrip-byte-equality | 12 |
| `proofs/annotation_directory_cap.rs` | `AnnotationDirectoryItem::parse` caps `Vec::with_capacity` on the sum `fields + methods + parameters` | 3 |
| `proofs/endian_tag_gauge.rs` | Endian-tag codec roundtrip correctness | 3 |
| `proofs/sign_extend_4bit.rs` | Sign-extension for 4-bit register widths | 2 |
| `proofs/try_item_start_addr.rs` | `EmptyTryRegion` violation fires on `insn_count == 0` (audit-spoof regression) | 2 |

Run a harness:

```sh
cd droidsaw-dex
cargo kani --harness non_canonical_header_size_always_rejected
```

Each proof anchors a concrete past regression — each is the codified gauge for a bug class, not a tautology. Theorems migrate from Lean to Kani once the statement fits Kani's bounded reach; broader Lean coverage (dominators, post-dominators, lattice monotonicity, path properties) sits in the workspace `droidsaw-lean` crate.

The compile-time floor on every non-test module:

```
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic,
        clippy::unreachable, clippy::todo,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing, clippy::string_slice,
        clippy::cast_lossless, clippy::cast_possible_truncation,
        clippy::cast_sign_loss, clippy::cast_precision_loss,
        clippy::cast_possible_wrap,
        clippy::as_conversions)]
```

`clippy::as_conversions` is denied at the crate root; new `as` casts in non-test code must carry a per-site or file-level `PROOF: ...` allow.

## Perf

`src/optimize.rs` uses `FxHashMap<VarId, _>` for per-pass intra-function maps. `VarId` is `Copy + Eq + Hash`, ordering is not load-bearing inside the optimizer (final emit re-sorts at the IR boundary).

`BTreeMap` remains the rule anywhere ordering crosses an emit boundary or a cross-pass output — the determinism guarantee holds.

## License

BSD-3-Clause.
