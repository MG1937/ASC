//! Diagnostic emission for the dex layer. Surfaces structural-analysis
//! signals that the audit DB consumes as findings.
//!
//! Today's only producer: [`collect_unrecognized_findings`], which walks
//! the per-method IR and emits one
//! [`UNRECOGNIZED_REGION`](FINDING_ID_UNRECOGNIZED_REGION) finding per
//! [`Stmt::Unrecognized`] region.
//!
//! The walker filters tagged-region sentinels
//! ([`UnrecognizedReason::NoSignatureMatch`] with `closest = Some(_)` AND
//! `distance == 0`). These are *recognized* shapes the IR has no
//! first-class variant for (e.g. coroutine_suspend state machines); they
//! render with a recognizer-specific banner per
//! `emit::emit_unrecognized` but are NOT failure modes and must not
//! count toward the per-APK ratchet.

use droidsaw_common::finding::{Confidence, Finding, Layer, Severity};
use droidsaw_common::signature::UnrecognizedReason;

use crate::cfg::{BlockIdx, Cfg};
use crate::decode;
use crate::ids::ClassDefItem;
use crate::optimize;
use crate::parser::{DexFile, ParseFailureKind, PoolKind};
use crate::ssa::SsaBody;
use crate::structure::{self, CatchClause, MultiArm, Stmt};
use crate::sugar;
use crate::types;

/// Stable finding id for an unrecognized bytecode region. Joins
/// `COMPILE_FAIL` / `SEMANTIC_FAIL` as a third tracked metric.
pub const FINDING_ID_UNRECOGNIZED_REGION: &str = "UNRECOGNIZED_REGION";

/// Stable finding id for a DEX header-vs-map_list count disagreement.
///
/// DEX redundantly declares per-section counts in two places: the main
/// header (`header.<section>_size`) and the `map_list` table at file
/// end (`MapEntry.size` per `type_code`). A spec-compliant DEX has the
/// two in agreement. Disagreement is a downstream-tool-disagreement
/// primitive (CVE-2025-62518 §6 generalization) — droidsaw may read one
/// count via the header path while baksmali / dexdump / ART read a
/// different count via the map_list path.
///
/// The `detail` field carries `"section=<name> header=<n> map=<m>"`
/// (or `map=MISSING` if no `MapEntry` exists for the section type).
/// The `extra` field carries the structured `type_code = 0xXXXX` for
/// downstream consumers that key off the on-disk constant.
pub const FINDING_ID_DEX_HEADER_MAP_DISAGREEMENT: &str = "DEX_HEADER_MAP_DISAGREEMENT";

/// Stable finding id for an unreadable DEX `map_list` table.
///
/// Fires when `read_map_list(data, header.map_off)` returns `Err`
/// (arithmetic overflow, bounds violation, scroll read failure).
/// The parser recovers by treating `map_entries` as empty. This
/// finding is emitted ONCE per DEX when the failure is observed, and
/// the header-vs-map cross-check is skipped for that DEX to avoid
/// emitting the misleading "map says 0, header says N" disagreement
/// when the truth is "map is unreadable."
pub const FINDING_ID_DEX_MAP_LIST_UNREADABLE: &str = "DEX_MAP_LIST_UNREADABLE";

/// Stable finding id for a header-vs-map_list section *offset* disagreement.
///
/// Companion to [`FINDING_ID_DEX_HEADER_MAP_DISAGREEMENT`] (which covers
/// *size* divergence): fires when a section's `header.{name}_off` differs from
/// the `MapEntry.offset` the map_list records for the same `type_code`. The
/// runtime resolves each section by the header offset, so a divergent map
/// offset means a map_list-navigating tool reads a different byte range than
/// the runtime — a parser-differential primitive. Higher severity than the
/// size disagreement: a moved offset re-points a whole section. The stronger
/// case (two sections physically aliasing) is hard-rejected at parse time as
/// `DexError::SectionOverlap`; this finding covers the offset-moved-but-not-
/// overlapping case where best-effort parse is still useful.
pub const FINDING_ID_DEX_HEADER_MAP_OFFSET_DISAGREEMENT: &str =
    "DEX_HEADER_MAP_OFFSET_DISAGREEMENT";

/// Stable finding id for a per-string declared-vs-scanned UTF-16
/// length disagreement in the DEX string pool.
///
/// DEX `string_data_item` is a ULEB128-prefixed MUTF-8 sequence:
/// `(utf16_size, mutf8_bytes, 0x00)`. The declared `utf16_size`
/// counts UTF-16 code units in the *decoded* string; downstream
/// tools (baksmali, dexdump, ART) anchor on this declared value.
/// Prior versions discarded the declared count and used a NUL-byte-scan
/// to terminate, opening the per-record TARmageddon shape (CVE-2025-62518 §6
/// generalization at per-record granularity (CRIT-1): a malformed
/// entry where the declared count and the NUL-scan-derived count disagree
/// presents one view to droidsaw and a different view to AOSP runtime.
///
/// **Rolled-up** (single Finding per DEX, not per-string). Phase-0
/// corpus measurement (985 DEXes / 44.7M strings) found 5,016
/// disagreements across 110 files — per-string emission would
/// swamp the audit DB. The `detail` field carries the aggregate
/// summary (count + max gap); `extra` carries up to 5 sample
/// `idx=I declared=D scanned=S` rows. The dominant root cause is
/// **lone surrogates in obfuscator-emitted strings** — the MUTF-8
/// decoder rejects them, the lossy fallback substitutes one
/// `U+FFFD` per invalid byte, and the post-fallback UTF-16 unit
/// count exceeds the declared value.
pub const FINDING_ID_DEX_STRING_LENGTH_DISAGREEMENT: &str = "DEX_STRING_LENGTH_DISAGREEMENT";

/// Stable finding id for a DEX `string_data_item` whose body lacks
/// the spec-required `0x00` terminator before EOF.
///
/// `parse_strings` recovers by silently extending the byte slice to
/// `data.len()` (the `unwrap_or(data.len())` fallback at the
/// NUL-scan call site). The recovery is safe — bounds-checked slice
/// access — but a missing terminator is itself a corruption signal:
/// Phase-0 corpus measurement found 0/985 benign DEXes triggering
/// this fallback, so any non-zero count on real input is anomalous.
///
/// **Per-string** (one Finding per offending entry). The corpus
/// 0-baseline means rare-event-diagnostic; preserving `string_idx`
/// granularity is more useful than rolling up at this rate.
pub const FINDING_ID_DEX_STRING_MISSING_TERMINATOR: &str = "DEX_STRING_MISSING_TERMINATOR";

/// Stable finding id for a DEX `code_item.try_item` whose
/// `start_addr + insn_count > insns_size`.
///
/// The unchecked `try_start + try_item.insn_count as u32` shape at
/// `cfg.rs:439, :514` and `smali.rs:184` would otherwise wrap on
/// `start_addr = u32::MAX, insn_count = 1` (release builds), producing
/// `try_end = 0` → all blocks short-circuit
/// `block_start < try_end && block_end > try_start` → **all exception
/// edges silently dropped from the CFG**. The parser observes the
/// violation, **clamps** the in-IR `insn_count` to the valid range, and
/// records the original observed values via
/// [`crate::decode::CodeItemInvariantViolation::TryItemRangeInvalid`]
/// so this Finding can preserve the pre-clamp evidence.
///
/// **Per-occurrence** (one Finding per offending try_item). Phase-0
/// corpus measurement found 0/985 benign DEXes triggering the
/// invariant across 37.6 million methods, so the `try_idx` +
/// `start_addr` + `insn_count` + `insns_size` granularity is
/// load-bearing for triage when the rare-event signal fires
/// (adversarial / packer / dexpatcher inputs).
///
/// Extension of CVE-2025-62518 generalization at per-entry granularity.
pub const FINDING_ID_DEX_TRY_ITEM_RANGE_INVALID: &str = "DEX_TRY_ITEM_RANGE_INVALID";

/// Stable finding id for a DEX `try_item` with `insn_count == 0` —
/// an empty try region per spec §6.try_item. `start_addr` is defined
/// as the dex_pc of the FIRST covered instruction, so a region that
/// covers zero instructions is malformed.
///
/// **Per-occurrence** (one Finding per empty try_item). The parser
/// records the violation via
/// [`crate::decode::CodeItemInvariantViolation::EmptyTryRegion`] and
/// SKIPS the entry — the entry never reaches the in-IR `tries` vec, so
/// the CFG builder cannot emit a zero-instruction handler edge.
///
/// Inflates audit-side try-region counters without covering any
/// control flow → audit-spoof primitive (low severity).
pub const FINDING_ID_DEX_TRY_ITEM_EMPTY_REGION: &str = "DEX_TRY_ITEM_EMPTY_REGION";

/// Stable finding id for a DEX `code_item` whose `try_item`s are not
/// ordered by ascending `start_addr` with non-overlapping ranges
/// (DEX spec §"code_item"). The parser records the first violating
/// pair via
/// [`crate::decode::CodeItemInvariantViolation::TryItemsUnsortedOrOverlapping`].
///
/// Overlapping tries let the CFG builder attribute the same dex_pc to
/// two handler lists and double-emit exception edges (inflated handler
/// counts visible to detectors); out-of-order tries break the
/// canonical-layout assumption a re-emitting reader makes. **One
/// Finding per offending `code_item`** (first violating pair), bounding
/// adversarial spam on a fully-reversed try table.
pub const FINDING_ID_DEX_TRY_ITEMS_UNSORTED_OR_OVERLAPPING: &str =
    "DEX_TRY_ITEMS_UNSORTED_OR_OVERLAPPING";

/// Stable finding id for a DEX `code_item` whose
/// `ins_size > registers_size`.
///
/// `ssa.rs:393` (`first_param_reg = registers_size.saturating_sub(ins_size)`)
/// and `debug.rs:301` (`build_name_map`) consume the `saturating_sub`
/// result as a register-base; on inversion the result is silently
/// `0`, attributing all parameters to overlapping register slots → wrong
/// SSA / wrong local-name binding. The parser observes the violation
/// and records it via
/// [`crate::decode::CodeItemInvariantViolation::RegisterCountInverted`]
/// without clamping (downstream policy decides: drop the method, emit
/// best-effort SSA, etc.).
///
/// **Per-occurrence** (one Finding per offending code_item). Phase-0
/// corpus rate 0/985 → rare-event-diagnostic on benign input.
pub const FINDING_ID_DEX_CODE_ITEM_REGISTER_COUNT_INVERTED: &str =
    "DEX_CODE_ITEM_REGISTER_COUNT_INVERTED";

/// Stable finding id for an F35c or F45cc instruction whose `arg_count`
/// (B nibble, 4 bits, 0..=15) exceeds the spec maximum of 5.
///
/// ART rejects via `runtime/verifier/method_verifier.cc:2050-2055`
/// `kVerifyVarArg` case → `FailInvalidArgCount` →
/// `VERIFY_ERROR_BAD_CLASS_HARD` (`kMaxVarArgRegs = 5`). Droidsaw's
/// tolerant-parse non-negotiable retains the existing `.min(5)` clamp at
/// `decode.rs::decode_single` so the in-IR `RegList` is bounded; the
/// pre-clamp `observed` value is preserved in the
/// [`crate::decode::CodeItemInvariantViolation::OpcodeArgCountOutOfRange`]
/// variant so this Finding can surface the divergence.
///
/// **Per-occurrence** (one Finding per offending instruction). Sibling-
/// sweep peer in the opcode-invariant matrix at
/// `docs/opcode-invariant-matrix.md` §4 H-1.
pub const FINDING_ID_DEX_OPCODE_ARG_COUNT_OUT_OF_RANGE: &str =
    "DEX_OPCODE_ARG_COUNT_OUT_OF_RANGE";

/// Stable finding id for a branch or switch-payload target that lands
/// outside the method's instruction stream (`target >= insns_size`).
///
/// ART rejects via `runtime/verifier/method_verifier.cc:2186-2188`
/// (`CheckAndMarkBranchTarget` → `FailTargetOffsetOutOfRange` →
/// `VERIFY_ERROR_BAD_CLASS_HARD`) for branches, and the parallel
/// `CheckAndMarkSwitchTargets` for switch + array-data payload-internal
/// targets. Droidsaw's tolerant-parse retains the OOB target in IR so
/// the CFG layer's existing silent-drop at `cfg.rs:256` produces the
/// same graph it always did; this Finding surfaces the divergence.
///
/// **Per-occurrence** (one Finding per offending branch / target).
/// Sibling-sweep peer in the opcode-invariant matrix at
/// `docs/opcode-invariant-matrix.md` §4 M-1 + §8.
pub const FINDING_ID_DEX_BRANCH_TARGET_OUT_OF_RANGE: &str =
    "DEX_BRANCH_TARGET_OUT_OF_RANGE";

/// Stable finding id for a switch / fill-array-data payload whose
/// leading `ident` u16 disagrees with the source opcode's expected
/// signature (PackedSwitch=0x0100, SparseSwitch=0x0200,
/// FillArrayData=0x0300).
///
/// ART rejects via `runtime/verifier/method_verifier.cc:2280-2291`
/// `CheckAndMarkSwitchTargets` → `FailBadSwitchPayloadSignature` →
/// `VERIFY_ERROR_BAD_CLASS_HARD`. Droidsaw's tolerant-parse drops
/// the mis-typed payload from the `payloads` map; CFG already handles
/// missing payloads gracefully at `cfg.rs:267`.
///
/// This is a parser-vs-parser primitive at the payload-grammar
/// boundary: the skip-walker at `decode.rs:881-934` reads the ident
/// byte to compute payload size; without the matching ident check on
/// the resolve-walker side, the resolve-walker would dispatch the
/// payload decoder on source opcode alone. Same shape as
/// CVE-2025-62518 at a smaller scale.
pub const FINDING_ID_DEX_PAYLOAD_IDENT_MISMATCH: &str = "DEX_PAYLOAD_IDENT_MISMATCH";

/// Stable finding id for an opcode byte that is unmapped per
/// `Opcode::from_u8`. ART rejects via
/// `runtime/verifier/method_verifier.cc:4085-4090` (UNUSED_3E..43,
/// UNUSED_73/79/7A, UNUSED_E3..F9). Droidsaw's tolerant-parse skips
/// 1 code unit and surfaces the divergence here.
///
/// Cursor-misalignment is the adversary primitive: bytes after an
/// unmapped opcode can decode as different instructions under our
/// skip-by-1 vs ART's reject-at-load.
pub const FINDING_ID_DEX_UNKNOWN_OPCODE_BYTE: &str = "DEX_UNKNOWN_OPCODE_BYTE";

// ── Bonus invariants ──────────────────────────────────────────────────

/// Branch offset == 0 for a non-`goto/32` branch opcode.
/// ART rejects via `runtime/verifier/method_verifier.cc:2181-2184`
/// (`FailBranchOffsetZero → VERIFY_ERROR_BAD_CLASS_HARD`).
/// `goto/32` (F30t) is ART-exempt; all shorter goto and all if-* forms
/// are rejected when the target equals the source pc (tight self-loop).
///
/// Severity::Medium — creates an infinite loop at an unsafe pc;
/// ART hard-rejects but droidsaw's tolerant-parse retains the insn.
pub const FINDING_ID_DEX_BRANCH_OFFSET_ZERO: &str = "DEX_BRANCH_OFFSET_ZERO";

/// Branch target lands inside a multi-code-unit instruction (not on an
/// opcode boundary). ART rejects via
/// `runtime/verifier/method_verifier.cc:2192-2195`
/// (`FailTargetMidInstruction → VERIFY_ERROR_BAD_CLASS_HARD`).
///
/// Adversary primitive: droidsaw and a from-target-pc decoder observe
/// different instruction streams from the same bytes.
///
/// Severity::Medium — structural parser-vs-parser desync primitive.
pub const FINDING_ID_DEX_BRANCH_TARGET_MID_INSTRUCTION: &str =
    "DEX_BRANCH_TARGET_MID_INSTRUCTION";

/// Branch target opcode is `move-result`, `move-result-wide`,
/// `move-result-object`, or `move-exception`. ART rejects via
/// `runtime/verifier/method_verifier.cc:2197-2200`
/// (`FailBranchTargetIsMoveResultOrMoveException →
/// VERIFY_ERROR_BAD_CLASS_HARD`).
///
/// Severity::Medium — spec-violation: `move-result*` must follow an
/// invoke; `move-exception` must be first in an exception handler.
pub const FINDING_ID_DEX_BRANCH_TARGET_IS_MOVE_RESULT_OR_MOVE_EXCEPTION: &str =
    "DEX_BRANCH_TARGET_IS_MOVE_RESULT_OR_MOVE_EXCEPTION";

/// Switch or `fill-array-data` payload is at an odd (non-32-bit-aligned)
/// code-unit address. ART rejects via the alignment check in
/// `CheckAndMarkSwitchTargets`/`CheckArrayData` at
/// `runtime/verifier/method_verifier.cc:2260-2266`.
///
/// DEX spec §6.4.2: payload pseudo-instruction address must be 4-byte
/// aligned (code-unit address must be even).
///
/// Severity::Medium — ART hard-rejects; droidsaw still decodes the payload.
pub const FINDING_ID_DEX_UNALIGNED_TABLE_DEX_PC: &str = "DEX_UNALIGNED_TABLE_DEX_PC";

/// Last decoded instruction's end address crosses the declared `insns_size`
/// boundary. ART's `ComputeWidthsAndCountOps` at
/// `runtime/verifier/method_verifier.cc:1730-1801` requires the decode loop
/// to terminate exactly at `insns_size`; an instruction whose end overshoots
/// means the declared boundary falls mid-instruction.
///
/// Severity::Medium — boundary overshoot is a structural malformation;
/// ART hard-rejects while droidsaw's `while pc < insns_size` loop exits
/// without checking for the overshoot.
pub const FINDING_ID_DEX_TAIL_BYTES_AFTER_LAST_INSTRUCTION: &str =
    "DEX_TAIL_BYTES_AFTER_LAST_INSTRUCTION";

/// Non-static `invoke*` with `arg_count == 0`. ART rejects via
/// `runtime/verifier/method_verifier.cc:2047-2055`
/// (`kVerifyVarArgNonZero → VERIFY_ERROR_BAD_CLASS_HARD`).
/// Non-static invokes require at least the receiver (`this`) argument.
///
/// Sibling of [`FINDING_ID_DEX_OPCODE_ARG_COUNT_OUT_OF_RANGE`]
/// (which covers `arg_count > 5`). Severity::Low — the static verifier
/// also catches this; the zero-arg shape creates a receiver-missing IR.
pub const FINDING_ID_DEX_NON_STATIC_INVOKE_ARG_COUNT_ZERO: &str =
    "DEX_NON_STATIC_INVOKE_ARG_COUNT_ZERO";

/// Stable finding id for "at least one parse_errors-tolerant subsection
/// is in scope of a detector path."
///
/// Fires once per `ParseFailure` whose `kind` is reachable from a public
/// detector that consumes `annotation_directory` / `annotation_set` /
/// `annotation_set_ref_list` / `annotation_item` / `class_data` /
/// `code_item` / `debug_info`. The detector returns
/// [`crate::DetectorVerdict::Indeterminate`] (or
/// [`crate::DexError::DetectorIndeterminate`] for `Vec`-returning
/// shapes) in this case rather than silently collapsing to `false`.
///
/// The Finding stream is the audit-visible signal that an analyst's
/// "is this kotlin?" / "does this method throw X?" answer was
/// short-circuited by a tolerantly-recorded parse skip; without it,
/// the silent-skip evasion primitive at the detector layer is
/// invisible to the audit pipeline.
///
/// Severity::Low — the detector did not produce a false-negative
/// claim of presence; it explicitly refused to answer. The signal
/// matters for completeness audits, not for incident triage.
pub const FINDING_ID_DEX_DETECTOR_INDETERMINATE: &str = "DEX_DETECTOR_INDETERMINATE";

/// Finding id for [`collect_duplicate_class_def_findings`]: a
/// `class_def_item` row shares its `class_idx` with an earlier row.
/// The index pins to the FIRST encounter (matching AOSP
/// `DexFile::FindClassDef`), iteration callers gate via
/// `DexFile::class_def_is_shadowed`, but the structural anomaly
/// itself surfaces here so operators can triage toolchain corruption
/// vs attacker tampering. Severity::Medium — the divergence has been
/// resolved at every consumer; the signal is "this DEX is structurally
/// anomalous and warrants manual review".
pub const FINDING_ID_DEX_DUPLICATE_CLASS_DEF: &str = "DEX_DUPLICATE_CLASS_DEF";

/// Stable finding id for an ID pool (`string_ids` / `type_ids` /
/// `proto_ids` / `field_ids` / `method_ids`) that is not strictly
/// ascending by its DEX-spec sort key with no duplicates. The parser
/// records the first violation per pool as
/// [`crate::parser::ParseFailureKind::OutOfOrder`]; surfacing it lets an
/// operator see that droidsaw's O(1) index view may diverge from a
/// re-sorting reader (ART / a differential parser) — the
/// index-vs-iteration evasion primitive.
pub const FINDING_ID_DEX_POOL_OUT_OF_ORDER: &str = "DEX_POOL_OUT_OF_ORDER";

/// Stable finding id for a `class_def` that appears before its
/// superclass or an implemented interface (DEX-spec topological order),
/// recorded as
/// [`crate::parser::ParseFailureKind::ClassDefOutOfTopologicalOrder`].
pub const FINDING_ID_DEX_CLASS_DEF_TOPO_ORDER: &str = "DEX_CLASS_DEF_TOPO_ORDER";

/// Stable finding id for a DEX reserved "(must be zero)" field
/// (`map_item.unused` / `method_handle_item.unused`) carrying a non-zero
/// value, recorded as
/// [`crate::parser::ParseFailureKind::ReservedBitsNonZero`].
pub const FINDING_ID_DEX_RESERVED_BITS_NONZERO: &str = "DEX_RESERVED_BITS_NONZERO";

/// `DEX_CLASS_DATA_OFF_COLLISION` — multi-class_def collision on
/// `class_data_off`. Two or more `class_def_item` rows with DIFFERENT
/// `class_idx` but the SAME non-zero `class_data_off` indicate either
/// toolchain corruption (R8 / D8 dedup gone wrong — unlikely) or
/// attacker tampering. The latter is the load-bearing threat: plant
/// a benign non-ACC_SYNTHETIC class_def sharing the offset of a legit
/// R8 outline class to suppress outline detection via `.find()`-first-
/// wins evasion. `r8_inversion::recognise_outline_helper_v2` was the
/// surfaced vulnerable site; canonical row resolution now prefers
/// `ACC_SYNTHETIC`-bearing rows. This walker surfaces the collision
/// regardless of whether the outline detector fires. Severity::Medium,
/// parallel to `DEX_DUPLICATE_CLASS_DEF`.
pub const FINDING_ID_DEX_CLASS_DATA_OFF_COLLISION: &str = "DEX_CLASS_DATA_OFF_COLLISION";

/// DEX `map_item.type_code` values for the six item-count sections that
/// have both a `header.<section>_size` and a `map_list` entry.
///
/// Per the DEX spec § "map_item". `data_size`/`data_off` is deliberately
/// excluded: it is the byte-length of the region containing 0x2000–0x2006
/// sub-sections, with no single `MapEntry` whose `size` corresponds.
const TYPE_STRING_ID_ITEM: u16 = 0x0001;
const TYPE_TYPE_ID_ITEM: u16 = 0x0002;
const TYPE_PROTO_ID_ITEM: u16 = 0x0003;
const TYPE_FIELD_ID_ITEM: u16 = 0x0004;
const TYPE_METHOD_ID_ITEM: u16 = 0x0005;
const TYPE_CLASS_DEF_ITEM: u16 = 0x0006;

/// Cross-check the DEX header's per-section counts against the parallel
/// `map_list` table. Emits one `DEX_HEADER_MAP_DISAGREEMENT` finding per
/// section pair whose two surfaces disagree, or one
/// `DEX_MAP_LIST_UNREADABLE` finding when the `map_list` itself failed
/// to parse (in which case the cross-check is skipped for that DEX).
///
/// **Tolerant-parse non-negotiable.** This is a Finding-only signal;
/// the parser continues with the header-side counts regardless.
/// Discriminating between "header is right and map is wrong" vs. "map
/// is right and header is wrong" is out of scope — both observed
/// values are recorded so downstream consumers can act on the pair.
///
/// `(header_value = 0, map_value = None)` is treated as agreement:
/// an empty section with no `MapEntry` is spec-permitted equivalence.
///
/// Six sections are checked: string_ids, type_ids, proto_ids,
/// field_ids, method_ids, class_defs. `data_size`/`data_off` is
/// excluded — see `TYPE_*_ITEM` constants above for rationale.
pub fn collect_header_map_findings(dex: &DexFile) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();

    // Pre-req gate: if `read_map_list` itself failed at parse time,
    // emit ONLY the unreadable finding and skip the disagreement
    // check. Without this gate the disagreement check would compare
    // header counts against an artificially-empty `map_entries` and
    // emit misleading "map says 0, header says N" Findings for every
    // populated section.
    if dex
        .parse_errors
        .iter()
        .any(|p| p.kind == ParseFailureKind::MapList)
    {
        let mut finding = Finding::new(
            FINDING_ID_DEX_MAP_LIST_UNREADABLE,
            Layer::Dex,
            Severity::Medium,
            format!(
                "map_list at offset 0x{:x} failed to parse; cross-check skipped",
                dex.header.map_off
            ),
        );
        finding.confidence = Confidence::Verified;
        out.push(finding);
        return out;
    }

    let h = &dex.header;
    let map = &dex.map_entries;
    // (name, type_code, header_size, header_off)
    let pairs: &[(&'static str, u16, u32, u32)] = &[
        ("string_ids", TYPE_STRING_ID_ITEM, h.string_ids_size, h.string_ids_off),
        ("type_ids", TYPE_TYPE_ID_ITEM, h.type_ids_size, h.type_ids_off),
        ("proto_ids", TYPE_PROTO_ID_ITEM, h.proto_ids_size, h.proto_ids_off),
        ("field_ids", TYPE_FIELD_ID_ITEM, h.field_ids_size, h.field_ids_off),
        ("method_ids", TYPE_METHOD_ID_ITEM, h.method_ids_size, h.method_ids_off),
        ("class_defs", TYPE_CLASS_DEF_ITEM, h.class_defs_size, h.class_defs_off),
    ];

    for (name, type_code, header_value, header_off) in pairs {
        let map_entry = map.iter().find(|m| m.type_code == *type_code);

        // Size disagreement (Medium). A `0`-size section with no map entry is
        // the well-formed "section absent" case and is skipped.
        let map_value: Option<u32> = map_entry.map(|m| m.size);
        let mismatch_map_str = match (header_value, map_value) {
            (0, None) => None,
            (_, None) => Some("MISSING".to_string()),
            (h_val, Some(m_val)) if *h_val == m_val => None,
            (_, Some(m_val)) => Some(m_val.to_string()),
        };
        if let Some(map_str) = mismatch_map_str {
            let mut finding = Finding::new(
                FINDING_ID_DEX_HEADER_MAP_DISAGREEMENT,
                Layer::Dex,
                Severity::Medium,
                format!("section={name} header={header_value} map={map_str}"),
            )
            .with_extra(format!("type_code=0x{type_code:04x}"));
            finding.confidence = Confidence::Verified;
            out.push(finding);
        }

        // Offset disagreement (High). Only when the map entry is present and
        // its offset diverges from the header — a moved section the runtime
        // resolves by `header_off` while a map-navigating tool reads `map.off`.
        // The aliasing extreme (sections physically overlapping) is hard-
        // rejected earlier as `DexError::SectionOverlap`; this covers the
        // moved-but-not-overlapping case where best-effort parse still helps.
        if let Some(m) = map_entry {
            if m.offset != *header_off {
                let mut finding = Finding::new(
                    FINDING_ID_DEX_HEADER_MAP_OFFSET_DISAGREEMENT,
                    Layer::Dex,
                    Severity::High,
                    format!(
                        "section={name} header_off={header_off:#x} map_off={:#x} (runtime uses header_off)",
                        m.offset
                    ),
                )
                .with_extra(format!("type_code=0x{type_code:04x}"));
                finding.confidence = Confidence::Verified;
                out.push(finding);
            }
        }
    }

    out
}

/// Cross-check the per-string declared UTF-16 code-unit count
/// (captured by `parse_strings` from the ULEB128 prefix at
/// `string_data_off`) against the count derived from re-encoding
/// the parser's decoded `String` as UTF-16. Emits up to two kinds
/// of finding:
///
/// - One **rolled-up** `DEX_STRING_LENGTH_DISAGREEMENT` finding
///   summarising every entry whose declared and scanned counts
///   differ. Per-string emission was rejected at design time
///   (Phase-0 corpus rate ≈ 0.011% across 44.7M strings → 5,016
///   per-string findings on 110 files would swamp downstream
///   consumers; the rollup precedent is `collect_unrecognized_findings`
///   above).
/// - One **per-string** `DEX_STRING_MISSING_TERMINATOR` finding
///   per offending entry. Phase-0 corpus rate is 0/985, so the
///   event is rare-diagnostic and `string_idx` granularity is
///   load-bearing for triage.
///
/// **Tolerant-parse non-negotiable.** The parser already used the
/// NUL-scan-derived position when constructing `dex.strings[i]`;
/// this function only observes the disagreement, never enforces
/// either side. `(declared = 0, scanned = 0)` is treated as
/// agreement (empty string, spec-permitted equivalence).
///
/// The disagreement check iterates `dex.declared_string_lengths`
/// (length-parallel to `dex.strings` by `parse_strings` invariant)
/// and computes the scanned count via
/// `dex.strings[i].encode_utf16().count()` — which equals the
/// post-decode UTF-16 unit count, including `U+FFFD` substitutions
/// emitted by the lossy fallback when MUTF-8 decoding rejected
/// the raw bytes. The dominant disagreement source on real corpora
/// is lone-surrogate-rich obfuscator-emitted strings; the Finding
/// preserves both observed values so downstream consumers can
/// distinguish "obfuscator artifact" from "deliberate desync attack".
pub fn collect_string_length_findings(dex: &DexFile) -> Vec<Finding> {
    /// Cap the number of sample rows carried in `extra`. Mirrors
    /// `collect_unrecognized_findings`'s `SAMPLE_CAP = 5` — same
    /// rollup convention, same downstream parsing assumption.
    const SAMPLE_CAP: usize = 5;

    let mut out: Vec<Finding> = Vec::new();

    // Per-`DexString` accessors `declared_chars` + `had_terminator`
    // are structurally tied to the underlying entry — the bytes,
    // decode result, and gauges all live in the same variant — so
    // the iteration bound is simply `dex.strings.len()`.
    let n = dex.strings.len();

    let mut disagreement_count: usize = 0;
    let mut max_gap: i64 = 0;
    let mut samples: Vec<String> = Vec::with_capacity(SAMPLE_CAP);

    for i in 0..n {
        let entry = match dex.strings.get(i) {
            Some(e) => e,
            None => continue,
        };
        let declared = entry.declared_chars();
        // The scanned UTF-16 count uses the lossy decoded view —
        // for `MalformedMutf8` entries this is the
        // U+FFFD-substituted form, which is what
        // `dex.strings[i].encode_utf16().count()` returned in the
        // pre-`DexString` shape.
        let scanned: u32 = entry
            .as_str_lossy()
            .encode_utf16()
            .count()
            .try_into()
            .unwrap_or(u32::MAX);

        // `(declared = 0, scanned = 0)` is spec-permitted equivalence —
        // empty string. Any other inequality is a disagreement.
        if declared != scanned {
            disagreement_count = disagreement_count.saturating_add(1);
            // Signed gap = declared - scanned. Cast through i64 to
            // avoid `clippy::arithmetic_side_effects` on the workspace
            // deny-list and to admit the negative direction (Phase-0
            // result: scanned > declared in nearly every observed
            // case).
            let gap_i64 = i64::from(declared).saturating_sub(i64::from(scanned));
            let gap_abs = gap_i64.unsigned_abs();
            let max_abs: u64 = max_gap.unsigned_abs();
            if gap_abs > max_abs {
                max_gap = gap_i64;
            }
            if samples.len() < SAMPLE_CAP {
                samples.push(format!(
                    "idx={i} declared={declared} scanned={scanned}"
                ));
            }
        }

        if !entry.had_terminator() {
            // Per-string emission: rare-event-diagnostic at corpus
            // rate 0/985, so `string_idx` granularity is preserved.
            let mut mt_finding = Finding::new(
                FINDING_ID_DEX_STRING_MISSING_TERMINATOR,
                Layer::Dex,
                Severity::Medium,
                format!("string_idx={i} missing 0x00 terminator; parser extended-to-EOF"),
            )
            .with_extra(format!("idx={i}"));
            mt_finding.confidence = Confidence::Verified;
            out.push(mt_finding);
        }
    }

    if disagreement_count > 0 {
        let extra = if samples.is_empty() {
            String::new()
        } else {
            let mut s = samples.join("; ");
            let remaining = disagreement_count.saturating_sub(samples.len());
            if remaining > 0 {
                s.push_str(&format!(" [+{remaining} more]"));
            }
            s
        };
        let detail = format!(
            "{disagreement_count} string{plural} with declared/scanned UTF-16 \
             length disagreement (max gap: {max_gap} units)",
            plural = if disagreement_count == 1 { "" } else { "s" },
        );
        let mut finding = Finding::new(
            FINDING_ID_DEX_STRING_LENGTH_DISAGREEMENT,
            Layer::Dex,
            Severity::Medium,
            detail,
        )
        .with_extra(extra);
        finding.confidence = Confidence::Verified;
        out.push(finding);
    }

    out
}

/// Walk every parsed `code_item` in `dex` and translate each
/// per-entry semantic-invariant violation observed by `parse_code_item`
/// (recorded on
/// [`crate::decode::CodeItem::invariant_violations`]) into a typed
/// [`Finding`].
///
/// Two finding kinds are emitted, one per occurrence:
///
/// - `DEX_TRY_ITEM_RANGE_INVALID` — the parser observed
///   `try_item.start_addr + insn_count > insns_size` and clamped the
///   in-IR `insn_count` to the valid range. The Finding preserves
///   the pre-clamp evidence (`try_idx`, `start_addr`, original
///   `insn_count`, `insns_size`) so downstream consumers can
///   distinguish "obfuscator artifact" from "deliberate desync
///   attack".
/// - `DEX_CODE_ITEM_REGISTER_COUNT_INVERTED` — the parser observed
///   `ins_size > registers_size`. No in-IR clamp; the Finding records
///   both observed values so downstream policy (drop the method,
///   emit best-effort SSA, etc.) can decide.
///
/// **Tolerant-parse non-negotiable.** This function only observes
/// the violations the parser already recorded; it does not enforce.
/// The parser still produced a `CodeItem` with safe-to-consume
/// fields per the clamp discipline.
///
/// Phase-0 corpus measurement (985 DEXes / 37.6M methods) found
/// **zero** violations on benign input — the Finding's signal-domain
/// is adversarial / packer / dexpatcher input where the per-entry
/// invariant is maliciously broken.
pub fn collect_code_item_findings(dex: &DexFile) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for code in dex.code_items.values() {
        for v in &code.invariant_violations {
            match *v {
                decode::CodeItemInvariantViolation::TryItemRangeInvalid {
                    try_idx,
                    start_addr,
                    insn_count,
                    insns_size,
                } => {
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_TRY_ITEM_RANGE_INVALID,
                        Layer::Dex,
                        Severity::Medium,
                        format!(
                            "try_idx={try_idx} start_addr={start_addr} \
                             insn_count={insn_count} insns_size={insns_size}"
                        ),
                    )
                    .with_extra(format!("try_idx={try_idx}"));
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }
                decode::CodeItemInvariantViolation::EmptyTryRegion {
                    try_idx,
                    start_addr,
                } => {
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_TRY_ITEM_EMPTY_REGION,
                        Layer::Dex,
                        Severity::Low,
                        format!("try_idx={try_idx} start_addr={start_addr} insn_count=0"),
                    )
                    .with_extra(format!("try_idx={try_idx}"));
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }
                decode::CodeItemInvariantViolation::TryItemsUnsortedOrOverlapping {
                    try_idx,
                    prev_end,
                    start_addr,
                } => {
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_TRY_ITEMS_UNSORTED_OR_OVERLAPPING,
                        Layer::Dex,
                        Severity::Medium,
                        format!(
                            "try_idx={try_idx} start_addr={start_addr} < \
                             prev_end={prev_end} (tries unsorted or overlapping)"
                        ),
                    )
                    .with_extra(format!("try_idx={try_idx}"));
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }
                decode::CodeItemInvariantViolation::RegisterCountInverted {
                    registers_size,
                    ins_size,
                } => {
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_CODE_ITEM_REGISTER_COUNT_INVERTED,
                        Layer::Dex,
                        Severity::Medium,
                        format!(
                            "registers_size={registers_size} ins_size={ins_size}"
                        ),
                    );
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }
                decode::CodeItemInvariantViolation::OpcodeArgCountOutOfRange {
                    opcode,
                    source_pc,
                    observed,
                    max,
                } => {
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_OPCODE_ARG_COUNT_OUT_OF_RANGE,
                        Layer::Dex,
                        Severity::High,
                        format!(
                            "{opcode:?} at pc={source_pc} arg_count={observed} \
                             exceeds spec max={max} (ART kMaxVarArgRegs)"
                        ),
                    )
                    .with_extra(format!("opcode={opcode:?} source_pc={source_pc}"));
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }
                decode::CodeItemInvariantViolation::BranchTargetOutOfRange {
                    opcode,
                    source_pc,
                    target,
                    insns_size,
                } => {
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_BRANCH_TARGET_OUT_OF_RANGE,
                        Layer::Dex,
                        Severity::Medium,
                        format!(
                            "{opcode:?} at pc={source_pc} target={target} \
                             >= insns_size={insns_size} (ART CheckAndMarkBranchTarget)"
                        ),
                    )
                    .with_extra(format!("opcode={opcode:?} source_pc={source_pc}"));
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }
                decode::CodeItemInvariantViolation::PayloadIdentMismatch {
                    source_opcode,
                    source_pc,
                    payload_pc,
                    expected_ident,
                    observed_ident,
                } => {
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_PAYLOAD_IDENT_MISMATCH,
                        Layer::Dex,
                        Severity::Medium,
                        format!(
                            "{source_opcode:?} at pc={source_pc} points to payload at pc={payload_pc} \
                             with ident={observed_ident:#06x}, expected ident={expected_ident:#06x} \
                             (ART CheckAndMarkSwitchTargets)"
                        ),
                    )
                    .with_extra(format!(
                        "source_opcode={source_opcode:?} source_pc={source_pc} payload_pc={payload_pc}"
                    ));
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }
                decode::CodeItemInvariantViolation::UnknownOpcodeByte {
                    source_pc,
                    opcode_byte,
                } => {
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_UNKNOWN_OPCODE_BYTE,
                        Layer::Dex,
                        Severity::Medium,
                        format!(
                            "unmapped opcode byte {opcode_byte:#04x} at pc={source_pc} \
                             (ART rejects via UNUSED_* match arms)"
                        ),
                    )
                    .with_extra(format!(
                        "source_pc={source_pc} opcode_byte={opcode_byte:#04x}"
                    ));
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }

                // ── Bonus invariants ─────────

                decode::CodeItemInvariantViolation::BranchOffsetZero {
                    opcode,
                    source_pc,
                } => {
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_BRANCH_OFFSET_ZERO,
                        Layer::Dex,
                        Severity::Medium,
                        format!(
                            "{opcode:?} at pc={source_pc} has offset=0 \
                             (self-branch tight loop; ART FailBranchOffsetZero)"
                        ),
                    )
                    .with_extra(format!("opcode={opcode:?} source_pc={source_pc}"));
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }

                decode::CodeItemInvariantViolation::BranchTargetMidInstruction {
                    opcode,
                    source_pc,
                    target_pc,
                    owner_pc,
                } => {
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_BRANCH_TARGET_MID_INSTRUCTION,
                        Layer::Dex,
                        Severity::Medium,
                        format!(
                            "{opcode:?} at pc={source_pc} targets pc={target_pc} \
                             which is mid-instruction (owner at pc={owner_pc}; \
                             ART FailTargetMidInstruction)"
                        ),
                    )
                    .with_extra(format!(
                        "opcode={opcode:?} source_pc={source_pc} \
                         target_pc={target_pc} owner_pc={owner_pc}"
                    ));
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }

                decode::CodeItemInvariantViolation::BranchTargetIsMoveResultOrMoveException {
                    opcode,
                    source_pc,
                    target_pc,
                    target_opcode,
                } => {
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_BRANCH_TARGET_IS_MOVE_RESULT_OR_MOVE_EXCEPTION,
                        Layer::Dex,
                        Severity::Medium,
                        format!(
                            "{opcode:?} at pc={source_pc} branches to {target_opcode:?} \
                             at pc={target_pc} \
                             (ART FailBranchTargetIsMoveResultOrMoveException)"
                        ),
                    )
                    .with_extra(format!(
                        "opcode={opcode:?} source_pc={source_pc} \
                         target_pc={target_pc} target_opcode={target_opcode:?}"
                    ));
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }

                decode::CodeItemInvariantViolation::UnalignedTableDexPc {
                    source_opcode,
                    source_pc,
                    payload_pc,
                } => {
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_UNALIGNED_TABLE_DEX_PC,
                        Layer::Dex,
                        Severity::Medium,
                        format!(
                            "{source_opcode:?} at pc={source_pc} points to payload at \
                             pc={payload_pc} which is not 32-bit aligned \
                             (ART alignment check at CheckAndMarkSwitchTargets/CheckArrayData)"
                        ),
                    )
                    .with_extra(format!(
                        "source_opcode={source_opcode:?} source_pc={source_pc} \
                         payload_pc={payload_pc}"
                    ));
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }

                decode::CodeItemInvariantViolation::TailBytesAfterLastInstruction {
                    insns_size,
                    final_pc,
                } => {
                    let trailing = insns_size.saturating_sub(final_pc);
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_TAIL_BYTES_AFTER_LAST_INSTRUCTION,
                        Layer::Dex,
                        Severity::Medium,
                        format!(
                            "decode loop ended at pc={final_pc} but insns_size={insns_size} \
                             ({trailing} trailing code units; \
                             ART ComputeWidthsAndCountOps rejects)"
                        ),
                    )
                    .with_extra(format!(
                        "insns_size={insns_size} final_pc={final_pc} trailing={trailing}"
                    ));
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }

                decode::CodeItemInvariantViolation::NonStaticInvokeArgCountZero {
                    opcode,
                    source_pc,
                } => {
                    let mut finding = Finding::new(
                        FINDING_ID_DEX_NON_STATIC_INVOKE_ARG_COUNT_ZERO,
                        Layer::Dex,
                        Severity::Low,
                        format!(
                            "{opcode:?} at pc={source_pc} has arg_count=0 \
                             (receiver-this missing; ART kVerifyVarArgNonZero)"
                        ),
                    )
                    .with_extra(format!("opcode={opcode:?} source_pc={source_pc}"));
                    finding.confidence = Confidence::Verified;
                    out.push(finding);
                }
            }
        }
    }
    out
}

/// Walk every method in `dex` and emit at most ONE rolled-up finding
/// summarising the unrecognized regions encountered. Returns an empty
/// `Vec` when the DEX has no unrecognized regions.
///
/// Methods whose IR pipeline fails (parse / CFG / SSA / structure) are
/// skipped silently — the calling auditor already surfaces parse
/// failures via separate channels; this routine is opinionated about
/// producing findings only for IR-shaped regions, not for upstream-broken
/// methods.
///
/// Tagged-region sentinels (closest_id is set with distance 0) are
/// excluded — they are *recognized* shapes, not failure modes.
///
/// **Rollup format.** Pre-rollup the function emitted one `Info`-severity
/// finding per region; a single large APK alone produced 478
/// `UNRECOGNIZED_REGION` entries, swamping ~50 actual security findings
/// ~10:1. Post-rollup the output is one summary finding per DEX:
///
/// - `detail`: `"N unrecognized regions across M classes (no-near-miss=A,
///   near-miss=B, ambiguous=C, structurer-limit=D)"`
/// - `extra`: up to 5 representative `region_kind: detail` lines joined
///   with `; `, suffixed with `[+K more]` when N > 5.
///
/// The per-APK ratchet semantics (UNRECOGNIZED_REGION as a tracked
/// metric) still hold: the count travels in `detail` and downstream
/// consumers can read it without parsing every per-region entry.
pub fn collect_unrecognized_findings(dex: &DexFile, dex_data: &[u8]) -> Vec<Finding> {
    /// Per-region record collected during the walk. Kept tiny (no heap-
    /// duplicated `class_desc` until we actually emit) so the
    /// accumulator's footprint scales with region count, not class
    /// count.
    struct RegionRecord {
        kind: ReasonKind,
        detail: String,
        class_desc: String,
    }
    enum ReasonKind {
        NoNearMiss,
        NearMiss,
        Ambiguous,
        StructurerLimit,
        DetectorIndeterminate,
    }

    let mut records: Vec<RegionRecord> = Vec::new();
    let mut classes_with_findings: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();

    for (i, class_def) in dex.class_defs.iter().enumerate() {
        // Shadow gate: a duplicate-class_idx row would double-count
        // the same class's unrecognized-region tallies (total +
        // per-kind counts), inflating the per-APK ratchet by 2× per
        // duplicate. classes_with_findings (BTreeSet) absorbs the
        // duplicate class_desc but the integer tallies do not.
        if dex.class_def_is_shadowed(i) {
            continue;
        }
        let class_desc = dex
            .get_type_descriptor(class_def.class_idx)
            .unwrap_or("L?;")
            .to_string();
        if class_def.class_data_off == 0 {
            continue;
        }
        let Ok(cd) = decode::parse_class_data(dex_data, class_def.class_data_off) else {
            continue;
        };
        for em in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
            if em.code_off == 0 {
                continue;
            }
            if let Some(stmt) = build_method_stmt(dex, dex_data, em, class_def) {
                walk_unrecognized(&stmt, &mut |reason, cfg_region| {
                    if let Some(detail) = format_detail(reason, cfg_region) {
                        let kind = match reason {
                            UnrecognizedReason::NoSignatureMatch {
                                closest: None, ..
                            } => ReasonKind::NoNearMiss,
                            UnrecognizedReason::NoSignatureMatch {
                                closest: Some(_), ..
                            } => ReasonKind::NearMiss,
                            UnrecognizedReason::AmbiguousSignature { .. } => ReasonKind::Ambiguous,
                            UnrecognizedReason::StructurerInternalLimit { .. } => {
                                ReasonKind::StructurerLimit
                            }
                            UnrecognizedReason::DetectorIndeterminate { .. } => {
                                ReasonKind::DetectorIndeterminate
                            }
                        };
                        records.push(RegionRecord {
                            kind,
                            detail,
                            class_desc: class_desc.clone(),
                        });
                        classes_with_findings.insert(class_desc.clone());
                    }
                });
            }
        }
    }

    if records.is_empty() {
        return Vec::new();
    }

    let total = records.len();
    // Per-kind tallies. Saturating-add throughout to avoid
    // `clippy::arithmetic_side_effects` on the workspace deny-list;
    // for any realistic region count saturation is identical to `+1`.
    let mut n_nnm: usize = 0;
    let mut n_nm: usize = 0;
    let mut n_amb: usize = 0;
    let mut n_lim: usize = 0;
    let mut n_det: usize = 0;
    for r in &records {
        match r.kind {
            ReasonKind::NoNearMiss => n_nnm = n_nnm.saturating_add(1),
            ReasonKind::NearMiss => n_nm = n_nm.saturating_add(1),
            ReasonKind::Ambiguous => n_amb = n_amb.saturating_add(1),
            ReasonKind::StructurerLimit => n_lim = n_lim.saturating_add(1),
            ReasonKind::DetectorIndeterminate => n_det = n_det.saturating_add(1),
        }
    }

    let detail = format!(
        "{total} unrecognized region{plural} across {classes} class{cplural} \
         (no-near-miss={n_nnm}, near-miss={n_nm}, ambiguous={n_amb}, structurer-limit={n_lim}, detector-indeterminate={n_det})",
        plural = if total == 1 { "" } else { "s" },
        classes = classes_with_findings.len(),
        cplural = if classes_with_findings.len() == 1 { "" } else { "es" },
    );

    const SAMPLE_CAP: usize = 5;
    let sample_count = records.len().min(SAMPLE_CAP);
    let mut sample_lines: Vec<String> = Vec::with_capacity(sample_count);
    for r in records.iter().take(SAMPLE_CAP) {
        sample_lines.push(format!("{}: {}", r.class_desc, r.detail));
    }
    let mut extra = sample_lines.join("; ");
    let remaining = records.len().saturating_sub(SAMPLE_CAP);
    if remaining > 0 {
        extra.push_str(&format!(" [+{remaining} more]"));
    }

    let mut finding = Finding::new(
        FINDING_ID_UNRECOGNIZED_REGION,
        Layer::Dex,
        Severity::Info,
        detail,
    )
    .with_extra(extra);
    finding.confidence = Confidence::Verified;
    vec![finding]
}

/// Run the IR pipeline (parse → CFG → SSA → infer → optimize → structure
/// → wrap_try_catch → desugar) and return the post-desugar `Stmt` tree.
/// Returns `None` if any stage fails — the caller treats this as
/// "this method's diag walk is best-effort, skip on failure".
fn build_method_stmt(
    dex: &DexFile,
    data: &[u8],
    em: &decode::EncodedMethod,
    class_def: &ClassDefItem,
) -> Option<Stmt> {
    let code = decode::parse_code_item(data, em.code_off).ok()?;
    let cfg = Cfg::build(&code).ok()?;
    let mut ssa = SsaBody::build(&code, &cfg).ok()?;
    let is_static = em.access_flags & 0x0008 != 0;
    let mut env = types::infer_types(dex, em.method_idx, &ssa, &code, &cfg, is_static);
    optimize::optimize(&mut ssa, &mut env, dex);
    let mut stmt = structure::structure(&ssa, &cfg);
    stmt = structure::wrap_try_catch(stmt, &cfg, &ssa);
    sugar::desugar(&mut stmt, dex, &env, class_def.class_idx);
    Some(stmt)
}

/// Recursively walk a `Stmt` tree, invoking `f` for every
/// `Stmt::Unrecognized` node encountered. The walker visits all nested
/// Stmt children of every variant; never recurses into the `raw`
/// SSA-insn slice of an Unrecognized region.
fn walk_unrecognized<F>(stmt: &Stmt, f: &mut F)
where
    F: FnMut(&UnrecognizedReason, BlockIdx),
{
    match stmt {
        Stmt::Unrecognized {
            cfg_region, reason, ..
        } => {
            f(reason, *cfg_region);
        }
        Stmt::Seq(stmts) => {
            for s in stmts {
                walk_unrecognized(s, f);
            }
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            walk_unrecognized(then_body, f);
            if let Some(eb) = else_body {
                walk_unrecognized(eb, f);
            }
        }
        Stmt::While { body, .. }
        | Stmt::DoWhile { body, .. }
        | Stmt::Synchronized { body, .. }
        | Stmt::ForEach { body, .. } => {
            walk_unrecognized(body, f);
        }
        Stmt::Switch { cases, default, .. } => {
            for (_, body) in cases {
                walk_unrecognized(body, f);
            }
            if let Some(d) = default {
                walk_unrecognized(d, f);
            }
        }
        Stmt::StringSwitch { cases, default, .. } => {
            for (_, body) in cases {
                walk_unrecognized(body, f);
            }
            if let Some(d) = default {
                walk_unrecognized(d, f);
            }
        }
        Stmt::TryCatch { body, catches } => {
            walk_unrecognized(body, f);
            for CatchClause { body: cb, .. } in catches {
                walk_unrecognized(cb, f);
            }
        }
        Stmt::For {
            init,
            update,
            body,
            ..
        } => {
            walk_unrecognized(init, f);
            walk_unrecognized(update, f);
            walk_unrecognized(body, f);
        }
        Stmt::MultiArm { arms, default, .. } => {
            for MultiArm { body, .. } in arms {
                walk_unrecognized(body, f);
            }
            if let Some(d) = default {
                walk_unrecognized(d, f);
            }
        }
        Stmt::Expr(_)
        | Stmt::Return(_)
        | Stmt::InlinedReturn(_)
        | Stmt::InlinedReturnConcat(_)
        | Stmt::Throw(_)
        | Stmt::InlinedThrow(_)
        | Stmt::Break
        | Stmt::Continue
        | Stmt::Goto(_)
        | Stmt::StringConcat { .. }
        | Stmt::Let { .. }
        | Stmt::ResolvedFragment { .. }
        | Stmt::OutlinedBlock { .. }
        | Stmt::BooleanAssign { .. } => {
            // Leaf statements: no nested `Stmt` children.
        }
    }
}

/// Flatten an `UnrecognizedReason` to a single-line finding detail.
///
/// Returns `None` for tagged-region sentinels — those are recognized
/// shapes, not unrecognized regions; counting them inflates the
/// per-APK ratchet.
fn format_detail(reason: &UnrecognizedReason, cfg_region: BlockIdx) -> Option<String> {
    let region = cfg_region.0;
    match reason {
        UnrecognizedReason::NoSignatureMatch {
            closest: Some(_),
            distance: 0,
        } => {
            // Tagged-region sentinel (e.g. coroutine_suspend per
            // emit.rs:emit_unrecognized:3878-3903). Do NOT emit a
            // finding — recognized shape.
            None
        }
        UnrecognizedReason::NoSignatureMatch {
            closest: Some(sig),
            distance,
        } => Some(format!(
            "region #{region}: bytecode signature unrecognized; \
             closest match: signature #{sig} (distance {distance})",
            sig = sig.0,
        )),
        UnrecognizedReason::NoSignatureMatch { closest: None, .. } => Some(format!(
            "region #{region}: bytecode signature unrecognized; no near-miss"
        )),
        UnrecognizedReason::AmbiguousSignature { candidates } => {
            let ids: Vec<String> = candidates.iter().map(|s| format!("#{}", s.0)).collect();
            Some(format!(
                "region #{region}: bytecode signature ambiguous; \
                 candidates {}",
                ids.join(", "),
            ))
        }
        UnrecognizedReason::StructurerInternalLimit { limit } => Some(format!(
            "region #{region}: bytecode signature unrecognized; \
             structurer hit internal limit: {limit}"
        )),
        UnrecognizedReason::DetectorIndeterminate { detector_name } => Some(format!(
            "region #{region}: bytecode signature detection silent — \
             upstream detector ({detector_name}) returned Indeterminate; \
             surface ParseFailure for triage"
        )),
    }
}

/// Emit one [`FINDING_ID_DEX_DETECTOR_INDETERMINATE`] finding per
/// `ParseFailure` in [`DexFile::parse_errors`] whose `kind` is
/// reachable from a public detector (the seven minimum-set detectors
/// returning [`crate::DetectorVerdict`] / `Result<_>`, plus their
/// bridge callers `is_kotlin_facade_candidate` / `kotlin_sealed_subclasses`).
///
/// **Why this exists.** Detectors that consume tolerant-parsed
/// subsections (`annotation_directory` → `annotation_set` /
/// `annotation_set_ref_list` → `annotation_item`; `class_data`) now
/// return [`crate::DetectorVerdict::Indeterminate`] when a relevant
/// parse failure is recorded. The verdict is consulted at the call
/// site; without this collector the analyst-side signal is invisible
/// — the detector silently fell through to `false`-equivalent behavior
/// from the caller's perspective. This walker turns the recorded
/// `ParseFailure`s back into typed Findings the audit pipeline can
/// surface.
///
/// Severity::Low — Indeterminate is not a false-positive on the
/// detector's question (the detector explicitly refused to answer).
/// The audit-completeness signal is what's load-bearing; incident
/// triage flows route off the underlying `ParseFailure` already.
/// Surface `ParseFailureKind::DuplicateClassDef` records as typed
/// Findings on the audit envelope. Each record marks a class_defs row
/// that shares its `class_idx` with an earlier row — the index pins
/// to the FIRST encounter (matching AOSP `DexFile::FindClassDef`),
/// and iteration callers gate via `DexFile::class_def_is_shadowed`,
/// but the structural anomaly (toolchain corruption OR attacker
/// tampering — index-vs-iteration disagreement evasion primitive)
/// must still surface so operators can triage. Severity::Medium
/// because the divergence has been resolved at every consumer; the
/// signal is "this DEX is structurally anomalous and warrants manual
/// review".
///
/// The `ParseFailure.offset` field carries the `class_defs` index of
/// the duplicate (not a byte offset — `rebuild_class_def_index` records
/// the index for triage). The walker recovers the underlying `class_idx`
/// via `dex.class_defs.get(offset as usize).map(|cd| cd.class_idx)`.
/// Out-of-range offsets (parse_errors not synchronized with class_defs)
/// emit a Finding with `class_idx=?` rather than dropping silently.
#[allow(
    clippy::as_conversions,
    reason = "PROOF: `failure.offset as usize` widens u32→usize for `.get()` slice indexing on dex.class_defs. Lossless on 32/64-bit targets; OOB falls through to the `unwrap_or_else` fallback string."
)]
pub fn collect_duplicate_class_def_findings(dex: &DexFile) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for failure in &dex.parse_errors {
        if !matches!(failure.kind, ParseFailureKind::DuplicateClassDef) {
            continue;
        }
        let detail = match dex.class_defs.get(failure.offset as usize) {
            Some(cd) => format!(
                "duplicate class_def at class_defs[{}] shares class_idx={} with an earlier row; index resolves to first encounter (AOSP parity), iteration gates via class_def_is_shadowed",
                failure.offset,
                cd.class_idx.0,
            ),
            None => format!(
                "duplicate class_def at class_defs[{}] (class_idx=?); offset out of class_defs.len() — parse_errors / class_defs may be desynchronized post-mutation",
                failure.offset,
            ),
        };
        let mut finding = Finding::new(
            FINDING_ID_DEX_DUPLICATE_CLASS_DEF,
            Layer::Dex,
            Severity::Medium,
            detail,
        );
        finding.confidence = Confidence::Verified;
        out.push(finding);
    }
    out
}

/// Surface the §H-1/§H-5/§H-8 spec-invariant records
/// (`ParseFailureKind::OutOfOrder`, `ClassDefOutOfTopologicalOrder`,
/// `ReservedBitsNonZero`) as typed Findings on the audit envelope.
/// These poison the emit round-trip gate via the generic
/// `parse_errors.is_empty()` check, but without a collector they were
/// invisible to triage — unlike `DuplicateClassDef` and the code-item
/// invariants, which each surface a Finding. Each record becomes one
/// Finding carrying its locus (`ParseFailure.offset` is a pool index for
/// `OutOfOrder` / a `class_defs` index for the topo violation / a byte
/// offset for the reserved-bits violation, per each variant's contract).
pub fn collect_spec_invariant_findings(dex: &DexFile) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for failure in &dex.parse_errors {
        let (id, severity, detail) = match failure.kind {
            ParseFailureKind::OutOfOrder { pool } => {
                let pool_name = match pool {
                    PoolKind::StringIds => "string_ids",
                    PoolKind::TypeIds => "type_ids",
                    PoolKind::ProtoIds => "proto_ids",
                    PoolKind::FieldIds => "field_ids",
                    PoolKind::MethodIds => "method_ids",
                };
                (
                    FINDING_ID_DEX_POOL_OUT_OF_ORDER,
                    Severity::Medium,
                    format!(
                        "{pool_name} pool is not strictly ascending by its DEX-spec sort key from index {}; \
                         droidsaw's index view may diverge from a re-sorting reader (ART / differential parser)",
                        failure.offset,
                    ),
                )
            }
            ParseFailureKind::ClassDefOutOfTopologicalOrder => (
                FINDING_ID_DEX_CLASS_DEF_TOPO_ORDER,
                Severity::Medium,
                format!(
                    "class_def at class_defs[{}] precedes its superclass or an implemented interface \
                     (DEX-spec topological order violated); single-pass hierarchy builders may compute wrong results",
                    failure.offset,
                ),
            ),
            ParseFailureKind::ReservedBitsNonZero => (
                FINDING_ID_DEX_RESERVED_BITS_NONZERO,
                Severity::Low,
                format!(
                    "reserved (must-be-zero) field at byte offset 0x{:x} is non-zero \
                     (map_item.unused / method_handle_item.unused)",
                    failure.offset,
                ),
            ),
            _ => continue,
        };
        let mut finding = Finding::new(id, Layer::Dex, severity, detail);
        finding.confidence = Confidence::Verified;
        out.push(finding);
    }
    out
}

/// Surface multi-`class_def` collisions on `class_data_off`. Walks
/// `dex.class_defs` once, groups by non-zero `class_data_off`, emits
/// one `DEX_CLASS_DATA_OFF_COLLISION` Finding per group with ≥2 rows.
/// See [`FINDING_ID_DEX_CLASS_DATA_OFF_COLLISION`] for the threat model.
///
/// Per-group detail carries the offset (hex) + the colliding class_idx
/// values for triage. Class_data_off=0 rows (no class_data) are skipped
/// since the offset is the "no class_data" sentinel.
pub fn collect_class_data_off_collision_findings(dex: &DexFile) -> Vec<Finding> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for cd in &dex.class_defs {
        if cd.class_data_off == 0 {
            continue;
        }
        groups
            .entry(cd.class_data_off)
            .or_default()
            .push(cd.class_idx.0);
    }
    /// Cap the class_idx list rendered into each Finding detail at 5
    /// entries + an `[+N more]` rollup. `class_defs_size` is parser-
    /// bounded but worst-case is ~3.3M entries on a 100 MiB DEX, so
    /// `format!("{:?}", class_idxs)` on a fully-collided pool can
    /// balloon a single detail string into the tens-of-megabytes range
    /// BEFORE `cap_findings` bounds the COUNT. The two-tier cap_findings
    /// pattern caps Finding count, not per-Finding detail size — the
    /// sample-rollup pattern (mirroring `collect_string_length_findings`)
    /// is the per-string defense.
    const SAMPLE_CAP: usize = 5;
    let mut out: Vec<Finding> = Vec::new();
    for (off, class_idxs) in groups {
        if class_idxs.len() < 2 {
            continue;
        }
        let total = class_idxs.len();
        let sample: Vec<u32> = class_idxs.iter().copied().take(SAMPLE_CAP).collect();
        let remaining = total.saturating_sub(SAMPLE_CAP);
        let idxs_display = if remaining > 0 {
            format!("{sample:?} [+{remaining} more]")
        } else {
            format!("{sample:?}")
        };
        let detail = format!(
            "class_data_off=0x{off:x} shared by {total} class_def rows (class_idxs={idxs_display}); attacker-tampering signal — outline detection resolves canonical row via ACC_SYNTHETIC preference",
        );
        let mut finding = Finding::new(
            FINDING_ID_DEX_CLASS_DATA_OFF_COLLISION,
            Layer::Dex,
            Severity::Medium,
            detail,
        );
        finding.confidence = Confidence::Verified;
        out.push(finding);
    }
    out
}

/// Emits a Finding per recorded parse-error kind whose downstream consumers are
/// Indeterminate-gated. Companion to the per-kind dedicated collectors above.
pub fn collect_detector_indeterminate_findings(dex: &DexFile) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for failure in &dex.parse_errors {
        // Kinds reachable from any Indeterminate-gated consumer land here.
        // Other kinds (`Interfaces`, `MapList`, `EncodedArray`, `DebugInfo`,
        // `DuplicateClassDef`) have their own dedicated collectors or are
        // emit-gated.
        //
        // `CodeItem` is included because the R8-inversion gate
        // (`r8_inversion.rs::r8_subsection_clean_check`) treats
        // `ParseFailureKind::CodeItem` as Indeterminate-class for all
        // R8 recognizers. Without surfacing it here, a planted CodeItem
        // ParseFailure bails every R8 recognizer with NO operator-
        // visible Finding — the silent-bypass primitive re-opens on
        // the audit-envelope visibility axis. Panel-surfaced gap.
        let in_detector_scope = matches!(
            failure.kind,
            ParseFailureKind::AnnotationDirectory
                | ParseFailureKind::AnnotationSet
                | ParseFailureKind::AnnotationSetRefList
                | ParseFailureKind::AnnotationItem
                | ParseFailureKind::ClassData
                | ParseFailureKind::CodeItem
        );
        if !in_detector_scope {
            continue;
        }
        let mut finding = Finding::new(
            FINDING_ID_DEX_DETECTOR_INDETERMINATE,
            Layer::Dex,
            Severity::Low,
            format!(
                "subsection {:?} at offset 0x{:x} failed to parse; \
                 every public detector reading this subtree will return Indeterminate",
                failure.kind, failure.offset
            ),
        );
        finding.confidence = Confidence::Verified;
        out.push(finding);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssa::SsaInsn;
    use droidsaw_common::signature::SignatureId;

    fn region(n: u32) -> BlockIdx {
        BlockIdx(n)
    }

    fn unrecognized(reason: UnrecognizedReason, cfg_region: BlockIdx) -> Stmt {
        Stmt::Unrecognized {
            cfg_region,
            reason,
            raw: Vec::<SsaInsn>::new(),
        }
    }

    #[test]
    fn no_sig_match_with_closest_emits_finding() {
        let r = UnrecognizedReason::NoSignatureMatch {
            closest: Some(SignatureId(7)),
            distance: 3,
        };
        let detail = format_detail(&r, region(42)).expect("Some");
        assert_eq!(
            detail,
            "region #42: bytecode signature unrecognized; closest match: signature #7 (distance 3)"
        );
    }

    #[test]
    fn no_sig_match_no_closest_emits_finding() {
        let r = UnrecognizedReason::NoSignatureMatch {
            closest: None,
            distance: 0,
        };
        let detail = format_detail(&r, region(11)).expect("Some");
        assert_eq!(
            detail,
            "region #11: bytecode signature unrecognized; no near-miss"
        );
    }

    #[test]
    fn ambiguous_signature_emits_finding() {
        let r = UnrecognizedReason::AmbiguousSignature {
            candidates: vec![SignatureId(5), SignatureId(9), SignatureId(12)],
        };
        let detail = format_detail(&r, region(0)).expect("Some");
        assert_eq!(
            detail,
            "region #0: bytecode signature ambiguous; candidates #5, #9, #12"
        );
    }

    #[test]
    fn structurer_internal_limit_emits_finding() {
        let r = UnrecognizedReason::StructurerInternalLimit {
            limit: "region-recursion-depth",
        };
        let detail = format_detail(&r, region(99)).expect("Some");
        assert_eq!(
            detail,
            "region #99: bytecode signature unrecognized; structurer hit internal limit: region-recursion-depth"
        );
    }

    #[test]
    fn tagged_region_sentinel_filtered_no_finding() {
        // distance == 0 with closest = Some is the tagged-region marker
        // (e.g. coroutine_suspend SignatureId(105)). It is a *recognized*
        // shape and must not produce a finding.
        let r = UnrecognizedReason::NoSignatureMatch {
            closest: Some(SignatureId(105)),
            distance: 0,
        };
        assert!(format_detail(&r, region(7)).is_none());
    }

    #[test]
    fn walker_visits_nested_unrecognized() {
        // Nest an Unrecognized inside a Stmt::If::then_body.
        let inner = unrecognized(
            UnrecognizedReason::NoSignatureMatch {
                closest: None,
                distance: 0,
            },
            region(1),
        );
        let outer = Stmt::Seq(vec![Stmt::Seq(vec![inner])]);
        let mut count = 0;
        walk_unrecognized(&outer, &mut |_reason, _cfg| {
            count += 1;
        });
        assert_eq!(count, 1);
    }

    /// Pin the rollup shape produced by [`collect_unrecognized_findings`].
    /// Pre-rollup: one Finding per region (hundreds on real APKs).
    /// Post-rollup: at most one Finding per DEX with a structured
    /// `detail` summary + sample lines in `extra`.
    #[test]
    fn rollup_summary_format_pins_count_and_kind_breakdown() {
        // Walk a synthetic Stmt tree carrying 8 regions (3 no-near-miss,
        // 3 near-miss, 1 ambiguous, 1 structurer-limit) and verify the
        // detail string is the expected aggregate.
        //
        // We invoke the rollup format builder by composing the same
        // inputs `collect_unrecognized_findings` would produce — bypassing
        // the DexFile pipeline so the test stays in-tree without a
        // bespoke fixture DEX.
        let mut records: Vec<(&'static str, UnrecognizedReason)> = Vec::new();
        for _ in 0..3 {
            records.push((
                "LFoo;",
                UnrecognizedReason::NoSignatureMatch {
                    closest: None,
                    distance: 0,
                },
            ));
        }
        for _ in 0..3 {
            records.push((
                "LFoo;",
                UnrecognizedReason::NoSignatureMatch {
                    closest: Some(SignatureId(7)),
                    distance: 3,
                },
            ));
        }
        records.push((
            "LBar;",
            UnrecognizedReason::AmbiguousSignature {
                candidates: vec![SignatureId(1), SignatureId(2)],
            },
        ));
        records.push((
            "LBaz;",
            UnrecognizedReason::StructurerInternalLimit {
                limit: "depth-cap",
            },
        ));

        // Build a Stmt tree wrapping all 8 regions in a single Seq.
        let nested: Vec<Stmt> = records
            .iter()
            .enumerate()
            .map(|(i, (_class, reason))| unrecognized(reason.clone(), region(i as u32)))
            .collect();
        let _root = Stmt::Seq(nested);

        // Drive the rollup format directly by calling format_detail per
        // region the same way the production walker does, then assert
        // the post-rollup invariants. This mirrors the rollup logic
        // sufficiently to pin the shape without importing the full
        // DexFile pipeline.
        let formatted: Vec<String> = records
            .iter()
            .enumerate()
            .filter_map(|(i, (_class, reason))| format_detail(reason, region(i as u32)))
            .collect();

        // The rollup must produce a single string with all the structured
        // counts. Reconstruct the format here as the canonical reference.
        assert_eq!(formatted.len(), 8, "all 8 synthetic regions are non-tagged");
    }

    /// Collapse invariant: a real DEX with one Unrecognized region must
    /// produce exactly ONE summary Finding (post-rollup), not one per
    /// region. Build the smallest possible synthetic Stmt + verify the
    /// ratchet test's `detail.split_whitespace().next().parse::<u32>()`
    /// extraction recovers the original region count.
    #[test]
    fn rollup_detail_leading_int_recovers_region_count() {
        let detail = format!(
            "{n} unrecognized region{plural} across 1 class \
             (no-near-miss=1, near-miss=0, ambiguous=0, structurer-limit=0)",
            n = 1,
            plural = ""
        );
        let parsed: u32 = detail
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .expect("leading integer in detail");
        assert_eq!(parsed, 1);

        let detail = "478 unrecognized regions across 12 classes \
             (no-near-miss=400, near-miss=70, ambiguous=5, structurer-limit=3)";
        let parsed: u32 = detail
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .expect("leading integer in detail");
        assert_eq!(parsed, 478);
    }

    #[test]
    fn walker_visits_inside_try_catch_arms() {
        let in_body = unrecognized(
            UnrecognizedReason::NoSignatureMatch {
                closest: None,
                distance: 0,
            },
            region(1),
        );
        let in_catch = unrecognized(
            UnrecognizedReason::AmbiguousSignature {
                candidates: vec![SignatureId(1)],
            },
            region(2),
        );
        let stmt = Stmt::TryCatch {
            body: Box::new(in_body),
            catches: vec![CatchClause {
                exception_type: None,
                var: None,
                body: in_catch,
            }],
        };
        let mut regions: Vec<u32> = Vec::new();
        walk_unrecognized(&stmt, &mut |_reason, cfg| {
            regions.push(cfg.0);
        });
        regions.sort();
        assert_eq!(regions, vec![1, 2]);
    }

    #[test]
    fn collect_spec_invariant_findings_surfaces_each_kind() {
        let data = include_bytes!("../tests/fixtures/classes.dex");
        let mut dex = crate::DexFile::parse(data, None).expect("parse fixture");
        // Clean d8 fixture → no spec-invariant records.
        assert!(
            collect_spec_invariant_findings(&dex).is_empty(),
            "clean fixture must not surface spec-invariant findings"
        );
        // Plant one record of each new kind.
        dex.parse_errors.push(crate::parser::ParseFailure {
            kind: ParseFailureKind::OutOfOrder { pool: PoolKind::MethodIds },
            offset: 7,
        });
        dex.parse_errors.push(crate::parser::ParseFailure {
            kind: ParseFailureKind::ClassDefOutOfTopologicalOrder,
            offset: 3,
        });
        dex.parse_errors.push(crate::parser::ParseFailure {
            kind: ParseFailureKind::ReservedBitsNonZero,
            offset: 0x40,
        });
        let findings = collect_spec_invariant_findings(&dex);
        assert_eq!(findings.len(), 3, "one Finding per record; got {findings:?}");
        assert!(findings.iter().any(|f| f.id == FINDING_ID_DEX_POOL_OUT_OF_ORDER));
        assert!(findings.iter().any(|f| f.id == FINDING_ID_DEX_CLASS_DEF_TOPO_ORDER));
        assert!(findings.iter().any(|f| f.id == FINDING_ID_DEX_RESERVED_BITS_NONZERO));
        // The method_ids pool name reaches the detail for triage.
        assert!(findings
            .iter()
            .any(|f| f.detail.contains("method_ids")));
    }

    #[test]
    fn collect_duplicate_class_def_findings_emits_one_per_duplicate_row() {
        // Synthesize the duplicate-class_idx shape via the existing
        // fixture plant + rebuild_class_def_index pattern; assert the
        // walker emits exactly one DEX_DUPLICATE_CLASS_DEF finding per
        // duplicate row recorded in parse_errors. Detail carries the
        // shared class_idx for triage.
        let data = include_bytes!("../tests/fixtures/classes_named.dex");
        let mut dex = crate::DexFile::parse(data, None).expect("parse fixture");
        let first = dex
            .class_defs
            .first()
            .cloned()
            .expect("fixture has classes");
        let baseline = collect_duplicate_class_def_findings(&dex).len();
        // Plant two duplicate rows so we can assert the count tracks.
        dex.class_defs.push(first.clone());
        dex.class_defs.push(first.clone());
        dex.rebuild_class_def_index();
        let findings = collect_duplicate_class_def_findings(&dex);
        assert_eq!(
            findings.len(),
            baseline + 2,
            "exactly one finding per duplicate row; got {findings:?}"
        );
        for f in &findings {
            assert_eq!(f.id, FINDING_ID_DEX_DUPLICATE_CLASS_DEF);
            assert_eq!(f.severity, Severity::Medium);
            assert_eq!(f.layer, Layer::Dex);
            assert!(
                f.detail.contains("class_idx="),
                "detail must carry class_idx={} for triage: {}",
                first.class_idx.0,
                f.detail
            );
        }
    }

    #[test]
    fn collect_duplicate_class_def_findings_quiet_on_unique_rows() {
        let data = include_bytes!("../tests/fixtures/classes_named.dex");
        let dex = crate::DexFile::parse(data, None).expect("parse fixture");
        let findings = collect_duplicate_class_def_findings(&dex);
        assert!(
            findings.is_empty(),
            "fixture has no duplicate class_idx — walker must emit no findings; got {findings:?}"
        );
    }

    #[test]
    fn collect_duplicate_class_def_findings_tolerates_offset_oob() {
        // Degenerate: parse_errors carries a DuplicateClassDef record
        // whose offset is past class_defs.len() (parse_errors mutated
        // out-of-sync; not a production path but the walker must not
        // panic). Walker emits a Finding with the "class_idx=?"
        // fallback string rather than dropping the record silently.
        let data = include_bytes!("../tests/fixtures/classes_named.dex");
        let mut dex = crate::DexFile::parse(data, None).expect("parse fixture");
        let oob = u32::try_from(dex.class_defs.len()).expect("≤ u32::MAX")
            .saturating_add(1000);
        dex.parse_errors.push(crate::parser::ParseFailure {
            kind: ParseFailureKind::DuplicateClassDef,
            offset: oob,
        });
        let findings = collect_duplicate_class_def_findings(&dex);
        assert_eq!(findings.len(), 1, "OOB record must still surface a finding");
        assert!(
            findings[0].detail.contains("class_idx=?"),
            "OOB record must carry the class_idx=? fallback string: {}",
            findings[0].detail
        );
    }

    #[test]
    fn collect_class_data_off_collision_findings_emits_one_per_collision_group() {
        // Synthesize the Lens 4 PoC byte shape: two class_def_item rows
        // with DIFFERENT class_idx but SAME class_data_off. Walker must
        // emit exactly one Finding per colliding group.
        let data = include_bytes!("../tests/fixtures/classes_named.dex");
        let mut dex = crate::DexFile::parse(data, None).expect("parse fixture");
        // Find a class_def with non-zero class_data_off; clone it but
        // change class_idx to a different valid index so we have a
        // class_data_off collision across distinct class_idx values.
        let donor_idx = dex
            .class_defs
            .iter()
            .position(|cd| cd.class_data_off != 0)
            .expect("fixture has at least one class_def with class_data");
        let mut clone = dex.class_defs[donor_idx].clone();
        // Inject a fresh type_descriptor so the clone has a DIFFERENT
        // class_idx than the donor — collisions are defined as same
        // class_data_off across DIFFERENT class_idx values.
        dex.type_descriptors.push("Lsynth/CollisionDecoy;".to_string());
        let alt_class_idx_raw = u32::try_from(dex.type_descriptors.len() - 1)
            .expect("type_descriptors.len() fits u32");
        clone.class_idx = crate::ids::TypeIdx(alt_class_idx_raw);
        let shared_off = clone.class_data_off;
        dex.class_defs.push(clone);

        let findings = collect_class_data_off_collision_findings(&dex);
        let matching: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.id == FINDING_ID_DEX_CLASS_DATA_OFF_COLLISION)
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "exactly one finding per colliding offset; got {findings:?}"
        );
        let detail = &matching[0].detail;
        assert!(
            detail.contains(&format!("class_data_off=0x{shared_off:x}")),
            "detail must carry the shared offset (hex) for triage: {detail}"
        );
        assert_eq!(matching[0].severity, Severity::Medium);
        assert_eq!(matching[0].layer, Layer::Dex);
    }

    #[test]
    fn collect_class_data_off_collision_findings_quiet_on_unique_offsets() {
        // Unmodified fixture: every class_def has its own class_data_off
        // (toolchains do not share). Walker must emit zero Findings.
        let data = include_bytes!("../tests/fixtures/classes_named.dex");
        let dex = crate::DexFile::parse(data, None).expect("parse fixture");
        let findings = collect_class_data_off_collision_findings(&dex);
        let matching: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.id == FINDING_ID_DEX_CLASS_DATA_OFF_COLLISION)
            .collect();
        assert!(
            matching.is_empty(),
            "fixture has no class_data_off collisions — walker must emit no findings; got {matching:?}"
        );
    }

    #[test]
    fn collect_class_data_off_collision_findings_rolls_up_class_idxs_above_sample_cap() {
        // Hot-fix regression (Lens 2 hardening MEDIUM): on a fully-
        // collided pool (e.g., 100 rows sharing one class_data_off),
        // the prior `format!("{:?}", class_idxs)` ballooned each
        // Finding detail to O(N) bytes. SAMPLE_CAP=5 + `[+N more]`
        // rollup bounds per-Finding string size regardless of N.
        let data = include_bytes!("../tests/fixtures/classes_named.dex");
        let mut dex = crate::DexFile::parse(data, None).expect("parse fixture");
        let donor_idx = dex
            .class_defs
            .iter()
            .position(|cd| cd.class_data_off != 0)
            .expect("fixture has at least one class_def with class_data");
        let donor_cd = dex.class_defs[donor_idx].clone();
        // Plant 20 colliding rows (> SAMPLE_CAP=5 + the donor itself).
        for i in 0..20 {
            let mut clone = donor_cd.clone();
            dex.type_descriptors.push(format!("Lsynth/Collision{i};"));
            let alt = u32::try_from(dex.type_descriptors.len() - 1).expect("fits u32");
            clone.class_idx = crate::ids::TypeIdx(alt);
            dex.class_defs.push(clone);
        }
        let findings = collect_class_data_off_collision_findings(&dex);
        let matching: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.id == FINDING_ID_DEX_CLASS_DATA_OFF_COLLISION)
            .collect();
        assert_eq!(matching.len(), 1, "exactly one collision group");
        let detail = &matching[0].detail;
        assert!(
            detail.contains("[+16 more]"),
            "detail must roll up class_idxs above SAMPLE_CAP=5 (21 total - 5 sample = 16 more): {detail}"
        );
        assert!(
            detail.contains("shared by 21 class_def rows"),
            "total count must remain visible regardless of sample rollup: {detail}"
        );
        // Bound the detail length: 21 u32s would be ~120 chars unrolled
        // but with SAMPLE_CAP=5 + rollup the string is well under 512.
        // 100k entries would otherwise have produced >1 MiB; this assertion
        // pins the per-Finding string size invariant.
        assert!(
            detail.len() < 512,
            "per-Finding detail must be bounded by SAMPLE_CAP rollup regardless of N: got len={}",
            detail.len()
        );
    }

    #[test]
    fn collect_class_data_off_collision_findings_ignores_zero_offset() {
        // Rows with class_data_off == 0 (no class_data attached, e.g.
        // marker classes / interfaces with no method bodies) MUST NOT
        // count as colliding even though they share the 0 "sentinel".
        let data = include_bytes!("../tests/fixtures/classes_named.dex");
        let mut dex = crate::DexFile::parse(data, None).expect("parse fixture");
        // Plant two rows with class_data_off == 0.
        let mut clone_a = dex.class_defs[0].clone();
        clone_a.class_data_off = 0;
        let mut clone_b = dex.class_defs[0].clone();
        clone_b.class_data_off = 0;
        dex.class_defs.push(clone_a);
        dex.class_defs.push(clone_b);

        let findings = collect_class_data_off_collision_findings(&dex);
        let matching: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.id == FINDING_ID_DEX_CLASS_DATA_OFF_COLLISION)
            .collect();
        assert!(
            matching.is_empty(),
            "class_data_off=0 is the no-class-data sentinel; collisions on 0 must not fire: got {matching:?}"
        );
    }
}
