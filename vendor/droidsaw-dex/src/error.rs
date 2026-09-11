//! Error types for DEX parsing and decompilation.
#![allow(missing_docs, reason = "internal")]

use droidsaw_common::budget::BudgetExhausted;
use thiserror::Error;

use droidsaw_common::ssa::SsaError;

#[derive(Debug, Error)]
pub enum DexError {
    #[error("invalid DEX magic: expected dex\n, got {found:?}")]
    BadMagic { found: [u8; 4] },

    #[error("unsupported DEX version: {version}")]
    UnsupportedVersion { version: String },

    /// Non-canonical endian tag in the DEX header. The DEX spec fixes
    /// `endian_tag` at exactly `0x12345678` (LE on every supported
    /// target). Any other value — including the byte-swapped
    /// `0x78563412` REVERSE_ENDIAN_CONSTANT that ART itself rejects —
    /// surfaces here. Carries the raw observed u32 so analysts can
    /// distinguish "garbage bytes" from "intentionally byte-swapped".
    ///
    /// Typed variant carrying the raw observed value so callers can
    /// pattern-match on the typed variant + raw value rather than
    /// scraping a String message, and so Kani harnesses can verify
    /// the endian gate without symbolically evaluating `format!()`.
    #[error("bad endian tag: {tag:#010x} (canonical: 0x12345678)")]
    BadEndianTag { tag: u32 },

    #[error("checksum mismatch: expected {expected:#010x}, computed {computed:#010x}")]
    ChecksumMismatch { expected: u32, computed: u32 },

    #[error("offset {offset:#x} out of bounds (file size: {file_size:#x})")]
    OffsetOutOfBounds { offset: u32, file_size: usize },

    /// Two header id-sections claim overlapping byte ranges, so the same bytes
    /// would decode as two different item types. The runtime resolves each
    /// section by its own header offset, so a tool that parses this file holds
    /// a different table than the runtime executes — behavior is undefined
    /// across Dalvik/ART. No IR built from aliased sections is trustworthy, so
    /// the parse is hard-rejected (detected before any id-section is loaded).
    #[error(
        "id-section overlap: {section_a} [{a_off:#x}..{a_end:#x}) overlaps \
         {section_b} [{b_off:#x}..{b_end:#x}); runtime resolution differs from \
         tool view (undefined across Dalvik/ART); map_list_present={map_present}"
    )]
    SectionOverlap {
        section_a: &'static str,
        a_off: u32,
        a_end: u64,
        section_b: &'static str,
        b_off: u32,
        b_end: u64,
        map_present: bool,
    },

    #[error("read error at offset {offset:#x}: {source}")]
    ScrollRead {
        offset: usize,
        #[source]
        source: scroll::Error,
    },

    #[error("invalid MUTF-8 string at offset {offset:#x}")]
    InvalidMutf8 { offset: usize },

    #[error("invalid ULEB128 at offset {offset:#x}")]
    InvalidUleb128 { offset: usize },

    #[error("{pool} index {index} out of bounds (pool size: {pool_size})")]
    IndexOob {
        pool: &'static str,
        index: u32,
        pool_size: u32,
    },

    #[error("truncated input: need {need} bytes at offset {offset:#x}, have {have}")]
    Truncated {
        offset: usize,
        need: usize,
        have: usize,
    },

    #[error("unknown opcode {opcode:#04x} at code offset {offset}")]
    UnknownOpcode { opcode: u8, offset: u32 },

    #[error("encoded_value {variant} size {size} exceeds spec cap")]
    EncodedValueSize {
        variant: &'static str,
        size: usize,
    },

    #[error("truncated instruction at code offset {offset}: need {need} code units, have {have}")]
    TruncatedInstruction {
        offset: u32,
        need: usize,
        have: usize,
    },

    #[error("invalid instruction at code offset {offset}: {detail}")]
    InvalidInstruction { offset: u32, detail: String },

    #[error("SSA var counter overflowed u32 during build")]
    SsaVarOverflow,

    /// Amplification defense: a parsed count exceeds the maximum number of
    /// items the input can physically hold (`data.len() / MIN_ITEM_SIZE`).
    /// Without this bound, a `Vec::with_capacity(count)` fed from the file
    /// can allocate gigabytes from a tiny input (see
    /// `fuzz/crashes/fuzz_{cfg,ssa,parser}/oom-*`).
    ///
    /// Thin wrapper over
    /// [`droidsaw_common::guard::CountExceeded`] via `#[from]`. The
    /// local `bound_count` helper was retired when dex migrated to the
    /// common canonical helper. `got` widens from u32 (prior local
    /// shape) to u64 (common's shape; upcast is free).
    #[error(transparent)]
    BoundCountExceeded(#[from] droidsaw_common::guard::CountExceeded),

    /// An arithmetic operation on attacker-controlled file-offset values
    /// would have overflowed `usize`. Surfaces checked-math failures at the
    /// 3 named sites in `decode.rs` (code-unit offset, try-table offset,
    /// catch-handlers offset) that operate on values read from the input.
    #[error("arithmetic overflow: {context}")]
    ArithmeticOverflow { context: String },

    /// The iterative `encoded_value` / `encoded_annotation` work-stack
    /// exceeded `PARSE_STACK_FRAME_CAP` frames, indicating adversarial
    /// nesting that would exhaust available heap memory.  Also surfaces
    /// as a typed error when an internal walk invariant is violated
    /// (e.g., annotation key delivered without a pending name slot).
    #[error("encoded_value iterative work-stack exhausted (too many nested frames)")]
    WorkStackExhausted,

    /// Adversarial `Stmt` tree depth exceeded the emit-layer recursion
    /// cap (`emit::MAX_STMT_DEPTH`). Prevents stack overflow on
    /// pathologically-nested try/catch or if/else. Recorded via
    /// `EmitCtx::record_error` (first-wins) and surfaced at the
    /// `emit_method` boundary; downstream callers receive
    /// `decompile_method(...) -> Err(...)` instead of a panic. Mirrors
    /// the `common-region-recursion-depth-cap` pattern.
    #[error("emit recursion depth {depth} exceeded cap {cap}")]
    EmitRecursionDepthExceeded { depth: usize, cap: usize },

    /// Parse or decompile resource budget exhausted. Surfaces when
    /// attacker-controlled input size exceeds the configured memory cap
    /// or when the SSA phi-sealing iteration limit fires (mapped from
    /// `SsaError::IterationLimit` at the error-conversion boundary).
    #[error(transparent)]
    Budget(#[from] BudgetExhausted),

    /// A debug-info `register` operand (uleb128, u32 on the wire) is
    /// outside the spec-mandated range `[0, registers_size)` for the
    /// owning method. The previous `register as u16` narrowing silently
    /// truncated bits 16-31, allowing key collisions in the active-locals
    /// map that overwrite legitimate variable names with attacker-chosen
    /// ones. Surfaces from `parse_debug_info` on the 4 register-operand
    /// debug opcodes (DBG_START_LOCAL, DBG_START_LOCAL_EXTENDED,
    /// DBG_END_LOCAL, DBG_RESTART_LOCAL). DEX spec §3.4.6.
    #[error(
        "invalid debug-info register operand: {uleb_value} (method registers_size = {method_registers_size})"
    )]
    InvalidDebugRegister {
        uleb_value: u32,
        method_registers_size: u16,
    },

    /// A DEX file header declared a `header_size` field other than the
    /// canonical `0x70` (112 bytes). DEX spec §3.1 fixes the header at
    /// exactly 112 bytes; the previous parser read the field into the
    /// struct without validating it, allowing observed-vs-declared
    /// geometry audits to silently miss the wrong-shape header. The
    /// canonical-header gauge now gates at parse time.
    #[error("invalid DEX header_size: {declared} (spec mandates 0x70)")]
    InvalidHeaderSize { declared: u32 },

    /// An `access_flags` uleb128 value carries bits outside the
    /// per-scope spec union. Without this typed Err, the raw value
    /// would be pushed into the IR verbatim, letting
    /// `access_flags = 0xFFFFFFFF` evaluate truthy on every bit-test
    /// simultaneously (a method becomes
    /// static+abstract+native+private+public+ACC_ENUM at once);
    /// downstream emit then masks for canonicalization while parse
    /// accepted the garbage, breaking roundtrip-byte-equality. Surfaces
    /// from the 5 parse sites in `decode.rs` (encoded_field × 2,
    /// encoded_method × 2) and `parser/mod.rs` (class_def). See
    /// [`crate::access_flags`].
    #[error("invalid {scope:?} access_flags: {raw:#010x} (bits outside spec union)")]
    InvalidAccessFlags {
        raw: u32,
        scope: crate::access_flags::AccessFlagScope,
    },

    /// An `annotation_directory_item` header declared a combined
    /// `fields_size + methods_size + parameters_size` that — when
    /// multiplied by the per-entry stride — would force a
    /// `Vec::with_capacity` allocation exceeding the input length.
    /// Without the combined-size cap, each individual size is
    /// `bound_count`-checked but the sum is not; an attacker setting
    /// all three to the individual cap drives ~3× the input size in
    /// allocator pressure per `AnnotationDirectoryItem::parse`.
    /// OOM-class on memory-constrained workers. Surfaces with the
    /// combined value (u64, to absorb a `3 * u32::MAX` sum without
    /// itself overflowing) and the data length so operators can
    /// triage from telemetry.
    #[error(
        "annotation_directory_item combined size {combined} would exceed input length {data_len}"
    )]
    AnnotationDirectoryAllocationCap { combined: u64, data_len: usize },

    /// A `class_def_item` offset field (`interfaces_off`,
    /// `annotations_off`, `class_data_off`, or `static_values_off`)
    /// pointed beyond `data.len()`. Without this parse-time gate,
    /// these are accepted as raw u32 at parse time; downstream
    /// parsers (`parse_class_data`, annotation parsers) bounds-check
    /// on read, so the failure mode is a deferred typed Err — never a
    /// panic — but the deferred shape makes audit-trail attribution
    /// harder (operators see the consumer's error variant, not the
    /// parse-time origin).
    /// `field` is one of `"interfaces_off"`, `"annotations_off"`,
    /// `"class_data_off"`, `"static_values_off"`. `off = 0` is the
    /// spec sentinel for "absent" and is always accepted.
    #[error("class_def {field} offset {off:#x} exceeds input length {data_len}")]
    ClassDefOffsetOutOfBounds {
        field: &'static str,
        off: u32,
        data_len: usize,
    },

    /// A detector that consumes a tolerantly-parsed subsection
    /// (`annotation_directory` / `annotation_set` / `annotation_set_ref_list`
    /// / `annotation_item` / `class_data` / `code_item` / `debug_info`)
    /// could not honestly answer because at least one subsection
    /// reachable from its query failed to parse and was recorded in
    /// `DexFile.parse_errors`. The detector returned `Indeterminate`
    /// in its native verdict shape (`Vec`-returning detectors surface
    /// the verdict as this typed `Err`).
    ///
    /// `context` is the detector's static name (e.g.
    /// `"method_throws"`, `"find_annotated_methods"`); use it to
    /// distinguish callers in audit logs. The parallel
    /// [`crate::DetectorVerdict::Indeterminate`] returned by
    /// boolean-shaped detectors carries the same semantics.
    #[error("detector {context} could not answer: tolerant-parsed subsection in scope")]
    DetectorIndeterminate { context: &'static str },

    /// Section walker (`walk_debug_info_section_full` and siblings)
    /// detected a tiling-invariant violation: gap, overlap, cursor
    /// overflow, or section bound miscompare. Surfaced by parse so
    /// preserve-mode emit can refuse with a typed error rather than
    /// silently producing partial bytes.
    #[error("section layout gauge: {section}: {why}")]
    SectionLayoutGauge {
        section: &'static str,
        why: &'static str,
    },
}

/// Clamp a parse-time count against the physical size of the input.
///
/// Thin wrapper over [`droidsaw_common::guard::bound_count`] that
/// preserves the dex-side u32 input shape (caller code takes `u32`
/// values off the DEX header/container fields; the cast to `u64` is
/// purely downcast-avoidance and free). The `CountExceeded` error
/// variant from common converts into [`DexError::BoundCountExceeded`]
/// via `#[from]` on the `?` boundary.
///
/// Retained as a thin wrapper (rather than callers importing common
/// directly) so every existing call site stays verbatim — the arg
/// shape is the one that actually matches DEX-header-read code.
#[inline]
pub fn bound_count(
    got: u32,
    stride: usize,
    data_len: usize,
    item: &'static str,
) -> Result<usize> {
    droidsaw_common::guard::bound_count(u64::from(got), stride, data_len, item)
        .map_err(DexError::from)
}

/// Checked addition routing overflow through `DexError::ArithmeticOverflow`.
///
/// Every parse-side arithmetic site on attacker-derived or input-size-bounded
/// `usize` values routes through this (or [`safe_mul`] / [`safe_add_u32`]) so
/// the crate-root `deny(clippy::arithmetic_side_effects)` lint is satisfied
/// by construction rather than module- or function-level `#[allow]`. The
/// context is `&'static str` so the happy path never allocates; only the
/// overflow branch formats a detailed diagnostic.
#[inline]
pub fn safe_add(a: usize, b: usize, context: &'static str) -> Result<usize> {
    a.checked_add(b).ok_or_else(|| DexError::ArithmeticOverflow {
        context: format!("{context}: {a} + {b} overflows usize"),
    })
}

/// Checked multiplication; see [`safe_add`] for the rationale.
#[inline]
pub fn safe_mul(a: usize, b: usize, context: &'static str) -> Result<usize> {
    a.checked_mul(b).ok_or_else(|| DexError::ArithmeticOverflow {
        context: format!("{context}: {a} * {b} overflows usize"),
    })
}

/// `u32` variant of [`safe_add`] for cursor accumulators that must stay in
/// `u32` (e.g. the `decode_insns` `pc` accumulator: `pc += insn.size as u32`).
#[inline]
pub fn safe_add_u32(a: u32, b: u32, context: &'static str) -> Result<u32> {
    a.checked_add(b).ok_or_else(|| DexError::ArithmeticOverflow {
        context: format!("{context}: {a} + {b} overflows u32"),
    })
}

/// `u32` variant of [`safe_mul`] for payload-size arithmetic inside
/// `decode_insns` that must stay in `u32` (e.g. `size * 2` in the
/// packed-switch payload-skip computation).
#[inline]
pub fn safe_mul_u32(a: u32, b: u32, context: &'static str) -> Result<u32> {
    a.checked_mul(b).ok_or_else(|| DexError::ArithmeticOverflow {
        context: format!("{context}: {a} * {b} overflows u32"),
    })
}

impl From<SsaError> for DexError {
    fn from(e: SsaError) -> Self {
        // `SsaError` is `#[non_exhaustive]` upstream; a catch-all keeps the
        // build sound if a new variant is added in droidsaw-common. The
        // detail string is preserved via Display so we never drop context.
        match e {
            SsaError::VarOverflow => DexError::SsaVarOverflow,
            SsaError::IterationLimit { .. } => DexError::Budget(BudgetExhausted {
                kind: droidsaw_common::budget::BudgetKind::Steps,
                context: "ssa-seal-phis",
            }),
            other => DexError::InvalidInstruction {
                offset: 0,
                detail: format!("ssa builder: {other}"),
            },
        }
    }
}

pub type Result<T> = std::result::Result<T, DexError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_add_ok() {
        assert_eq!(safe_add(2, 3, "t").unwrap(), 5);
        assert_eq!(safe_add(0, usize::MAX, "t").unwrap(), usize::MAX);
    }

    #[test]
    fn safe_add_overflow_is_typed() {
        let err = safe_add(usize::MAX, 1, "test-ctx").unwrap_err();
        match err {
            DexError::ArithmeticOverflow { context } => {
                assert!(context.starts_with("test-ctx: "));
                assert!(context.contains("overflows usize"));
            }
            other => panic!("expected ArithmeticOverflow, got {other:?}"),
        }
    }

    #[test]
    fn safe_mul_ok_and_overflow() {
        assert_eq!(safe_mul(6, 7, "t").unwrap(), 42);
        let err = safe_mul(usize::MAX, 2, "mul-ctx").unwrap_err();
        assert!(matches!(err, DexError::ArithmeticOverflow { .. }));
    }

    #[test]
    fn safe_add_u32_ok_and_overflow() {
        assert_eq!(safe_add_u32(1, 2, "t").unwrap(), 3);
        let err = safe_add_u32(u32::MAX, 1, "u32-ctx").unwrap_err();
        match err {
            DexError::ArithmeticOverflow { context } => {
                assert!(context.contains("overflows u32"));
            }
            other => panic!("expected ArithmeticOverflow, got {other:?}"),
        }
    }

    #[test]
    fn safe_mul_u32_ok_and_overflow() {
        assert_eq!(safe_mul_u32(3, 4, "t").unwrap(), 12);
        let err = safe_mul_u32(u32::MAX, 2, "u32-mul-ctx").unwrap_err();
        match err {
            DexError::ArithmeticOverflow { context } => {
                assert!(context.contains("overflows u32"));
            }
            other => panic!("expected ArithmeticOverflow, got {other:?}"),
        }
    }
}
