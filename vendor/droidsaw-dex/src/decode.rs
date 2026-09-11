//! DEX instruction decoding into typed operand structs.
#![allow(missing_docs, reason = "internal")]
use std::collections::BTreeMap;

use scroll::{Pread, LE};

use crate::error::{bound_count, safe_add, safe_add_u32, safe_mul, safe_mul_u32, DexError, Result};
use crate::ids::*;
use crate::mutf8;
use crate::opcodes::Opcode;

/// On-disk stride in bytes for a packed/sparse-switch target entry (int).
const SWITCH_TARGET_SIZE: usize = 4;
/// On-disk stride in bytes for a `try_item` (uint start_addr + ushort
/// insn_count + ushort handler_off = 8 bytes).
const TRY_ITEM_SIZE: usize = 8;
/// Minimum on-disk byte count per `encoded_catch_handler` catch entry:
/// two ULEB128 values (type_idx, addr) → lower bound 2 bytes.
const CATCH_HANDLER_ITEM_MIN_SIZE: usize = 2;
/// Minimum on-disk bytes per `encoded_field` in class_data: diff +
/// access_flags → 2 ULEB128 values → lower bound 2 bytes.
const ENCODED_FIELD_MIN_SIZE: usize = 2;
/// Minimum on-disk bytes per `encoded_method` in class_data: diff +
/// access_flags + code_off → 3 ULEB128 values → lower bound 3 bytes.
const ENCODED_METHOD_MIN_SIZE: usize = 3;

// ── Instruction format ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InsnFormat {
    F10x,
    F12x,
    F11n,
    F11x,
    F10t,
    F20t,
    F22x,
    F21t,
    F21s,
    F21h,
    F21c,
    F23x,
    F22t,
    F22s,
    F22c,
    F22b,
    F30t,
    F32x,
    F31i,
    F31t,
    F31c,
    F35c,
    F3rc,
    /// `invoke-polymorphic {vC,vD,vE,vF,vG}, meth@BBBB, proto@HHHH` —
    /// 4 code units; carries both a method_id and a per-call-site
    /// proto_id (the signature-polymorphic feature of
    /// `MethodHandle.invokeExact`). Same operand layout as F35c plus an
    /// extra u16 for the call-site proto in the trailing unit.
    F45cc,
    /// `invoke-polymorphic/range {vCCCC .. vNNNN}, meth@BBBB, proto@HHHH`
    /// — 4 code units; same as F3rc plus an extra u16 for the
    /// call-site proto in the trailing unit.
    F4rcc,
    F51l,
}

// MATRIX-LOCKSTEP-BEGIN
// Sentinel-delimited inventory of the InsnFormat variants used by
// `insn_format`. The matching list lives in
// `docs/opcode-invariant-matrix.md` §1. `build.rs::matrix_lockstep_check()`
// extracts both lists and fails the build on set divergence — adding a
// new format here without a matching matrix row (or vice versa) becomes
// a compile-time error rather than silent doc drift.
// Format names tracked: "F10x" "F12x" "F11n" "F11x" "F10t" "F20t"
// "F22x" "F21t" "F21s" "F21h" "F21c" "F23x" "F22t" "F22s" "F22c"
// "F22b" "F30t" "F32x" "F31i" "F31t" "F31c" "F35c" "F45cc" "F3rc"
// "F4rcc" "F51l"
// MATRIX-LOCKSTEP-END
pub(crate) fn insn_format(op: Opcode) -> InsnFormat {
    use InsnFormat::*;
    use Opcode::*;
    match op {
        Nop | ReturnVoid => F10x,

        Move | MoveWide | MoveObject => F12x,
        // Unary ops and 2addr ops are also F12x
        NegInt | NotInt | NegLong | NotLong | NegFloat | NegDouble | IntToLong | IntToFloat
        | IntToDouble | LongToInt | LongToFloat | LongToDouble | FloatToInt | FloatToLong
        | FloatToDouble | DoubleToInt | DoubleToLong | DoubleToFloat | IntToByte | IntToChar
        | IntToShort => F12x,
        AddInt2Addr | SubInt2Addr | MulInt2Addr | DivInt2Addr | RemInt2Addr | AndInt2Addr
        | OrInt2Addr | XorInt2Addr | ShlInt2Addr | ShrInt2Addr | UshrInt2Addr | AddLong2Addr
        | SubLong2Addr | MulLong2Addr | DivLong2Addr | RemLong2Addr | AndLong2Addr
        | OrLong2Addr | XorLong2Addr | ShlLong2Addr | ShrLong2Addr | UshrLong2Addr
        | AddFloat2Addr | SubFloat2Addr | MulFloat2Addr | DivFloat2Addr | RemFloat2Addr
        | AddDouble2Addr | SubDouble2Addr | MulDouble2Addr | DivDouble2Addr | RemDouble2Addr => {
            F12x
        }
        ArrayLength => F12x,

        Const4 => F11n,

        MoveResult | MoveResultWide | MoveResultObject | MoveException | Return | ReturnWide
        | ReturnObject | MonitorEnter | MonitorExit | Throw => F11x,

        Goto => F10t,
        Goto16 => F20t,

        MoveFrom16 | MoveWideFrom16 | MoveObjectFrom16 => F22x,

        IfEqz | IfNez | IfLtz | IfGez | IfGtz | IfLez => F21t,

        Const16 | ConstWide16 => F21s,
        ConstHigh16 | ConstWideHigh16 => F21h,

        ConstString | ConstClass | CheckCast | NewInstance => F21c,
        Sget | SgetWide | SgetObject | SgetBoolean | SgetByte | SgetChar | SgetShort | Sput
        | SputWide | SputObject | SputBoolean | SputByte | SputChar | SputShort => F21c,
        ConstMethodHandle | ConstMethodType => F21c,

        CmplFloat | CmpgFloat | CmplDouble | CmpgDouble | CmpLong => F23x,
        Aget | AgetWide | AgetObject | AgetBoolean | AgetByte | AgetChar | AgetShort | Aput
        | AputWide | AputObject | AputBoolean | AputByte | AputChar | AputShort => F23x,
        AddInt | SubInt | MulInt | DivInt | RemInt | AndInt | OrInt | XorInt | ShlInt | ShrInt
        | UshrInt | AddLong | SubLong | MulLong | DivLong | RemLong | AndLong | OrLong
        | XorLong | ShlLong | ShrLong | UshrLong | AddFloat | SubFloat | MulFloat | DivFloat
        | RemFloat | AddDouble | SubDouble | MulDouble | DivDouble | RemDouble => F23x,

        IfEq | IfNe | IfLt | IfGe | IfGt | IfLe => F22t,

        AddIntLit16 | RsubInt | MulIntLit16 | DivIntLit16 | RemIntLit16 | AndIntLit16
        | OrIntLit16 | XorIntLit16 => F22s,

        InstanceOf | NewArray => F22c,
        Iget | IgetWide | IgetObject | IgetBoolean | IgetByte | IgetChar | IgetShort | Iput
        | IputWide | IputObject | IputBoolean | IputByte | IputChar | IputShort => F22c,

        AddIntLit8 | RsubIntLit8 | MulIntLit8 | DivIntLit8 | RemIntLit8 | AndIntLit8
        | OrIntLit8 | XorIntLit8 | ShlIntLit8 | ShrIntLit8 | UshrIntLit8 => F22b,

        Goto32 => F30t,
        Move16 | MoveWide16 | MoveObject16 => F32x,
        Const | ConstWide32 => F31i,
        PackedSwitch | SparseSwitch | FillArrayData => F31t,
        ConstStringJumbo => F31c,

        FilledNewArray | InvokeVirtual | InvokeSuper | InvokeDirect | InvokeStatic
        | InvokeInterface | InvokeCustom => F35c,
        InvokePolymorphic => F45cc,

        FilledNewArrayRange
        | InvokeVirtualRange
        | InvokeSuperRange
        | InvokeDirectRange
        | InvokeStaticRange
        | InvokeInterfaceRange
        | InvokeCustomRange => F3rc,
        InvokePolymorphicRange => F4rcc,

        ConstWide => F51l,
    }
}

/// Sign-extend a 4-bit nibble (`0..=15`) to a signed 64-bit literal.
///
/// Used by the F11n instruction format (DEX spec §6: `const/4 vA, #+B`)
/// where the 4-bit literal `B` is encoded as a two's-complement signed
/// value: `0..=7` map to themselves, `8..=15` map to `-8..=-1`.
///
/// The caller must guarantee `nibble <= 15` (typically via a `& 0x0F`
/// mask on a `u16` code-unit nibble extract). Inputs outside this range
/// produce undefined-but-bounded results constrained by `i8` two's-
/// complement arithmetic; in practice every callsite is mask-fenced.
///
/// Verified by `proofs/sign_extend_4bit.rs` against a subtraction-form
/// arithmetic oracle (`v >= 8 ? v - 16 : v`) over the full `0..=15`
/// domain.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    reason = "PROOF: caller guarantees `nibble ≤ 15` via `& 0x0F`. \
              `nibble as i8` is exact on this range (value preserved). \
              The OR-mask `!0xF_u8 as i8` (-16i8) only fires when bit 3 \
              is set, transforming high-half [8..=15] -> [-8..=-1]; sign \
              bits propagate per i8 two's complement, computed once."
)]
pub(crate) const fn sign_extend_4bit_to_i64(nibble: u16) -> i64 {
    let b = nibble as i8;
    let extended = if b & 0x8 != 0 { b | !0xF_u8 as i8 } else { b };
    extended as i64
}

/// Number of 16-bit code units an instruction format occupies.
pub(crate) fn format_size(fmt: InsnFormat) -> u8 {
    use InsnFormat::*;
    match fmt {
        F10x | F12x | F11n | F11x | F10t => 1,
        F20t | F22x | F21t | F21s | F21h | F21c | F23x | F22t | F22s | F22c | F22b => 2,
        F30t | F32x | F31i | F31t | F31c | F35c | F3rc => 3,
        F45cc | F4rcc => 4,
        F51l => 5,
    }
}

// ── Instruction types ───────────────────────────────────────────────

/// Up to 5 source registers, stored inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct RegList {
    regs: [u16; 5],
    len: u8,
}

impl RegList {
    pub fn empty() -> Self {
        Self {
            regs: [0; 5],
            len: 0,
        }
    }

    pub fn one(r: u16) -> Self {
        Self {
            regs: [r, 0, 0, 0, 0],
            len: 1,
        }
    }

    pub fn two(a: u16, b: u16) -> Self {
        Self {
            regs: [a, b, 0, 0, 0],
            len: 2,
        }
    }

    pub fn from_slice(s: &[u16]) -> Self {
        let mut regs = [0u16; 5];
        let count = s.len().min(5);
        // PROOF: `count = s.len().min(5) ≤ 5`; `regs: [u16; 5]` so `regs.get_mut(..count)` and `s.get(..count)` are both `Some`. `unwrap_or` defense-in-depth fires on no path.
        if let (Some(dst), Some(src)) = (regs.get_mut(..count), s.get(..count)) {
            dst.copy_from_slice(src);
        }
        Self {
            regs,
            #[allow(
                clippy::as_conversions,
                clippy::cast_possible_truncation,
                reason = "PROOF: count = s.len().min(5) ≤ 5 (usize, masked by .min(5)); fits u8 on all platforms."
            )]
            len: count as u8,
        }
    }

    pub fn as_slice(&self) -> &[u16] {
        // PROOF: `self.len ≤ 5` is enforced at every constructor (`empty/one/two/from_slice/...`). `regs: [u16; 5]` so `.get(..usize::from(self.len))` is `Some` on every well-constructed RegList. `unwrap_or(&[])` is dead defense-in-depth.
        self.regs.get(..usize::from(self.len)).unwrap_or(&[])
    }

    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return `regs[idx]` regardless of `len`. Used by F3rc/F4rcc emit
    /// to recover the input's start_reg field even when the instruction
    /// declares zero arguments (where the field is spec-irrelevant but
    /// still load-bearing for byte-identity preservation).
    ///
    /// Returns 0 if `idx >= 5`.
    pub fn raw_at(&self, idx: usize) -> u16 {
        self.regs.get(idx).copied().unwrap_or(0)
    }
}

/// A pool reference carried by an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum PoolIndex {
    String(StringIdx),
    Type(TypeIdx),
    Field(FieldIdx),
    Method(MethodIdx),
    MethodAndProto(MethodIdx, ProtoIdx),
    /// `invoke-custom{,/range}` operand: an index into
    /// `DexFile.call_site_ids`, whose encoded_array carries the
    /// bootstrap-method handle + SAM-method name/proto + implementation
    /// handle. Distinct from `Method` so emit paths can dispatch on
    /// call-site shape without re-parsing the encoded_array per use.
    CallSite(CallSiteIdx),
}

/// Decoded instruction with address and operands.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Instruction {
    pub addr: u32,
    pub op: Opcode,
    pub size: u8,
    pub dst: Option<u16>,
    pub src: RegList,
    pub literal: i64,
    pub target: Option<u32>,
    pub pool_idx: Option<PoolIndex>,
}

// ── Payload data ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum PayloadData {
    PackedSwitch { first_key: i32, targets: Vec<u32> },
    SparseSwitch { keys: Vec<i32>, targets: Vec<u32> },
    FillArrayData { element_width: u16, data: Vec<u8> },
}

// ── Code item + exception handling ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_idx: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedCatch {
    pub exception_type: TypeIdx,
    pub handler_addr: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchHandler {
    pub catches: Vec<TypedCatch>,
    pub catch_all_addr: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub debug_info_off: u32,
    pub instructions: Vec<Instruction>,
    pub tries: Vec<TryItem>,
    pub catch_handlers: Vec<CatchHandler>,
    pub payloads: BTreeMap<u32, PayloadData>,
    /// Per-entry semantic-invariant violations observed at parse time.
    /// Empty for spec-compliant DEX. Populated by `parse_code_item` when
    /// `try_item.start_addr + insn_count > insns_size` (CFG silent-edge-drop
    /// primitive — `cfg.rs:439, :514`) or `ins_size > registers_size`
    /// (`saturating_sub` silent-zero primitive — `ssa.rs:393`,
    /// `debug.rs:301`). The parser **clamps** the offending `insn_count`
    /// to the valid range so the IR carried downstream is consistent;
    /// the original observed values are preserved here so
    /// `diag::collect_code_item_findings` can emit typed Findings
    /// without re-walking the byte stream.
    ///
    /// Extension of CVE-2025-62518 generalization at per-entry granularity.
    pub invariant_violations: Vec<CodeItemInvariantViolation>,
}

/// Per-entry semantic-invariant violations observed by `parse_code_item`.
///
/// Tolerant-parse non-negotiable applies: parsing continues with the
/// invariant violation flagged. Downstream consumers
/// (`diag::collect_code_item_findings`) translate these into typed
/// Findings; the parser does NOT hard-error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeItemInvariantViolation {
    /// `try_item.start_addr + insn_count > insns_size`. The unchecked
    /// `try_start + insn_count as u32` at `cfg.rs:439, :514` and
    /// `smali.rs:184` would otherwise wrap (release builds) and silently
    /// drop all exception edges from the CFG. Original observed values
    /// preserved here; `parse_code_item` clamps the in-IR `insn_count`
    /// to `insns_size.saturating_sub(start_addr)` so downstream is safe.
    TryItemRangeInvalid {
        try_idx: u16,
        start_addr: u32,
        insn_count: u16,
        insns_size: u32,
    },
    /// `try_item.insn_count == 0` — an empty try region per DEX spec
    /// §6.try_item. `start_addr` is defined as the dex_pc of the FIRST
    /// covered instruction, so a try_item that covers zero instructions
    /// is malformed: it inflates audit-side try-region counters without
    /// covering any control flow. Downstream the CFG builder would emit
    /// a zero-instruction try region (no-op for analysis but visible to
    /// audit envelopes). Parser records and SKIPS the entry rather than
    /// hard-erroring — the tolerant-parse non-negotiable lets the rest
    /// of the method continue decoding even when one try_item is
    /// malformed.
    EmptyTryRegion {
        try_idx: u16,
        start_addr: u32,
    },
    /// Two consecutive `try_item`s are not ordered by ascending
    /// `start_addr` with non-overlapping ranges: for the previous try,
    /// `start_addr + insn_count` (recorded here as `prev_end`, computed
    /// from the original on-disk values with saturating arithmetic)
    /// exceeds this try's `start_addr`. DEX spec §"code_item": the
    /// `tries` array must be ordered by `start_addr` and the covered
    /// ranges must not overlap; ART's verifier rejects out-of-order /
    /// overlapping tries. Left unchecked, an overlap lets the CFG
    /// builder attribute the same dex_pc to two handler lists and
    /// double-emit exception edges (inflated handler counts visible to
    /// detectors), and a canonical-sort emit would change byte layout
    /// and break round-trip equality on non-canonical input.
    ///
    /// `try_idx` is the index of the offending (second) try. Recorded
    /// once per `code_item` (the first violating pair) to bound
    /// adversarial spam on a fully-reversed try table — "this method's
    /// try table is unsorted/overlapping from try N" is the
    /// load-bearing signal. Tolerant-parse: every try is retained as
    /// parsed (each individually range-clamped); only the ordering
    /// relationship between tries is flagged here.
    TryItemsUnsortedOrOverlapping {
        try_idx: u16,
        prev_end: u32,
        start_addr: u32,
    },
    /// `ins_size > registers_size`. The `saturating_sub` at `ssa.rs:393`
    /// (`first_param_reg = registers_size.saturating_sub(ins_size)`)
    /// silently produces 0, attributing all parameters to overlapping
    /// register slots → silently wrong SSA. The parser does NOT clamp
    /// this case; the IR carries the spec-violation flagged so
    /// downstream consumers can decide policy (drop the method, emit
    /// best-effort SSA, etc.).
    RegisterCountInverted {
        registers_size: u16,
        ins_size: u16,
    },
    /// F35c / F45cc instruction's `arg_count` (B nibble, 4-bit, can encode
    /// 0..=15) exceeds the spec maximum of 5. ART rejects via
    /// `runtime/verifier/method_verifier.cc:2050-2055`
    /// (`kVerifyVarArg` → `FailInvalidArgCount` → `VERIFY_ERROR_BAD_CLASS_HARD`,
    /// `kMaxVarArgRegs = 5`).
    ///
    /// Droidsaw decoder retains the existing `.min(5)` clamp at
    /// `decode.rs::decode_single` so downstream IR consumers see a
    /// `RegList` with `len <= 5`; the pre-clamp `observed` value is
    /// preserved here for analyst-side visibility.
    OpcodeArgCountOutOfRange {
        opcode: Opcode,
        source_pc: u32,
        observed: u8,
        max: u8,
    },
    /// Branch / switch-to-payload / payload-internal target lands outside
    /// `[0, insns_size)`. ART rejects via `runtime/verifier/method_verifier.cc:2186-2188`
    /// (`CheckAndMarkBranchTarget` → `FailTargetOffsetOutOfRange` →
    /// `VERIFY_ERROR_BAD_CLASS_HARD`) for branches, and the parallel
    /// `CheckAndMarkSwitchTargets` for switch + array-data payloads.
    ///
    /// Droidsaw retains the OOB target in the IR (so CFG-layer
    /// observation is consistent with what the parser produced), and
    /// surfaces this violation for analyst visibility. The CFG layer's
    /// existing silent-drop discipline at `cfg.rs:256` continues to
    /// remove the OOB edge from the resulting graph.
    BranchTargetOutOfRange {
        opcode: Opcode,
        source_pc: u32,
        target: u32,
        insns_size: u32,
    },
    /// Switch / fill-array-data payload's leading `ident` u16 does not
    /// match the source opcode's expected signature:
    /// `PackedSwitch → 0x0100`, `SparseSwitch → 0x0200`,
    /// `FillArrayData → 0x0300`. ART rejects via
    /// `runtime/verifier/method_verifier.cc:2280-2291`
    /// (`CheckAndMarkSwitchTargets` → `FailBadSwitchPayloadSignature` →
    /// `VERIFY_ERROR_BAD_CLASS_HARD`).
    ///
    /// Without the ident check, the resolve-walker at
    /// `decode.rs:962-977` would dispatch the payload decoder on
    /// source opcode alone — two parsers (the skip-walker and the
    /// resolve-walker) over identical bytes with different grammars.
    /// Tolerant-parse: the mis-typed payload is DROPPED from
    /// `payloads` so downstream CFG sees a switch with no resolved
    /// cases (already handled gracefully at `cfg.rs:267`).
    PayloadIdentMismatch {
        source_opcode: Opcode,
        source_pc: u32,
        payload_pc: u32,
        expected_ident: u16,
        observed_ident: u16,
    },
    /// Opcode byte at `source_pc` is not mapped to any `Opcode` variant
    /// (`Opcode::from_u8` returned `None`). ART rejects unused opcode
    /// bytes via `runtime/verifier/method_verifier.cc:4085-4090`
    /// (`case Instruction::UNUSED_3E..43 | UNUSED_73 | UNUSED_79 |
    /// UNUSED_7A | UNUSED_E3..F9: Fail(VERIFY_ERROR_BAD_CLASS_HARD)`).
    ///
    /// Droidsaw's tolerant-parse retains the existing 1-code-unit skip
    /// at `decode.rs::decode_insns` so subsequent bytes continue to be
    /// decoded; the violation surfaces the divergence. Cursor-
    /// misalignment is the adversary primitive: the bytes after an
    /// unmapped opcode can decode as different instructions under our
    /// skip-by-1 vs ART's reject-at-load disciplines.
    UnknownOpcodeByte {
        source_pc: u32,
        opcode_byte: u8,
    },

    // ── Bonus invariants ────────────────────────────────────────────────

    /// Branch offset == 0 for any branch opcode other than `goto/32`.
    /// ART rejects via `method_verifier.cc:2181-2184`
    /// (`FailBranchOffsetZero → VERIFY_ERROR_BAD_CLASS_HARD`).
    ///
    /// A zero offset creates a tight self-branch infinite loop. ART
    /// exempts `goto/32` (F30t, offset encoded as 32-bit i32) because
    /// the zero-offset encoding of a 32-bit offset is the canonical
    /// representation of an unconditional self-branch in DEX art tests;
    /// all shorter `goto` / `goto/16` forms (8-bit / 16-bit offsets)
    /// are rejected unconditionally.
    ///
    /// Tolerant-parse: the instruction is retained in IR; the violation
    /// is surfaced for analyst visibility. CFG's existing dead-loop
    /// detection is unaffected.
    BranchOffsetZero {
        opcode: Opcode,
        source_pc: u32,
    },

    /// Branch target lands inside a multi-code-unit instruction (not
    /// on an opcode boundary). ART rejects via
    /// `method_verifier.cc:2192-2195`
    /// (`FailTargetMidInstruction → VERIFY_ERROR_BAD_CLASS_HARD`).
    ///
    /// Adversary primitive: the same byte stream is decoded differently
    /// by droidsaw's instruction-start-tracking decoder and by a
    /// hypothetical verifier that starts fresh at the branch target pc.
    ///
    /// `target_pc` is the in-bounds branch target that falls mid-insn;
    /// `owner_pc` is the pc of the multi-unit instruction that spans it.
    /// The target value is retained in IR (tolerant-parse).
    BranchTargetMidInstruction {
        opcode: Opcode,
        source_pc: u32,
        target_pc: u32,
        owner_pc: u32,
    },

    /// Branch target opcode is `move-result`, `move-result-wide`,
    /// `move-result-object`, or `move-exception`. ART rejects via
    /// `method_verifier.cc:2197-2200`
    /// (`FailBranchTargetIsMoveResultOrMoveException →
    /// VERIFY_ERROR_BAD_CLASS_HARD`).
    ///
    /// Spec invariant: `move-result*` opcodes must immediately follow an
    /// `invoke*` opcode; `move-exception` must be the first instruction
    /// of an exception handler. Branching into either opcode mid-flow
    /// violates both preconditions. The target instruction is retained in
    /// IR (tolerant-parse).
    BranchTargetIsMoveResultOrMoveException {
        opcode: Opcode,
        source_pc: u32,
        target_pc: u32,
        target_opcode: Opcode,
    },

    /// A switch or `fill-array-data` payload is located at an odd
    /// (non-32-bit-aligned) code-unit address. ART rejects via the
    /// alignment check in `CheckAndMarkSwitchTargets` and
    /// `CheckArrayData` at `method_verifier.cc:2260-2266`.
    ///
    /// DEX spec §6.4.2 states: "The address of the payload pseudo
    /// instruction MUST be aligned to a 4-byte boundary." A 4-byte
    /// boundary in code-unit space means `payload_pc % 2 == 0`.
    ///
    /// Tolerant-parse: the payload is still decoded and retained (if
    /// valid); the alignment violation is surfaced separately.
    UnalignedTableDexPc {
        source_opcode: Opcode,
        source_pc: u32,
        payload_pc: u32,
    },

    /// The last decoded instruction's end address crosses the declared
    /// `insns_size` boundary. ART's `ComputeWidthsAndCountOps` at
    /// `method_verifier.cc:1730-1801` enforces that the decode loop
    /// terminates exactly at `insns_size`; an instruction whose end
    /// overshoots means the declared code-item boundary falls mid-instruction.
    ///
    /// `final_pc` is the pc value after advancing past the last decoded
    /// instruction. On a conformant method `final_pc == insns_size`.
    /// Droidsaw's `while pc < insns_size` loop continues past the
    /// declared boundary when the last instruction overshoots, so
    /// `final_pc > insns_size` is the violation signal.
    TailBytesAfterLastInstruction {
        insns_size: u32,
        final_pc: u32,
    },

    /// A non-static `invoke*` instruction (F35c `invoke-virtual`,
    /// `invoke-super`, `invoke-direct`, `invoke-interface`,
    /// `invoke-polymorphic`; F45cc `invoke-polymorphic`; and their range
    /// variants) has `arg_count == 0`. ART rejects via
    /// `method_verifier.cc:2047-2055` (`kVerifyVarArgNonZero`):
    /// non-static invokes require at least the receiver (`this`) argument.
    ///
    /// Sibling of `OpcodeArgCountOutOfRange` (which covers `> 5` for
    /// F35c/F45cc formats). Severity::Low because ART's static verifier
    /// also catches this, but it creates a receiver-missing IR shape that
    /// downstream SSA builders silently accept.
    ///
    /// Tolerant-parse: the zero-arg invoke is retained in IR;
    /// the violation is surfaced for analyst visibility.
    NonStaticInvokeArgCountZero {
        opcode: Opcode,
        source_pc: u32,
    },
}

// ── Class data ──────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedField {
    pub field_idx: FieldIdx,
    pub access_flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedMethod {
    pub method_idx: MethodIdx,
    pub access_flags: u32,
    pub code_off: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

// ── Instruction decoding ────────────────────────────────────────────

fn branch_target(pc: u32, offset: i32) -> Result<u32> {
    pc.checked_add_signed(offset)
        .ok_or_else(|| DexError::InvalidInstruction {
            offset: pc,
            detail: format!("branch target overflow: pc {pc} + offset {offset} outside u32"),
        })
}

fn read_unit(data: &[u8], insns_off: usize, pc: u32, unit_idx: u32) -> Result<u16> {
    let unit = pc
        .checked_add(unit_idx)
        .ok_or_else(|| DexError::InvalidInstruction {
            offset: pc,
            detail: format!("code-unit index overflow: pc {pc} + unit_idx {unit_idx} exceeds u32"),
        })?;
    #[allow(
        clippy::as_conversions,
        reason = "PROOF: widen u32→usize; lossless on all 64-bit targets. Subsequent checked_mul catches any overflow on 32-bit hypotheticals."
    )]
    let off = (unit as usize)
        .checked_mul(2)
        .and_then(|bytes| insns_off.checked_add(bytes))
        .ok_or_else(|| DexError::ArithmeticOverflow {
            context: format!(
                "code-unit offset: insns_off={insns_off:#x} + unit={unit}*2 overflowed usize"
            ),
        })?;
    data.pread_with::<u16>(off, LE)
        .map_err(|e| DexError::ScrollRead {
            offset: off,
            source: e,
        })
}

#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: F35c/F45cc/F3rc/F4rcc branches index `regs.regs: [u16; 5]` and `all: [u16; 5]` by `count = arg_count.min(5)` (bounded ≤ 5) or by `i in 0..count as u16` (bounded < 5). The Dalvik invoke-* opcodes are spec-bounded to ≤ 5 args (35c) or unlimited but unrolled into a separate F3rc/F4rcc range slot, so `min(5)` masks the parser-supplied byte to a value the fixed-size array can hold."
)]
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "PROOF: every `as` here is dominated by the Dalvik instruction-format spec. (1) F11n / F22b: `b as i8` / `cc as i8` extract a signed-byte immediate from a u8 / u16 by IDIOM (reinterpretation). (2) F10t/F20t/F21t/F21s/F22s/F22t: `u1 as i16` and `aa as i8` extract signed branch-offsets / literals from the LE-decoded u16 / u8 code unit — the source unit IS the sign-bit pattern. (3) F21h ConstHigh16: `(u32::from(u1) << 16) as i32` reinterprets the high-half as signed; F21h ConstWideHigh16 is `(u64::from(u1) << 48) as i64`. (4) F23x/F22b/F35c/F45cc: 4-bit and 8-bit nibble extracts via `(u >> N) & 0xF` `as u16`/`as u8` — width-narrowing is exact, the masks dominate. (5) F30t/F31t/F31i: `(lo | hi << 16) as i32` reinterprets the LE-decoded 32-bit unit as signed branch-offset or signed literal. (6) F51l: 4×u16 assembled to u64 then `as i64` for signed-long literal — IDIOM. (7) `count as u8` where count = arg_count.min(5) (so count ≤ 5, fits u8 trivially)."
)]
fn decode_single(
    data: &[u8],
    insns_off: usize,
    pc: u32,
    op: Opcode,
    violations: &mut Vec<CodeItemInvariantViolation>,
) -> Result<Instruction> {
    let fmt = insn_format(op);
    let size = format_size(fmt);
    let u0 = read_unit(data, insns_off, pc, 0)?;
    let aa = ((u0 >> 8) & 0xFF) as u16;
    let a_nibble = ((u0 >> 8) & 0x0F) as u16;
    let b_nibble = ((u0 >> 12) & 0x0F) as u16;

    let mut insn = Instruction {
        addr: pc,
        op,
        size,
        dst: None,
        src: RegList::empty(),
        literal: 0,
        target: None,
        pool_idx: None,
    };

    match fmt {
        InsnFormat::F10x => {}

        InsnFormat::F12x => {
            insn.dst = Some(a_nibble);
            insn.src = RegList::one(b_nibble);
        }

        InsnFormat::F11n => {
            insn.dst = Some(a_nibble);
            // B is a 4-bit signed literal — extract via sign_extend_4bit
            // helper so the bit-twiddle is independently Kani-provable
            // (proofs/sign_extend_4bit.rs).
            insn.literal = sign_extend_4bit_to_i64(b_nibble);
        }

        InsnFormat::F11x => {
            insn.dst = Some(aa);
        }

        InsnFormat::F10t => {
            let offset = i32::from(aa as i8);
            insn.target = Some(branch_target(pc, offset)?);
        }

        InsnFormat::F20t => {
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let offset = i32::from(u1 as i16);
            insn.target = Some(branch_target(pc, offset)?);
        }

        InsnFormat::F22x => {
            insn.dst = Some(aa);
            let u1 = read_unit(data, insns_off, pc, 1)?;
            insn.src = RegList::one(u1);
        }

        InsnFormat::F21t => {
            insn.dst = Some(aa);
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let offset = i32::from(u1 as i16);
            insn.target = Some(branch_target(pc, offset)?);
        }

        InsnFormat::F21s => {
            insn.dst = Some(aa);
            let u1 = read_unit(data, insns_off, pc, 1)?;
            insn.literal = i64::from(u1 as i16);
        }

        InsnFormat::F21h => {
            insn.dst = Some(aa);
            let u1 = read_unit(data, insns_off, pc, 1)?;
            insn.literal = match op {
                Opcode::ConstHigh16 => i64::from((u32::from(u1) << 16) as i32),
                Opcode::ConstWideHigh16 => (u64::from(u1) << 48) as i64,
                _ => i64::from(u1),
            };
        }

        InsnFormat::F21c => {
            insn.dst = Some(aa);
            let u1 = read_unit(data, insns_off, pc, 1)?;
            insn.pool_idx = Some(classify_pool_21c(op, u32::from(u1)));
        }

        InsnFormat::F23x => {
            insn.dst = Some(aa);
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let bb = (u1 & 0xFF) as u16;
            let cc = ((u1 >> 8) & 0xFF) as u16;
            insn.src = RegList::two(bb, cc);
        }

        InsnFormat::F22t => {
            insn.src = RegList::two(a_nibble, b_nibble);
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let offset = i32::from(u1 as i16);
            insn.target = Some(branch_target(pc, offset)?);
        }

        InsnFormat::F22s => {
            insn.dst = Some(a_nibble);
            insn.src = RegList::one(b_nibble);
            let u1 = read_unit(data, insns_off, pc, 1)?;
            insn.literal = i64::from(u1 as i16);
        }

        InsnFormat::F22c => {
            insn.dst = Some(a_nibble);
            insn.src = RegList::one(b_nibble);
            let u1 = read_unit(data, insns_off, pc, 1)?;
            insn.pool_idx = Some(classify_pool_22c(op, u32::from(u1)));
        }

        InsnFormat::F22b => {
            insn.dst = Some(aa);
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let bb = (u1 & 0xFF) as u16;
            let cc = ((u1 >> 8) & 0xFF) as u8;
            insn.src = RegList::one(bb);
            insn.literal = i64::from(cc as i8);
        }

        InsnFormat::F30t => {
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let u2 = read_unit(data, insns_off, pc, 2)?;
            let offset = (u32::from(u1) | u32::from(u2) << 16) as i32;
            insn.target = Some(branch_target(pc, offset)?);
        }

        InsnFormat::F32x => {
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let u2 = read_unit(data, insns_off, pc, 2)?;
            insn.dst = Some(u1);
            insn.src = RegList::one(u2);
        }

        InsnFormat::F31i => {
            insn.dst = Some(aa);
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let u2 = read_unit(data, insns_off, pc, 2)?;
            insn.literal = i64::from((u32::from(u1) | u32::from(u2) << 16) as i32);
        }

        InsnFormat::F31t => {
            insn.dst = Some(aa);
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let u2 = read_unit(data, insns_off, pc, 2)?;
            let offset = (u32::from(u1) | u32::from(u2) << 16) as i32;
            insn.target = Some(branch_target(pc, offset)?);
        }

        InsnFormat::F31c => {
            insn.dst = Some(aa);
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let u2 = read_unit(data, insns_off, pc, 2)?;
            let idx = u32::from(u1) | u32::from(u2) << 16;
            insn.pool_idx = Some(PoolIndex::String(StringIdx(idx)));
        }

        InsnFormat::F35c => {
            let arg_count = b_nibble;
            // ART verifier kMaxVarArgRegs = 5: arg_count > 5 is malformed.
            // method_verifier.cc:2050-2055 FailInvalidArgCount.
            if arg_count > 5 {
                violations.push(CodeItemInvariantViolation::OpcodeArgCountOutOfRange {
                    opcode: op,
                    source_pc: pc,
                    observed: arg_count as u8,
                    max: 5,
                });
            }
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let u2 = read_unit(data, insns_off, pc, 2)?;

            let c = (u2 & 0x0F) as u16;
            let d = ((u2 >> 4) & 0x0F) as u16;
            let e = ((u2 >> 8) & 0x0F) as u16;
            let f = ((u2 >> 12) & 0x0F) as u16;
            let g = a_nibble;

            let mut regs = RegList::empty();
            let all = [c, d, e, f, g];
            let count = (arg_count as usize).min(5);
            regs.regs[..count].copy_from_slice(&all[..count]);
            regs.len = count as u8;
            insn.src = regs;
            insn.pool_idx = Some(classify_pool_35c(op, u32::from(u1)));
        }

        InsnFormat::F3rc => {
            let arg_count = aa;
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let u2 = read_unit(data, insns_off, pc, 2)?;

            let start_reg = u2;
            let mut regs = RegList::empty();
            // Always preserve start_reg in regs.regs[0], even when
            // arg_count == 0 (where the spec marks the CCCC field as
            // irrelevant). The bytes are still on disk and load-bearing
            // for byte-identity preservation. Real-world files sometimes
            // have non-zero CCCC under AA=0 invokes that canonical emit
            // would silently re-zero.
            regs.regs[0] = start_reg;
            let count = arg_count.min(5) as u8;
            for i in 0..u16::from(count) {
                regs.regs[i as usize] = start_reg.checked_add(i).ok_or_else(|| {
                    DexError::InvalidInstruction {
                        offset: pc,
                        detail: format!(
                            "start_reg overflow in F3rc: {start_reg} + {i} exceeds u16"
                        ),
                    }
                })?;
            }
            regs.len = count;
            insn.src = regs;
            insn.literal = i64::from(arg_count); // store full count for range
            insn.pool_idx = Some(classify_pool_3rc(op, u32::from(u1)));
        }

        InsnFormat::F45cc => {
            let arg_count = b_nibble;
            // Mirror F35c: arg_count > 5 violates ART kMaxVarArgRegs.
            // method_verifier.cc:2050-2055 FailInvalidArgCount.
            if arg_count > 5 {
                violations.push(CodeItemInvariantViolation::OpcodeArgCountOutOfRange {
                    opcode: op,
                    source_pc: pc,
                    observed: arg_count as u8,
                    max: 5,
                });
            }
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let u2 = read_unit(data, insns_off, pc, 2)?;
            let u3 = read_unit(data, insns_off, pc, 3)?;

            let c = (u2 & 0x0F) as u16;
            let d = ((u2 >> 4) & 0x0F) as u16;
            let e = ((u2 >> 8) & 0x0F) as u16;
            let f = ((u2 >> 12) & 0x0F) as u16;
            let g = a_nibble;

            let mut regs = RegList::empty();
            let all = [c, d, e, f, g];
            let count = (arg_count as usize).min(5);
            regs.regs[..count].copy_from_slice(&all[..count]);
            regs.len = count as u8;
            insn.src = regs;
            // method_id in u1, call-site proto_id in u3. invoke-polymorphic
            // is the only 45cc opcode today, so route direct to
            // `MethodAndProto` without a `classify_pool_45cc` helper.
            insn.pool_idx = Some(PoolIndex::MethodAndProto(
                MethodIdx(u32::from(u1)),
                ProtoIdx(u32::from(u3)),
            ));
        }

        InsnFormat::F4rcc => {
            let arg_count = aa;
            let u1 = read_unit(data, insns_off, pc, 1)?;
            let u2 = read_unit(data, insns_off, pc, 2)?;
            let u3 = read_unit(data, insns_off, pc, 3)?;

            let start_reg = u2;
            let mut regs = RegList::empty();
            let count = arg_count.min(5) as u8;
            for i in 0..u16::from(count) {
                regs.regs[i as usize] = start_reg.checked_add(i).ok_or_else(|| {
                    DexError::InvalidInstruction {
                        offset: pc,
                        detail: format!(
                            "start_reg overflow in F4rcc: {start_reg} + {i} exceeds u16"
                        ),
                    }
                })?;
            }
            regs.len = count;
            insn.src = regs;
            insn.literal = i64::from(arg_count);
            insn.pool_idx = Some(PoolIndex::MethodAndProto(
                MethodIdx(u32::from(u1)),
                ProtoIdx(u32::from(u3)),
            ));
        }

        InsnFormat::F51l => {
            insn.dst = Some(aa);
            let u1 = u64::from(read_unit(data, insns_off, pc, 1)?);
            let u2 = u64::from(read_unit(data, insns_off, pc, 2)?);
            let u3 = u64::from(read_unit(data, insns_off, pc, 3)?);
            let u4 = u64::from(read_unit(data, insns_off, pc, 4)?);
            insn.literal = (u1 | u2 << 16 | u3 << 32 | u4 << 48) as i64;
        }
    }

    Ok(insn)
}

fn classify_pool_21c(op: Opcode, idx: u32) -> PoolIndex {
    match op {
        Opcode::ConstString => PoolIndex::String(StringIdx(idx)),
        Opcode::ConstClass | Opcode::CheckCast | Opcode::NewInstance => {
            PoolIndex::Type(TypeIdx(idx))
        }
        Opcode::Sget
        | Opcode::SgetWide
        | Opcode::SgetObject
        | Opcode::SgetBoolean
        | Opcode::SgetByte
        | Opcode::SgetChar
        | Opcode::SgetShort
        | Opcode::Sput
        | Opcode::SputWide
        | Opcode::SputObject
        | Opcode::SputBoolean
        | Opcode::SputByte
        | Opcode::SputChar
        | Opcode::SputShort => PoolIndex::Field(FieldIdx(idx)),
        Opcode::ConstMethodHandle => PoolIndex::Method(MethodIdx(idx)),
        Opcode::ConstMethodType => PoolIndex::Method(MethodIdx(idx)),
        _ => PoolIndex::Type(TypeIdx(idx)),
    }
}

fn classify_pool_22c(op: Opcode, idx: u32) -> PoolIndex {
    match op {
        Opcode::InstanceOf | Opcode::NewArray => PoolIndex::Type(TypeIdx(idx)),
        _ => PoolIndex::Field(FieldIdx(idx)),
    }
}

fn classify_pool_35c(op: Opcode, idx: u32) -> PoolIndex {
    match op {
        Opcode::FilledNewArray => PoolIndex::Type(TypeIdx(idx)),
        Opcode::InvokePolymorphic => {
            // Polymorphic also needs proto, but proto is in a different unit
            // For now store as Method; proto would need separate handling
            PoolIndex::Method(MethodIdx(idx))
        }
        // invoke-custom operand is a call_site_id, NOT a method_id —
        // classifying it as `Method` causes `dex.methods[idx]` misreads
        // (e.g. the `10.lambda$main$1()` decompile artifact).
        Opcode::InvokeCustom => PoolIndex::CallSite(CallSiteIdx(idx)),
        _ => PoolIndex::Method(MethodIdx(idx)),
    }
}

fn classify_pool_3rc(op: Opcode, idx: u32) -> PoolIndex {
    match op {
        Opcode::FilledNewArrayRange => PoolIndex::Type(TypeIdx(idx)),
        Opcode::InvokeCustomRange => PoolIndex::CallSite(CallSiteIdx(idx)),
        _ => PoolIndex::Method(MethodIdx(idx)),
    }
}

// ── Payload decoding ────────────────────────────────────────────────

fn decode_packed_switch(
    data: &[u8],
    insns_off: usize,
    payload_pc: u32,
    switch_pc: u32,
) -> Result<PayloadData> {
    let size_raw = read_unit(data, insns_off, payload_pc, 1)?;
    let size = bound_count(
        u32::from(size_raw),
        SWITCH_TARGET_SIZE,
        data.len(),
        "packed_switch_targets",
    )?;
    #[allow(
        clippy::as_conversions,
        reason = "PROOF: widen u32→usize (payload_pc is a DEX code-unit address bounded by insns_size, a u32); lossless on 64-bit targets."
    )]
    let payload_off = safe_mul(payload_pc as usize, 2, "decode_packed_switch:payload_pc*2")?;
    let base = safe_add(insns_off, payload_off, "decode_packed_switch:base")?;
    let key_off = safe_add(base, 4, "decode_packed_switch:first_key_off")?;
    let first_key: i32 = data
        .pread_with(key_off, LE)
        .map_err(|e| DexError::ScrollRead {
            offset: key_off,
            source: e,
        })?;

    let mut targets = Vec::with_capacity(size);
    let base8 = safe_add(base, 8, "decode_packed_switch:base+8")?;
    for i in 0..size {
        let i4 = safe_mul(i, 4, "decode_packed_switch:i*4")?;
        let off = safe_add(base8, i4, "decode_packed_switch:off")?;
        let rel: i32 = data.pread_with(off, LE).map_err(|e| DexError::ScrollRead {
            offset: off,
            source: e,
        })?;
        targets.push(branch_target(switch_pc, rel)?);
    }

    Ok(PayloadData::PackedSwitch { first_key, targets })
}

fn decode_sparse_switch(
    data: &[u8],
    insns_off: usize,
    payload_pc: u32,
    switch_pc: u32,
) -> Result<PayloadData> {
    let size_raw = read_unit(data, insns_off, payload_pc, 1)?;
    // Sparse-switch emits keys + targets — each 4 bytes — so stride is
    // 8 bytes per logical entry; bound at the combined stride.
    let size = bound_count(
        u32::from(size_raw),
        SWITCH_TARGET_SIZE * 2,
        data.len(),
        "sparse_switch_entries",
    )?;
    #[allow(
        clippy::as_conversions,
        reason = "PROOF: widen u32→usize (payload_pc is a DEX code-unit address bounded by insns_size, a u32); lossless on 64-bit targets."
    )]
    let payload_off = safe_mul(payload_pc as usize, 2, "decode_sparse_switch:payload_pc*2")?;
    let base = safe_add(insns_off, payload_off, "decode_sparse_switch:base")?;
    let base4 = safe_add(base, 4, "decode_sparse_switch:base+4")?;

    let mut keys = Vec::with_capacity(size);
    for i in 0..size {
        let i4 = safe_mul(i, 4, "decode_sparse_switch:keys_i*4")?;
        let off = safe_add(base4, i4, "decode_sparse_switch:keys_off")?;
        let key: i32 = data.pread_with(off, LE).map_err(|e| DexError::ScrollRead {
            offset: off,
            source: e,
        })?;
        keys.push(key);
    }

    let size4 = safe_mul(size, 4, "decode_sparse_switch:size*4")?;
    let targets_base = safe_add(base4, size4, "decode_sparse_switch:targets_base")?;
    let mut targets = Vec::with_capacity(size);
    for i in 0..size {
        let i4 = safe_mul(i, 4, "decode_sparse_switch:targets_i*4")?;
        let off = safe_add(targets_base, i4, "decode_sparse_switch:targets_off")?;
        let rel: i32 = data.pread_with(off, LE).map_err(|e| DexError::ScrollRead {
            offset: off,
            source: e,
        })?;
        targets.push(branch_target(switch_pc, rel)?);
    }

    Ok(PayloadData::SparseSwitch { keys, targets })
}

fn decode_fill_array_data(data: &[u8], insns_off: usize, payload_pc: u32) -> Result<PayloadData> {
    let element_width = read_unit(data, insns_off, payload_pc, 1)?;
    // DEX spec §6: fill-array-data element_width is the size in bytes
    // of one primitive-array element, constrained to {1, 2, 4, 8}
    // (byte/short+char / int+float / long+double). Any other value is
    // malformed input — reject rather than silently carry it into IR
    // and mismatch emit (which rejects out-of-set widths as
    // UnrepresentableIR).
    match element_width {
        1 | 2 | 4 | 8 => {}
        _ => {
            return Err(DexError::InvalidInstruction {
                offset: payload_pc,
                detail: format!(
                    "fill-array-data: element_width {element_width} is not in {{1, 2, 4, 8}} (DEX spec §6)"
                ),
            });
        }
    }
    #[allow(
        clippy::as_conversions,
        reason = "PROOF: widen u32→usize (payload_pc is a DEX code-unit address bounded by insns_size, a u32); lossless on 64-bit targets."
    )]
    let payload_off = safe_mul(payload_pc as usize, 2, "decode_fill_array_data:payload_pc*2")?;
    let base = safe_add(insns_off, payload_off, "decode_fill_array_data:base")?;
    let size_off = safe_add(base, 4, "decode_fill_array_data:size_off")?;
    let size: u32 = data
        .pread_with(size_off, LE)
        .map_err(|e| DexError::ScrollRead {
            offset: size_off,
            source: e,
        })?;

    let data_off = safe_add(base, 8, "decode_fill_array_data:data_off")?;
    #[allow(
        clippy::as_conversions,
        reason = "PROOF: widen u32→usize (size is a DEX fill-array-data element count, parser-read u32); lossless on 64-bit targets. element_width is u16 — widened via usize::from."
    )]
    let byte_count = safe_mul(size as usize, usize::from(element_width), "decode_fill_array_data:byte_count")?;
    let end = safe_add(data_off, byte_count, "decode_fill_array_data:end")?;
    if end > data.len() {
        return Err(DexError::Truncated {
            offset: data_off,
            need: byte_count,
            // Saturating: `data_off > data.len()` is the Truncated-error
            // path where the `have:` field is diagnostic, not parsed output.
            have: data.len().saturating_sub(data_off),
        });
    }
    // PROOF: `if end > data.len()` guard above returns Err early; on this line `end ≤ data.len()` and `data_off ≤ end`, so `.get(data_off..end)` is `Some`. `unwrap_or(&[])` is dead defense-in-depth.
    let payload = data.get(data_off..end).unwrap_or(&[]).to_vec();

    Ok(PayloadData::FillArrayData {
        element_width,
        data: payload,
    })
}

// ── Main decode loop ────────────────────────────────────────────────

/// Decoded instruction stream returned by [`decode_insns`].
///
/// - `0` — instructions in order.
/// - `1` — payload map keyed by payload pc.
/// - `2` — per-instruction invariant violations observed during
///   decoding (see [`CodeItemInvariantViolation`]). Empty on
///   spec-compliant input.
pub type DecodedInsnStream = (
    Vec<Instruction>,
    BTreeMap<u32, PayloadData>,
    Vec<CodeItemInvariantViolation>,
);

#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "PROOF: four cast patterns in this function. (1) `(u0 & 0xFF) as u8`: u16 low-byte extract, mask 0xFF bounds to 0..=255, exact; (2) `(u0 >> 8) as u8`: u16 high-byte extract, right-shift eliminates upper bits, exact; (3) `pc as usize`: widen u32→usize (pc is a DEX code-unit address, bounded by insns_size u32), lossless on 64-bit targets; (4) `insn.src.len() as u64`: widen usize→u64, lossless on all platforms where usize ≤ 64 bits; (5) `insn.literal as u64`: i64→u64 reinterpretation of arg_count stored as signed, dominators ensure literal is a non-negative u8-range value from the DEX wire format."
)]
pub fn decode_insns(
    data: &[u8],
    insns_off: usize,
    insns_size: u32,
) -> Result<DecodedInsnStream> {
    let mut instructions = Vec::new();
    let mut payloads = BTreeMap::new();
    let mut violations: Vec<CodeItemInvariantViolation> = Vec::new();
    // Track switch/fill-array-data instructions to resolve payloads
    let mut pending_payloads: Vec<(u32, u32, Opcode)> = Vec::new(); // (switch_pc, payload_pc, op)
    // Track valid opcode-start PCs for BranchTargetMidInstruction check.
    // Populated on every instruction and payload-skip advance so that
    // post-loop branch-target boundary checks can validate in-bounds targets
    // against the decoded instruction starts.
    let mut opcode_starts: BTreeMap<u32, ()> = BTreeMap::new();
    let mut pc: u32 = 0;

    while pc < insns_size {
        let u0 = read_unit(data, insns_off, pc, 0)?;
        let op_byte = (u0 & 0xFF) as u8;

        // Pseudo-instructions (NOP with payload marker in high byte)
        if op_byte == 0x00 {
            let ident = (u0 >> 8) as u8;
            if ident == 0x01 || ident == 0x02 || ident == 0x03 {
                // Skip payload — handled via pending_payloads
                // Compute payload size to skip past it
                let payload_size = match ident {
                    0x01 => {
                        // packed-switch: 1 + 1 + 2 + size*2 code units
                        let size = u32::from(read_unit(data, insns_off, pc, 1)?);
                        safe_add_u32(
                            safe_mul_u32(size, 2, "decode_insns:packed_switch:size*2")?,
                            4,
                            "decode_insns:packed_switch:payload_size",
                        )?
                    }
                    0x02 => {
                        // sparse-switch: 1 + 1 + size*2 + size*2 code units
                        let size = u32::from(read_unit(data, insns_off, pc, 1)?);
                        safe_add_u32(
                            safe_mul_u32(size, 4, "decode_insns:sparse_switch:size*4")?,
                            2,
                            "decode_insns:sparse_switch:payload_size",
                        )?
                    }
                    0x03 => {
                        // fill-array-data: 1 + 1 + 2 + ceil(size*width/2) code units
                        let width = u32::from(read_unit(data, insns_off, pc, 1)?);
                        let pc2 = safe_mul(pc as usize, 2, "decode_insns:fill_array:pc*2")?;
                        let base = safe_add(insns_off, pc2, "decode_insns:fill_array:base")?;
                        let size_off = safe_add(base, 4, "decode_insns:fill_array:size_off")?;
                        let size: u32 =
                            data.pread_with(size_off, LE)
                                .map_err(|e| DexError::ScrollRead {
                                    offset: size_off,
                                    source: e,
                                })?;
                        let bytes =
                            safe_mul_u32(size, width, "decode_insns:fill_array:bytes")?;
                        safe_add_u32(4, bytes.div_ceil(2), "decode_insns:fill_array:payload_size")?
                    }
                    _ => {
                        return Err(DexError::InvalidInstruction {
                            offset: pc,
                            detail: format!(
                                "payload ident {ident:#04x} reached dispatch match after outer guard accepted only 0x01/0x02/0x03"
                            ),
                        })
                    }
                };
                // Payload pseudo-instructions are NOT valid branch targets
                // (ART rejects branches into payload regions), so we do NOT
                // insert their PCs into opcode_starts.
                pc = safe_add_u32(pc, payload_size, "decode_insns:pc+=payload_size")?;
                continue;
            }
            // Regular NOP (ident == 0x00) — fall through to normal decode
        }

        // Record this pc as a valid opcode start before decoding.
        opcode_starts.insert(pc, ());

        let op = match Opcode::from_u8(op_byte) {
            Some(op) => op,
            None => {
                // UNCHECKED-1: ART rejects unmapped opcodes via
                // method_verifier.cc:4085-4090
                // (`Fail(VERIFY_ERROR_BAD_CLASS_HARD) << "Unexpected opcode"`).
                // Droidsaw tolerant-parses: skip 1 code unit + surface
                // the divergence as a typed violation.
                violations.push(CodeItemInvariantViolation::UnknownOpcodeByte {
                    source_pc: pc,
                    opcode_byte: op_byte,
                });
                pc = safe_add_u32(pc, 1, "decode_insns:pc+=1_unknown_op")?;
                continue;
            }
        };

        let insn = decode_single(data, insns_off, pc, op, &mut violations)?;

        // M-1: per-instruction branch / switch-to-payload target bound
        // check. ART rejects via method_verifier.cc:2186-2188
        // CheckAndMarkBranchTarget -> FailTargetOffsetOutOfRange.
        // Tolerant-parse: retain the OOB target in IR so the CFG layer's
        // silent-drop discipline (cfg.rs:256) sees the same input.
        if let Some(target) = insn.target {
            if target >= insns_size {
                violations.push(CodeItemInvariantViolation::BranchTargetOutOfRange {
                    opcode: op,
                    source_pc: pc,
                    target,
                    insns_size,
                });
            }
        }

        // BONUS-1: branch offset == 0 for non-goto/32 branches.
        // ART rejects via method_verifier.cc:2181-2184 (FailBranchOffsetZero).
        // goto/32 (F30t) is exempt; all shorter goto and all if-* forms are
        // rejected when offset == 0 (self-branch tight loop).
        // We detect this by checking whether target == source_pc on a
        // branch instruction that is not Goto32.
        let is_branch_op = matches!(
            op,
            Opcode::Goto
                | Opcode::Goto16
                | Opcode::IfEq
                | Opcode::IfNe
                | Opcode::IfLt
                | Opcode::IfGe
                | Opcode::IfGt
                | Opcode::IfLe
                | Opcode::IfEqz
                | Opcode::IfNez
                | Opcode::IfLtz
                | Opcode::IfGez
                | Opcode::IfGtz
                | Opcode::IfLez
        );
        if is_branch_op {
            if let Some(target) = insn.target {
                if target == pc {
                    violations.push(CodeItemInvariantViolation::BranchOffsetZero {
                        opcode: op,
                        source_pc: pc,
                    });
                }
            }
        }

        // BONUS-4: switch / fill-array-data payload pc must be 32-bit aligned
        // (code-unit address must be even). ART rejects via the alignment
        // check at method_verifier.cc:2260-2266
        // (CheckAndMarkSwitchTargets/CheckArrayData alignment branch).
        // DEX code units are 2 bytes each; a 4-byte boundary = payload_pc % 2 == 0.
        // Tolerant-parse: if unaligned, surface the violation and skip payload
        // resolution (same drop discipline as PayloadIdentMismatch).
        match op {
            Opcode::PackedSwitch | Opcode::SparseSwitch | Opcode::FillArrayData => {
                if let Some(target) = insn.target {
                    if target % 2 != 0 {
                        violations.push(CodeItemInvariantViolation::UnalignedTableDexPc {
                            source_opcode: op,
                            source_pc: pc,
                            payload_pc: target,
                        });
                        // Skip payload resolution for unaligned addresses.
                        // ART hard-rejects; we drop the payload entry so CFG
                        // sees a switch with no resolved cases (same graceful
                        // handling as PayloadIdentMismatch via cfg.rs:267).
                    } else {
                        pending_payloads.push((pc, target, op));
                    }
                }
            }
            _ => {}
        }

        // BONUS-6: non-static invoke arg_count == 0.
        // ART rejects via method_verifier.cc:2047-2055 (kVerifyVarArgNonZero).
        // Non-static invokes require at least the receiver (this) argument.
        // This covers F35c non-static forms (InvokeVirtual, InvokeSuper,
        // InvokeDirect, InvokeInterface, InvokePolymorphic) and their range
        // variants (F3rc/F4rcc). InvokeStatic and FilledNewArray are exempt.
        // For range variants (F3rc/F4rcc) arg_count is stored in insn.literal.
        let is_non_static_invoke = matches!(
            op,
            Opcode::InvokeVirtual
                | Opcode::InvokeSuper
                | Opcode::InvokeDirect
                | Opcode::InvokeInterface
                | Opcode::InvokePolymorphic
                | Opcode::InvokeVirtualRange
                | Opcode::InvokeSuperRange
                | Opcode::InvokeDirectRange
                | Opcode::InvokeInterfaceRange
                | Opcode::InvokePolymorphicRange
        );
        if is_non_static_invoke {
            // F35c/F45cc: arg_count is insn.src.len() (already clamped to ≥0).
            // F3rc/F4rcc: arg_count is insn.literal (stored full count for range).
            #[allow(
                clippy::cast_sign_loss,
                reason = "PROOF: F3rc/F4rcc store arg_count (a u8 in the DEX wire format) into insn.literal: i64; the cast back to u64 is the reverse of a widening, not real sign loss."
            )]
            let arg_count: u64 = match insn_format(op) {
                InsnFormat::F35c | InsnFormat::F45cc => insn.src.len() as u64,
                InsnFormat::F3rc | InsnFormat::F4rcc => insn.literal as u64,
                _ => 1, // unreachable for non-static-invoke ops; treat as non-zero
            };
            if arg_count == 0 {
                violations.push(CodeItemInvariantViolation::NonStaticInvokeArgCountZero {
                    opcode: op,
                    source_pc: pc,
                });
            }
        }

        pc = safe_add_u32(pc, u32::from(insn.size), "decode_insns:pc+=insn.size")?;
        instructions.push(insn);
    }

    // BONUS-5: last decoded instruction crosses the declared insns_size boundary.
    // ART's ComputeWidthsAndCountOps at method_verifier.cc:1730-1801
    // requires that the loop terminate exactly at insns_size; a final
    // instruction whose end address (pc after advance) overshoots insns_size
    // means the declared code-item boundary is mid-instruction.
    // Our loop exits when pc >= insns_size, so pc > insns_size indicates overshoot.
    if pc > insns_size {
        violations.push(CodeItemInvariantViolation::TailBytesAfterLastInstruction {
            insns_size,
            final_pc: pc,
        });
    }

    // BONUS-2 & BONUS-3: post-loop branch-target boundary checks.
    // These require the full opcode_starts set (populated above) and the
    // decoded instruction list to look up the target opcode.
    //
    // Build a pc→Opcode map for target-opcode lookup (BONUS-3 only).
    let pc_to_opcode: BTreeMap<u32, Opcode> = instructions
        .iter()
        .map(|insn| (insn.addr, insn.op))
        .collect();

    for insn in &instructions {
        let Some(target) = insn.target else { continue };
        // Only check in-bounds targets (OOB already handled by M-1).
        if target >= insns_size {
            continue;
        }
        // Skip switch/fill-array-data: their `insn.target` is a payload PC,
        // not a branch target. Payload PCs are pseudo-instruction addresses
        // not present in opcode_starts; checking them here would produce false
        // BranchTargetMidInstruction violations for all valid switch layouts.
        // BONUS-4 handles payload-alignment separately.
        if matches!(
            insn.op,
            Opcode::PackedSwitch | Opcode::SparseSwitch | Opcode::FillArrayData
        ) {
            continue;
        }
        // BONUS-2: target must land on an opcode boundary.
        // ART rejects via method_verifier.cc:2192-2195
        // (FailTargetMidInstruction).
        if !opcode_starts.contains_key(&target) {
            // Find the instruction whose span covers target (owner).
            // We look for the largest opcode_start ≤ target.
            let owner_pc = opcode_starts
                .range(..=target)
                .next_back()
                .map_or(0, |(&k, _)| k);
            violations.push(CodeItemInvariantViolation::BranchTargetMidInstruction {
                opcode: insn.op,
                source_pc: insn.addr,
                target_pc: target,
                owner_pc,
            });
        }
        // BONUS-3: target opcode must not be move-result* or move-exception.
        // ART rejects via method_verifier.cc:2197-2200
        // (FailBranchTargetIsMoveResultOrMoveException).
        if let Some(&target_op) = pc_to_opcode.get(&target) {
            if matches!(
                target_op,
                Opcode::MoveResult
                    | Opcode::MoveResultWide
                    | Opcode::MoveResultObject
                    | Opcode::MoveException
            ) {
                violations.push(
                    CodeItemInvariantViolation::BranchTargetIsMoveResultOrMoveException {
                        opcode: insn.op,
                        source_pc: insn.addr,
                        target_pc: target,
                        target_opcode: target_op,
                    },
                );
            }
        }
    }

    // Resolve payloads
    for (switch_pc, payload_pc, op) in pending_payloads {
        // M-2: payload-ident-vs-source-opcode reconciliation. ART rejects
        // via method_verifier.cc:2280-2291 CheckAndMarkSwitchTargets ->
        // FailBadSwitchPayloadSignature. Tolerant-parse: skip the
        // mis-typed payload entirely; downstream CFG handles missing
        // payloads gracefully (cfg.rs:267 falls through when
        // `code.payloads.get(&target)` is None).
        let expected_ident: u16 = match op {
            Opcode::PackedSwitch => 0x0100,
            Opcode::SparseSwitch => 0x0200,
            Opcode::FillArrayData => 0x0300,
            _ => {
                return Err(DexError::InvalidInstruction {
                    offset: switch_pc,
                    detail: format!(
                        "payload dispatch reached for non-switch/fill op {op:?}; outer filter (PackedSwitch|SparseSwitch|FillArrayData) drifted"
                    ),
                });
            }
        };
        let observed_ident = read_unit(data, insns_off, payload_pc, 0)?;
        if observed_ident != expected_ident {
            violations.push(CodeItemInvariantViolation::PayloadIdentMismatch {
                source_opcode: op,
                source_pc: switch_pc,
                payload_pc,
                expected_ident,
                observed_ident,
            });
            continue;
        }
        let payload = match op {
            Opcode::PackedSwitch => decode_packed_switch(data, insns_off, payload_pc, switch_pc)?,
            Opcode::SparseSwitch => decode_sparse_switch(data, insns_off, payload_pc, switch_pc)?,
            Opcode::FillArrayData => decode_fill_array_data(data, insns_off, payload_pc)?,
            _ => {
                return Err(DexError::InvalidInstruction {
                    offset: switch_pc,
                    detail: format!(
                        "payload dispatch reached for non-switch/fill op {op:?}; expected_ident filter drifted"
                    ),
                });
            }
        };
        // M-1: payload-internal per-case targets must also land in
        // [0, insns_size). ART's CheckAndMarkSwitchTargets enforces.
        if let PayloadData::PackedSwitch { targets, .. }
        | PayloadData::SparseSwitch { targets, .. } = &payload
        {
            for &t in targets {
                if t >= insns_size {
                    violations.push(CodeItemInvariantViolation::BranchTargetOutOfRange {
                        opcode: op,
                        source_pc: switch_pc,
                        target: t,
                        insns_size,
                    });
                }
            }
        }
        payloads.insert(payload_pc, payload);
    }

    droidsaw_common::diag::stage_dump("decode", &instructions);
    Ok((instructions, payloads, violations))
}

// ── Code item parsing ───────────────────────────────────────────────

/// Parse a `code_item` at `code_off` and return the decoded
/// [`CodeItem`].
///
/// **Per-entry semantic invariants** observed at parse time:
///
/// 1. `try_item.start_addr + insn_count <= insns_size` for every try.
///    Violation → [`CodeItemInvariantViolation::TryItemRangeInvalid`]
///    pushed to `code.invariant_violations`; the offending
///    `insn_count` is **clamped** in-IR to
///    `insns_size.saturating_sub(start_addr)` so downstream CFG /
///    SSA / emit consumers do not silently wrap on the unchecked
///    `try_start + insn_count as u32` shape (cfg.rs:439, :514;
///    smali.rs:184).
/// 2. `registers_size >= ins_size`. Violation →
///    [`CodeItemInvariantViolation::RegisterCountInverted`] pushed;
///    no in-IR clamp (downstream consumes raw values per the
///    spec-violation-flagged contract — see `ssa.rs:393` /
///    `debug.rs:301` `saturating_sub` silent-zero primitive).
///
/// Tolerant-parse non-negotiable applies to both: parsing continues
/// with the violation recorded; the function returns `Ok(_)`.
///
/// Extension of CVE-2025-62518 generalization at per-entry granularity.
#[allow(
    clippy::as_conversions,
    reason = "PROOF: two u32→usize widen sites. (1) `code_off as usize`: code_off is a DEX file offset read from the class_def header (u32); lossless on 64-bit targets. (2) `insns_size as usize`: DEX insns_size field (u32 code-unit count); used in checked_mul chain so any hypothetical 32-bit overflow is caught downstream."
)]
pub fn parse_code_item(data: &[u8], code_off: u32) -> Result<CodeItem> {
    let base = code_off as usize;

    let registers_size: u16 = data
        .pread_with(base, LE)
        .map_err(|e| DexError::ScrollRead {
            offset: base,
            source: e,
        })?;
    let off_ins = safe_add(base, 2, "parse_code_item:base+2")?;
    let ins_size: u16 = data
        .pread_with(off_ins, LE)
        .map_err(|e| DexError::ScrollRead {
            offset: off_ins,
            source: e,
        })?;
    let off_outs = safe_add(base, 4, "parse_code_item:base+4")?;
    let outs_size: u16 = data
        .pread_with(off_outs, LE)
        .map_err(|e| DexError::ScrollRead {
            offset: off_outs,
            source: e,
        })?;
    let off_tries = safe_add(base, 6, "parse_code_item:base+6")?;
    let tries_size: u16 = data
        .pread_with(off_tries, LE)
        .map_err(|e| DexError::ScrollRead {
            offset: off_tries,
            source: e,
        })?;
    let off_debug = safe_add(base, 8, "parse_code_item:base+8")?;
    let debug_info_off: u32 = data
        .pread_with(off_debug, LE)
        .map_err(|e| DexError::ScrollRead {
            offset: off_debug,
            source: e,
        })?;
    let off_insns_size = safe_add(base, 12, "parse_code_item:base+12")?;
    let insns_size: u32 = data
        .pread_with(off_insns_size, LE)
        .map_err(|e| DexError::ScrollRead {
            offset: off_insns_size,
            source: e,
        })?;

    let insns_off = safe_add(base, 16, "parse_code_item:insns_off")?;
    let (instructions, payloads, decode_violations) =
        decode_insns(data, insns_off, insns_size)?;

    let mut tries = Vec::new();
    let mut catch_handlers = Vec::new();
    let mut invariant_violations: Vec<CodeItemInvariantViolation> = decode_violations;

    if tries_size > 0 {
        let tries_count =
            bound_count(u32::from(tries_size), TRY_ITEM_SIZE, data.len(), "tries")?;
        // Padding: if insns_size is odd, skip 2 bytes
        let padding = if !insns_size.is_multiple_of(2) { 2usize } else { 0 };
        let tries_off = (insns_size as usize)
            .checked_mul(2)
            .and_then(|bytes| insns_off.checked_add(bytes))
            .and_then(|off| off.checked_add(padding))
            .ok_or_else(|| DexError::ArithmeticOverflow {
                context: format!(
                    "try-table offset: insns_off={insns_off:#x} + insns_size={insns_size}*2 + padding={padding} overflowed usize"
                ),
            })?;

        // §H-4 ordering gauge: carry the previous try's original on-disk
        // end (`start_addr + insn_count`, saturating) to detect the first
        // pair that is unsorted or overlapping. Independent of the
        // per-try range clamp below (which mutates the in-IR `insn_count`
        // but never `start_addr`).
        let mut try_prev_end: Option<u32> = None;
        let mut try_order_recorded = false;

        for i in 0..tries_count {
            let i8 = safe_mul(i, 8, "parse_code_item:try:i*8")?;
            let t_off = safe_add(tries_off, i8, "parse_code_item:try:t_off")?;
            let start_addr: u32 = data
                .pread_with(t_off, LE)
                .map_err(|e| DexError::ScrollRead {
                    offset: t_off,
                    source: e,
                })?;
            let off_insn = safe_add(t_off, 4, "parse_code_item:try:t_off+4")?;
            let insn_count: u16 =
                data.pread_with(off_insn, LE)
                    .map_err(|e| DexError::ScrollRead {
                        offset: off_insn,
                        source: e,
                    })?;
            let off_handler = safe_add(t_off, 6, "parse_code_item:try:t_off+6")?;
            let handler_off: u16 =
                data.pread_with(off_handler, LE)
                    .map_err(|e| DexError::ScrollRead {
                        offset: off_handler,
                        source: e,
                    })?;

            let try_idx_u16: u16 = u16::try_from(i).unwrap_or(u16::MAX);

            // §H-4: tries must be ordered by ascending start_addr and
            // non-overlapping. Compare this try's start_addr against the
            // previous try's original on-disk end; record the first
            // violating pair only. Runs before the empty-region skip so
            // every on-disk try participates in the ordering relation.
            let this_end = start_addr.saturating_add(u32::from(insn_count));
            if let Some(prev_end) = try_prev_end {
                if start_addr < prev_end && !try_order_recorded {
                    invariant_violations.push(
                        CodeItemInvariantViolation::TryItemsUnsortedOrOverlapping {
                            try_idx: try_idx_u16,
                            prev_end,
                            start_addr,
                        },
                    );
                    try_order_recorded = true;
                }
            }
            try_prev_end = Some(this_end);

            // Empty-try-region gauge: per DEX spec §6.try_item,
            // `start_addr` is the dex_pc of the FIRST covered
            // instruction — a try region covering zero instructions
            // is malformed and inflates audit-side counters. Record
            // and skip (rather than emit the empty region) so the
            // CFG doesn't carry a zero-instruction handler edge.
            if insn_count == 0 {
                invariant_violations.push(
                    CodeItemInvariantViolation::EmptyTryRegion {
                        try_idx: try_idx_u16,
                        start_addr,
                    },
                );
                continue;
            }

            // Cross-validate `start_addr + insn_count <= insns_size`.
            // Use checked u32 arithmetic to detect either wrap OR
            // out-of-range; on violation, record the original observed
            // values and clamp the in-IR `insn_count` to the valid
            // range so downstream `try_start + insn_count as u32`
            // shapes (cfg.rs:439, :514; smali.rs:184) cannot wrap.
            let clamped_insn_count: u16 = match start_addr.checked_add(u32::from(insn_count)) {
                Some(end) if end <= insns_size => insn_count,
                _ => {
                    invariant_violations.push(
                        CodeItemInvariantViolation::TryItemRangeInvalid {
                            try_idx: try_idx_u16,
                            start_addr,
                            insn_count,
                            insns_size,
                        },
                    );
                    let max_valid_u32: u32 = insns_size.saturating_sub(start_addr);
                    u16::try_from(max_valid_u32.min(u32::from(u16::MAX))).unwrap_or(u16::MAX)
                }
            };
            tries.push(TryItem {
                start_addr,
                insn_count: clamped_insn_count,
                handler_idx: handler_off as usize, // temporary: byte offset, resolved below
            });
        }

        // Parse encoded_catch_handler_list
        let handlers_off = usize::from(tries_size)
            .checked_mul(8)
            .and_then(|bytes| tries_off.checked_add(bytes))
            .ok_or_else(|| DexError::ArithmeticOverflow {
                context: format!(
                    "catch-handlers offset: tries_off={tries_off:#x} + tries_size={tries_size}*8 overflowed usize"
                ),
            })?;
        let (handler_count_raw, hc_len) = mutf8::read_uleb128(data, handlers_off)?;
        // Each `encoded_catch_handler` is at minimum one SLEB128 (size). Use
        // stride 1 to bound the outer iteration against the input size.
        let handler_count =
            bound_count(handler_count_raw, 1, data.len(), "catch_handlers")?;

        // Build a map from byte offset (relative to handlers_off) to handler index
        let mut handler_offset_to_idx = BTreeMap::new();
        let mut pos = safe_add(handlers_off, hc_len, "parse_code_item:handler_pos")?;

        for i in 0..handler_count {
            // Monotone: `pos ≥ handlers_off` by construction (pos started at
            // `handlers_off + hc_len` and only grows).
            let handler_byte_off = pos.saturating_sub(handlers_off);
            handler_offset_to_idx.insert(handler_byte_off, i);

            let (size_raw, sz_len) = mutf8::read_sleb128(data, pos)?;
            pos = safe_add(pos, sz_len, "parse_code_item:catch:size_len")?;
            let has_catch_all = size_raw <= 0;
            let catch_count = bound_count(
                size_raw.unsigned_abs(),
                CATCH_HANDLER_ITEM_MIN_SIZE,
                data.len(),
                "typed_catches",
            )?;

            let mut catches = Vec::with_capacity(catch_count);
            for _ in 0..catch_count {
                let (type_idx, tl) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, tl, "parse_code_item:catch:type_len")?;
                let (addr, al) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, al, "parse_code_item:catch:addr_len")?;
                catches.push(TypedCatch {
                    exception_type: TypeIdx(type_idx),
                    handler_addr: addr,
                });
            }

            let catch_all_addr = if has_catch_all {
                let (addr, al) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, al, "parse_code_item:catch:catch_all_len")?;
                Some(addr)
            } else {
                None
            };

            catch_handlers.push(CatchHandler {
                catches,
                catch_all_addr,
            });
        }

        // Resolve try handler_idx from byte offsets to handler indices
        for t in &mut tries {
            t.handler_idx = *handler_offset_to_idx.get(&t.handler_idx).ok_or_else(|| {
                DexError::InvalidInstruction {
                    offset: 0,
                    detail: format!(
                        "try handler_off {} not found in handler list",
                        t.handler_idx
                    ),
                }
            })?;
        }
    }

    // Cross-validate `registers_size >= ins_size`. Spec violation
    // is observed-not-enforced: the parser records the violation but
    // does not clamp; downstream `ssa.rs:393` /
    // `debug.rs:301` `saturating_sub` silent-zero is the
    // policy-decision site (drop the method, emit best-effort SSA,
    // etc.) — recording at the `Err` analog here is the precise
    // gauge for `diag::collect_code_item_findings`.
    if ins_size > registers_size {
        invariant_violations.push(CodeItemInvariantViolation::RegisterCountInverted {
            registers_size,
            ins_size,
        });
    }

    Ok(CodeItem {
        registers_size,
        ins_size,
        outs_size,
        debug_info_off,
        instructions,
        tries,
        catch_handlers,
        payloads,
        invariant_violations,
    })
}

// ── Class data parsing ──────────────────────────────────────────────

#[allow(
    clippy::as_conversions,
    reason = "PROOF: widen u32→usize; class_data_off is a DEX file offset from the class_def header (u32); lossless on 64-bit targets."
)]
pub fn parse_class_data(data: &[u8], class_data_off: u32) -> Result<ClassData> {
    parse_class_data_with_consumed(data, class_data_off).map(|(cd, _)| cd)
}

/// Same as `parse_class_data` but also returns the number of on-disk
/// bytes consumed (= byte length of the parsed class_data record).
/// Used by `EmitConfig::preserve_data_section_layout` to capture
/// `raw_class_data_bytes` at parse time so the emitter can replay
/// the input bytes verbatim. This preserves byte-identity where the
/// input has non-minimal ULEB128 encodings for code_off / access_flags
/// that canonical re-emit would normalize to min-form.
pub fn parse_class_data_with_consumed(
    data: &[u8],
    class_data_off: u32,
) -> Result<(ClassData, usize)> {
    #[allow(
        clippy::as_conversions,
        reason = "PROOF: class_data_off is a u32 DEX header field; usize is ≥32-bit on every target Rust supports (16-bit dropped); widening u32→usize is lossless."
    )]
    let start = class_data_off as usize;
    let mut pos = start;

    let (static_fields_size, len) = mutf8::read_uleb128(data, pos)?;
    pos = safe_add(pos, len, "parse_class_data:static_fields_size")?;
    let (instance_fields_size, len) = mutf8::read_uleb128(data, pos)?;
    pos = safe_add(pos, len, "parse_class_data:instance_fields_size")?;
    let (direct_methods_size, len) = mutf8::read_uleb128(data, pos)?;
    pos = safe_add(pos, len, "parse_class_data:direct_methods_size")?;
    let (virtual_methods_size, len) = mutf8::read_uleb128(data, pos)?;
    pos = safe_add(pos, len, "parse_class_data:virtual_methods_size")?;

    let static_fields_size = bound_count(
        static_fields_size,
        ENCODED_FIELD_MIN_SIZE,
        data.len(),
        "static_fields",
    )?;
    let instance_fields_size = bound_count(
        instance_fields_size,
        ENCODED_FIELD_MIN_SIZE,
        data.len(),
        "instance_fields",
    )?;
    let direct_methods_size = bound_count(
        direct_methods_size,
        ENCODED_METHOD_MIN_SIZE,
        data.len(),
        "direct_methods",
    )?;
    let virtual_methods_size = bound_count(
        virtual_methods_size,
        ENCODED_METHOD_MIN_SIZE,
        data.len(),
        "virtual_methods",
    )?;

    let mut static_fields = Vec::with_capacity(static_fields_size);
    let mut field_idx_acc: u32 = 0;
    for _ in 0..static_fields_size {
        let (diff, len) = mutf8::read_uleb128(data, pos)?;
        pos = safe_add(pos, len, "parse_class_data:static_fields:diff_len")?;
        field_idx_acc = field_idx_acc.checked_add(diff).ok_or_else(|| {
            DexError::InvalidInstruction {
                offset: class_data_off,
                detail: format!(
                    "static_fields field_idx_diff accumulator overflow: {field_idx_acc} + {diff} exceeds u32"
                ),
            }
        })?;
        let (access_flags, len) = mutf8::read_uleb128(data, pos)?;
        pos = safe_add(pos, len, "parse_class_data:static_fields:access_flags_len")?;
        let access_flags = crate::access_flags::validate(
            access_flags,
            crate::access_flags::AccessFlagScope::Field,
        )?;
        static_fields.push(EncodedField {
            field_idx: FieldIdx(field_idx_acc),
            access_flags,
        });
    }

    let mut instance_fields = Vec::with_capacity(instance_fields_size);
    field_idx_acc = 0;
    for _ in 0..instance_fields_size {
        let (diff, len) = mutf8::read_uleb128(data, pos)?;
        pos = safe_add(pos, len, "parse_class_data:instance_fields:diff_len")?;
        field_idx_acc = field_idx_acc.checked_add(diff).ok_or_else(|| {
            DexError::InvalidInstruction {
                offset: class_data_off,
                detail: format!(
                    "instance_fields field_idx_diff accumulator overflow: {field_idx_acc} + {diff} exceeds u32"
                ),
            }
        })?;
        let (access_flags, len) = mutf8::read_uleb128(data, pos)?;
        pos = safe_add(pos, len, "parse_class_data:instance_fields:access_flags_len")?;
        let access_flags = crate::access_flags::validate(
            access_flags,
            crate::access_flags::AccessFlagScope::Field,
        )?;
        instance_fields.push(EncodedField {
            field_idx: FieldIdx(field_idx_acc),
            access_flags,
        });
    }

    let mut direct_methods = Vec::with_capacity(direct_methods_size);
    let mut method_idx_acc: u32 = 0;
    for _ in 0..direct_methods_size {
        let (diff, len) = mutf8::read_uleb128(data, pos)?;
        pos = safe_add(pos, len, "parse_class_data:direct_methods:diff_len")?;
        method_idx_acc = method_idx_acc.checked_add(diff).ok_or_else(|| {
            DexError::InvalidInstruction {
                offset: class_data_off,
                detail: format!(
                    "direct_methods method_idx_diff accumulator overflow: {method_idx_acc} + {diff} exceeds u32"
                ),
            }
        })?;
        let (access_flags, len) = mutf8::read_uleb128(data, pos)?;
        pos = safe_add(pos, len, "parse_class_data:direct_methods:access_flags_len")?;
        let access_flags = crate::access_flags::validate(
            access_flags,
            crate::access_flags::AccessFlagScope::Method,
        )?;
        let (code_off, len) = mutf8::read_uleb128(data, pos)?;
        pos = safe_add(pos, len, "parse_class_data:direct_methods:code_off_len")?;
        direct_methods.push(EncodedMethod {
            method_idx: MethodIdx(method_idx_acc),
            access_flags,
            code_off,
        });
    }

    let mut virtual_methods = Vec::with_capacity(virtual_methods_size);
    method_idx_acc = 0;
    for _ in 0..virtual_methods_size {
        let (diff, len) = mutf8::read_uleb128(data, pos)?;
        pos = safe_add(pos, len, "parse_class_data:virtual_methods:diff_len")?;
        method_idx_acc = method_idx_acc.checked_add(diff).ok_or_else(|| {
            DexError::InvalidInstruction {
                offset: class_data_off,
                detail: format!(
                    "virtual_methods method_idx_diff accumulator overflow: {method_idx_acc} + {diff} exceeds u32"
                ),
            }
        })?;
        let (access_flags, len) = mutf8::read_uleb128(data, pos)?;
        pos = safe_add(pos, len, "parse_class_data:virtual_methods:access_flags_len")?;
        let access_flags = crate::access_flags::validate(
            access_flags,
            crate::access_flags::AccessFlagScope::Method,
        )?;
        let (code_off, len) = mutf8::read_uleb128(data, pos)?;
        pos = safe_add(pos, len, "parse_class_data:virtual_methods:code_off_len")?;
        virtual_methods.push(EncodedMethod {
            method_idx: MethodIdx(method_idx_acc),
            access_flags,
            code_off,
        });
    }

    let consumed = pos.saturating_sub(start);
    Ok((
        ClassData {
            static_fields,
            instance_fields,
            direct_methods,
            virtual_methods,
        },
        consumed,
    ))
}

// ── Unit tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_insns(units: &[u16]) -> Vec<u8> {
        let mut data = Vec::with_capacity(units.len() * 2);
        for u in units {
            data.extend_from_slice(&u.to_le_bytes());
        }
        data
    }

    #[test]
    fn decode_nop() {
        let data = make_insns(&[0x0000]);
        let (insns, _, _) = decode_insns(&data, 0, 1).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].op, Opcode::Nop);
        assert_eq!(insns[0].size, 1);
    }

    #[test]
    fn decode_return_void() {
        let data = make_insns(&[0x000E]);
        let (insns, _, _) = decode_insns(&data, 0, 1).unwrap();
        assert_eq!(insns[0].op, Opcode::ReturnVoid);
    }

    #[test]
    fn decode_move_f12x() {
        // move v0, v1 → op=0x01, A=0, B=1 → unit = 0x1001
        let data = make_insns(&[0x1001]);
        let (insns, _, _) = decode_insns(&data, 0, 1).unwrap();
        assert_eq!(insns[0].op, Opcode::Move);
        assert_eq!(insns[0].dst, Some(0));
        assert_eq!(insns[0].src.as_slice(), &[1]);
    }

    #[test]
    fn decode_const4_f11n() {
        // const/4 v0, #-1 → op=0x12, A=0, B=0xF → unit = 0xF012
        let data = make_insns(&[0xF012]);
        let (insns, _, _) = decode_insns(&data, 0, 1).unwrap();
        assert_eq!(insns[0].op, Opcode::Const4);
        assert_eq!(insns[0].dst, Some(0));
        assert_eq!(insns[0].literal, -1);
    }

    #[test]
    fn decode_const4_positive() {
        // const/4 v2, #3 → op=0x12, A=2, B=3 → unit = 0x3212
        let data = make_insns(&[0x3212]);
        let (insns, _, _) = decode_insns(&data, 0, 1).unwrap();
        assert_eq!(insns[0].op, Opcode::Const4);
        assert_eq!(insns[0].dst, Some(2));
        assert_eq!(insns[0].literal, 3);
    }

    #[test]
    fn decode_return_f11x() {
        // return v5 → op=0x0F, AA=5 → unit = 0x050F
        let data = make_insns(&[0x050F]);
        let (insns, _, _) = decode_insns(&data, 0, 1).unwrap();
        assert_eq!(insns[0].op, Opcode::Return);
        assert_eq!(insns[0].dst, Some(5));
    }

    #[test]
    fn decode_goto_f10t() {
        // goto +3 → op=0x28, AA=3 → unit = 0x0328
        let data = make_insns(&[0x0328]);
        let (insns, _, _) = decode_insns(&data, 0, 1).unwrap();
        assert_eq!(insns[0].op, Opcode::Goto);
        assert_eq!(insns[0].target, Some(3));
    }

    #[test]
    fn decode_goto_negative_f10t() {
        // goto -2 → op=0x28, AA=0xFE → unit = 0xFE28
        // pc=0, offset=-2 → underflows below 0, which is malformed.
        // Post-hardening, this returns InvalidInstruction instead of
        // silently wrapping to 0xFFFFFFFE.
        let data = make_insns(&[0xFE28]);
        let err = decode_insns(&data, 0, 1).expect_err("underflow must be rejected");
        assert!(matches!(err, crate::error::DexError::InvalidInstruction { .. }));
    }

    #[test]
    fn decode_goto_positive_offset_from_nonzero_pc_f10t() {
        // NOP at pc=0, then goto +3 at pc=1 → op=0x28, AA=3 → unit = 0x0328
        // target = pc(1) + offset(3) = 4
        let data = make_insns(&[0x0000, 0x0328]);
        let (insns, _, _) = decode_insns(&data, 0, 2).unwrap();
        assert_eq!(insns[1].op, Opcode::Goto);
        assert_eq!(insns[1].target, Some(4));
    }

    #[test]
    fn decode_const16_f21s() {
        // const/16 v0, #1234 → op=0x13, AA=0, BBBB=1234
        let data = make_insns(&[0x0013, 1234]);
        let (insns, _, _) = decode_insns(&data, 0, 2).unwrap();
        assert_eq!(insns[0].op, Opcode::Const16);
        assert_eq!(insns[0].dst, Some(0));
        assert_eq!(insns[0].literal, 1234);
    }

    #[test]
    fn decode_const_string_f21c() {
        // const-string v1, string@0x000F → op=0x1A, AA=1, BBBB=0x0F
        let data = make_insns(&[0x011A, 0x000F]);
        let (insns, _, _) = decode_insns(&data, 0, 2).unwrap();
        assert_eq!(insns[0].op, Opcode::ConstString);
        assert_eq!(insns[0].dst, Some(1));
        assert_eq!(insns[0].pool_idx, Some(PoolIndex::String(StringIdx(0x0F))));
    }

    #[test]
    fn decode_iget_f22c() {
        // iget v0, v1, field@0000 → op=0x52, A=0, B=1, CCCC=0
        let data = make_insns(&[0x1052, 0x0000]);
        let (insns, _, _) = decode_insns(&data, 0, 2).unwrap();
        assert_eq!(insns[0].op, Opcode::Iget);
        assert_eq!(insns[0].dst, Some(0));
        assert_eq!(insns[0].src.as_slice(), &[1]);
        assert_eq!(insns[0].pool_idx, Some(PoolIndex::Field(FieldIdx(0))));
    }

    #[test]
    fn decode_add_int_f23x() {
        // add-int v0, v1, v2 → op=0x90, AA=0, BB=1, CC=2
        let data = make_insns(&[0x0090, 0x0201]);
        let (insns, _, _) = decode_insns(&data, 0, 2).unwrap();
        assert_eq!(insns[0].op, Opcode::AddInt);
        assert_eq!(insns[0].dst, Some(0));
        assert_eq!(insns[0].src.as_slice(), &[1, 2]);
    }

    #[test]
    fn decode_if_eq_f22t() {
        // if-eq v0, v1, +5 → op=0x32, A=0, B=1, CCCC=5
        let data = make_insns(&[0x1032, 0x0005]);
        let (insns, _, _) = decode_insns(&data, 0, 2).unwrap();
        assert_eq!(insns[0].op, Opcode::IfEq);
        assert_eq!(insns[0].src.as_slice(), &[0, 1]);
        assert_eq!(insns[0].target, Some(5));
    }

    #[test]
    fn decode_invoke_virtual_f35c() {
        // invoke-virtual {v0, v1}, method@0006
        // op=0x6E, A=2(count), G=0(unused for count<5)
        // u0 = 0x206E, u1 = 0x0006, u2 = 0x0010 (C=0,D=1)
        let data = make_insns(&[0x206E, 0x0006, 0x0010]);
        let (insns, _, _) = decode_insns(&data, 0, 3).unwrap();
        assert_eq!(insns[0].op, Opcode::InvokeVirtual);
        assert_eq!(insns[0].src.as_slice(), &[0, 1]);
        assert_eq!(insns[0].pool_idx, Some(PoolIndex::Method(MethodIdx(6))));
    }

    #[test]
    fn decode_invoke_direct_f35c_one_arg() {
        // invoke-direct {v0}, method@0003
        // op=0x70, count=1, G=0
        // u0 = 0x1070, u1 = 0x0003, u2 = 0x0000 (C=0)
        let data = make_insns(&[0x1070, 0x0003, 0x0000]);
        let (insns, _, _) = decode_insns(&data, 0, 3).unwrap();
        assert_eq!(insns[0].op, Opcode::InvokeDirect);
        assert_eq!(insns[0].src.as_slice(), &[0]);
        assert_eq!(insns[0].pool_idx, Some(PoolIndex::Method(MethodIdx(3))));
    }

    #[test]
    fn decode_const_wide_f51l() {
        // const-wide v0, #0x0000000000010000 (65536)
        // op=0x18, AA=0, units: 0x0000, 0x0001, 0x0000, 0x0000
        let data = make_insns(&[0x0018, 0x0000, 0x0001, 0x0000, 0x0000]);
        let (insns, _, _) = decode_insns(&data, 0, 5).unwrap();
        assert_eq!(insns[0].op, Opcode::ConstWide);
        assert_eq!(insns[0].dst, Some(0));
        assert_eq!(insns[0].literal, 0x0001_0000i64);
    }

    #[test]
    fn decode_sequence() {
        // iget v0, v1, field@0000 (2 units)
        // return v0 (1 unit)
        let data = make_insns(&[0x1052, 0x0000, 0x000F]);
        let (insns, _, _) = decode_insns(&data, 0, 3).unwrap();
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].op, Opcode::Iget);
        assert_eq!(insns[0].addr, 0);
        assert_eq!(insns[1].op, Opcode::Return);
        assert_eq!(insns[1].addr, 2);
    }

    #[test]
    fn read_unit_overflow_surfaces_typed_err() {
        // Pins the Critical-3 `read_unit` checked-arithmetic site: an
        // `insns_off` near `usize::MAX` would silently wrap on bare `+`,
        // producing a small-looking-but-wrong `off` that passes the
        // subsequent `pread_with::<u16>` bounds check and reads the wrong
        // bytes. The `checked_add` surfaces the overflow as a typed
        // `DexError::ArithmeticOverflow` instead.
        let data = [0u8; 4];
        let err = read_unit(&data, usize::MAX, 0, 1).unwrap_err();
        assert!(
            matches!(err, DexError::ArithmeticOverflow { .. }),
            "expected ArithmeticOverflow, got {err:?}"
        );
    }

    // ── EmptyTryRegion gauge — try_item.insn_count == 0 ──────────────

    /// Build a minimal `code_item` byte stream with `tries_size = 1`
    /// and a single try_item at the given `(start_addr, insn_count)`,
    /// followed by an empty `encoded_catch_handler_list` (handler_size
    /// = 0). The code_item itself uses `insns_size = 4` (one nop pair)
    /// so the empty-try check fires regardless of range.
    fn make_code_item_one_try(start_addr: u32, insn_count: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        // code_item header (16 bytes):
        //   registers_size = 1
        buf.extend_from_slice(&1u16.to_le_bytes());
        //   ins_size = 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        //   outs_size = 0
        buf.extend_from_slice(&0u16.to_le_bytes());
        //   tries_size = 1
        buf.extend_from_slice(&1u16.to_le_bytes());
        //   debug_info_off = 0
        buf.extend_from_slice(&0u32.to_le_bytes());
        //   insns_size = 2 (one 4-byte `nop` is 2 code units; here we
        //   use 2 to give the existing range check headroom)
        buf.extend_from_slice(&2u32.to_le_bytes());
        // insns[0..2]: 2 code units = 4 bytes (zero-filled = nop nop)
        buf.extend_from_slice(&[0u8; 4]);
        // try_item (8 bytes):
        //   start_addr (u32)
        buf.extend_from_slice(&start_addr.to_le_bytes());
        //   insn_count (u16)
        buf.extend_from_slice(&insn_count.to_le_bytes());
        //   handler_off (u16 from encoded_catch_handler_list start)
        buf.extend_from_slice(&0u16.to_le_bytes());
        // encoded_catch_handler_list: handlers_size = 0 (single ULEB byte)
        buf.push(0x00);
        buf
    }

    /// Run `parse_code_item` against a hand-crafted code_item byte
    /// stream and return the parsed CodeItem. The CodeItem carries
    /// its own `invariant_violations` vec; no separate return.
    fn parse_code_item_helper(data: &[u8]) -> CodeItem {
        super::parse_code_item(data, 0).expect("must parse")
    }

    #[test]
    fn try_item_empty_region_records_violation_and_skips() {
        // start_addr=0, insn_count=0 — the spec-empty case. Parser
        // must record EmptyTryRegion + skip the entry (tries vec is
        // empty post-parse).
        let buf = make_code_item_one_try(0, 0);
        let code = parse_code_item_helper(&buf);
        // The empty try region was SKIPPED — tries vec is empty.
        assert!(
            code.tries.is_empty(),
            "empty try region must not reach the in-IR `tries` vec; got {} entries",
            code.tries.len()
        );
        // The violation was recorded.
        assert!(
            code.invariant_violations.iter().any(|v| matches!(
                v,
                CodeItemInvariantViolation::EmptyTryRegion {
                    try_idx: 0,
                    start_addr: 0,
                }
            )),
            "expected EmptyTryRegion violation; got {:?}",
            code.invariant_violations
        );
    }

    #[test]
    fn try_item_empty_region_at_nonzero_start_addr_recorded() {
        // start_addr = 5, insn_count = 0. Still empty; violation
        // carries start_addr=5 verbatim. The current range check is
        // bypassed because `insn_count == 0` short-circuits first.
        let buf = make_code_item_one_try(5, 0);
        let code = parse_code_item_helper(&buf);
        assert!(code.tries.is_empty());
        let saw = code.invariant_violations.iter().any(|v| matches!(
            v,
            CodeItemInvariantViolation::EmptyTryRegion {
                try_idx: 0,
                start_addr: 5,
            }
        ));
        assert!(saw, "expected EmptyTryRegion(start_addr=5)");
    }

    // Non-empty in-range try regions: covered by the existing dex
    // lib test suite via real-DEX fixtures (e.g. classes.dex,
    // classes_named.dex). Constructing a minimal hand-crafted
    // encoded_catch_handler_list for a single-try non-empty test
    // would require synthesizing a full per-type-pair stream + type
    // pool entries, which is out of scope for the EmptyTryRegion
    // regression check. The empty-region path is the
    // focus and the 2 tests above pin both `start_addr = 0` and
    // `start_addr ≠ 0` shapes.

    /// Build a `code_item` with two non-empty `try_item`s at the given
    /// `(start_addr, insn_count)` pairs, both pointing at a single
    /// catch-all `encoded_catch_handler` (handler_off = 1, the first
    /// handler past the one-byte handlers_size uleb). `insns_size = 8`
    /// code units keeps both tries in range so the per-try range check
    /// stays silent and only the ordering relation is under test.
    fn make_code_item_two_tries(t0: (u32, u16), t1: (u32, u16)) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_le_bytes()); // registers_size
        buf.extend_from_slice(&0u16.to_le_bytes()); // ins_size
        buf.extend_from_slice(&0u16.to_le_bytes()); // outs_size
        buf.extend_from_slice(&2u16.to_le_bytes()); // tries_size = 2
        buf.extend_from_slice(&0u32.to_le_bytes()); // debug_info_off
        buf.extend_from_slice(&8u32.to_le_bytes()); // insns_size = 8 code units
        buf.extend_from_slice(&[0u8; 16]); // insns: 8 code units (nops)
        for (start, count) in [t0, t1] {
            buf.extend_from_slice(&start.to_le_bytes());
            buf.extend_from_slice(&count.to_le_bytes());
            buf.extend_from_slice(&1u16.to_le_bytes()); // handler_off = 1
        }
        // encoded_catch_handler_list: handlers_size = 1.
        buf.push(0x01);
        // encoded_catch_handler at rel offset 1: size = 0 (catch-all only).
        buf.push(0x00);
        // catch_all_addr = 0 (uleb).
        buf.push(0x00);
        buf
    }

    #[test]
    fn try_items_unsorted_start_addr_records_violation() {
        // try0 start_addr=4, try1 start_addr=0 — descending, so the
        // table is not sorted by start_addr.
        let code = parse_code_item_helper(&make_code_item_two_tries((4, 2), (0, 2)));
        assert!(
            code.invariant_violations.iter().any(|v| matches!(
                v,
                CodeItemInvariantViolation::TryItemsUnsortedOrOverlapping {
                    try_idx: 1,
                    prev_end: 6,
                    start_addr: 0,
                }
            )),
            "expected TryItemsUnsortedOrOverlapping(try_idx=1, prev_end=6, start_addr=0); got {:?}",
            code.invariant_violations
        );
    }

    #[test]
    fn try_items_overlapping_records_violation() {
        // try0 covers [0, 4), try1 starts at 2 — ascending start_addr but
        // overlapping: try0's end (4) is past try1's start (2).
        let code = parse_code_item_helper(&make_code_item_two_tries((0, 4), (2, 2)));
        assert!(
            code.invariant_violations.iter().any(|v| matches!(
                v,
                CodeItemInvariantViolation::TryItemsUnsortedOrOverlapping {
                    try_idx: 1,
                    prev_end: 4,
                    start_addr: 2,
                }
            )),
            "expected TryItemsUnsortedOrOverlapping(try_idx=1, prev_end=4, start_addr=2); got {:?}",
            code.invariant_violations
        );
    }

    #[test]
    fn try_items_sorted_non_overlapping_clean() {
        // try0 covers [0, 2), try1 starts at 2 — abutting but not
        // overlapping (prev_end == next start is allowed).
        let code = parse_code_item_helper(&make_code_item_two_tries((0, 2), (2, 2)));
        assert!(
            !code.invariant_violations.iter().any(|v| matches!(
                v,
                CodeItemInvariantViolation::TryItemsUnsortedOrOverlapping { .. }
            )),
            "abutting sorted tries must not flag ordering; got {:?}",
            code.invariant_violations
        );
        // And both tries reached the in-IR vec (non-empty, in-range).
        assert_eq!(code.tries.len(), 2);
    }

    mod decode_single_proptests {
        //! Structural proptests over [`decode_single`].
        //!
        //! `decode_single` carries large `#[allow(clippy::indexing_slicing)]`
        //! and `#[allow(clippy::as_conversions)]` blocks justified by the
        //! Dalvik instruction-format spec. Each PROOF block claims a
        //! dominator over the parsed input. These proptests drive the
        //! function with arbitrary byte slices, offsets, PCs, and opcodes
        //! to verify the dominators actually hold under adversarial input:
        //!
        //! - No panic on any input combination (the lint suppression's
        //!   load-bearing assumption).
        //! - `insn.addr == pc`, `insn.op == op`, and `insn.size ==
        //!   format_size(insn_format(op))` whenever decode succeeds.
        //! - Idempotency: the (Result, violations-delta) pair is
        //!   deterministic for a fixed input.
        //! - `violations` only grows; the parser never shrinks the caller's
        //!   sink. Any pushed entry must reference `source_pc == pc`.
        use super::*;
        use proptest::prelude::*;

        // Cap data length so each iteration is cheap. 512 bytes accommodates
        // every Dalvik instruction format (max 5 code units = 10 bytes) plus
        // adversarial offsets up to ~250 with room for the largest read.
        const MAX_DATA_LEN: usize = 512;

        fn arb_opcode() -> impl Strategy<Value = Opcode> {
            any::<u8>().prop_filter_map("valid Dalvik opcode byte", Opcode::from_u8)
        }

        fn arb_inputs() -> impl Strategy<Value = (Vec<u8>, usize, u32, Opcode)> {
            (
                proptest::collection::vec(any::<u8>(), 0..=MAX_DATA_LEN),
                any::<usize>(),
                any::<u32>(),
                arb_opcode(),
            )
                .prop_map(|(data, off, pc, op)| {
                    // Bound `insns_off` to a value that can plausibly produce
                    // both bounds-hits and successful reads; same for pc. The
                    // function itself bounds-checks via read_unit, so any
                    // pair is acceptable input — we just want the
                    // distribution skewed toward in-range to exercise the
                    // decode arms more often than the bounds-err arm.
                    let insns_off = if data.is_empty() { 0 } else { off % data.len().max(1) };
                    let pc_capped = pc % 256;
                    (data, insns_off, pc_capped, op)
                })
        }

        proptest! {
            #[test]
            fn no_panic((data, off, pc, op) in arb_inputs()) {
                let mut violations = Vec::new();
                // Result is intentionally ignored — the property is no-panic.
                let _ = decode_single(&data, off, pc, op, &mut violations);
            }

            #[test]
            fn ok_preserves_addr_op_size((data, off, pc, op) in arb_inputs()) {
                let mut violations = Vec::new();
                if let Ok(insn) = decode_single(&data, off, pc, op, &mut violations) {
                    prop_assert_eq!(insn.addr, pc, "addr must equal pc");
                    prop_assert_eq!(insn.op, op, "op must round-trip");
                    let expected_size = format_size(insn_format(op));
                    prop_assert_eq!(insn.size, expected_size, "size must equal format_size");
                }
            }

            #[test]
            fn idempotent((data, off, pc, op) in arb_inputs()) {
                let mut v1 = Vec::new();
                let r1 = decode_single(&data, off, pc, op, &mut v1);
                let mut v2 = Vec::new();
                let r2 = decode_single(&data, off, pc, op, &mut v2);
                // Both Result and pushed-violations are byte-for-byte equal.
                prop_assert_eq!(format!("{:?}", r1), format!("{:?}", r2));
                prop_assert_eq!(v1, v2);
            }

            #[test]
            fn violations_only_grow((data, off, pc, op) in arb_inputs()) {
                let mut violations = vec![
                    CodeItemInvariantViolation::EmptyTryRegion { try_idx: 99, start_addr: 999 },
                ];
                let pre_len = violations.len();
                let _ = decode_single(&data, off, pc, op, &mut violations);
                prop_assert!(
                    violations.len() >= pre_len,
                    "decode_single must not shrink the caller's violations sink",
                );
                // Pre-existing entry must be preserved at index 0.
                let preserved = matches!(
                    violations[0],
                    CodeItemInvariantViolation::EmptyTryRegion { try_idx: 99, start_addr: 999 },
                );
                prop_assert!(preserved, "pre-existing violation at index 0 was overwritten");
                // Any newly-pushed entry references this call's pc.
                for v in violations.iter().skip(pre_len) {
                    if let CodeItemInvariantViolation::OpcodeArgCountOutOfRange {
                        source_pc, ..
                    } = v {
                        prop_assert_eq!(*source_pc, pc);
                    }
                }
            }
        }
    }
}
