// CFG-ORACLE: Dragon Book §8.4 leader-set algorithm with bytecode-specific
// exception-handler extension. Sole purpose: differential cross-check on
// production Cfg::build.
// MUST be byte-for-byte the textbook spec — do not share code with production
// Cfg::build. MUST NOT call production Instruction::decode types — own minimal
// CF-only decoder. If both implementations share a decoder, both can be wrong
// in the same way (the dangerous shared surface for a bytes-in parser).

// MAINTENANCE: This oracle covers the control-flow-affecting opcode categories
// enumerated in the cfg-builder-differential-oracle maintenance doc. The
// production CFG builder's opcode-handling sites are:
//   droidsaw-dex/src/cfg.rs:256 (find_leaders)
//   droidsaw-dex/src/cfg.rs:298 (build_blocks)
//   droidsaw-dex/src/cfg.rs:330 (add_edges)
//   droidsaw-dex/src/cfg.rs:432 (add_exception_edges)
//   droidsaw-dex/src/cfg.rs:491 (build_exception_regions)
// A build.rs gate (opcode_lockstep_check) parses both sites' match arms and
// fails if the production opcode list and the naive opcode list diverge.

// Coverage table (opcode categories):
// - Conditional branches (if-eq, if-ne, …): COVERED — two successors
// - Unconditional branches (goto, goto/16, goto/32): COVERED — one successor
// - packed-switch payload: COVERED — N+1 successors
// - sparse-switch payload: COVERED — N+1 successors
// - Exception handlers (ExceptionHandler + ExceptionCatchAll): COVERED
// - monitor-enter / monitor-exit: COVERED (no special CF semantics in production)
// - throw: COVERED — no fall-through
// - return*: COVERED — no successors
// - Non-CF instructions: COVERED — fall-through only
// - invoke* semantics (implicit throw): OUT-OF-SCOPE (same as production)

#![cfg(any(test, kani, fuzzing))]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    missing_docs,
    reason = "PROOF: arithmetic in this module operates on instruction addresses and sizes \
              bounds-checked before use. Overflow is guarded by checked_add/checked_mul; \
              as-casts from i8/i16/i32 to i32/i64 are widening (lossless). \
              Narrowing casts from i64 to i32 use checked_add or explicit range checks. \
              Sign-extends (u8 as i8, u16 as i16, u32 as i32) and addr/len narrowing \
              (byte_pos / 2 as u32) are INTENT for opcode-stream decoding and \
              bounded by DEX file-format spec (u32 file_size). \
              missing_docs: oracle module is test/fuzz-only; doc coverage not required."
)]

use std::collections::{BTreeMap, BTreeSet};

// ─── CfgShape — the oracle's comparison subject ──────────────────────────────

/// Extracted CFG shape for differential comparison.
///
/// Production CFG goes through `Cfg::to_shape()` before comparison; the naive
/// oracle returns this type directly. Cross-use accidents in test code are
/// caught at the type level (there is no `OracleCfg<Cfg>` newtype — the shape
/// is the only comparison surface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgShape {
    /// Block-leader offsets (code-unit addresses, not byte offsets).
    pub leaders: BTreeSet<u32>,
    /// Edges: (from_leader, to_leader, kind). Sorted for determinism.
    pub edges: BTreeSet<(u32, u32, EdgeKindOracle)>,
    /// Entry offset (always 0 for well-formed DEX methods).
    pub entry: u32,
    /// leader → instruction offsets in monotone-increasing order.
    pub block_instructions: BTreeMap<u32, Vec<u32>>,
}

/// Edge kind for oracle comparison — mirrors production `EdgeKind` without
/// sharing the type. Independence is intentional: shared types hide mismatches.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdgeKindOracle {
    /// Normal fall-through from a non-branch instruction or conditional branch fall-through.
    FallThrough,
    /// Unconditional or conditional branch taken.
    Branch,
    /// Switch case edge carrying the integer case key.
    SwitchCase(i32),
    /// Switch default (fall-through from switch instruction when no case matches).
    SwitchDefault,
    /// Exception handler for a typed exception. Carries the raw type-index u32
    /// (not `TypeIdx`) to avoid importing production types.
    ExceptionHandler(u32),
    /// Catch-all exception handler (no specific type).
    ExceptionCatchAll,
}

// ─── Oracle errors ────────────────────────────────────────────────────────────

/// Errors from the naive CFG oracle. Must be disjoint from production errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgOracleError {
    /// Input too short to contain a valid code_item header (< 16 bytes).
    TooShort,
    /// Arithmetic overflow computing instruction-stream bounds.
    ArithmeticOverflow { context: &'static str },
    /// A byte-offset read would go out of range.
    OutOfBounds { offset: usize },
}

// ─── Minimal instruction-size table ──────────────────────────────────────────
//
// DEX instruction format reference: AOSP dalvik/docs/dex-format.html
// Each entry maps the instruction's first-byte opcode to its size in 16-bit
// code units. This table is derived from the canonical DEX spec, NOT from
// production InsnFormat / format_size — independence is intentional.
//
// Size encoding:
//   1  = 1 code unit (2 bytes)
//   2  = 2 code units (4 bytes)
//   3  = 3 code units (6 bytes)
//   4  = 4 code units (8 bytes)
//   5  = 5 code units (10 bytes)
//   0  = variable-size payload (computed separately)
//
// Opcode byte ranges are from AOSP dex-format.html Table of opcodes.
// CF-affecting opcodes are annotated; others are sized for cursor advancement.

/// Returns the size in code units of the instruction starting at `byte_pos`
/// in `insn_bytes`. For payload pseudo-ops (first byte 0x00, second byte 0x01–0x03)
/// the payload size is computed from the payload header.
///
/// Returns `Err(OutOfBounds)` if the header bytes are unreadable.
fn insn_size_units(insn_bytes: &[u8], byte_pos: usize) -> Result<u32, CfgOracleError> {
    let b0 = *insn_bytes.get(byte_pos).ok_or(CfgOracleError::OutOfBounds { offset: byte_pos })?;

    // Payload pseudo-opcodes: first byte is 0x00, second byte identifies the type.
    if b0 == 0x00 {
        let b1_pos = byte_pos.checked_add(1).ok_or(CfgOracleError::ArithmeticOverflow { context: "payload b1" })?;
        let b1 = insn_bytes.get(b1_pos).copied().unwrap_or(0);
        return match b1 {
            0x01 => packed_switch_payload_size(insn_bytes, byte_pos), // packed-switch-payload
            0x02 => sparse_switch_payload_size(insn_bytes, byte_pos), // sparse-switch-payload
            0x03 => fill_array_data_payload_size(insn_bytes, byte_pos), // fill-array-data
            _ => Ok(1), // true NOP: 1 code unit
        };
    }

    // Regular instruction sizes by opcode byte (from DEX spec).
    // Groups are by InsnFormat:
    //   F10x (1): 0x00 nop, 0x0e return-void
    //   F12x (1): move, move-wide, move-object, unary/2addr ops, array-length
    //   F11n (1): const/4
    //   F11x (1): move-result*, monitor-*, throw, return*
    //   F10t (1): goto
    //   F20t (2): goto/16
    //   F22x (2): move/from16 variants
    //   F21t (2): if-*z
    //   F21s (2): const/16, const-wide/16
    //   F21h (2): const/high16, const-wide/high16
    //   F21c (2): const-class, check-cast, sget/sput, const-string
    //   F23x (2): cmp*, array ops
    //   F22t (2): if-*
    //   F22s (2): binary-op/lit16
    //   F22c (2): instance-of, new-array, iget/iput
    //   F22b (2): binary-op/lit8
    //   F30t (3): goto/32
    //   F32x (3): move/16 variants
    //   F31i (3): const, const-wide/32
    //   F31t (3): packed-switch, sparse-switch, fill-array-data (CF opcodes)
    //   F31c (3): const-string/jumbo
    //   F35c (3): invoke-*, filled-new-array
    //   F3rc (3): invoke-*/range, filled-new-array/range
    //   F45cc (4): invoke-polymorphic
    //   F4rcc (4): invoke-polymorphic/range
    //   F51l (5): const-wide
    Ok(match b0 {
        // 1-unit instructions
        0x00..=0x0d => 1, // nop, move*, move-result*, ...
        0x0e => 1,        // return-void [CF: terminal]
        0x0f..=0x11 => 1, // return, return-wide, return-object [CF: terminal]
        0x12 => 1,        // const/4
        0x1d => 1,        // monitor-enter
        0x1e => 1,        // monitor-exit
        0x27 => 1,        // throw [CF: terminal]
        0x28 => 1,        // goto [CF: unconditional branch]
        0x7b..=0x8f => 1, // unary ops (neg-int, not-int, conversions, ...)
        0xb0..=0xcf => 1, // binary-op/2addr
        // 2-unit instructions
        0x13 => 2,        // const/16
        0x14 => 3,        // const — actually F31i (3 units) but 0x14 is below
        0x15 => 2,        // const/high16
        0x16 => 2,        // const-wide/16
        0x17 => 3,        // const-wide/32 (F31i)
        0x19 => 2,        // const-wide/high16
        0x1a => 2,        // const-string
        0x1b => 3,        // const-string/jumbo (F31c)
        0x1c => 2,        // const-class
        0x1f => 2,        // check-cast
        0x20 => 2,        // instance-of
        0x21 => 1,        // array-length
        0x22 => 2,        // new-instance (F21c)
        0x23 => 2,        // new-array (F22c)
        0x24 => 3,        // filled-new-array (F35c)
        0x25 => 3,        // filled-new-array/range (F3rc)
        0x26 => 3,        // fill-array-data (F31t)
        0x29 => 2,        // goto/16 [CF: unconditional branch]
        0x2a => 3,        // goto/32 [CF: unconditional branch]
        0x2b => 3,        // packed-switch [CF: switch]
        0x2c => 3,        // sparse-switch [CF: switch]
        0x2d..=0x31 => 2, // cmp* (F23x)
        0x32..=0x37 => 2, // if-eq, if-ne, if-lt, if-ge, if-gt, if-le [CF: conditional]
        0x38..=0x3d => 2, // if-eqz..if-lez [CF: conditional]
        0x3e..=0x43 => 1, // (unused opcodes — treat as 1)
        0x44..=0x51 => 2, // aget*, aput* (F23x) — these are actually F23x (2 units)
        0x52..=0x5f => 2, // iget*, iput* (F22c)
        0x60..=0x6d => 2, // sget*, sput* (F21c)
        0x6e..=0x72 => 3, // invoke-* (F35c)
        0x73 => 1,        // (unused)
        0x74..=0x78 => 3, // invoke-*/range (F3rc)
        0x79..=0x7a => 1, // (unused)
        0x90..=0xaf => 2, // binary-op (F23x)
        0xd0..=0xd7 => 2, // binary-op/lit16 (F22s)
        0xd8..=0xe2 => 2, // binary-op/lit8 (F22b)
        0xe3..=0xf9 => 1, // (unused/nop — treat as 1)
        0xfa => 4,        // invoke-polymorphic (F45cc)
        0xfb => 4,        // invoke-polymorphic/range (F4rcc)
        0xfc..=0xfd => 3, // invoke-custom, invoke-custom/range (F35c / F3rc)
        0xfe..=0xff => 2, // const-method-handle, const-method-type (F21c)
        // Catch-all: unknown opcode → 1 unit to allow continuing
        #[allow(unreachable_patterns)]
        _ => 1,
    })
}

fn packed_switch_payload_size(insn_bytes: &[u8], byte_pos: usize) -> Result<u32, CfgOracleError> {
    // packed-switch-payload layout (code units):
    //   ident(u16=0x0100) + size(u16) + first_key(i32=2 code units) + targets[size](i32 each)
    //   total code units = 2 + size * 2
    let size_pos = byte_pos.checked_add(2).ok_or(CfgOracleError::ArithmeticOverflow { context: "packed size pos" })?;
    if size_pos.checked_add(1).map(|e| e >= insn_bytes.len()).unwrap_or(true) {
        return Ok(2); // truncated — return minimum
    }
    let size = u32::from(read_u16_le(insn_bytes, size_pos)?);
    let code_units = size.checked_mul(2).and_then(|x| x.checked_add(4))
        .ok_or(CfgOracleError::ArithmeticOverflow { context: "packed payload units" })?;
    Ok(code_units)
}

fn sparse_switch_payload_size(insn_bytes: &[u8], byte_pos: usize) -> Result<u32, CfgOracleError> {
    // sparse-switch-payload layout (code units):
    //   ident(u16=0x0200) + size(u16) + keys[size](i32) + targets[size](i32)
    //   total code units = 2 + size * 4
    let size_pos = byte_pos.checked_add(2).ok_or(CfgOracleError::ArithmeticOverflow { context: "sparse size pos" })?;
    if size_pos.checked_add(1).map(|e| e >= insn_bytes.len()).unwrap_or(true) {
        return Ok(2); // truncated
    }
    let size = u32::from(read_u16_le(insn_bytes, size_pos)?);
    let code_units = size.checked_mul(4).and_then(|x| x.checked_add(4))
        .ok_or(CfgOracleError::ArithmeticOverflow { context: "sparse payload units" })?;
    Ok(code_units)
}

fn fill_array_data_payload_size(insn_bytes: &[u8], byte_pos: usize) -> Result<u32, CfgOracleError> {
    // fill-array-data-payload layout (code units):
    //   ident(u16=0x0300) + element_width(u16) + size(u32=2 code units) + data[...]
    //   total code units = 4 + ceil(element_width * size / 2)
    let w_pos = byte_pos.checked_add(2).ok_or(CfgOracleError::ArithmeticOverflow { context: "fill w_pos" })?;
    let s_pos = byte_pos.checked_add(4).ok_or(CfgOracleError::ArithmeticOverflow { context: "fill s_pos" })?;
    if w_pos.checked_add(1).map(|e| e >= insn_bytes.len()).unwrap_or(true)
        || s_pos.checked_add(3).map(|e| e >= insn_bytes.len()).unwrap_or(true)
    {
        return Ok(4); // truncated
    }
    let element_width = u64::from(read_u16_le(insn_bytes, w_pos)?);
    let size = u64::from(read_u32_le(insn_bytes, s_pos)?);
    let data_bytes = element_width.checked_mul(size).ok_or(CfgOracleError::ArithmeticOverflow { context: "fill data bytes" })?;
    let data_units = data_bytes.saturating_add(1) / 2;
    let total = data_units.checked_add(4).ok_or(CfgOracleError::ArithmeticOverflow { context: "fill total" })?;
    u32::try_from(total).map_err(|_| CfgOracleError::ArithmeticOverflow { context: "fill total u32" })
}

// ─── I/O helpers ─────────────────────────────────────────────────────────────

fn read_u16_le(bytes: &[u8], pos: usize) -> Result<u16, CfgOracleError> {
    let end = pos.checked_add(1).ok_or(CfgOracleError::ArithmeticOverflow { context: "read_u16_le" })?;
    if end >= bytes.len() {
        return Err(CfgOracleError::OutOfBounds { offset: end });
    }
    Ok(u16::from_le_bytes([bytes[pos], bytes[end]]))
}

fn read_i16_le(bytes: &[u8], pos: usize) -> Result<i16, CfgOracleError> {
    Ok(read_u16_le(bytes, pos)? as i16)
}

fn read_u32_le(bytes: &[u8], pos: usize) -> Result<u32, CfgOracleError> {
    let end = pos.checked_add(3).ok_or(CfgOracleError::ArithmeticOverflow { context: "read_u32_le" })?;
    if end >= bytes.len() {
        return Err(CfgOracleError::OutOfBounds { offset: end });
    }
    Ok(u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]))
}

fn read_i32_le(bytes: &[u8], pos: usize) -> Result<i32, CfgOracleError> {
    Ok(read_u32_le(bytes, pos)? as i32)
}

// ─── CF-opcode predicates — MUST NOT reuse production is_branch/is_terminal ──

// ORACLE-OPCODE-LOCKSTEP-BEGIN
// Canonical CF opcode names tracked by this oracle.
// build.rs parses this section and cross-checks it against cfg.rs.
// If a new CF opcode is added to production, it MUST also appear here.
//
// Unconditional branches: "Goto"  "Goto16"  "Goto32"
// Switch:                 "PackedSwitch"  "SparseSwitch"
// Conditional branches:   "IfEq"  "IfNe"  "IfLt"  "IfGe"  "IfGt"  "IfLe"
//                         "IfEqz"  "IfNez"  "IfLtz"  "IfGez"  "IfGtz"  "IfLez"
// Terminals:              "Throw"  "ReturnVoid"  "Return"  "ReturnWide"  "ReturnObject"
// ORACLE-OPCODE-LOCKSTEP-END

// Unconditional branches
const OP_GOTO:    u8 = 0x28;
const OP_GOTO16:  u8 = 0x29;
const OP_GOTO32:  u8 = 0x2a;
// Switch
const OP_PACKED_SWITCH: u8 = 0x2b;
const OP_SPARSE_SWITCH: u8 = 0x2c;
// Conditional branches
const OP_IF_EQ:  u8 = 0x32;
const OP_IF_NE:  u8 = 0x33;
const OP_IF_LT:  u8 = 0x34;
const OP_IF_GE:  u8 = 0x35;
const OP_IF_GT:  u8 = 0x36;
const OP_IF_LE:  u8 = 0x37;
const OP_IF_EQZ: u8 = 0x38;
const OP_IF_NEZ: u8 = 0x39;
const OP_IF_LTZ: u8 = 0x3a;
const OP_IF_GEZ: u8 = 0x3b;
const OP_IF_GTZ: u8 = 0x3c;
const OP_IF_LEZ: u8 = 0x3d;
// Terminals
const OP_THROW:         u8 = 0x27;
const OP_RETURN_VOID:   u8 = 0x0e;
const OP_RETURN:        u8 = 0x0f;
const OP_RETURN_WIDE:   u8 = 0x10;
const OP_RETURN_OBJECT: u8 = 0x11;

fn is_uncond_branch(op: u8) -> bool {
    matches!(op, OP_GOTO | OP_GOTO16 | OP_GOTO32)
}

fn is_cond_branch(op: u8) -> bool {
    matches!(op,
        OP_IF_EQ | OP_IF_NE | OP_IF_LT | OP_IF_GE | OP_IF_GT | OP_IF_LE
        | OP_IF_EQZ | OP_IF_NEZ | OP_IF_LTZ | OP_IF_GEZ | OP_IF_GTZ | OP_IF_LEZ
    )
}

fn is_switch_op(op: u8) -> bool {
    matches!(op, OP_PACKED_SWITCH | OP_SPARSE_SWITCH)
}

fn is_terminal_op(op: u8) -> bool {
    matches!(op,
        OP_THROW | OP_RETURN_VOID | OP_RETURN | OP_RETURN_WIDE | OP_RETURN_OBJECT
    )
}

fn is_any_branch(op: u8) -> bool {
    is_uncond_branch(op) || is_cond_branch(op) || is_switch_op(op)
}

// ─── Decoded CF-relevant instruction info ────────────────────────────────────

/// CF-relevant summary of one DEX instruction. Shares no types with production.
struct NaiveInsn {
    /// Code-unit address (matches production Instruction::addr).
    addr: u32,
    /// Size in code units (matches production Instruction::size as u8).
    size: u32,
    /// First opcode byte (corrected for payload pseudo-ops).
    opcode: u8,
    /// Branch / switch payload target code-unit address.
    target: Option<u32>,
    /// packed-switch: first key (from payload at target).
    packed_first_key: Option<i32>,
    /// packed-switch: case target code-unit addresses (from payload).
    packed_targets: Vec<u32>,
    /// sparse-switch: (key, target code-unit address) pairs (from payload).
    sparse_entries: Vec<(i32, u32)>,
}

/// Decode all CF-relevant instructions from `insn_bytes` (the raw code-unit stream).
/// MUST NOT call production Instruction::decode or use production Opcode types.
fn decode_cf_insns(insn_bytes: &[u8], insns_size: u32) -> Result<Vec<NaiveInsn>, CfgOracleError> {
    let total_bytes = (insns_size as usize).checked_mul(2)
        .ok_or(CfgOracleError::ArithmeticOverflow { context: "decode_cf_insns total" })?;
    let limit = total_bytes.min(insn_bytes.len());

    let mut insns = Vec::new();
    let mut byte_pos = 0usize;

    while byte_pos < limit {
        let b0 = insn_bytes[byte_pos]; // bounds checked by `byte_pos < limit`
        let addr = (byte_pos / 2) as u32;

        // Determine opcode for classification
        let opcode = if b0 == 0x00 {
            // NOP or payload pseudo-op
            let b1 = insn_bytes.get(byte_pos + 1).copied().unwrap_or(0);
            match b1 { 0x01..=0x03 => b1, _ => 0x00 }
        } else {
            b0
        };

        let size_units = insn_size_units(insn_bytes, byte_pos)?;

        let mut insn = NaiveInsn {
            addr,
            size: size_units,
            opcode,
            target: None,
            packed_first_key: None,
            packed_targets: Vec::new(),
            sparse_entries: Vec::new(),
        };

        // Decode CF-relevant operands only
        match b0 {
            OP_GOTO => {
                // F10t: opcode_byte | rel_byte (single 16-bit code unit)
                // offset is in the second byte of the first code unit (signed i8)
                let rel_pos = byte_pos.checked_add(1).ok_or(CfgOracleError::ArithmeticOverflow { context: "goto rel" })?;
                if rel_pos < insn_bytes.len() {
                    let rel = insn_bytes[rel_pos] as i8;
                    insn.target = (addr as i32).checked_add(i32::from(rel)).and_then(|v| u32::try_from(v).ok());
                }
            }
            OP_GOTO16 => {
                // F20t: opcode_lo(u8=0x29) | 0x00 | offset_lo | offset_hi (i16 LE, code units 1..2)
                let off_pos = byte_pos.checked_add(2).ok_or(CfgOracleError::ArithmeticOverflow { context: "goto16 off" })?;
                if off_pos.checked_add(1).map(|e| e < insn_bytes.len()).unwrap_or(false) {
                    let rel = i32::from(read_i16_le(insn_bytes, off_pos)?);
                    insn.target = (addr as i32).checked_add(rel).and_then(|v| u32::try_from(v).ok());
                }
            }
            OP_GOTO32 => {
                // F30t: opcode_lo(u8=0x2a) | 0x00 | offset_0 | offset_1 | offset_2 | offset_3 (i32 LE)
                let off_pos = byte_pos.checked_add(2).ok_or(CfgOracleError::ArithmeticOverflow { context: "goto32 off" })?;
                if off_pos.checked_add(3).map(|e| e < insn_bytes.len()).unwrap_or(false) {
                    let rel = read_i32_le(insn_bytes, off_pos)?;
                    insn.target = (addr as i32).checked_add(rel).and_then(|v| u32::try_from(v).ok());
                }
            }
            OP_IF_EQZ | OP_IF_NEZ | OP_IF_LTZ | OP_IF_GEZ | OP_IF_GTZ | OP_IF_LEZ => {
                // F21t: opcode_lo | AA | BBBB_lo | BBBB_hi  (i16 offset at bytes 2-3)
                let off_pos = byte_pos.checked_add(2).ok_or(CfgOracleError::ArithmeticOverflow { context: "ifz off" })?;
                if off_pos.checked_add(1).map(|e| e < insn_bytes.len()).unwrap_or(false) {
                    let rel = i32::from(read_i16_le(insn_bytes, off_pos)?);
                    insn.target = (addr as i32).checked_add(rel).and_then(|v| u32::try_from(v).ok());
                }
            }
            OP_IF_EQ | OP_IF_NE | OP_IF_LT | OP_IF_GE | OP_IF_GT | OP_IF_LE => {
                // F22t: opcode_lo | A|B | CCCC_lo | CCCC_hi  (i16 offset at bytes 2-3)
                let off_pos = byte_pos.checked_add(2).ok_or(CfgOracleError::ArithmeticOverflow { context: "if off" })?;
                if off_pos.checked_add(1).map(|e| e < insn_bytes.len()).unwrap_or(false) {
                    let rel = i32::from(read_i16_le(insn_bytes, off_pos)?);
                    insn.target = (addr as i32).checked_add(rel).and_then(|v| u32::try_from(v).ok());
                }
            }
            OP_PACKED_SWITCH | OP_SPARSE_SWITCH => {
                // F31t: opcode_lo | AA | BBBBBBBB (i32 offset, code units 1..2)
                let off_pos = byte_pos.checked_add(2).ok_or(CfgOracleError::ArithmeticOverflow { context: "switch off" })?;
                if off_pos.checked_add(3).map(|e| e < insn_bytes.len()).unwrap_or(false) {
                    let rel = read_i32_le(insn_bytes, off_pos)?;
                    if let Some(payload_addr) = (addr as i32).checked_add(rel).and_then(|v| u32::try_from(v).ok()) {
                        insn.target = Some(payload_addr);
                        let payload_byte_pos = (payload_addr as usize).checked_mul(2)
                            .ok_or(CfgOracleError::ArithmeticOverflow { context: "payload byte pos" })?;
                        if b0 == OP_PACKED_SWITCH {
                            if let Ok((fk, tgts)) = decode_packed_payload(insn_bytes, payload_byte_pos, addr) {
                                insn.packed_first_key = Some(fk);
                                insn.packed_targets = tgts;
                            }
                        } else if let Ok(entries) = decode_sparse_payload(insn_bytes, payload_byte_pos, addr) {
                            insn.sparse_entries = entries;
                        }
                    }
                }
            }
            _ => {} // non-CF or terminal: no operand extraction needed
        }

        insns.push(insn);

        let advance = (size_units as usize).checked_mul(2)
            .ok_or(CfgOracleError::ArithmeticOverflow { context: "advance" })?;
        byte_pos = byte_pos.checked_add(advance)
            .ok_or(CfgOracleError::ArithmeticOverflow { context: "byte_pos advance" })?;
    }

    Ok(insns)
}

/// Decode packed-switch payload at `payload_byte_pos` in `insn_bytes`.
/// `switch_addr` is the code-unit address of the switch instruction (for target resolution).
/// packed-switch-payload: ident(u16=0x0100) + size(u16) + first_key(i32) + targets[size](i32)
/// Targets are relative to the switch instruction addr.
fn decode_packed_payload(
    insn_bytes: &[u8],
    payload_byte_pos: usize,
    switch_addr: u32,
) -> Result<(i32, Vec<u32>), CfgOracleError> {
    // ident at payload_byte_pos (skip — should be 0x00, 0x01)
    let size_pos = payload_byte_pos.checked_add(2).ok_or(CfgOracleError::ArithmeticOverflow { context: "packed size" })?;
    if size_pos.checked_add(1).map(|e| e >= insn_bytes.len()).unwrap_or(true) {
        return Err(CfgOracleError::OutOfBounds { offset: size_pos });
    }
    let size = read_u16_le(insn_bytes, size_pos)? as usize;
    let key_pos = payload_byte_pos.checked_add(4).ok_or(CfgOracleError::ArithmeticOverflow { context: "packed key" })?;
    if key_pos.checked_add(3).map(|e| e >= insn_bytes.len()).unwrap_or(true) {
        return Err(CfgOracleError::OutOfBounds { offset: key_pos });
    }
    let first_key = read_i32_le(insn_bytes, key_pos)?;
    let targets_start = payload_byte_pos.checked_add(8).ok_or(CfgOracleError::ArithmeticOverflow { context: "packed targets" })?;

    let count = size.min(65536);
    let mut targets = Vec::with_capacity(count);
    for j in 0..count {
        let t_pos = targets_start
            .checked_add(j.checked_mul(4).ok_or(CfgOracleError::ArithmeticOverflow { context: "packed j*4" })?)
            .ok_or(CfgOracleError::ArithmeticOverflow { context: "packed t_pos" })?;
        if t_pos.checked_add(3).map(|e| e >= insn_bytes.len()).unwrap_or(true) {
            break; // truncated payload
        }
        let rel = read_i32_le(insn_bytes, t_pos)?;
        // Target is relative to switch instruction addr
        if let Some(abs) = (switch_addr as i32).checked_add(rel).and_then(|v| u32::try_from(v).ok()) {
            targets.push(abs);
        }
    }
    Ok((first_key, targets))
}

/// Decode sparse-switch payload at `payload_byte_pos` in `insn_bytes`.
/// sparse-switch-payload: ident(u16=0x0200) + size(u16) + keys[size](i32) + targets[size](i32)
/// Targets are relative to the switch instruction addr.
fn decode_sparse_payload(
    insn_bytes: &[u8],
    payload_byte_pos: usize,
    switch_addr: u32,
) -> Result<Vec<(i32, u32)>, CfgOracleError> {
    let size_pos = payload_byte_pos.checked_add(2).ok_or(CfgOracleError::ArithmeticOverflow { context: "sparse size" })?;
    if size_pos.checked_add(1).map(|e| e >= insn_bytes.len()).unwrap_or(true) {
        return Err(CfgOracleError::OutOfBounds { offset: size_pos });
    }
    let size = read_u16_le(insn_bytes, size_pos)? as usize;
    let keys_start = payload_byte_pos.checked_add(4).ok_or(CfgOracleError::ArithmeticOverflow { context: "sparse keys" })?;
    let stride4 = size.checked_mul(4).ok_or(CfgOracleError::ArithmeticOverflow { context: "sparse stride" })?;
    let targets_start = keys_start.checked_add(stride4).ok_or(CfgOracleError::ArithmeticOverflow { context: "sparse targets" })?;

    let count = size.min(65536);
    let mut entries = Vec::with_capacity(count);
    for j in 0..count {
        let k_pos = keys_start
            .checked_add(j.checked_mul(4).ok_or(CfgOracleError::ArithmeticOverflow { context: "sparse k j*4" })?)
            .ok_or(CfgOracleError::ArithmeticOverflow { context: "sparse k_pos" })?;
        let t_pos = targets_start
            .checked_add(j.checked_mul(4).ok_or(CfgOracleError::ArithmeticOverflow { context: "sparse t j*4" })?)
            .ok_or(CfgOracleError::ArithmeticOverflow { context: "sparse t_pos" })?;
        if k_pos.checked_add(3).map(|e| e >= insn_bytes.len()).unwrap_or(true)
            || t_pos.checked_add(3).map(|e| e >= insn_bytes.len()).unwrap_or(true)
        {
            break; // truncated
        }
        let key = read_i32_le(insn_bytes, k_pos)?;
        let rel = read_i32_le(insn_bytes, t_pos)?;
        if let Some(abs) = (switch_addr as i32).checked_add(rel).and_then(|v| u32::try_from(v).ok()) {
            entries.push((key, abs));
        }
    }
    Ok(entries)
}

// ─── Exception handler decoding ───────────────────────────────────────────────

struct NaiveTryItem {
    start_addr: u32,
    end_addr: u32, // exclusive
    catches: Vec<(u32, u32)>, // (type_idx, handler_code_unit_addr)
    catch_all: Option<u32>,   // handler code-unit addr
}

fn decode_try_items(
    code_item_bytes: &[u8],
    insns_start_byte: usize,
    insns_byte_len: usize,
    tries_size: u32,
) -> Result<Vec<NaiveTryItem>, CfgOracleError> {
    if tries_size == 0 {
        return Ok(Vec::new());
    }

    // After instruction bytes: optional 2-byte alignment if insns_size is odd
    let insns_size_units = (insns_byte_len / 2) as u32;
    let padding = if !insns_size_units.is_multiple_of(2) { 2usize } else { 0 };
    let try_items_start = insns_start_byte
        .checked_add(insns_byte_len)
        .and_then(|x| x.checked_add(padding))
        .ok_or(CfgOracleError::ArithmeticOverflow { context: "try_items_start" })?;

    // Each try_item: u32 start_addr + u16 insn_count + u16 handler_off = 8 bytes
    let tries_byte_len = (tries_size as usize).checked_mul(8)
        .ok_or(CfgOracleError::ArithmeticOverflow { context: "tries_byte_len" })?;
    let handler_list_start = try_items_start.checked_add(tries_byte_len)
        .ok_or(CfgOracleError::ArithmeticOverflow { context: "handler_list_start" })?;

    let mut result = Vec::with_capacity(tries_size as usize);
    for i in 0..tries_size as usize {
        let ti_pos = try_items_start
            .checked_add(i.checked_mul(8).ok_or(CfgOracleError::ArithmeticOverflow { context: "try i*8" })?)
            .ok_or(CfgOracleError::ArithmeticOverflow { context: "try pos" })?;
        if ti_pos.checked_add(7).map(|e| e >= code_item_bytes.len()).unwrap_or(true) {
            break; // truncated
        }
        let start_addr = read_u32_le(code_item_bytes, ti_pos)?;
        let insn_count = u32::from(read_u16_le(code_item_bytes, ti_pos + 4)?);
        let handler_off = read_u16_le(code_item_bytes, ti_pos + 6)? as usize;

        let end_addr = start_addr.checked_add(insn_count)
            .ok_or(CfgOracleError::ArithmeticOverflow { context: "try end_addr" })?;
        let handler_pos = handler_list_start.checked_add(handler_off)
            .ok_or(CfgOracleError::ArithmeticOverflow { context: "handler_pos" })?;

        let (catches, catch_all) = decode_catch_handler(code_item_bytes, handler_pos)?;
        result.push(NaiveTryItem { start_addr, end_addr, catches, catch_all });
    }
    Ok(result)
}

/// (type_idx, handler_code_unit_addr) pairs + optional catch-all addr.
type CatchHandlerDecoded = (Vec<(u32, u32)>, Option<u32>);

fn decode_catch_handler(
    bytes: &[u8],
    pos: usize,
) -> Result<CatchHandlerDecoded, CfgOracleError> {
    let (size_raw, mut cursor) = read_sleb128(bytes, pos)?;
    let has_catch_all = size_raw <= 0;
    let count = (size_raw.unsigned_abs() as usize).min(65536);

    let mut catches = Vec::with_capacity(count);
    for _ in 0..count {
        let (type_idx, nc) = read_uleb128(bytes, cursor)?;
        cursor = nc;
        let (handler_addr, nc) = read_uleb128(bytes, cursor)?;
        cursor = nc;
        catches.push((type_idx, handler_addr));
    }

    let catch_all = if has_catch_all {
        let (addr, _) = read_uleb128(bytes, cursor)?;
        Some(addr)
    } else {
        None
    };
    Ok((catches, catch_all))
}

fn read_uleb128(bytes: &[u8], pos: usize) -> Result<(u32, usize), CfgOracleError> {
    let mut result = 0u32;
    let mut shift = 0u32;
    let mut cur = pos;
    loop {
        let b = *bytes.get(cur).ok_or(CfgOracleError::OutOfBounds { offset: cur })?;
        cur = cur.checked_add(1).ok_or(CfgOracleError::ArithmeticOverflow { context: "uleb" })?;
        result |= u32::from(b & 0x7f).wrapping_shl(shift);
        shift = shift.saturating_add(7);
        if b & 0x80 == 0 { break; }
        if shift >= 35 { break; }
    }
    Ok((result, cur))
}

fn read_sleb128(bytes: &[u8], pos: usize) -> Result<(i32, usize), CfgOracleError> {
    // Decode signed LEB128 per DWARF spec.
    // Accumulate bits; after the terminal byte, sign-extend if needed.
    let mut result = 0u32; // u32 accumulator avoids signed-shift UB
    let mut shift = 0u32;
    let mut cur = pos;
    // Read until the continuation bit (0x80) is clear or 5 bytes consumed.
    // Returns early on each byte read; `result` + `shift` carry the state.
    // Sign-extension uses the terminal byte's bit 6 after the loop exits.
    let terminal: u8 = loop {
        let b = *bytes.get(cur).ok_or(CfgOracleError::OutOfBounds { offset: cur })?;
        cur = cur.checked_add(1).ok_or(CfgOracleError::ArithmeticOverflow { context: "sleb" })?;
        result |= u32::from(b & 0x7f).wrapping_shl(shift);
        shift = shift.saturating_add(7);
        if b & 0x80 == 0 || shift >= 35 {
            break b;
        }
    };
    let mut signed = result as i32;
    if shift < 32 && (terminal & 0x40) != 0 {
        signed |= (!0u32 << shift) as i32;
    }
    Ok((signed, cur))
}

// ─── Main oracle entry point ──────────────────────────────────────────────────

/// Textbook Dragon Book §8.4 leader-set CFG construction oracle.
///
/// Input: raw `code_item` bytes from a DEX file (registers_size field at byte 0).
/// Decodes bytecode independently from production `Instruction::decode`.
///
/// Returns a `CfgShape` for differential comparison against
/// `Cfg::build(&code_item).to_shape()`.
///
/// **Sole purpose:** differential cross-check against production `Cfg::build`.
pub fn naive_cfg(code_item_bytes: &[u8]) -> Result<CfgShape, CfgOracleError> {
    if code_item_bytes.len() < 16 {
        return Err(CfgOracleError::TooShort);
    }

    let tries_size = u32::from(read_u16_le(code_item_bytes, 6)?);
    let insns_size = read_u32_le(code_item_bytes, 12)?;

    let insns_start: usize = 16;
    let insns_byte_len = (insns_size as usize).checked_mul(2)
        .ok_or(CfgOracleError::ArithmeticOverflow { context: "insns_byte_len" })?;
    let insns_end = insns_start.checked_add(insns_byte_len)
        .ok_or(CfgOracleError::ArithmeticOverflow { context: "insns_end" })?;

    if insns_end > code_item_bytes.len() {
        return Err(CfgOracleError::OutOfBounds { offset: insns_end });
    }

    if insns_size == 0 {
        return Ok(CfgShape {
            leaders: BTreeSet::new(),
            edges: BTreeSet::new(),
            entry: 0,
            block_instructions: BTreeMap::new(),
        });
    }

    let insn_bytes = &code_item_bytes[insns_start..insns_end];

    // ── Decode instructions ────────────────────────────────────────────────────
    let instructions = decode_cf_insns(insn_bytes, insns_size)?;

    // Build addr → instruction index map
    let addr_to_idx: BTreeMap<u32, usize> = instructions.iter().enumerate()
        .map(|(i, insn)| (insn.addr, i))
        .collect();

    // ── Find leaders (Dragon Book §8.4) ───────────────────────────────────────
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    leaders.insert(0); // Rule 1: first instruction is a leader

    for insn in &instructions {
        // Payload pseudo-ops are not real instructions — skip CF analysis
        if is_payload_opcode(insn.opcode) {
            continue;
        }

        let next_addr = insn.addr.checked_add(insn.size)
            .ok_or(CfgOracleError::ArithmeticOverflow { context: "next_addr" })?;

        // Rule 3: instruction after branch/terminal is a leader
        if is_any_branch(insn.opcode) || is_terminal_op(insn.opcode) {
            leaders.insert(next_addr);
        }

        // Rule 2: branch targets are leaders
        if is_uncond_branch(insn.opcode) || is_cond_branch(insn.opcode) {
            if let Some(t) = insn.target {
                leaders.insert(t);
            }
        }
        if is_switch_op(insn.opcode) {
            for &t in &insn.packed_targets { leaders.insert(t); }
            for &(_, t) in &insn.sparse_entries { leaders.insert(t); }
        }
    }

    // Rule 4: exception handler entries are leaders
    let try_items = decode_try_items(code_item_bytes, insns_start, insns_byte_len, tries_size)?;
    for ti in &try_items {
        for &(_, ha) in &ti.catches { leaders.insert(ha); }
        if let Some(ca) = ti.catch_all { leaders.insert(ca); }
    }

    // ── Build block_instructions ───────────────────────────────────────────────
    // Each block gets all instructions (by addr) that fall in [leader, next_leader).
    let leader_vec: Vec<u32> = leaders.iter().copied().collect();
    let mut block_instructions: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for &l in &leader_vec {
        block_instructions.insert(l, Vec::new());
    }

    for insn in &instructions {
        if is_payload_opcode(insn.opcode) {
            continue; // payload pseudo-ops are not in blocks
        }
        // The block leader for this instruction is the largest leader <= insn.addr
        if let Some((&leader, _)) = block_instructions.range(..=insn.addr).next_back() {
            block_instructions.entry(leader).or_default().push(insn.addr);
        }
    }

    // ── Add normal-flow edges ─────────────────────────────────────────────────
    let mut edges: BTreeSet<(u32, u32, EdgeKindOracle)> = BTreeSet::new();

    for &leader in &leader_vec {
        let block_insns = block_instructions.get(&leader).map(|v| v.as_slice()).unwrap_or(&[]);
        let last_addr = match block_insns.last() {
            Some(&a) => a,
            None => continue, // empty block (no real instructions)
        };
        let last = match addr_to_idx.get(&last_addr).and_then(|&i| instructions.get(i)) {
            Some(i) => i,
            None => continue,
        };
        let next_addr = match last.addr.checked_add(last.size) {
            Some(a) => a,
            None => continue,
        };

        if is_terminal_op(last.opcode) {
            continue; // no successors
        }

        if is_uncond_branch(last.opcode) {
            if let Some(t) = last.target {
                if leaders.contains(&t) {
                    edges.insert((leader, t, EdgeKindOracle::Branch));
                }
            }
            continue; // no fall-through
        }

        if is_switch_op(last.opcode) {
            // Fall-through = default edge
            if leaders.contains(&next_addr) {
                edges.insert((leader, next_addr, EdgeKindOracle::SwitchDefault));
            }
            // packed-switch case edges
            if let Some(fk) = last.packed_first_key {
                for (j, &t) in last.packed_targets.iter().enumerate() {
                    if leaders.contains(&t) {
                        let key = i64::from(fk).checked_add(j as i64)
                            .and_then(|k| i32::try_from(k).ok())
                            .ok_or(CfgOracleError::ArithmeticOverflow { context: "switch key" })?;
                        edges.insert((leader, t, EdgeKindOracle::SwitchCase(key)));
                    }
                }
            }
            // sparse-switch case edges
            for &(key, t) in &last.sparse_entries {
                if leaders.contains(&t) {
                    edges.insert((leader, t, EdgeKindOracle::SwitchCase(key)));
                }
            }
            continue;
        }

        if is_cond_branch(last.opcode) {
            if leaders.contains(&next_addr) {
                edges.insert((leader, next_addr, EdgeKindOracle::FallThrough));
            }
            if let Some(t) = last.target {
                if leaders.contains(&t) {
                    edges.insert((leader, t, EdgeKindOracle::Branch));
                }
            }
            continue;
        }

        // Non-CF: fall-through
        if leaders.contains(&next_addr) {
            edges.insert((leader, next_addr, EdgeKindOracle::FallThrough));
        }
    }

    // ── Add exception edges ────────────────────────────────────────────────────
    // Anchored to production add_exception_edges semantics:
    // For each try item, every block overlapping [try_start, try_end) gets
    // exception edges to all handlers.
    for ti in &try_items {
        let try_start = ti.start_addr;
        let try_end = ti.end_addr;

        for (idx, &block_start) in leader_vec.iter().enumerate() {
            // Determine block's exclusive end address
            let block_end: u32 = if let Some(&next_leader) = leader_vec.get(idx + 1) {
                // Production uses last_insn.addr + last_insn.size, not next_leader,
                // for block_end in the overlap check. But for non-empty blocks the
                // last instruction's end matches the next leader start.
                // For correctness we use the last instruction's end where possible.
                let block_insns = block_instructions.get(&block_start).map(|v| v.as_slice()).unwrap_or(&[]);
                match block_insns.last() {
                    Some(&last_addr) => {
                        match addr_to_idx.get(&last_addr).and_then(|&i| instructions.get(i)) {
                            Some(li) => li.addr.saturating_add(li.size),
                            None => next_leader,
                        }
                    }
                    None => next_leader,
                }
            } else {
                // Last block: end = after last instruction
                let block_insns = block_instructions.get(&block_start).map(|v| v.as_slice()).unwrap_or(&[]);
                match block_insns.last() {
                    Some(&last_addr) => {
                        match addr_to_idx.get(&last_addr).and_then(|&i| instructions.get(i)) {
                            Some(li) => li.addr.saturating_add(li.size),
                            None => block_start.saturating_add(1),
                        }
                    }
                    None => continue,
                }
            };

            // Overlap: block_start < try_end AND block_end > try_start
            if block_start < try_end && block_end > try_start {
                for &(type_idx, handler_addr) in &ti.catches {
                    if leaders.contains(&handler_addr) {
                        edges.insert((block_start, handler_addr, EdgeKindOracle::ExceptionHandler(type_idx)));
                    }
                }
                if let Some(ca) = ti.catch_all {
                    if leaders.contains(&ca) {
                        edges.insert((block_start, ca, EdgeKindOracle::ExceptionCatchAll));
                    }
                }
            }
        }
    }

    Ok(CfgShape {
        leaders,
        edges,
        entry: 0,
        block_instructions,
    })
}

fn is_payload_opcode(opcode: u8) -> bool {
    matches!(opcode, 0x01..=0x03)
}

// ─── Production adapter: Cfg::to_shape() ─────────────────────────────────────

use crate::cfg::{Cfg, EdgeKind};
use crate::ids::TypeIdx;

impl Cfg {
    /// Extract the `CfgShape` comparison subject from a production CFG.
    /// Used by differential tests to compare against the oracle's output.
    pub fn to_shape(&self) -> CfgShape {
        let leaders: BTreeSet<u32> = self.blocks.iter().map(|b| b.start_addr).collect();
        let entry_addr = self.blocks.get(self.entry.0 as usize)
            .map(|b| b.start_addr)
            .unwrap_or(0);

        let mut edges: BTreeSet<(u32, u32, EdgeKindOracle)> = BTreeSet::new();
        for block in &self.blocks {
            for edge in &block.successors {
                if let Some(tb) = self.blocks.get(edge.target.0 as usize) {
                    edges.insert((block.start_addr, tb.start_addr, edge_kind_to_oracle(&edge.kind)));
                }
            }
        }

        let mut block_instructions: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for block in &self.blocks {
            let addrs: Vec<u32> = block.instructions.iter().map(|i| i.addr).collect();
            block_instructions.insert(block.start_addr, addrs);
        }

        CfgShape { leaders, edges, entry: entry_addr, block_instructions }
    }
}

fn edge_kind_to_oracle(kind: &EdgeKind) -> EdgeKindOracle {
    match kind {
        EdgeKind::FallThrough => EdgeKindOracle::FallThrough,
        EdgeKind::Branch => EdgeKindOracle::Branch,
        EdgeKind::SwitchCase(k) => EdgeKindOracle::SwitchCase(*k),
        EdgeKind::SwitchDefault => EdgeKindOracle::SwitchDefault,
        EdgeKind::ExceptionHandler(TypeIdx(idx)) => EdgeKindOracle::ExceptionHandler(*idx),
        EdgeKind::ExceptionCatchAll => EdgeKindOracle::ExceptionCatchAll,
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::Cfg;
    use crate::decode::CodeItem;
    use crate::opcodes::Opcode;

    /// Build raw code_item bytes from instruction bytes (no try items).
    fn wrap_insns(insn_bytes: &[u8]) -> Vec<u8> {
        assert!(insn_bytes.len().is_multiple_of(2));
        let insns_size = (insn_bytes.len() / 2) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&1u16.to_le_bytes()); // registers_size
        out.extend_from_slice(&0u16.to_le_bytes()); // ins_size
        out.extend_from_slice(&0u16.to_le_bytes()); // outs_size
        out.extend_from_slice(&0u16.to_le_bytes()); // tries_size
        out.extend_from_slice(&0u32.to_le_bytes()); // debug_info_off
        out.extend_from_slice(&insns_size.to_le_bytes());
        out.extend_from_slice(insn_bytes);
        out
    }

    fn make_insn(addr: u32, op: Opcode, size: u8) -> crate::decode::Instruction {
        crate::decode::Instruction {
            addr,
            op,
            size,
            dst: None,
            src: crate::decode::RegList::empty(),
            literal: 0,
            target: None,
            pool_idx: None,
        }
    }

    fn code_no_try(instructions: Vec<crate::decode::Instruction>) -> CodeItem {
        CodeItem {
            registers_size: 2,
            ins_size: 0,
            outs_size: 0,
            debug_info_off: 0,
            instructions,
            tries: vec![],
            catch_handlers: vec![],
            payloads: std::collections::BTreeMap::new(),
            invariant_violations: vec![],
        }
    }

    // ── Category: return-void — single terminal block ─────────────────────
    #[test]
    fn return_void_terminal() {
        // return-void at addr 0: opcode 0x0e, padding byte 0x00
        let insn_bytes: &[u8] = &[0x0e, 0x00];
        let shape = naive_cfg(&wrap_insns(insn_bytes)).expect("oracle");
        let from_0: Vec<_> = shape.edges.iter().filter(|(f, _, _)| *f == 0).collect();
        assert!(from_0.is_empty(), "return-void should have no successors; got {:?}", from_0);
    }

    // ── Category: throw — terminal ────────────────────────────────────────
    #[test]
    fn throw_terminal() {
        // throw vA: F11x, opcode 0x27, reg byte
        let insn_bytes: &[u8] = &[0x27, 0x00];
        let shape = naive_cfg(&wrap_insns(insn_bytes)).expect("oracle");
        let from_0: Vec<_> = shape.edges.iter().filter(|(f, _, _)| *f == 0).collect();
        assert!(from_0.is_empty(), "throw should have no successors; got {:?}", from_0);
    }

    // ── Category: return* variants ────────────────────────────────────────
    #[test]
    fn return_variants_terminal() {
        for opcode in [0x0fu8, 0x10, 0x11] {
            let insn_bytes = vec![opcode, 0x00];
            let shape = naive_cfg(&wrap_insns(&insn_bytes)).expect("oracle");
            let from_0: Vec<_> = shape.edges.iter().filter(|(f, _, _)| *f == 0).collect();
            assert!(from_0.is_empty(), "return 0x{opcode:02x} should have no successors");
        }
    }

    // ── Category: goto — unconditional branch ────────────────────────────
    #[test]
    fn goto_branch_edge() {
        // goto +2 (addr 0): opcode 0x28 | offset(i8=+2)
        // nop (addr 1): 0x00 0x00
        // return-void (addr 2): 0x0e 0x00
        let insn_bytes: &[u8] = &[0x28, 0x02, 0x00, 0x00, 0x0e, 0x00];
        let shape = naive_cfg(&wrap_insns(insn_bytes)).expect("oracle");
        assert!(shape.leaders.contains(&0));
        assert!(shape.leaders.contains(&2), "addr 2 should be a leader; leaders={:?}", shape.leaders);
        let branch = shape.edges.iter().find(|(f, t, k)| *f == 0 && *t == 2 && matches!(k, EdgeKindOracle::Branch));
        assert!(branch.is_some(), "goto should produce Branch(0→2); edges={:?}", shape.edges);
    }

    // ── Category: if-eqz — conditional (two successors) ──────────────────
    #[test]
    fn if_eqz_two_successors() {
        // if-eqz v0, +3 (addr 0, 2 units): F21t opcode 0x38 | v0(0x00) | +3(LE i16)
        // return-void (addr 2): 0x0e 0x00
        // nop (addr 3): 0x00 0x00
        // return-void (addr 4): 0x0e 0x00
        let insn_bytes: &[u8] = &[
            0x38, 0x00, 0x03, 0x00,
            0x0e, 0x00,
            0x00, 0x00,
            0x0e, 0x00,
        ];
        let shape = naive_cfg(&wrap_insns(insn_bytes)).expect("oracle");
        let ft = shape.edges.iter().find(|(f, t, k)| *f == 0 && *t == 2 && matches!(k, EdgeKindOracle::FallThrough));
        let br = shape.edges.iter().find(|(f, t, k)| *f == 0 && *t == 3 && matches!(k, EdgeKindOracle::Branch));
        assert!(ft.is_some(), "if-eqz missing FallThrough; edges={:?}", shape.edges);
        assert!(br.is_some(), "if-eqz missing Branch; edges={:?}", shape.edges);
    }

    // ── Differential: linear code ─────────────────────────────────────────
    #[test]
    fn diff_linear() {
        let code = code_no_try(vec![
            make_insn(0, Opcode::Nop, 1),
            make_insn(1, Opcode::ReturnVoid, 1),
        ]);
        let prod = Cfg::build(&code).expect("prod").to_shape();
        // nop = 0x00 0x00; return-void = 0x0e 0x00
        let oracle = naive_cfg(&wrap_insns(&[0x00, 0x00, 0x0e, 0x00])).expect("oracle");
        assert_eq!(prod.leaders, oracle.leaders, "linear leaders");
        assert_eq!(prod.edges, oracle.edges, "linear edges");
    }

    // ── Differential: goto ────────────────────────────────────────────────
    #[test]
    fn diff_goto() {
        let mut g = make_insn(0, Opcode::Goto, 1);
        g.target = Some(2);
        let code = code_no_try(vec![g, make_insn(1, Opcode::Nop, 1), make_insn(2, Opcode::ReturnVoid, 1)]);
        let prod = Cfg::build(&code).expect("prod").to_shape();
        // goto +2 at addr 0: 0x28 0x02; nop: 0x00 0x00; return-void: 0x0e 0x00
        let oracle = naive_cfg(&wrap_insns(&[0x28, 0x02, 0x00, 0x00, 0x0e, 0x00])).expect("oracle");
        assert_eq!(prod.leaders, oracle.leaders, "goto leaders");
        assert_eq!(prod.edges, oracle.edges, "goto edges");
    }

    // ── Differential: if-eqz ─────────────────────────────────────────────
    #[test]
    fn diff_if_eqz() {
        let mut i = make_insn(0, Opcode::IfEqz, 2);
        i.dst = Some(0); i.target = Some(3);
        let code = code_no_try(vec![
            i,
            make_insn(2, Opcode::ReturnVoid, 1),
            make_insn(3, Opcode::Nop, 1),
            make_insn(4, Opcode::ReturnVoid, 1),
        ]);
        let prod = Cfg::build(&code).expect("prod").to_shape();
        let insn_bytes: &[u8] = &[0x38, 0x00, 0x03, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x0e, 0x00];
        let oracle = naive_cfg(&wrap_insns(insn_bytes)).expect("oracle");
        assert_eq!(prod.leaders, oracle.leaders, "if-eqz leaders");
        assert_eq!(prod.edges, oracle.edges, "if-eqz edges");
    }

    // ── Differential: if (two registers) ─────────────────────────────────
    #[test]
    fn diff_if_eq_two_regs() {
        // if-eq v0, v1, +2 (addr 0, 2 units): F22t 0x32 | A=0,B=1 | CCCC=+2
        // return-void (addr 2): fall-through
        // nop (addr 2... wait, addr 2 is fall-through, branch target is addr 0+2=2)
        // Actually if offset=+2, target = addr 0 + 2 = 2, which is also fall-through addr.
        // Use offset=+3: target = 3.
        // if-eq v0, v1, +3 (addr 0): 0x32, 0x10, 0x03, 0x00
        // return-void (addr 2): fall-through
        // nop (addr 3): branch target
        // return-void (addr 4)
        let mut i = make_insn(0, Opcode::IfEq, 2);
        i.dst = Some(0); i.target = Some(3);
        let code = code_no_try(vec![
            i,
            make_insn(2, Opcode::ReturnVoid, 1),
            make_insn(3, Opcode::Nop, 1),
            make_insn(4, Opcode::ReturnVoid, 1),
        ]);
        let prod = Cfg::build(&code).expect("prod").to_shape();
        // F22t: opcode(0x32) | A<<4|B(0x10 = v0,v1 — low nibble A=0, high nibble B=1) | CCCC=+3
        let insn_bytes: &[u8] = &[0x32, 0x10, 0x03, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x0e, 0x00];
        let oracle = naive_cfg(&wrap_insns(insn_bytes)).expect("oracle");
        assert_eq!(prod.leaders, oracle.leaders, "if-eq leaders");
        assert_eq!(prod.edges, oracle.edges, "if-eq edges");
    }

    // ── Differential: goto/16 ─────────────────────────────────────────────
    #[test]
    fn diff_goto16() {
        // goto/16 at addr 0 (2 units): F20t 0x29 | 0x00 | offset_lo | offset_hi
        // offset = +3: target = addr 0 + 3 = 3
        // return-void at addr 2 (unreachable)
        // nop at addr 3 (target)
        // return-void at addr 4
        let mut g = make_insn(0, Opcode::Goto16, 2);
        g.target = Some(3);
        let code = code_no_try(vec![
            g,
            make_insn(2, Opcode::ReturnVoid, 1),
            make_insn(3, Opcode::Nop, 1),
            make_insn(4, Opcode::ReturnVoid, 1),
        ]);
        let prod = Cfg::build(&code).expect("prod").to_shape();
        // F20t: 0x29 0x00 | offset_lo=0x03 offset_hi=0x00
        let insn_bytes: &[u8] = &[0x29, 0x00, 0x03, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x0e, 0x00];
        let oracle = naive_cfg(&wrap_insns(insn_bytes)).expect("oracle");
        assert_eq!(prod.leaders, oracle.leaders, "goto16 leaders");
        assert_eq!(prod.edges, oracle.edges, "goto16 edges");
    }
}
