// SPDX-License-Identifier: BSD-3-Clause

#![allow(missing_docs, reason = "internal — error-variant struct fields are self-documenting by the #[error] attribute.")]
#![cfg_attr(not(test), allow(clippy::as_conversions, reason = "PROOF (bulk allow, 25 sites): emulator/mod runs a sandboxed Dalvik interpreter. Casts cluster into: (a) `u16 register-id as usize` for `Vec::get(...)` against the register file, lossless on all targets; (b) `usize as u16` for size-to-register-count narrowing, dominated by a per-constructor `assert!(size <= u16::MAX)` precondition (register file is bounded by `code.registers_size: u16` at construction); (c) `i64 literal as i32/f32/f64 bit-cast` for Dalvik-defined truncation/reassembly semantics — the cast IS the operation per the spec. Per-site PROOF refinement deferred."))]

//! Sandboxed Dalvik bytecode emulator for single-method execution.
//!
//! Implements a subset of the Dalvik instruction set sufficient for
//! executing string-deobfuscator methods (const-ops, arithmetic, move-ops,
//! branch-ops, array-ops, return, invoke-virtual/static to mocked Android
//! APIs). Execution is bounded by a hard instruction-count budget;
//! adversarial inputs cannot cause unbounded loops.
//!
//! # Design
//!
//! Operates on **raw DEX bytecode** (decoded via [`crate::decode`]) rather
//! than SSA IR. This avoids coupling to the SSA pipeline and preserves the
//! register-slot correspondence that the bytecode uses for argument passing.
//!
//! # Non-negotiables
//!
//! - No panics on adversarial input. Every register access is bounds-checked;
//!   out-of-range register → `Err(EmulatorError::RegisterOutOfRange)`.
//! - Unsupported opcodes → `Err(EmulatorError::Unsupported)`, not panic.
//! - Halt budget enforced: when `budget` instructions have executed,
//!   return `Err(EmulatorError::BudgetExceeded)`.
//! - No file I/O, no network, no system calls. Static-field writes land in
//!   a method-local map.
//! - No `unwrap()`, `expect()`, `panic!()` on any execution path in
//!   non-test code.


pub mod android_mocks;
pub mod driver;

use std::collections::BTreeMap;

use crate::decode::{CodeItem, Instruction, PoolIndex};
use crate::opcodes::Opcode;
use crate::parser::DexFile;

// Local result alias so helper functions don't need to spell out `EmulatorError` everywhere.
type EResult<T> = std::result::Result<T, EmulatorError>;

// ── Value type ──────────────────────────────────────────────────────

/// A runtime value in the emulator's register file.
///
/// Covers the types used by string-deobfuscator methods: integers
/// (including booleans and chars), wide integers, `String` literals
/// (from `const-string`), and integer arrays (from `new-array`).
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Value {
    /// A 32-bit integer (covers boolean, byte, char, short, int).
    Int(i32),
    /// A 64-bit wide integer (covers long).
    Wide(i64),
    /// A Rust `String` obtained from `const-string`.
    Str(String),
    /// An integer array (`new-array` of byte/char/int).
    Array(Vec<i32>),
    /// Uninitialized / null register slot.
    #[default]
    Void,
}

// ── Error types ─────────────────────────────────────────────────────

/// Errors produced by the emulator.
#[derive(Debug, thiserror::Error)]
pub enum EmulatorError {
    /// The instruction-count budget was exceeded; abort to prevent
    /// unbounded loops on adversarial input.
    #[error("emulator budget exceeded after {budget} instructions")]
    BudgetExceeded { budget: u32 },

    /// A register index was out of range for this method's register file.
    #[error("register {reg} out of range (register file size {size})")]
    RegisterOutOfRange { reg: u16, size: u16 },

    /// An array index was out of bounds.
    #[error("array index {index} out of bounds (array length {length})")]
    ArrayOutOfBounds { index: i32, length: usize },

    /// An opcode or feature is not supported by the emulator core.
    /// The caller should treat this as "emulation not possible" and fall back.
    #[error("unsupported: {feature}")]
    Unsupported { feature: &'static str },

    /// Division by zero.
    #[error("division by zero")]
    DivisionByZero,

    /// A `const-string` pool index was out of bounds in the DEX string pool.
    #[error("string pool index {idx} out of bounds (pool size {size})")]
    StringPoolOob { idx: u32, size: usize },

    /// The instruction stream itself is malformed (e.g., no `return` before
    /// the end of the bytecode, or a branch to a non-existent address).
    #[error("instruction stream error: {detail}")]
    InstructionError { detail: &'static str },

    /// A type mismatch: an operation expected one `Value` variant but got
    /// another (e.g., expecting `Int` but the register holds `Void`).
    #[error("type mismatch: expected {expected}, got {got}")]
    TypeMismatch {
        expected: &'static str,
        got: &'static str,
    },

    /// The `new-array` length was negative.
    #[error("negative array length {length}")]
    NegativeArrayLength { length: i32 },

    /// The `new-array` requested an allocation beyond the emulator cap.
    #[error("array length {length} exceeds emulator cap {cap}")]
    ArrayTooLarge { length: usize, cap: usize },

    /// An `invoke-*` targeted a method that is not in the Android mock
    /// layer. The caller should treat this as "emulation not possible" and
    /// fall back.
    #[error("unsupported method: {class}.{name}")]
    UnsupportedMethod { class: String, name: String },

    /// The method-index pool lookup failed (index out of bounds or missing
    /// DEX context) during invoke dispatch.
    #[error("invoke method resolution failed: {detail}")]
    InvokeResolutionError { detail: &'static str },
}

/// Maximum array allocation the emulator will service.
const ARRAY_SIZE_CAP: usize = 65_536;

// ── Register file ───────────────────────────────────────────────────

/// A flat register file indexed by Dalvik register number.
struct RegFile {
    slots: Vec<Value>,
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: RegFile is constructed via `new(size: u16)`, so `slots.len() <= u16::MAX`. Narrowing back to u16 for the RegisterOutOfRange diagnostic is exact."
)]
impl RegFile {
    fn new(size: u16) -> Self {
        Self {
            slots: vec![Value::Void; size as usize],
        }
    }

    /// Read a register; bounds-check against `slots.len()`.
    fn get(&self, reg: u16) -> EResult<&Value> {
        self.slots
            .get(reg as usize)
            .ok_or(EmulatorError::RegisterOutOfRange {
                reg,
                size: self.slots.len() as u16,
            })
    }

    /// Write a register; bounds-check against `slots.len()`.
    fn set(&mut self, reg: u16, val: Value) -> EResult<()> {
        let size = self.slots.len() as u16;
        let slot = self
            .slots
            .get_mut(reg as usize)
            .ok_or(EmulatorError::RegisterOutOfRange { reg, size })?;
        *slot = val;
        Ok(())
    }

    /// Read as `i32`; errors if the slot is not `Value::Int`.
    fn get_int(&self, reg: u16) -> EResult<i32> {
        match self.get(reg)? {
            Value::Int(v) => Ok(*v),
            other => Err(EmulatorError::TypeMismatch {
                expected: "Int",
                got: value_kind_name(other),
            }),
        }
    }
}

fn value_kind_name(v: &Value) -> &'static str {
    match v {
        Value::Int(_) => "Int",
        Value::Wide(_) => "Wide",
        Value::Str(_) => "Str",
        Value::Array(_) => "Array",
        Value::Void => "Void",
    }
}

// ── Address map ─────────────────────────────────────────────────────

/// Build a map from instruction address (in code units) to Vec index for O(1) branch lookup.
fn build_addr_map(instructions: &[Instruction]) -> BTreeMap<u32, usize> {
    instructions
        .iter()
        .enumerate()
        .map(|(i, insn)| (insn.addr, i))
        .collect()
}

// ── EmulatorCore ────────────────────────────────────────────────────

/// Sandboxed Dalvik bytecode emulator for a single method.
///
/// Does not persist state between calls; every [`EmulatorCore::execute`]
/// call starts with a fresh register file.
pub struct EmulatorCore<'dex> {
    /// The DEX file providing the string pool for `const-string` resolution.
    dex: Option<&'dex DexFile>,
}

impl<'dex> EmulatorCore<'dex> {
    /// Create an emulator with access to the DEX string pool.
    pub fn with_dex(dex: &'dex DexFile) -> Self {
        Self { dex: Some(dex) }
    }

    /// Create an emulator without a DEX string pool (for fuzz targets and
    /// unit tests that supply raw bytecode without a full DEX context).
    /// `const-string` instructions will produce `Err(Unsupported)`.
    pub fn without_dex() -> Self {
        Self { dex: None }
    }

    /// Execute `code_item` with `args` and the given instruction-count
    /// `budget`. Returns the return `Value` on success.
    ///
    /// # Arguments
    ///
    /// - `code_item`: the decoded `CodeItem` for the target method.
    /// - `args`: concrete argument tuple. Copied into the trailing
    ///   registers of the register file per the Dalvik calling convention
    ///   (arguments occupy `registers_size - ins_size` .. `registers_size`).
    /// - `budget`: maximum number of instructions to execute before
    ///   returning `Err(EmulatorError::BudgetExceeded)`.
    #[allow(clippy::arithmetic_side_effects, reason = "every arithmetic site in the opcode-dispatch body uses `wrapping_*` (DivInt/RemInt/AddInt/SubInt/MulInt + Long variants); zero-check fires before div/rem; semantics match JVM/DEX VM int wrapping. Intentional.")]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "INTENT / PROOF: opcode-dispatch body. (1) `reg_idx as u16` is bounded by the `if reg_idx < reg_size as usize` guard above, and reg_size: u16. (2) `insn.literal as i32` is on opcode dispatch where the literal originates from the wire format (8/16/32-bit signed immediates widened to i64 in the IR) — narrowing back is IDIOM. (3) ushr `((va as u32) >> (vb & 0x1F)) as i32`: DEX VM ushr semantics — unsigned-narrow, logical-shift, signed-reinterpret. (4) AgetByte/AgetShort `elem as i8 / as i16`: array element is u32 in `Value::Int`; AgetByte extracts the low byte as signed per DEX VM `aget-byte` semantics. (5) AputByte/AputShort `val as i8 / as i16`: dual of get. (6) length_usize/index_usize from i32: array indices are i32 in DEX IR; bounds checks above the cast catch negative."
    )]
    pub fn execute(
        &self,
        code_item: &CodeItem,
        args: &[Value],
        budget: u32,
    ) -> std::result::Result<Value, EmulatorError> {
        let reg_size = code_item.registers_size;
        let ins_size = code_item.ins_size;
        let mut regs = RegFile::new(reg_size);

        // Populate argument registers: trailing `ins_size` slots.
        // Per Dalvik spec: args occupy registers [registers_size - ins_size .. registers_size).
        let first_arg_reg = (reg_size as usize).saturating_sub(ins_size as usize);
        for (i, arg) in args.iter().enumerate() {
            let reg_idx = first_arg_reg.saturating_add(i);
            if reg_idx < reg_size as usize {
                regs.set(reg_idx as u16, arg.clone())?;
            }
        }

        let instructions = &code_item.instructions;
        if instructions.is_empty() {
            return Ok(Value::Void);
        }

        let addr_map = build_addr_map(instructions);
        let mut pc_idx: usize = 0;
        let mut budget_remaining = budget;
        // `move-result` staging slot — filled by invoke stubs if ever extended.
        let mut result_slot: Value = Value::Void;

        loop {
            if budget_remaining == 0 {
                return Err(EmulatorError::BudgetExceeded { budget });
            }
            budget_remaining = budget_remaining.saturating_sub(1);

            let insn = instructions
                .get(pc_idx)
                .ok_or(EmulatorError::InstructionError {
                    detail: "pc_idx out of bounds — missing return?",
                })?;

            // Advance by default; branches override below.
            let next_pc_idx = pc_idx.saturating_add(1);

            match insn.op {
                // ── No-op ────────────────────────────────────────────
                Opcode::Nop => {
                    pc_idx = next_pc_idx;
                }

                // ── Const ops ────────────────────────────────────────
                Opcode::Const4 | Opcode::Const16 | Opcode::Const | Opcode::ConstHigh16 => {
                    let dst = insn.dst.ok_or(EmulatorError::InstructionError {
                        detail: "const op missing dst",
                    })?;
                    // literal sign-extended to i64 by decoder; truncate to i32.
                    // Intentional truncation: Dalvik 32-bit const ops.
                    let val = insn.literal as i32;
                    regs.set(dst, Value::Int(val))?;
                    pc_idx = next_pc_idx;
                }

                Opcode::ConstWide16
                | Opcode::ConstWide32
                | Opcode::ConstWide
                | Opcode::ConstWideHigh16 => {
                    let dst = insn.dst.ok_or(EmulatorError::InstructionError {
                        detail: "const-wide op missing dst",
                    })?;
                    regs.set(dst, Value::Wide(insn.literal))?;
                    pc_idx = next_pc_idx;
                }

                Opcode::ConstString | Opcode::ConstStringJumbo => {
                    let dst = insn.dst.ok_or(EmulatorError::InstructionError {
                        detail: "const-string missing dst",
                    })?;
                    let idx = match insn.pool_idx {
                        Some(PoolIndex::String(s)) => s,
                        _ => {
                            return Err(EmulatorError::InstructionError {
                                detail: "const-string missing string pool index",
                            })
                        }
                    };
                    let s = match self.dex {
                        Some(dex) => {
                            let pool_size = dex.strings.len();
                            // `get_string` returns `Err(DexError::IndexOob{..})` on OOB;
                            // we reclassify to `StringPoolOob` for the emulator error surface.
                            // The `DexError` detail is subsumed: idx + pool_size are captured.
                            match dex.get_string(idx) {
                                Ok(s) => s.to_owned(),
                                Err(_dex_err) => {
                                    return Err(EmulatorError::StringPoolOob {
                                        idx: idx.0,
                                        size: pool_size,
                                    })
                                }
                            }
                        }
                        None => {
                            return Err(EmulatorError::Unsupported {
                                feature: "const-string (no DEX context)",
                            })
                        }
                    };
                    regs.set(dst, Value::Str(s))?;
                    pc_idx = next_pc_idx;
                }

                // ── Move ops ─────────────────────────────────────────
                Opcode::Move
                | Opcode::MoveFrom16
                | Opcode::Move16
                | Opcode::MoveObject
                | Opcode::MoveObjectFrom16
                | Opcode::MoveObject16
                | Opcode::MoveWide
                | Opcode::MoveWideFrom16
                | Opcode::MoveWide16 => {
                    let dst = insn.dst.ok_or(EmulatorError::InstructionError {
                        detail: "move op missing dst",
                    })?;
                    let src = insn
                        .src
                        .as_slice()
                        .first()
                        .copied()
                        .ok_or(EmulatorError::InstructionError {
                            detail: "move op missing src",
                        })?;
                    let val = regs.get(src)?.clone();
                    regs.set(dst, val)?;
                    pc_idx = next_pc_idx;
                }

                Opcode::MoveResult | Opcode::MoveResultWide | Opcode::MoveResultObject => {
                    let dst = insn.dst.ok_or(EmulatorError::InstructionError {
                        detail: "move-result missing dst",
                    })?;
                    regs.set(dst, result_slot.clone())?;
                    result_slot = Value::Void;
                    pc_idx = next_pc_idx;
                }

                // ── Return ops ───────────────────────────────────────
                Opcode::ReturnVoid => {
                    return Ok(Value::Void);
                }

                Opcode::Return | Opcode::ReturnObject | Opcode::ReturnWide => {
                    // F11x: register encoded in `dst` field.
                    let src = insn.dst.ok_or(EmulatorError::InstructionError {
                        detail: "return missing register (F11x uses dst field)",
                    })?;
                    return Ok(regs.get(src)?.clone());
                }

                // ── Arithmetic — 3-register (F23x) ───────────────────
                // Dalvik arithmetic wraps on overflow to match JVM semantics.
                Opcode::AddInt => {
                    let (dst, va, vb) = three_reg_int(insn, &regs)?;
                    // JVM wrapping add. Intentional wrap.
                    regs.set(dst, Value::Int(va.wrapping_add(vb)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::SubInt => {
                    let (dst, va, vb) = three_reg_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va.wrapping_sub(vb)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::MulInt => {
                    let (dst, va, vb) = three_reg_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va.wrapping_mul(vb)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::DivInt => {
                    let (dst, va, vb) = three_reg_int(insn, &regs)?;
                    if vb == 0 {
                        return Err(EmulatorError::DivisionByZero);
                    }
                    // i32::MIN / -1 wraps to i32::MIN in JVM. Intentional.
                    regs.set(dst, Value::Int(va.wrapping_div(vb)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::RemInt => {
                    let (dst, va, vb) = three_reg_int(insn, &regs)?;
                    if vb == 0 {
                        return Err(EmulatorError::DivisionByZero);
                    }
                    regs.set(dst, Value::Int(va.wrapping_rem(vb)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::AndInt => {
                    let (dst, va, vb) = three_reg_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va & vb))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::OrInt => {
                    let (dst, va, vb) = three_reg_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va | vb))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::XorInt => {
                    let (dst, va, vb) = three_reg_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va ^ vb))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::ShlInt => {
                    let (dst, va, vb) = three_reg_int(insn, &regs)?;
                    // JVM: shift amount masked to 5 bits. Intentional bitwise-and.
                    regs.set(dst, Value::Int(va << (vb & 0x1F)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::ShrInt => {
                    let (dst, va, vb) = three_reg_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va >> (vb & 0x1F)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::UshrInt => {
                    let (dst, va, vb) = three_reg_int(insn, &regs)?;
                    // Logical right shift. Intentional cast.
                    regs.set(dst, Value::Int(((va as u32) >> (vb & 0x1F)) as i32))?;
                    pc_idx = next_pc_idx;
                }

                // ── Arithmetic — 2addr (F12x) ─────────────────────────
                Opcode::AddInt2Addr => {
                    let (dst, va, vb) = two_addr_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va.wrapping_add(vb)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::SubInt2Addr => {
                    let (dst, va, vb) = two_addr_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va.wrapping_sub(vb)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::MulInt2Addr => {
                    let (dst, va, vb) = two_addr_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va.wrapping_mul(vb)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::DivInt2Addr => {
                    let (dst, va, vb) = two_addr_int(insn, &regs)?;
                    if vb == 0 {
                        return Err(EmulatorError::DivisionByZero);
                    }
                    regs.set(dst, Value::Int(va.wrapping_div(vb)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::RemInt2Addr => {
                    let (dst, va, vb) = two_addr_int(insn, &regs)?;
                    if vb == 0 {
                        return Err(EmulatorError::DivisionByZero);
                    }
                    regs.set(dst, Value::Int(va.wrapping_rem(vb)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::AndInt2Addr => {
                    let (dst, va, vb) = two_addr_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va & vb))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::OrInt2Addr => {
                    let (dst, va, vb) = two_addr_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va | vb))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::XorInt2Addr => {
                    let (dst, va, vb) = two_addr_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va ^ vb))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::ShlInt2Addr => {
                    let (dst, va, vb) = two_addr_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va << (vb & 0x1F)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::ShrInt2Addr => {
                    let (dst, va, vb) = two_addr_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va >> (vb & 0x1F)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::UshrInt2Addr => {
                    let (dst, va, vb) = two_addr_int(insn, &regs)?;
                    regs.set(dst, Value::Int(((va as u32) >> (vb & 0x1F)) as i32))?;
                    pc_idx = next_pc_idx;
                }

                // ── Arithmetic — lit8 (F22b) ──────────────────────────
                Opcode::AddIntLit8 => {
                    let (dst, va, lit) = lit8_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va.wrapping_add(lit)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::RsubIntLit8 => {
                    let (dst, va, lit) = lit8_int(insn, &regs)?;
                    regs.set(dst, Value::Int(lit.wrapping_sub(va)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::MulIntLit8 => {
                    let (dst, va, lit) = lit8_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va.wrapping_mul(lit)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::DivIntLit8 => {
                    let (dst, va, lit) = lit8_int(insn, &regs)?;
                    if lit == 0 {
                        return Err(EmulatorError::DivisionByZero);
                    }
                    regs.set(dst, Value::Int(va.wrapping_div(lit)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::RemIntLit8 => {
                    let (dst, va, lit) = lit8_int(insn, &regs)?;
                    if lit == 0 {
                        return Err(EmulatorError::DivisionByZero);
                    }
                    regs.set(dst, Value::Int(va.wrapping_rem(lit)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::AndIntLit8 => {
                    let (dst, va, lit) = lit8_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va & lit))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::OrIntLit8 => {
                    let (dst, va, lit) = lit8_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va | lit))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::XorIntLit8 => {
                    let (dst, va, lit) = lit8_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va ^ lit))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::ShlIntLit8 => {
                    let (dst, va, lit) = lit8_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va << (lit & 0x1F)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::ShrIntLit8 => {
                    let (dst, va, lit) = lit8_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va >> (lit & 0x1F)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::UshrIntLit8 => {
                    let (dst, va, lit) = lit8_int(insn, &regs)?;
                    regs.set(dst, Value::Int(((va as u32) >> (lit & 0x1F)) as i32))?;
                    pc_idx = next_pc_idx;
                }

                // ── Arithmetic — lit16 (F22s) ─────────────────────────
                Opcode::AddIntLit16 => {
                    let (dst, va, lit) = lit16_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va.wrapping_add(lit)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::RsubInt => {
                    // rsub-int is: dst = lit - src (reversed subtraction)
                    let (dst, va, lit) = lit16_int(insn, &regs)?;
                    regs.set(dst, Value::Int(lit.wrapping_sub(va)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::MulIntLit16 => {
                    let (dst, va, lit) = lit16_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va.wrapping_mul(lit)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::DivIntLit16 => {
                    let (dst, va, lit) = lit16_int(insn, &regs)?;
                    if lit == 0 {
                        return Err(EmulatorError::DivisionByZero);
                    }
                    regs.set(dst, Value::Int(va.wrapping_div(lit)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::RemIntLit16 => {
                    let (dst, va, lit) = lit16_int(insn, &regs)?;
                    if lit == 0 {
                        return Err(EmulatorError::DivisionByZero);
                    }
                    regs.set(dst, Value::Int(va.wrapping_rem(lit)))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::AndIntLit16 => {
                    let (dst, va, lit) = lit16_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va & lit))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::OrIntLit16 => {
                    let (dst, va, lit) = lit16_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va | lit))?;
                    pc_idx = next_pc_idx;
                }
                Opcode::XorIntLit16 => {
                    let (dst, va, lit) = lit16_int(insn, &regs)?;
                    regs.set(dst, Value::Int(va ^ lit))?;
                    pc_idx = next_pc_idx;
                }

                // ── Array ops ─────────────────────────────────────────
                Opcode::NewArray => {
                    // F22c: dst=A, src=B (length reg), pool_idx=C (type)
                    let dst = insn.dst.ok_or(EmulatorError::InstructionError {
                        detail: "new-array missing dst",
                    })?;
                    let len_reg =
                        insn.src
                            .as_slice()
                            .first()
                            .copied()
                            .ok_or(EmulatorError::InstructionError {
                                detail: "new-array missing length reg",
                            })?;
                    let length = regs.get_int(len_reg)?;
                    if length < 0 {
                        return Err(EmulatorError::NegativeArrayLength { length });
                    }
                    let length_usize = length as usize;
                    if length_usize > ARRAY_SIZE_CAP {
                        return Err(EmulatorError::ArrayTooLarge {
                            length: length_usize,
                            cap: ARRAY_SIZE_CAP,
                        });
                    }
                    regs.set(dst, Value::Array(vec![0_i32; length_usize]))?;
                    pc_idx = next_pc_idx;
                }

                Opcode::Aget
                | Opcode::AgetByte
                | Opcode::AgetChar
                | Opcode::AgetBoolean
                | Opcode::AgetShort => {
                    // F23x: dst=AA, src={BB(array), CC(index)}
                    let dst = insn.dst.ok_or(EmulatorError::InstructionError {
                        detail: "aget missing dst",
                    })?;
                    let (arr_reg, idx_reg) = two_src_regs(insn)?;
                    let index = regs.get_int(idx_reg)?;
                    if index < 0 {
                        return Err(EmulatorError::ArrayOutOfBounds {
                            index,
                            length: 0,
                        });
                    }
                    let index_usize = index as usize;
                    // Clone the array value to avoid holding an immutable borrow.
                    let arr = match regs.get(arr_reg)?.clone() {
                        Value::Array(a) => a,
                        other => {
                            return Err(EmulatorError::TypeMismatch {
                                expected: "Array",
                                got: value_kind_name(&other),
                            })
                        }
                    };
                    let elem = arr.get(index_usize).copied().ok_or(
                        EmulatorError::ArrayOutOfBounds {
                            index,
                            length: arr.len(),
                        },
                    )?;
                    let val = match insn.op {
                        Opcode::AgetByte => Value::Int(i32::from(elem as i8)),
                        Opcode::AgetChar => Value::Int(elem & 0xFFFF),
                        Opcode::AgetBoolean => Value::Int(elem & 1),
                        Opcode::AgetShort => Value::Int(i32::from(elem as i16)),
                        _ => Value::Int(elem),
                    };
                    regs.set(dst, val)?;
                    pc_idx = next_pc_idx;
                }

                Opcode::Aput
                | Opcode::AputByte
                | Opcode::AputChar
                | Opcode::AputBoolean
                | Opcode::AputShort => {
                    // F23x: dst=AA (value register), src={BB(array), CC(index)}
                    let (val_reg, arr_reg, idx_reg) = aput_regs(insn)?;
                    let val = regs.get_int(val_reg)?;
                    let index = regs.get_int(idx_reg)?;
                    if index < 0 {
                        return Err(EmulatorError::ArrayOutOfBounds {
                            index,
                            length: 0,
                        });
                    }
                    let index_usize = index as usize;
                    let masked = match insn.op {
                        Opcode::AputByte => i32::from(val as i8),
                        Opcode::AputChar => val & 0xFFFF,
                        Opcode::AputBoolean => val & 1,
                        Opcode::AputShort => i32::from(val as i16),
                        _ => val,
                    };
                    // Clone, mutate, write back to avoid aliasing with borrow.
                    let mut arr = match regs.get(arr_reg)?.clone() {
                        Value::Array(a) => a,
                        other => {
                            return Err(EmulatorError::TypeMismatch {
                                expected: "Array",
                                got: value_kind_name(&other),
                            })
                        }
                    };
                    let arr_len = arr.len();
                    let slot = arr.get_mut(index_usize).ok_or(
                        EmulatorError::ArrayOutOfBounds {
                            index,
                            length: arr_len,
                        },
                    )?;
                    *slot = masked;
                    regs.set(arr_reg, Value::Array(arr))?;
                    pc_idx = next_pc_idx;
                }

                // ── Branch ops ────────────────────────────────────────
                Opcode::IfEq
                | Opcode::IfNe
                | Opcode::IfLt
                | Opcode::IfGe
                | Opcode::IfGt
                | Opcode::IfLe => {
                    let (ra, rb) = two_src_regs(insn)?;
                    let va = regs.get_int(ra)?;
                    let vb = regs.get_int(rb)?;
                    let taken = match insn.op {
                        Opcode::IfEq => va == vb,
                        Opcode::IfNe => va != vb,
                        Opcode::IfLt => va < vb,
                        Opcode::IfGe => va >= vb,
                        Opcode::IfGt => va > vb,
                        Opcode::IfLe => va <= vb,
                        _ => false,
                    };
                    if taken {
                        let target = insn.target.ok_or(EmulatorError::InstructionError {
                            detail: "if-* branch missing target",
                        })?;
                        pc_idx = addr_map.get(&target).copied().ok_or(
                            EmulatorError::InstructionError {
                                detail: "if-* branch target not in addr_map",
                            },
                        )?;
                    } else {
                        pc_idx = next_pc_idx;
                    }
                }

                Opcode::IfEqz
                | Opcode::IfNez
                | Opcode::IfLtz
                | Opcode::IfGez
                | Opcode::IfGtz
                | Opcode::IfLez => {
                    // F21t: register encoded in `dst` field, target in `target`.
                    let ra = insn.dst.ok_or(EmulatorError::InstructionError {
                        detail: "if-*z missing register (F21t uses dst field)",
                    })?;
                    let va = regs.get_int(ra)?;
                    let taken = match insn.op {
                        Opcode::IfEqz => va == 0,
                        Opcode::IfNez => va != 0,
                        Opcode::IfLtz => va < 0,
                        Opcode::IfGez => va >= 0,
                        Opcode::IfGtz => va > 0,
                        Opcode::IfLez => va <= 0,
                        _ => false,
                    };
                    if taken {
                        let target = insn.target.ok_or(EmulatorError::InstructionError {
                            detail: "if-*z branch missing target",
                        })?;
                        pc_idx = addr_map.get(&target).copied().ok_or(
                            EmulatorError::InstructionError {
                                detail: "if-*z branch target not in addr_map",
                            },
                        )?;
                    } else {
                        pc_idx = next_pc_idx;
                    }
                }

                Opcode::Goto | Opcode::Goto16 | Opcode::Goto32 => {
                    let target = insn.target.ok_or(EmulatorError::InstructionError {
                        detail: "goto missing target",
                    })?;
                    pc_idx = addr_map.get(&target).copied().ok_or(
                        EmulatorError::InstructionError {
                            detail: "goto target not in addr_map",
                        },
                    )?;
                }

                // ── Invoke — dispatched to Android mock layer ─────────
                //
                // invoke-virtual, invoke-direct:
                //   src[0] = this-register, src[1..] = arguments.
                // invoke-static:
                //   src[0..] = all arguments (no this-register).
                //
                // Range variants are structurally equivalent but use a
                // contiguous register range; the decoder normalises them
                // into the same `src` RegList.
                //
                // Non-F35c / non-F3rc variants (invoke-polymorphic,
                // invoke-custom) are not dispatch candidates because they
                // don't target named Android API methods.
                Opcode::InvokeVirtual
                | Opcode::InvokeDirect
                | Opcode::InvokeStatic
                | Opcode::InvokeVirtualRange
                | Opcode::InvokeDirectRange
                | Opcode::InvokeStaticRange => {
                    let is_static = matches!(
                        insn.op,
                        Opcode::InvokeStatic | Opcode::InvokeStaticRange
                    );
                    let method_idx = match insn.pool_idx {
                        Some(PoolIndex::Method(m)) => m,
                        _ => {
                            return Err(EmulatorError::InvokeResolutionError {
                                detail: "invoke missing method pool index",
                            });
                        }
                    };
                    let dex = match self.dex {
                        Some(d) => d,
                        None => {
                            return Err(EmulatorError::Unsupported {
                                feature: "invoke (no DEX context)",
                            });
                        }
                    };
                    // Collect argument values from the register file.
                    // For invoke-virtual / invoke-direct: src[0] is `this`,
                    // src[1..] are the typed arguments.
                    // For invoke-static: src[0..] are all arguments.
                    let arg_regs = insn.src.as_slice();
                    let (this_val, typed_args) = if is_static {
                        let args: Vec<Value> = arg_regs
                            .iter()
                            .map(|&r| regs.get(r).cloned())
                            .collect::<EResult<Vec<_>>>()?;
                        (None, args)
                    } else {
                        let this_reg = arg_regs
                            .first()
                            .copied()
                            .ok_or(EmulatorError::InvokeResolutionError {
                                detail: "invoke-virtual missing this-register",
                            })?;
                        let this = regs.get(this_reg)?.clone();
                        let rest: Vec<Value> = arg_regs
                            .get(1..)
                            .unwrap_or(&[])
                            .iter()
                            .map(|&r| regs.get(r).cloned())
                            .collect::<EResult<Vec<_>>>()?;
                        (Some(this), rest)
                    };
                    // Dispatch through the Android mock layer. The mock
                    // returns the result value on success or an error.
                    // `UnsupportedMethod` means "not a mocked API" — the
                    // caller should handle this as "emulation not possible".
                    let dispatch_result = android_mocks::dispatch(
                        dex,
                        method_idx,
                        this_val.as_ref(),
                        &typed_args,
                    )?;
                    // For invoke-virtual on `this`-mutating methods
                    // (StringBuilder), the mock returns the updated `this`
                    // value as a side-channel via MockResult.
                    if let Some(updated_this) = dispatch_result.updated_this {
                        // Restore the updated this-value to the this-register.
                        let this_reg = insn
                            .src
                            .as_slice()
                            .first()
                            .copied()
                            .ok_or(EmulatorError::InvokeResolutionError {
                                detail: "updated_this but no this-register",
                            })?;
                        regs.set(this_reg, updated_this)?;
                    }
                    result_slot = dispatch_result.return_value;
                    pc_idx = next_pc_idx;
                }

                // ── Remaining invoke forms — no mock support ───────────
                Opcode::InvokeSuper
                | Opcode::InvokeInterface
                | Opcode::InvokeSuperRange
                | Opcode::InvokeInterfaceRange
                | Opcode::InvokePolymorphic
                | Opcode::InvokePolymorphicRange
                | Opcode::InvokeCustom
                | Opcode::InvokeCustomRange => {
                    return Err(EmulatorError::Unsupported {
                        feature: "invoke-super/interface/polymorphic/custom",
                    });
                }

                // ── Catch-block entry ─────────────────────────────────
                Opcode::MoveException => {
                    return Err(EmulatorError::Unsupported {
                        feature: "exception-handling",
                    });
                }

                // ── Everything else → Unsupported ─────────────────────
                _ => {
                    return Err(EmulatorError::Unsupported {
                        feature: "opcode-not-in-emulator-core-subset",
                    });
                }
            }
        }
    }
}

// ── Helper extractors ────────────────────────────────────────────────

/// F23x (3-register): dst=AA, src={BB, CC}. Reads VA and VB as i32.
fn three_reg_int(insn: &Instruction, regs: &RegFile) -> EResult<(u16, i32, i32)> {
    let dst = insn
        .dst
        .ok_or(EmulatorError::InstructionError { detail: "arith missing dst" })?;
    let srcs = insn.src.as_slice();
    let ra = srcs
        .first()
        .copied()
        .ok_or(EmulatorError::InstructionError { detail: "arith missing src[0]" })?;
    let rb = srcs
        .get(1)
        .copied()
        .ok_or(EmulatorError::InstructionError { detail: "arith missing src[1]" })?;
    Ok((dst, regs.get_int(ra)?, regs.get_int(rb)?))
}

/// F12x (2addr): dst/src-A = `dst` field, src-B = `src[0]`.
/// The destination register also serves as the first source.
fn two_addr_int(insn: &Instruction, regs: &RegFile) -> EResult<(u16, i32, i32)> {
    let dst = insn
        .dst
        .ok_or(EmulatorError::InstructionError { detail: "2addr missing dst" })?;
    let rb = insn
        .src
        .as_slice()
        .first()
        .copied()
        .ok_or(EmulatorError::InstructionError { detail: "2addr missing src" })?;
    Ok((dst, regs.get_int(dst)?, regs.get_int(rb)?))
}

/// F22b: dst=AA, src=BB, literal=CC (i8 sign-extended to i64 by decoder).
#[allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: F22b literal is an i8 sign-extended to i64 by the decoder, so the value fits in i32 without truncation. INTENT: matches Dalvik 8-bit-literal operand semantics."
)]
fn lit8_int(insn: &Instruction, regs: &RegFile) -> EResult<(u16, i32, i32)> {
    let dst = insn
        .dst
        .ok_or(EmulatorError::InstructionError { detail: "lit8 missing dst" })?;
    let rb = insn
        .src
        .as_slice()
        .first()
        .copied()
        .ok_or(EmulatorError::InstructionError { detail: "lit8 missing src" })?;
    // literal is sign-extended i8 stored as i64; truncate to i32.
    // Intentional truncation: Dalvik 8-bit literal operand.
    let lit = insn.literal as i32;
    Ok((dst, regs.get_int(rb)?, lit))
}

/// F22s: dst=A, src=B, literal=CC (i16 sign-extended to i64 by decoder).
#[allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: F22s literal is an i16 sign-extended to i64 by the decoder, so the value fits in i32 without truncation. INTENT: matches Dalvik 16-bit-literal operand semantics."
)]
fn lit16_int(insn: &Instruction, regs: &RegFile) -> EResult<(u16, i32, i32)> {
    let dst = insn
        .dst
        .ok_or(EmulatorError::InstructionError { detail: "lit16 missing dst" })?;
    let rb = insn
        .src
        .as_slice()
        .first()
        .copied()
        .ok_or(EmulatorError::InstructionError { detail: "lit16 missing src" })?;
    // literal is sign-extended i16 stored as i64; truncate to i32.
    let lit = insn.literal as i32;
    Ok((dst, regs.get_int(rb)?, lit))
}

/// F23x: read src[0] and src[1] register indices.
fn two_src_regs(insn: &Instruction) -> EResult<(u16, u16)> {
    let srcs = insn.src.as_slice();
    let ra = srcs
        .first()
        .copied()
        .ok_or(EmulatorError::InstructionError { detail: "missing src[0]" })?;
    let rb = srcs
        .get(1)
        .copied()
        .ok_or(EmulatorError::InstructionError { detail: "missing src[1]" })?;
    Ok((ra, rb))
}

/// aput F23x: dst = value register, src[0] = array register, src[1] = index register.
fn aput_regs(insn: &Instruction) -> EResult<(u16, u16, u16)> {
    let val_reg = insn
        .dst
        .ok_or(EmulatorError::InstructionError { detail: "aput missing val reg" })?;
    let srcs = insn.src.as_slice();
    let arr_reg = srcs
        .first()
        .copied()
        .ok_or(EmulatorError::InstructionError { detail: "aput missing arr reg" })?;
    let idx_reg = srcs
        .get(1)
        .copied()
        .ok_or(EmulatorError::InstructionError { detail: "aput missing idx reg" })?;
    Ok((val_reg, arr_reg, idx_reg))
}

// ── Public constructor helper ─────────────────────────────────────────

/// Build a minimal [`CodeItem`] from decoded instructions.
///
/// Useful for unit tests and the fuzz target that don't need a full DEX
/// file. `registers_size` must be large enough to hold all registers
/// referenced by `instructions`. `ins_size` is the number of parameter
/// registers (trailing slots).
pub fn make_code_item(
    registers_size: u16,
    ins_size: u16,
    instructions: Vec<Instruction>,
) -> CodeItem {
    CodeItem {
        registers_size,
        ins_size,
        outs_size: 0,
        debug_info_off: 0,
        instructions,
        tries: vec![],
        catch_handlers: vec![],
        payloads: BTreeMap::new(),
        invariant_violations: vec![],
    }
}

/// Build a [`CodeItem`] from decoded instructions and payloads.
///
/// Variant of [`make_code_item`] for callers (e.g. the fuzz target) that
/// also have a payload map from `decode_insns`.
pub fn make_code_item_with_payloads(
    registers_size: u16,
    ins_size: u16,
    instructions: Vec<Instruction>,
    payloads: std::collections::BTreeMap<u32, crate::decode::PayloadData>,
) -> CodeItem {
    CodeItem {
        registers_size,
        ins_size,
        outs_size: 0,
        debug_info_off: 0,
        instructions,
        tries: vec![],
        catch_handlers: vec![],
        payloads,
        invariant_violations: vec![],
    }
}

// ── Unit tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{Instruction, RegList};
    use crate::opcodes::Opcode;

    fn insn_base(addr: u32, op: Opcode) -> Instruction {
        Instruction {
            addr,
            op,
            size: 1,
            dst: None,
            src: RegList::empty(),
            literal: 0,
            target: None,
            pool_idx: None,
        }
    }

    fn insn_dst(addr: u32, op: Opcode, dst: u16) -> Instruction {
        let mut i = insn_base(addr, op);
        i.dst = Some(dst);
        i
    }

    fn insn_dst_lit(addr: u32, op: Opcode, dst: u16, literal: i64) -> Instruction {
        let mut i = insn_dst(addr, op, dst);
        i.literal = literal;
        i
    }

    fn insn_dst_src2(addr: u32, op: Opcode, dst: u16, src0: u16, src1: u16) -> Instruction {
        let mut i = insn_dst(addr, op, dst);
        i.src = RegList::two(src0, src1);
        i
    }

    fn insn_dst_src1(addr: u32, op: Opcode, dst: u16, src0: u16) -> Instruction {
        let mut i = insn_dst(addr, op, dst);
        i.src = RegList::one(src0);
        i
    }

    fn emu() -> EmulatorCore<'static> {
        EmulatorCore::without_dex()
    }

    // ── return-void ──────────────────────────────────────────────────
    #[test]
    fn test_return_void() {
        let ci = make_code_item(1, 0, vec![insn_base(0, Opcode::ReturnVoid)]);
        assert_eq!(emu().execute(&ci, &[], 100).unwrap(), Value::Void);
    }

    // ── const ops ────────────────────────────────────────────────────
    #[test]
    fn test_const4_return() {
        let load = insn_dst_lit(0, Opcode::Const4, 0, 7);
        let ret = insn_dst(1, Opcode::Return, 0);
        let ci = make_code_item(1, 0, vec![load, ret]);
        assert_eq!(emu().execute(&ci, &[], 100).unwrap(), Value::Int(7));
    }

    #[test]
    fn test_const_wide() {
        let load = insn_dst_lit(0, Opcode::ConstWide, 0, i64::MAX);
        let ret = insn_dst(5, Opcode::ReturnWide, 0);
        let ci = make_code_item(2, 0, vec![load, ret]);
        assert_eq!(emu().execute(&ci, &[], 100).unwrap(), Value::Wide(i64::MAX));
    }

    #[test]
    fn test_const_high16() {
        // const/high16 v0, 0x0001 → v0 = 0x00010000
        let load = insn_dst_lit(0, Opcode::ConstHigh16, 0, i64::from(0x0001_0000_i32));
        let ret = insn_dst(2, Opcode::Return, 0);
        let ci = make_code_item(1, 0, vec![load, ret]);
        assert_eq!(emu().execute(&ci, &[], 100).unwrap(), Value::Int(0x0001_0000));
    }

    // ── arithmetic ───────────────────────────────────────────────────
    #[test]
    fn test_add_int() {
        let c0 = insn_dst_lit(0, Opcode::Const16, 0, 10);
        let c1 = insn_dst_lit(2, Opcode::Const16, 1, 20);
        let add = insn_dst_src2(4, Opcode::AddInt, 2, 0, 1);
        let ret = insn_dst(6, Opcode::Return, 2);
        let ci = make_code_item(3, 0, vec![c0, c1, add, ret]);
        assert_eq!(emu().execute(&ci, &[], 100).unwrap(), Value::Int(30));
    }

    #[test]
    fn test_xor_int() {
        let c0 = insn_dst_lit(0, Opcode::Const16, 0, 0xFF);
        let c1 = insn_dst_lit(2, Opcode::Const16, 1, 0x0F);
        let xor = insn_dst_src2(4, Opcode::XorInt, 2, 0, 1);
        let ret = insn_dst(6, Opcode::Return, 2);
        let ci = make_code_item(3, 0, vec![c0, c1, xor, ret]);
        assert_eq!(emu().execute(&ci, &[], 100).unwrap(), Value::Int(0xF0));
    }

    #[test]
    fn test_div_by_zero() {
        let c0 = insn_dst_lit(0, Opcode::Const16, 0, 5);
        let c1 = insn_dst_lit(2, Opcode::Const16, 1, 0);
        let div = insn_dst_src2(4, Opcode::DivInt, 2, 0, 1);
        let ret = insn_dst(6, Opcode::Return, 2);
        let ci = make_code_item(3, 0, vec![c0, c1, div, ret]);
        assert!(matches!(
            emu().execute(&ci, &[], 100),
            Err(EmulatorError::DivisionByZero)
        ));
    }

    #[test]
    fn test_lit8_add() {
        // ins_size=1 → arg in v1; v1 = arg(3); v1 = v1 + 5; return v1
        let add = {
            let mut i = insn_dst(0, Opcode::AddIntLit8, 1);
            i.src = RegList::one(1);
            i.literal = 5;
            i
        };
        let ret = insn_dst(2, Opcode::Return, 1);
        let ci = make_code_item(2, 1, vec![add, ret]);
        assert_eq!(emu().execute(&ci, &[Value::Int(3)], 100).unwrap(), Value::Int(8));
    }

    #[test]
    fn test_rsub_int() {
        // rsub-int: dst = lit - src. v1 = 100 - v0
        let c0 = insn_dst_lit(0, Opcode::Const16, 0, 30);
        let rsub = {
            let mut i = insn_dst(2, Opcode::RsubInt, 1);
            i.src = RegList::one(0);
            i.literal = 100;
            i
        };
        let ret = insn_dst(4, Opcode::Return, 1);
        let ci = make_code_item(2, 0, vec![c0, rsub, ret]);
        assert_eq!(emu().execute(&ci, &[], 100).unwrap(), Value::Int(70));
    }

    #[test]
    fn test_2addr_xor() {
        // v0 ^= v1
        let c0 = insn_dst_lit(0, Opcode::Const16, 0, 0xAA);
        let c1 = insn_dst_lit(2, Opcode::Const16, 1, 0x55);
        let xor = {
            let mut i = insn_dst(4, Opcode::XorInt2Addr, 0);
            i.src = RegList::one(1);
            i
        };
        let ret = insn_dst(5, Opcode::Return, 0);
        let ci = make_code_item(2, 0, vec![c0, c1, xor, ret]);
        assert_eq!(emu().execute(&ci, &[], 100).unwrap(), Value::Int(0xFF));
    }

    // ── budget enforcement ────────────────────────────────────────────
    #[test]
    fn test_budget_exceeded() {
        // infinite loop: goto 0
        let mut goto = insn_base(0, Opcode::Goto);
        goto.target = Some(0);
        goto.size = 1;
        let ci = make_code_item(1, 0, vec![goto]);
        assert!(matches!(
            emu().execute(&ci, &[], 100),
            Err(EmulatorError::BudgetExceeded { budget: 100 })
        ));
    }

    // ── register out-of-range ─────────────────────────────────────────
    #[test]
    fn test_register_oob() {
        // return register 5, but register file size is only 2.
        let ret = insn_dst(0, Opcode::Return, 5);
        let ci = make_code_item(2, 0, vec![ret]);
        assert!(matches!(
            emu().execute(&ci, &[], 100),
            Err(EmulatorError::RegisterOutOfRange { reg: 5, size: 2 })
        ));
    }

    // ── unsupported opcode ────────────────────────────────────────────
    #[test]
    fn test_unsupported_invoke_no_pool_idx() {
        // InvokeStatic with no method pool index → InvokeResolutionError
        // (pool_idx is None; the mock dispatcher can't resolve the method).
        let invoke = insn_base(0, Opcode::InvokeStatic);
        let ci = make_code_item(1, 0, vec![invoke]);
        assert!(matches!(
            emu().execute(&ci, &[], 100),
            Err(EmulatorError::InvokeResolutionError { .. })
        ));
    }

    #[test]
    fn test_unsupported_invoke_super() {
        // invoke-super is not dispatched through the mock layer; still Unsupported.
        let invoke = insn_base(0, Opcode::InvokeSuper);
        let ci = make_code_item(1, 0, vec![invoke]);
        assert!(matches!(
            emu().execute(&ci, &[], 100),
            Err(EmulatorError::Unsupported { .. })
        ));
    }

    #[test]
    fn test_unsupported_const_string_no_dex() {
        let cs = {
            let mut i = insn_dst(0, Opcode::ConstString, 0);
            i.pool_idx = Some(crate::decode::PoolIndex::String(crate::ids::StringIdx(0)));
            i
        };
        let ci = make_code_item(1, 0, vec![cs]);
        assert!(matches!(
            emu().execute(&ci, &[], 100),
            Err(EmulatorError::Unsupported { .. })
        ));
    }

    // ── branch ops ───────────────────────────────────────────────────
    #[test]
    fn test_if_eq_taken() {
        // v0=5, v1=5; if-eq v0,v1 → addr 6; (fall) const v2=1; (taken addr 6) const v2=2; return v2
        let c0 = insn_dst_lit(0, Opcode::Const16, 0, 5);
        let c1 = insn_dst_lit(2, Opcode::Const16, 1, 5);
        let mut branch = insn_base(4, Opcode::IfEq);
        branch.src = RegList::two(0, 1);
        branch.target = Some(8);
        branch.size = 2;
        let fall_const = insn_dst_lit(6, Opcode::Const16, 2, 1); // not reached when taken
        let taken_const = insn_dst_lit(8, Opcode::Const16, 2, 2);
        let ret = insn_dst(10, Opcode::Return, 2);
        let ci = make_code_item(3, 0, vec![c0, c1, branch, fall_const, taken_const, ret]);
        assert_eq!(emu().execute(&ci, &[], 100).unwrap(), Value::Int(2));
    }

    #[test]
    fn test_if_eq_not_taken() {
        // v0=3, v1=5; if-eq v0,v1 → addr 10 (not taken); const v2=1; return v2
        // addr 10 is never reached because we return first
        let c0 = insn_dst_lit(0, Opcode::Const16, 0, 3);
        let c1 = insn_dst_lit(2, Opcode::Const16, 1, 5);
        let mut branch = insn_base(4, Opcode::IfEq);
        branch.src = RegList::two(0, 1);
        branch.target = Some(10); // target is past the return
        branch.size = 2;
        let fall_const = insn_dst_lit(6, Opcode::Const16, 2, 1); // fall-through: v2=1
        let ret = insn_dst(8, Opcode::Return, 2); // return v2 (1) before target
        let taken_const = insn_dst_lit(10, Opcode::Const16, 2, 2); // never reached
        let ret2 = insn_dst(12, Opcode::Return, 2);
        let ci = make_code_item(3, 0, vec![c0, c1, branch, fall_const, ret, taken_const, ret2]);
        assert_eq!(emu().execute(&ci, &[], 100).unwrap(), Value::Int(1));
    }

    #[test]
    fn test_if_eqz() {
        let c0 = insn_dst_lit(0, Opcode::Const16, 0, 0);
        let mut branch = insn_dst(2, Opcode::IfEqz, 0);
        branch.target = Some(6);
        branch.size = 2;
        let fall = insn_dst_lit(4, Opcode::Const16, 1, 10);
        let taken = insn_dst_lit(6, Opcode::Const16, 1, 99);
        let ret = insn_dst(8, Opcode::Return, 1);
        let ci = make_code_item(2, 0, vec![c0, branch, fall, taken, ret]);
        assert_eq!(emu().execute(&ci, &[], 100).unwrap(), Value::Int(99));
    }

    // ── array ops ────────────────────────────────────────────────────
    #[test]
    fn test_array_put_get() {
        // new int[3]; arr[1] = 99; return arr[1]
        let len_reg = insn_dst_lit(0, Opcode::Const16, 0, 3); // v0 = 3
        let mut new_arr = insn_dst(2, Opcode::NewArray, 1); // v1 = new int[v0]
        new_arr.src = RegList::one(0);
        new_arr.size = 2;
        let c_val = insn_dst_lit(4, Opcode::Const16, 2, 99); // v2 = 99
        let c_idx = insn_dst_lit(6, Opcode::Const16, 3, 1); // v3 = 1 (index)
        // aput v2, v1, v3
        let mut aput = insn_dst(8, Opcode::Aput, 2);
        aput.src = RegList::two(1, 3);
        aput.size = 2;
        // aget v4, v1, v3
        let mut aget = insn_dst(10, Opcode::Aget, 4);
        aget.src = RegList::two(1, 3);
        aget.size = 2;
        let ret = insn_dst(12, Opcode::Return, 4);
        let ci =
            make_code_item(5, 0, vec![len_reg, new_arr, c_val, c_idx, aput, aget, ret]);
        assert_eq!(emu().execute(&ci, &[], 200).unwrap(), Value::Int(99));
    }

    #[test]
    fn test_array_oob() {
        let c_len = insn_dst_lit(0, Opcode::Const16, 0, 2); // len=2
        let mut new_arr = insn_dst(2, Opcode::NewArray, 1);
        new_arr.src = RegList::one(0);
        new_arr.size = 2;
        let c_idx = insn_dst_lit(4, Opcode::Const16, 2, 5); // index 5 > len 2
        let mut aget = insn_dst(6, Opcode::Aget, 3);
        aget.src = RegList::two(1, 2);
        aget.size = 2;
        let ret = insn_dst(8, Opcode::Return, 3);
        let ci = make_code_item(4, 0, vec![c_len, new_arr, c_idx, aget, ret]);
        assert!(matches!(
            emu().execute(&ci, &[], 100),
            Err(EmulatorError::ArrayOutOfBounds { .. })
        ));
    }

    #[test]
    fn test_negative_array_length() {
        let c_len = insn_dst_lit(0, Opcode::Const16, 0, i64::from(-1_i32));
        let mut new_arr = insn_dst(2, Opcode::NewArray, 1);
        new_arr.src = RegList::one(0);
        new_arr.size = 2;
        let ret = insn_dst(4, Opcode::Return, 1);
        let ci = make_code_item(2, 0, vec![c_len, new_arr, ret]);
        assert!(matches!(
            emu().execute(&ci, &[], 100),
            Err(EmulatorError::NegativeArrayLength { length: -1 })
        ));
    }

    #[test]
    fn test_aput_byte_masks() {
        // aput-byte: stores val & 0xFF sign-extended to byte range
        let c_len = insn_dst_lit(0, Opcode::Const16, 0, 1);
        let mut new_arr = insn_dst(2, Opcode::NewArray, 1);
        new_arr.src = RegList::one(0);
        new_arr.size = 2;
        let c_val = insn_dst_lit(4, Opcode::Const16, 2, 0x1FF); // 511; as byte = -1
        let c_idx = insn_dst_lit(6, Opcode::Const16, 3, 0);
        let mut aput = insn_dst(8, Opcode::AputByte, 2);
        aput.src = RegList::two(1, 3);
        aput.size = 2;
        let mut aget = insn_dst(10, Opcode::AgetByte, 4);
        aget.src = RegList::two(1, 3);
        aget.size = 2;
        let ret = insn_dst(12, Opcode::Return, 4);
        let ci =
            make_code_item(5, 0, vec![c_len, new_arr, c_val, c_idx, aput, aget, ret]);
        // 0x1FF stored as byte → (0x1FF as i8) = -1 sign-extended = -1 as i32
        assert_eq!(emu().execute(&ci, &[], 200).unwrap(), Value::Int(-1));
    }

    // ── move ops ─────────────────────────────────────────────────────
    #[test]
    fn test_move() {
        let c0 = insn_dst_lit(0, Opcode::Const16, 0, 42);
        let mv = insn_dst_src1(2, Opcode::Move, 1, 0);
        let ret = insn_dst(4, Opcode::Return, 1);
        let ci = make_code_item(2, 0, vec![c0, mv, ret]);
        assert_eq!(emu().execute(&ci, &[], 100).unwrap(), Value::Int(42));
    }

    // ── argument passing ──────────────────────────────────────────────
    #[test]
    fn test_argument_passing() {
        // registers_size=2, ins_size=1 → arg in v1
        let add = {
            let mut i = insn_dst(0, Opcode::AddIntLit8, 0);
            i.src = RegList::one(1);
            i.literal = 10;
            i
        };
        let ret = insn_dst(2, Opcode::Return, 0);
        let ci = make_code_item(2, 1, vec![add, ret]);
        assert_eq!(
            emu().execute(&ci, &[Value::Int(5)], 100).unwrap(),
            Value::Int(15)
        );
    }

    // ── ushr (logical shift) ──────────────────────────────────────────
    #[test]
    fn test_ushr_int() {
        // -4 >>> 1 = 0x7FFFFFFE
        let c0 = insn_dst_lit(0, Opcode::Const, 0, i64::from(-4_i32));
        let c1 = insn_dst_lit(3, Opcode::Const16, 1, 1);
        let ushr = insn_dst_src2(5, Opcode::UshrInt, 2, 0, 1);
        let ret = insn_dst(7, Opcode::Return, 2);
        let ci = make_code_item(3, 0, vec![c0, c1, ushr, ret]);
        assert_eq!(
            emu().execute(&ci, &[], 100).unwrap(),
            Value::Int(0x7FFF_FFFE_u32 as i32)
        );
    }

    // ── wrapping arithmetic ───────────────────────────────────────────
    #[test]
    fn test_wrapping_add() {
        let c0 = insn_dst_lit(0, Opcode::Const, 0, i64::from(i32::MAX));
        let c1 = insn_dst_lit(3, Opcode::Const16, 1, 1);
        let add = insn_dst_src2(5, Opcode::AddInt, 2, 0, 1);
        let ret = insn_dst(7, Opcode::Return, 2);
        let ci = make_code_item(3, 0, vec![c0, c1, add, ret]);
        assert_eq!(
            emu().execute(&ci, &[], 100).unwrap(),
            Value::Int(i32::MIN) // wraps around
        );
    }
}
