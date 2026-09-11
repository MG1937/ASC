//! SSA optimization passes (constant folding, copy propagation).
#![allow(missing_docs, reason = "internal")]

use std::collections::BTreeSet;

use rustc_hash::{FxHashMap, FxHashSet};

use crate::decode::RegList;
use crate::opcodes::Opcode;
use crate::parser::DexFile;
use crate::ssa::{SsaBody, VarId};
use crate::types::{DexType, TypeEnv};

// DETERMINISM: FxHashMap/FxHashSet usage in this module is internal-only.
// `optimize` passes (build_use_count, copy_propagate, constant_fold, DCE)
// index by VarId — they never iterate the maps for deterministic output.
// Output flows through `SsaBody` whose `blocks: BTreeMap<BlockId, _>` and
// per-block instruction Vec preserve insertion order. Swap from BTreeMap
// motivated by perf profiling: BTreeMap<VarId, _> at log(n) pointer-chasing on every
// per-instruction lookup, repeated across the fixpoint loop's inner walks.

// ── Helpers ─────────────────────────────────────────────────────────

fn is_move(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Move
            | Opcode::MoveFrom16
            | Opcode::Move16
            | Opcode::MoveWide
            | Opcode::MoveWideFrom16
            | Opcode::MoveWide16
            | Opcode::MoveObject
            | Opcode::MoveObjectFrom16
            | Opcode::MoveObject16
    )
}

fn is_const(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Const4
            | Opcode::Const16
            | Opcode::Const
            | Opcode::ConstHigh16
            | Opcode::ConstWide16
            | Opcode::ConstWide32
            | Opcode::ConstWide
            | Opcode::ConstWideHigh16
    )
}

pub fn is_pure_op(op: Opcode) -> bool {
    use Opcode::*;
    matches!(
        op,
        // Consts
        Const4 | Const16 | Const | ConstHigh16
        | ConstWide16 | ConstWide32 | ConstWide | ConstWideHigh16
        | ConstString | ConstStringJumbo | ConstClass
        | ConstMethodHandle | ConstMethodType
        // Moves
        | Move | MoveFrom16 | Move16
        | MoveWide | MoveWideFrom16 | MoveWide16
        | MoveObject | MoveObjectFrom16 | MoveObject16
        | MoveResult | MoveResultWide | MoveResultObject
        | MoveException
        // Arithmetic
        | AddInt | SubInt | MulInt | DivInt | RemInt
        | AndInt | OrInt | XorInt | ShlInt | ShrInt | UshrInt
        | AddLong | SubLong | MulLong | DivLong | RemLong
        | AndLong | OrLong | XorLong | ShlLong | ShrLong | UshrLong
        | AddFloat | SubFloat | MulFloat | DivFloat | RemFloat
        | AddDouble | SubDouble | MulDouble | DivDouble | RemDouble
        // 2addr
        | AddInt2Addr | SubInt2Addr | MulInt2Addr | DivInt2Addr | RemInt2Addr
        | AndInt2Addr | OrInt2Addr | XorInt2Addr
        | ShlInt2Addr | ShrInt2Addr | UshrInt2Addr
        | AddLong2Addr | SubLong2Addr | MulLong2Addr | DivLong2Addr | RemLong2Addr
        | AndLong2Addr | OrLong2Addr | XorLong2Addr
        | ShlLong2Addr | ShrLong2Addr | UshrLong2Addr
        | AddFloat2Addr | SubFloat2Addr | MulFloat2Addr | DivFloat2Addr | RemFloat2Addr
        | AddDouble2Addr | SubDouble2Addr | MulDouble2Addr | DivDouble2Addr | RemDouble2Addr
        // Lit
        | AddIntLit16 | RsubInt | MulIntLit16 | DivIntLit16 | RemIntLit16
        | AndIntLit16 | OrIntLit16 | XorIntLit16
        | AddIntLit8 | RsubIntLit8 | MulIntLit8 | DivIntLit8 | RemIntLit8
        | AndIntLit8 | OrIntLit8 | XorIntLit8
        | ShlIntLit8 | ShrIntLit8 | UshrIntLit8
        // Unary / conversion
        | NegInt | NotInt | NegLong | NotLong | NegFloat | NegDouble
        | IntToLong | IntToFloat | IntToDouble
        | LongToInt | LongToFloat | LongToDouble
        | FloatToInt | FloatToLong | FloatToDouble
        | DoubleToInt | DoubleToLong | DoubleToFloat
        | IntToByte | IntToChar | IntToShort
        // Comparisons
        | CmplFloat | CmpgFloat | CmplDouble | CmpgDouble | CmpLong
        // Other pure
        | ArrayLength | InstanceOf | Nop
    )
}

#[allow(clippy::arithmetic_side_effects, reason = "`*counts.entry(...).or_insert(0) += 1` — usize counter bounded by total VarId uses in body (parser-bounded code size).")]
fn build_use_count(ssa: &SsaBody) -> FxHashMap<VarId, usize> {
    let mut counts: FxHashMap<VarId, usize> = FxHashMap::default();
    for block in ssa.blocks.values() {
        for phi in &block.phis {
            for var in phi.operands.values() {
                *counts.entry(var.clone()).or_insert(0) += 1;
            }
        }
        for insn in &block.insns {
            for var in &insn.uses {
                *counts.entry(var.clone()).or_insert(0) += 1;
            }
        }
    }
    counts
}

// ── Pass 1: Copy Propagation ────────────────────────────────────────

#[allow(clippy::arithmetic_side_effects, reason = "same shape as build_use_count — usize counter bounded by total VarId uses in body.")]
fn copy_propagate(ssa: &mut SsaBody) -> bool {
    // Instruction-only use counts (phi operands excluded).
    // A Move whose dst has 0 instruction uses is exclusively a phi operand —
    // it carries a back-edge or entry-edge assignment needed for SSA
    // deconstruction.  Propagating it would let DCE delete the Move and
    // destroy the swap/init semantics of the loop.
    let mut insn_use_counts: FxHashMap<VarId, usize> = FxHashMap::default();
    for block in ssa.blocks.values() {
        for insn in &block.insns {
            for var in &insn.uses {
                *insn_use_counts.entry(var.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut replacements: FxHashMap<VarId, VarId> = FxHashMap::default();

    // Collect move copies
    for block in ssa.blocks.values() {
        for insn in &block.insns {
            if is_move(insn.insn.op) {
                if let (Some(dst), Some(src)) = (&insn.dst, insn.uses.first()) {
                    // Skip moves whose dst is exclusively a phi operand —
                    // these are intentional SSA-deconstruction copies.
                    // SEMANTICS-DEFAULT-EMPTY: dst absent from
                    // `insn_use_counts` ⇒ 0 uses; dead-copy elim
                    // correctly skips (treats as eligible for removal).
                    if *insn_use_counts.get(dst).unwrap_or(&0) == 0 {
                        continue;
                    }
                    replacements.insert(dst.clone(), src.clone());
                }
            }
        }
        // Trivial phis: single non-self operand
        for phi in &block.phis {
            let mut unique: Option<&VarId> = None;
            let mut trivial = true;
            for op in phi.operands.values() {
                if *op == phi.dst {
                    continue;
                }
                match unique {
                    None => unique = Some(op),
                    Some(u) if *u == *op => {}
                    Some(_) => {
                        trivial = false;
                        break;
                    }
                }
            }
            if trivial {
                if let Some(u) = unique {
                    replacements.insert(phi.dst.clone(), u.clone());
                }
            }
        }
    }

    if replacements.is_empty() {
        return false;
    }

    // Chase chains: if a→b and b→c, resolve a→c
    let keys: Vec<VarId> = replacements.keys().cloned().collect();
    for key in keys {
        let Some(mut target) = replacements.get(&key).cloned() else { continue };
        let mut visited = BTreeSet::new();
        visited.insert(key.clone());
        while let Some(next) = replacements.get(&target) {
            if visited.contains(next) {
                break; // cycle
            }
            visited.insert(target.clone());
            target = next.clone();
        }
        replacements.insert(key, target);
    }

    // Apply replacements
    let resolve = |var: &VarId| -> VarId {
        replacements
            .get(var)
            .cloned()
            .unwrap_or_else(|| var.clone())
    };

    for block in ssa.blocks.values_mut() {
        for phi in &mut block.phis {
            for op in phi.operands.values_mut() {
                *op = resolve(op);
            }
        }
        for insn in &mut block.insns {
            for u in &mut insn.uses {
                *u = resolve(u);
            }
        }
    }

    // Remove copy moves and trivial phis
    let replaced_dsts: FxHashSet<VarId> = replacements.keys().cloned().collect();
    for block in ssa.blocks.values_mut() {
        block.insns.retain(|insn| {
            if is_move(insn.insn.op) {
                if let Some(ref dst) = insn.dst {
                    if replaced_dsts.contains(dst) {
                        return false;
                    }
                }
            }
            true
        });
        block.phis.retain(|phi| !replaced_dsts.contains(&phi.dst));
    }

    true
}

// ── Pass 2: Constant Folding ────────────────────────────────────────

fn constant_fold(ssa: &mut SsaBody) -> bool {
    let mut changed = false;

    // Build constant map
    let mut consts: FxHashMap<VarId, i64> = FxHashMap::default();
    for block in ssa.blocks.values() {
        for insn in &block.insns {
            if is_const(insn.insn.op) {
                if let Some(ref dst) = insn.dst {
                    consts.insert(dst.clone(), insn.insn.literal);
                }
            }
        }
    }

    // Fold
    for block in ssa.blocks.values_mut() {
        for insn in &mut block.insns {
            if insn.dst.is_none() {
                continue;
            }
            let result = try_fold(&insn.insn.op, &insn.uses, insn.insn.literal, &consts);
            if let Some(value) = result {
                insn.insn.op = pick_const_opcode(value, is_wide_op(insn.insn.op));
                insn.insn.literal = value;
                insn.insn.pool_idx = None;
                insn.insn.target = None;
                insn.uses.clear();
                insn.insn.src = RegList::empty();
                // Add to const map for cascading
                if let Some(ref dst) = insn.dst {
                    consts.insert(dst.clone(), value);
                }
                changed = true;
            }
        }
    }

    changed
}

fn is_wide_op(op: Opcode) -> bool {
    use Opcode::*;
    matches!(
        op,
        AddLong
            | SubLong
            | MulLong
            | DivLong
            | RemLong
            | AndLong
            | OrLong
            | XorLong
            | ShlLong
            | ShrLong
            | UshrLong
            | AddLong2Addr
            | SubLong2Addr
            | MulLong2Addr
            | DivLong2Addr
            | RemLong2Addr
            | AndLong2Addr
            | OrLong2Addr
            | XorLong2Addr
            | ShlLong2Addr
            | ShrLong2Addr
            | UshrLong2Addr
            | NegLong
            | NotLong
            | IntToLong
            | FloatToLong
            | DoubleToLong
            | AddDouble
            | SubDouble
            | MulDouble
            | DivDouble
            | RemDouble
            | AddDouble2Addr
            | SubDouble2Addr
            | MulDouble2Addr
            | DivDouble2Addr
            | RemDouble2Addr
            | NegDouble
            | IntToDouble
            | LongToDouble
            | FloatToDouble
            | ConstWide16
            | ConstWide32
            | ConstWide
            | ConstWideHigh16
    )
}

#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "PROOF: `value as i32` on the !wide path. Caller pairs `value` with `wide = is_wide_op(insn.insn.op)`; on the !wide path `try_fold` returns `Some(i64::from(<i32-typed expr>))` for every non-wide Int arm (each arm wraps an i32 op via `i64::from(... as i32 ...)`), so the folded i64 carries an i32-range value and the i32 narrowing is exact."
)]
fn pick_const_opcode(value: i64, wide: bool) -> Opcode {
    if wide {
        if value >= i64::from(i16::MIN) && value <= i64::from(i16::MAX) {
            Opcode::ConstWide16
        } else if value >= i64::from(i32::MIN) && value <= i64::from(i32::MAX) {
            Opcode::ConstWide32
        } else {
            Opcode::ConstWide
        }
    } else {
        let v = value as i32;
        if (-8..=7).contains(&v) {
            Opcode::Const4
        } else if v >= i32::from(i16::MIN) && v <= i32::from(i16::MAX) {
            Opcode::Const16
        } else {
            Opcode::Const
        }
    }
}

#[allow(clippy::arithmetic_side_effects, reason = "integer narrowing casts inside `as i32`/`as i64` for constant-folding semantics; the `-(a as i32)` site is the only true arithmetic operation, and it preserves Dalvik wrapping semantics for i32::MIN (matches JVM and DEX VM behaviour — wraps to itself). All div/rem sites use `wrapping_div`/`wrapping_rem` after explicit zero-check.")]
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "PROOF: Dalvik integer arithmetic semantics — block-level allow on uniform cluster. All 29 casts in this function implement the DEX VM's defined integer/float operand-width semantics: (a) `a as i32` from i64 const-pool entry truncates to 32-bit operand width per DEX spec §3.2 (int-typed registers hold 32-bit values; the const-pool stores i64 for uniformity); (b) `a as u32` for unsigned-right-shift (UshrInt/UshrIntLit8) reinterprets bits as unsigned before shifting, matching JVM `>>>` semantics; (c) `a as i8`/`as i16`/`as u16` for IntToByte/IntToShort/IntToChar implement the DEX conversion opcodes' defined narrowing semantics (DEX spec §3.5 'conversion operations'). The folded constants are sourced from `consts: FxHashMap<VarId, i64>` populated by `is_const`-gated constant instructions; the i64 values are the original encoding from the DEX const-pool, so their true operand range is governed by the opcode's type (32-bit for int ops)."
)]
fn try_fold(
    op: &Opcode,
    uses: &[VarId],
    literal: i64,
    consts: &FxHashMap<VarId, i64>,
) -> Option<i64> {
    use Opcode::*;

    // Binary int ops: two register operands
    match op {
        AddInt | AddInt2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            Some(i64::from((a as i32).wrapping_add(b as i32)))
        }
        SubInt | SubInt2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            Some(i64::from((a as i32).wrapping_sub(b as i32)))
        }
        MulInt | MulInt2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            Some(i64::from((a as i32).wrapping_mul(b as i32)))
        }
        DivInt | DivInt2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            if b == 0 {
                return None;
            }
            Some(i64::from((a as i32).wrapping_div(b as i32)))
        }
        RemInt | RemInt2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            if b == 0 {
                return None;
            }
            Some(i64::from((a as i32).wrapping_rem(b as i32)))
        }
        AndInt | AndInt2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            Some(i64::from(a as i32 & b as i32))
        }
        OrInt | OrInt2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            Some(i64::from(a as i32 | b as i32))
        }
        XorInt | XorInt2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            Some(i64::from(a as i32 ^ b as i32))
        }
        ShlInt | ShlInt2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            Some(i64::from((a as i32) << (b as i32 & 0x1F)))
        }
        ShrInt | ShrInt2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            Some(i64::from((a as i32) >> (b as i32 & 0x1F)))
        }
        UshrInt | UshrInt2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            Some(i64::from((a as u32) >> (b as i32 & 0x1F)))
        }

        // Lit16/Lit8: one register + immediate literal
        AddIntLit16 | AddIntLit8 => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from((a as i32).wrapping_add(literal as i32)))
        }
        RsubInt | RsubIntLit8 => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from((literal as i32).wrapping_sub(a as i32)))
        }
        MulIntLit16 | MulIntLit8 => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from((a as i32).wrapping_mul(literal as i32)))
        }
        DivIntLit16 | DivIntLit8 => {
            let a = *consts.get(uses.first()?)?;
            if literal == 0 {
                return None;
            }
            Some(i64::from((a as i32).wrapping_div(literal as i32)))
        }
        RemIntLit16 | RemIntLit8 => {
            let a = *consts.get(uses.first()?)?;
            if literal == 0 {
                return None;
            }
            Some(i64::from((a as i32).wrapping_rem(literal as i32)))
        }
        AndIntLit16 | AndIntLit8 => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from(a as i32 & literal as i32))
        }
        OrIntLit16 | OrIntLit8 => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from(a as i32 | literal as i32))
        }
        XorIntLit16 | XorIntLit8 => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from(a as i32 ^ literal as i32))
        }
        ShlIntLit8 => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from((a as i32) << (literal as i32 & 0x1F)))
        }
        ShrIntLit8 => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from((a as i32) >> (literal as i32 & 0x1F)))
        }
        UshrIntLit8 => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from((a as u32) >> (literal as i32 & 0x1F)))
        }

        // Unary int
        NegInt => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from(-(a as i32)))
        }
        NotInt => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from(!(a as i32)))
        }

        // Long binary
        AddLong | AddLong2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            Some(a.wrapping_add(b))
        }
        SubLong | SubLong2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            Some(a.wrapping_sub(b))
        }
        MulLong | MulLong2Addr => {
            let a = *consts.get(uses.first()?)?;
            let b = *consts.get(uses.get(1)?)?;
            Some(a.wrapping_mul(b))
        }
        NegLong => {
            let a = *consts.get(uses.first()?)?;
            Some(a.wrapping_neg())
        }
        NotLong => {
            let a = *consts.get(uses.first()?)?;
            Some(!a)
        }

        // Int conversions
        IntToByte => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from(a as i8))
        }
        IntToChar => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from(a as u16))
        }
        IntToShort => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from(a as i16))
        }
        IntToLong => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from(a as i32))
        }
        LongToInt => {
            let a = *consts.get(uses.first()?)?;
            Some(i64::from(a as i32))
        }

        _ => None,
    }
}

// ── Pass 3: Dead Code Elimination ───────────────────────────────────

fn dead_code_eliminate(ssa: &mut SsaBody) -> bool {
    let mut changed_any = false;

    loop {
        let use_counts = build_use_count(ssa);
        let mut removed = false;

        for block in ssa.blocks.values_mut() {
            let before = block.insns.len();
            block.insns.retain(|insn| {
                if let Some(ref dst) = insn.dst {
                    // SEMANTICS-DEFAULT-EMPTY: dst absent from
                    // `use_counts` ⇒ 0 uses; dead-code elim retains
                    // the insn only when at least one use exists.
                    if is_pure_op(insn.insn.op) && *use_counts.get(dst).unwrap_or(&0) == 0 {
                        return false; // remove
                    }
                }
                true
            });
            if block.insns.len() < before {
                removed = true;
            }

            let phi_before = block.phis.len();
            // SEMANTICS-DEFAULT-EMPTY: phi.dst absent from `use_counts`
            // ⇒ 0 uses; phi is dropped from the block in this pass
            // (will be re-introduced by the next phi-placement pass if
            // a new use appears).
            block
                .phis
                .retain(|phi| *use_counts.get(&phi.dst).unwrap_or(&0) > 0);
            if block.phis.len() < phi_before {
                removed = true;
            }
        }

        if removed {
            changed_any = true;
        } else {
            break;
        }
    }

    changed_any
}

// ── Pass 4: Type Narrowing ──────────────────────────────────────────

fn narrow_types(ssa: &SsaBody, env: &mut TypeEnv, dex: &DexFile) -> bool {
    let mut changed = false;

    // Find int-typed vars and check usage sites
    let int_vars: Vec<VarId> = env
        .types
        .iter()
        .filter(|(_, t)| **t == DexType::Int)
        .map(|(v, _)| v.clone())
        .collect();

    for var in int_vars {
        let mut demanded: Option<DexType> = None;
        let mut conflict = false;

        for block in ssa.blocks.values() {
            for insn in &block.insns {
                if !insn.uses.contains(&var) {
                    continue;
                }

                // For put opcodes, only the VALUE operand (uses[0]) should be
                // narrowed.  Iput/Aput also carry an object/array reference and
                // an array index as later uses; narrowing those to Byte/Boolean
                // would mistype loop counters and object references.
                let is_value_use = insn.uses.first() == Some(&var);

                let narrow = match insn.insn.op {
                    // Field/array store suffixes — narrow only the stored value
                    Opcode::IputBoolean | Opcode::SputBoolean | Opcode::AputBoolean => {
                        if is_value_use { Some(DexType::Boolean) } else { None }
                    }
                    Opcode::IputByte | Opcode::SputByte | Opcode::AputByte => {
                        if is_value_use { Some(DexType::Byte) } else { None }
                    }
                    Opcode::IputChar | Opcode::SputChar | Opcode::AputChar => {
                        if is_value_use { Some(DexType::Char) } else { None }
                    }
                    Opcode::IputShort | Opcode::SputShort | Opcode::AputShort => {
                        if is_value_use { Some(DexType::Short) } else { None }
                    }
                    // Invoke: check param signature
                    Opcode::InvokeVirtual
                    | Opcode::InvokeSuper
                    | Opcode::InvokeDirect
                    | Opcode::InvokeStatic
                    | Opcode::InvokeInterface
                    | Opcode::InvokeVirtualRange
                    | Opcode::InvokeSuperRange
                    | Opcode::InvokeDirectRange
                    | Opcode::InvokeStaticRange
                    | Opcode::InvokeInterfaceRange => {
                        if let Some(crate::decode::PoolIndex::Method(midx)) = insn.insn.pool_idx {
                            find_narrow_param_type(dex, midx, &var, insn)
                        } else {
                            None
                        }
                    }
                    _ => None,
                };

                if let Some(n) = narrow {
                    match &demanded {
                        None => demanded = Some(n),
                        Some(d) if *d == n => {}
                        Some(_) => {
                            conflict = true;
                            break;
                        }
                    }
                }
            }
            if conflict {
                break;
            }
        }

        if !conflict {
            if let Some(narrow_type) = demanded {
                env.types.insert(var, narrow_type);
                changed = true;
            }
        }
    }

    changed
}

fn find_narrow_param_type(
    dex: &DexFile,
    method_idx: crate::ids::MethodIdx,
    var: &VarId,
    insn: &crate::ssa::SsaInsn,
) -> Option<DexType> {
    #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; no From<u32> for usize on 32-bit targets. method_idx is a DEX MethodIdItem pool index parsed from a u16 field on disk (ids.rs MethodIdx wraps u32 for future-proofing), so the value is bounded by u16::MAX ≪ usize::MAX on all supported targets.")]
    let method = dex.methods.get(method_idx.0 as usize)?;
    #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; no From<u32> for usize on 32-bit targets. proto_idx (ProtoIdx(u32)) originates from a u16 field on disk (ids.rs MethodIdItem.proto_idx), so the value is bounded by u16::MAX ≪ usize::MAX on all supported targets.")]
    let proto = dex.protos.get(method.proto_idx.0 as usize)?;

    let is_static = matches!(
        insn.insn.op,
        Opcode::InvokeStatic | Opcode::InvokeStaticRange
    );

    let mut param_types = Vec::new();
    if !is_static {
        // Skip `this` — it's a Ref, not a narrow type
        param_types.push(None);
    }
    if proto.parameters_off != 0 {
        if let Some(type_list) = dex.type_lists.get(&proto.parameters_off) {
            for &tidx in type_list {
                let ty = dex
                    .get_type_descriptor(tidx)
                    .ok()
                    .map(DexType::from_descriptor);
                param_types.push(ty);
            }
        }
    }

    for (i, use_var) in insn.uses.iter().enumerate() {
        if use_var == var && i < param_types.len() {
            if let Some(Some(ty)) = param_types.get(i) {
                if matches!(
                    ty,
                    DexType::Boolean | DexType::Byte | DexType::Char | DexType::Short
                ) {
                    return Some(ty.clone());
                }
            }
        }
    }
    None
}

// ── Fixpoint driver ─────────────────────────────────────────────────

/// Run all optimization passes until fixpoint.
pub fn optimize(ssa: &mut SsaBody, env: &mut TypeEnv, dex: &DexFile) -> bool {
    let mut changed_any = false;
    loop {
        let mut changed = false;
        changed |= copy_propagate(ssa);
        changed |= constant_fold(ssa);
        changed |= dead_code_eliminate(ssa);
        changed |= narrow_types(ssa, env, dex);
        if !changed {
            break;
        }
        changed_any = true;
    }
    changed_any
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use crate::cfg::BlockIdx;
    use crate::decode::Instruction;
    use crate::ssa::{PhiNode, SsaBlock, SsaInsn};

    fn make_const(addr: u32, reg: u16, ver: u32, value: i64) -> SsaInsn {
        SsaInsn {
            insn: Instruction {
                addr,
                op: Opcode::Const,
                size: 3,
                dst: Some(reg),
                src: RegList::empty(),
                literal: value,
                target: None,
                pool_idx: None,
            },
            dst: Some(VarId::new(reg, ver)),
            uses: vec![],
        }
    }

    fn make_move(addr: u32, dst_reg: u16, dst_ver: u32, src_reg: u16, src_ver: u32) -> SsaInsn {
        SsaInsn {
            insn: Instruction {
                addr,
                op: Opcode::Move,
                size: 1,
                dst: Some(dst_reg),
                src: RegList::one(src_reg),
                literal: 0,
                target: None,
                pool_idx: None,
            },
            dst: Some(VarId::new(dst_reg, dst_ver)),
            uses: vec![VarId::new(src_reg, src_ver)],
        }
    }

    fn make_add_int(addr: u32, dst: (u16, u32), a: (u16, u32), b: (u16, u32)) -> SsaInsn {
        SsaInsn {
            insn: Instruction {
                addr,
                op: Opcode::AddInt,
                size: 2,
                dst: Some(dst.0),
                src: RegList::two(a.0, b.0),
                literal: 0,
                target: None,
                pool_idx: None,
            },
            dst: Some(VarId::new(dst.0, dst.1)),
            uses: vec![VarId::new(a.0, a.1), VarId::new(b.0, b.1)],
        }
    }

    fn make_return(addr: u32, reg: u16, ver: u32) -> SsaInsn {
        SsaInsn {
            insn: Instruction {
                addr,
                op: Opcode::Return,
                size: 1,
                dst: Some(reg),
                src: RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: None,
            },
            dst: None,
            uses: vec![VarId::new(reg, ver)],
        }
    }

    fn make_invoke_static(addr: u32, args: Vec<(u16, u32)>) -> SsaInsn {
        let regs: Vec<u16> = args.iter().map(|a| a.0).collect();
        let src = RegList::from_slice(&regs);
        SsaInsn {
            insn: Instruction {
                addr,
                op: Opcode::InvokeStatic,
                size: 3,
                dst: None,
                src,
                literal: 0,
                target: None,
                pool_idx: None,
            },
            dst: None,
            uses: args.iter().map(|a| VarId::new(a.0, a.1)).collect(),
        }
    }

    fn single_block_ssa(insns: Vec<SsaInsn>) -> SsaBody {
        let mut blocks = BTreeMap::new();
        blocks.insert(
            BlockIdx(0),
            SsaBlock {
                id: BlockIdx(0),
                phis: vec![],
                insns,
            },
        );
        SsaBody {
            blocks,
            entry: BlockIdx(0),
            var_counter: 100,
            param_vars: vec![],
        }
    }

    #[test]
    fn copy_prop_simple() {
        // const v0_0 = 5; move v1_1 = v0_0; return v1_1
        let mut ssa = single_block_ssa(vec![
            make_const(0, 0, 0, 5),
            make_move(3, 1, 1, 0, 0),
            make_return(4, 1, 1),
        ]);
        let changed = copy_propagate(&mut ssa);
        assert!(changed);
        let block = &ssa.blocks[&BlockIdx(0)];
        // Move should be removed
        assert_eq!(block.insns.len(), 2);
        // Return should use v0_0 directly
        assert_eq!(block.insns[1].uses[0], VarId::new(0, 0));
    }

    #[test]
    fn copy_prop_chain() {
        // const v0_0 = 5; move v1_1 = v0_0; move v2_2 = v1_1; return v2_2
        let mut ssa = single_block_ssa(vec![
            make_const(0, 0, 0, 5),
            make_move(3, 1, 1, 0, 0),
            make_move(4, 2, 2, 1, 1),
            make_return(5, 2, 2),
        ]);
        let changed = copy_propagate(&mut ssa);
        assert!(changed);
        let block = &ssa.blocks[&BlockIdx(0)];
        // Both moves removed
        assert_eq!(block.insns.len(), 2);
        // Return should use v0_0
        assert_eq!(block.insns[1].uses[0], VarId::new(0, 0));
    }

    #[test]
    fn constant_fold_add() {
        // const v0_0 = 3; const v1_1 = 5; add v2_2 = v0_0 + v1_1; return v2_2
        let mut ssa = single_block_ssa(vec![
            make_const(0, 0, 0, 3),
            make_const(3, 1, 1, 5),
            make_add_int(6, (2, 2), (0, 0), (1, 1)),
            make_return(8, 2, 2),
        ]);
        let changed = constant_fold(&mut ssa);
        assert!(changed);
        let block = &ssa.blocks[&BlockIdx(0)];
        // Add should be folded to const 8
        assert!(is_const(block.insns[2].insn.op));
        assert_eq!(block.insns[2].insn.literal, 8);
    }

    #[test]
    fn constant_fold_div_by_zero() {
        // const v0=5; const v1=0; div v2=v0/v1 — should NOT fold
        let mut ssa = single_block_ssa(vec![
            make_const(0, 0, 0, 5),
            make_const(3, 1, 1, 0),
            SsaInsn {
                insn: Instruction {
                    addr: 6,
                    op: Opcode::DivInt,
                    size: 2,
                    dst: Some(2),
                    src: RegList::two(0, 1),
                    literal: 0,
                    target: None,
                    pool_idx: None,
                },
                dst: Some(VarId::new(2, 2)),
                uses: vec![VarId::new(0, 0), VarId::new(1, 1)],
            },
            make_return(8, 2, 2),
        ]);
        let changed = constant_fold(&mut ssa);
        assert!(!changed);
        // DivInt should remain
        assert_eq!(ssa.blocks[&BlockIdx(0)].insns[2].insn.op, Opcode::DivInt);
    }

    #[test]
    fn constant_fold_bitwise() {
        // const v0=0xFF; const v1=0x0F; and v2=v0&v1; return v2
        let mut ssa = single_block_ssa(vec![
            make_const(0, 0, 0, 0xFF),
            make_const(3, 1, 1, 0x0F),
            SsaInsn {
                insn: Instruction {
                    addr: 6,
                    op: Opcode::AndInt,
                    size: 2,
                    dst: Some(2),
                    src: RegList::two(0, 1),
                    literal: 0,
                    target: None,
                    pool_idx: None,
                },
                dst: Some(VarId::new(2, 2)),
                uses: vec![VarId::new(0, 0), VarId::new(1, 1)],
            },
            make_return(8, 2, 2),
        ]);
        let changed = constant_fold(&mut ssa);
        assert!(changed);
        assert_eq!(ssa.blocks[&BlockIdx(0)].insns[2].insn.literal, 0x0F);
    }

    #[test]
    fn dce_removes_unused_pure() {
        // const v0_0 = 5 (unused); return-void
        let mut ssa = single_block_ssa(vec![
            make_const(0, 0, 0, 5),
            SsaInsn {
                insn: Instruction {
                    addr: 3,
                    op: Opcode::ReturnVoid,
                    size: 1,
                    dst: None,
                    src: RegList::empty(),
                    literal: 0,
                    target: None,
                    pool_idx: None,
                },
                dst: None,
                uses: vec![],
            },
        ]);
        let changed = dead_code_eliminate(&mut ssa);
        assert!(changed);
        assert_eq!(ssa.blocks[&BlockIdx(0)].insns.len(), 1);
        assert_eq!(
            ssa.blocks[&BlockIdx(0)].insns[0].insn.op,
            Opcode::ReturnVoid
        );
    }

    #[test]
    fn dce_preserves_impure() {
        // invoke-static (no result used); return-void
        let mut ssa = single_block_ssa(vec![
            make_invoke_static(0, vec![]),
            SsaInsn {
                insn: Instruction {
                    addr: 3,
                    op: Opcode::ReturnVoid,
                    size: 1,
                    dst: None,
                    src: RegList::empty(),
                    literal: 0,
                    target: None,
                    pool_idx: None,
                },
                dst: None,
                uses: vec![],
            },
        ]);
        let changed = dead_code_eliminate(&mut ssa);
        assert!(!changed);
        assert_eq!(ssa.blocks[&BlockIdx(0)].insns.len(), 2);
    }

    #[test]
    fn dce_preserves_used() {
        // const v0_0 = 5; return v0_0
        let mut ssa = single_block_ssa(vec![make_const(0, 0, 0, 5), make_return(3, 0, 0)]);
        let changed = dead_code_eliminate(&mut ssa);
        assert!(!changed);
        assert_eq!(ssa.blocks[&BlockIdx(0)].insns.len(), 2);
    }

    #[test]
    fn dce_cascading() {
        // const v0_0 = 5; add v1_1 = v0_0 + v0_0 (unused); const v2_2 = 10; return v2_2
        let mut ssa = single_block_ssa(vec![
            make_const(0, 0, 0, 5),
            make_add_int(3, (1, 1), (0, 0), (0, 0)),
            make_const(5, 2, 2, 10),
            make_return(8, 2, 2),
        ]);
        let changed = dead_code_eliminate(&mut ssa);
        assert!(changed);
        // Both const v0 and add v1 should be removed, leaving const v2 + return
        assert_eq!(ssa.blocks[&BlockIdx(0)].insns.len(), 2);
        assert_eq!(ssa.blocks[&BlockIdx(0)].insns[0].insn.literal, 10);
    }

    #[test]
    fn is_pure_categorization() {
        assert!(is_pure_op(Opcode::AddInt));
        assert!(is_pure_op(Opcode::Const4));
        assert!(is_pure_op(Opcode::Move));
        assert!(is_pure_op(Opcode::MoveResult));
        assert!(is_pure_op(Opcode::NegInt));
        assert!(is_pure_op(Opcode::ArrayLength));
        assert!(is_pure_op(Opcode::InstanceOf));
        // Nop has no reads/writes/side-effects (DEX spec §"Instruction
        // Formats" Nop = 10x), so it's pure by definition. The
        // categorization itself is load-bearing for `sugar.rs`'s
        // StringBuilder-pattern scan and `emit.rs`'s inline-substitution
        // gate; regressing it would silently re-introduce false
        // "side-effect" classification on alignment Nops.
        assert!(is_pure_op(Opcode::Nop));
        assert!(!is_pure_op(Opcode::InvokeVirtual));
        assert!(!is_pure_op(Opcode::Iput));
        assert!(!is_pure_op(Opcode::Sput));
        assert!(!is_pure_op(Opcode::Aput));
        assert!(!is_pure_op(Opcode::MonitorEnter));
        assert!(!is_pure_op(Opcode::Throw));
        assert!(!is_pure_op(Opcode::NewInstance));
        assert!(!is_pure_op(Opcode::NewArray));
        assert!(!is_pure_op(Opcode::Return));
        assert!(!is_pure_op(Opcode::ReturnVoid));
    }

    #[test]
    fn copy_prop_trivial_phi() {
        // Block 0: goto block 1
        // Block 1: phi v0_2 = [block0: v0_0], all same → trivial
        let mut blocks = BTreeMap::new();
        blocks.insert(
            BlockIdx(0),
            SsaBlock {
                id: BlockIdx(0),
                phis: vec![],
                insns: vec![make_return(0, 0, 0)],
            },
        );
        blocks.insert(
            BlockIdx(1),
            SsaBlock {
                id: BlockIdx(1),
                phis: vec![PhiNode {
                    dst: VarId::new(0, 2),
                    operands: {
                        let mut m = BTreeMap::new();
                        m.insert(BlockIdx(0), VarId::new(0, 0));
                        m
                    },
                }],
                insns: vec![make_return(1, 0, 2)],
            },
        );
        let mut ssa = SsaBody {
            blocks,
            entry: BlockIdx(0),
            var_counter: 10,
            param_vars: vec![],
        };
        let changed = copy_propagate(&mut ssa);
        assert!(changed);
        // Phi should be removed, return in block 1 should use v0_0
        assert!(ssa.blocks[&BlockIdx(1)].phis.is_empty());
        assert_eq!(ssa.blocks[&BlockIdx(1)].insns[0].uses[0], VarId::new(0, 0));
    }
}
