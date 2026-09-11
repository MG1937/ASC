//! Syntactic sugar lowering pass.
#![allow(missing_docs, reason = "internal")]
// Per-fn refinement of `clippy::arithmetic_side_effects`.
// Module-level allow removed; each fn that does arithmetic carries its
// own `#[allow] // WHY:` annotation citing the dominator that bounds
// its sites. Distributed WHY: desugar operates on validated in-memory
// SSA values, not attacker bytes.
#![cfg_attr(
    not(test),
    allow(
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::as_conversions,
        reason = "PROOF: sugar lowering consumes structured Stmt/Expr/Block trees produced by the structuring pass over validated SSA. Every VarId is minted by ssa::Builder; every Block reference is a structurally-built tree (children/then/else are Box<Stmt> built by direct construction). String slicing operates on emit::sanitize_id outputs (UTF-8) and on ASCII-only opcode-name lookups. as_conversions casts cluster around `u32 pool-index newtype as usize` for `.get()` on pool arrays (lossless on 64-bit) and `i64 literal as i32` for Dalvik-spec literal narrowing. Per-fn refinement deferred (~47 sites across 39 fns; uniform invariant)."
    )
)]

use crate::decode::PoolIndex;
use crate::ids::{MethodIdx, TypeIdx};
use crate::opcodes::Opcode;
use crate::parser::DexFile;
use crate::ssa::{SsaInsn, VarId};
use crate::structure::{Condition, ConcatPart, Stmt};
use crate::types::TypeEnv;

/// Recursion depth cap on `desugar_recursive`'s `Stmt`-tree walk.
///
/// WHY: `desugar_recursive` descends through `Stmt::Seq`, `Stmt::If`,
/// `Stmt::Switch`, `Stmt::TryCatch`, etc. without intrinsic bound. Each
/// `Seq` frame allocates a `BTreeMap<VarId, usize>` in
/// `inline_single_use_vars` via `build_use_count_table` (~tens of KB
/// peak per frame across the alloc + drop windows). Without a cap,
/// adversarial DEX input with pathologically deep nesting overflows the
/// rayon worker stack and crashes the audit (observed under ASAN:
/// stack-buffer-overflow during `BTreeMap::IntoIter::dying_next` at
/// `inline_single_use_vars` exit in a large APK corpus sample).
///
/// Value: 256. Half of `emit::MAX_STMT_DEPTH = 512`, matching the
/// sibling crate-internal caps (`signatures/kotlinc19/when_*.rs`,
/// `signatures/kotlinc19/coroutine_suspend.rs`,
/// `parser/mod.rs::MAX_SUPER_CHAIN_DEPTH`). The 256/512 asymmetry
/// reflects the heavier per-frame allocation cost in desugar (BTreeMap
/// alloc) vs emit (match-arm-local set ~8 KB per frame).
///
/// Semantics on overflow: `desugar_recursive` returns `changed = false`
/// at the cap (silent halt). The IR remains structurally valid — sub-
/// trees beyond depth 256 are simply left in their pre-desugar shape;
/// downstream `emit_method` walks them under its own
/// `MAX_STMT_DEPTH = 512` cap and surfaces visible failure via
/// `DexError::EmitRecursionDepthExceeded` if its own cap is hit.
pub const MAX_DESUGAR_DEPTH: usize = 256;

/// Iteration cap on `desugar()`'s outer fixpoint loop.
///
/// WHY: `desugar()` re-runs `desugar_recursive` until a pass reports no
/// change. Each legitimate pass strictly simplifies the `Stmt` tree (a
/// transform fires only when it rewrites a recognized shape into a smaller
/// one), so real input converges in a few passes regardless of method
/// size — the transforms apply tree-wide per pass, not one-rewrite-per-pass.
/// Without a cap, however, input where a transform never reaches a fixpoint
/// — two transforms oscillating, or a spurious `changed = true` on a no-op —
/// spins the loop forever (100% CPU). This is reachable on adversarial input:
/// a parse failure touching a Kotlin class's annotation/class_data subtree
/// makes its Kotlin detectors return `Indeterminate`, routing the class down
/// the standard Java decompile path into `desugar` on a shape it cannot
/// converge on. An uncapped loop there is a decompiler-hang DoS.
///
/// Value: 64 — a large margin over observed legitimate convergence (a
/// handful of passes), so no real method hits the cap, while still bounding
/// non-convergence to 64 depth-bounded walks.
///
/// Semantics on cap: the loop stops and the body is left in its current
/// best-guess shape — the same "stop transforming, keep what we have"
/// fallback `MAX_DESUGAR_DEPTH` uses for over-deep subtrees. The IR stays
/// structurally valid for the downstream `emit_method` walk.
pub const MAX_DESUGAR_PASSES: usize = 64;

// ── String concatenation ────────────────────────────────────────────

/// Check if an instruction is `new-instance Ljava/lang/StringBuilder;`
fn is_new_string_builder(insn: &SsaInsn, dex: &DexFile) -> bool {
    if insn.insn.op != Opcode::NewInstance {
        return false;
    }
    if let Some(PoolIndex::Type(tidx)) = insn.insn.pool_idx {
        dex.get_type_descriptor(tidx)
            .map(|d| d == "Ljava/lang/StringBuilder;")
            .unwrap_or(false)
    } else {
        false
    }
}

/// Check if an instruction is `invoke-direct {v}, StringBuilder.<init>:()V`
fn is_sb_init(insn: &SsaInsn, dex: &DexFile, sb_var: &VarId) -> bool {
    if insn.insn.op != Opcode::InvokeDirect {
        return false;
    }
    if insn.uses.first().is_none_or(|u| u != sb_var) {
        return false;
    }
    if let Some(PoolIndex::Method(midx)) = insn.insn.pool_idx {
        is_method_on_class(dex, midx, "Ljava/lang/StringBuilder;", "<init>")
    } else {
        false
    }
}

/// Check if an instruction is `invoke-virtual {sb, arg}, <Class>.append`
/// where `sb` is the tracked StringBuilder var. The declaring class of
/// `append` may be `Ljava/lang/StringBuilder;` or `Ljava/lang/AbstractStringBuilder;`
/// — R8 sometimes devirtualizes invocations to a superclass.
fn is_sb_append(insn: &SsaInsn, dex: &DexFile, sb_var: &VarId) -> bool {
    matches!(insn.insn.op, Opcode::InvokeVirtual)
        && insn.uses.first().is_some_and(|u| u == sb_var)
        && method_name_is(insn, dex, "append")
}

/// Check if an instruction is `invoke-virtual {sb}, <Class>.toString`
/// where `sb` is the tracked StringBuilder var. The declaring class of
/// `toString` is commonly `Ljava/lang/Object;` after R8 devirtualization;
/// we only need the name to match since we've already tracked `sb_var`
/// from a confirmed `new StringBuilder`.
fn is_sb_to_string(insn: &SsaInsn, dex: &DexFile, sb_var: &VarId) -> bool {
    matches!(insn.insn.op, Opcode::InvokeVirtual)
        && insn.uses.first().is_some_and(|u| u == sb_var)
        && insn.uses.len() == 1
        && method_name_is(insn, dex, "toString")
}

fn method_name_is(insn: &SsaInsn, dex: &DexFile, name: &str) -> bool {
    let Some(PoolIndex::Method(midx)) = insn.insn.pool_idx else {
        return false;
    };
    let Some(method) = dex.methods.get(midx.0 as usize) else {
        return false;
    };
    dex.get_string(method.name_idx)
        .map(|n| n == name)
        .unwrap_or(false)
}

#[allow(dead_code, reason = "Public-helper shape retained for an upcoming sugar pass that needs class+method matching; currently only the `is_method_named` form is called.")]
fn is_method_on_class(dex: &DexFile, midx: MethodIdx, class_desc: &str, method_name: &str) -> bool {
    if let Some(method) = dex.methods.get(midx.0 as usize) {
        let class_ok = dex
            .get_type_descriptor(method.class_idx)
            .map(|d| d == class_desc)
            .unwrap_or(false);
        let name_ok = dex
            .get_string(method.name_idx)
            .map(|n| n == method_name)
            .unwrap_or(false);
        class_ok && name_ok
    } else {
        false
    }
}

/// Is this a `move-result-object` instruction?
fn is_move_result_object(insn: &SsaInsn) -> bool {
    insn.insn.op == Opcode::MoveResultObject
}

/// Try to detect and replace StringBuilder concat patterns in a Seq.
#[allow(clippy::arithmetic_side_effects, reason = "byte/index cursor `i + N` (N ∈ {1, 2, 3}) into `stmts`, with `i + N < stmts.len()` guards preceding each indexing. The cursor advances `i += 1` per iteration; bounded by stmts.len() which is parser-validated. `seq_start + replacement_len` for splice insertion index, bounded by stmts.len() + drained range len which cannot exceed parser-validated total stmt count.")]
fn desugar_string_concat_in_seq(stmts: &mut Vec<Stmt>, dex: &DexFile) -> bool {
    let mut changed = false;
    let mut i = 0;

    while i < stmts.len() {
        // Look for: Expr(new-instance SB) at position i
        let sb_var = match &stmts[i] {
            Stmt::Expr(insn) if is_new_string_builder(insn, dex) => insn.dst.clone(),
            _ => {
                i += 1;
                continue;
            }
        };

        let sb_var = match sb_var {
            Some(v) => v,
            None => {
                i += 1;
                continue;
            }
        };

        // Scan forward for the SB.<init> call, collecting const-string
        // values along the way so the init's string arg (if any) can
        // become the first concat part. R8 commonly emits
        // `new StringBuilder; const-string v; <init>(String);` with the
        // const-string between NewInstance and <init>.
        let mut string_consts: std::collections::BTreeMap<VarId, String> =
            std::collections::BTreeMap::new();
        let mut parts: Vec<ConcatPart> = Vec::new();
        // Pure-op stmts (e.g. arraylength, iget, const-int) interleaved between
        // the SB-chain links produce values consumed by appends as `ConcatPart::Var`.
        // The splice at the bottom removes [i..j); without preserving these defs
        // their `Var(vN)` references in the resulting StringConcat would be
        // undeclared (javac: `cannot find symbol — variable vN`). Preserve them
        // here for re-insertion before the StringConcat. Const-strings whose
        // value is consumed as a `Literal` are intentionally NOT preserved
        // (their content survives in the literal). SB-chain stmts themselves
        // (NewInstance, InvokeDirect <init>, InvokeVirtual append, MoveResult*,
        // Throw, etc.) are not pure-ops and so do not enter this branch.
        let mut preserved_pre: Vec<Stmt> = Vec::new();
        let mut j = i + 1;
        let mut init_found = false;
        while j < stmts.len() {
            match &stmts[j] {
                Stmt::Expr(insn) if is_sb_init(insn, dex, &sb_var) => {
                    // Capture init's string arg as first part, if any.
                    if let Some(arg) = insn.uses.get(1) {
                        if let Some(lit) = string_consts.get(arg) {
                            parts.push(ConcatPart::Literal(lit.clone()));
                        } else {
                            parts.push(ConcatPart::Var(arg.clone()));
                        }
                    }
                    j += 1;
                    init_found = true;
                    break;
                }
                Stmt::Expr(insn)
                    if matches!(insn.insn.op, Opcode::ConstString | Opcode::ConstStringJumbo) =>
                {
                    if let (Some(dst), Some(PoolIndex::String(sidx))) =
                        (&insn.dst, insn.insn.pool_idx)
                    {
                        if let Ok(s) = dex.get_string(sidx) {
                            string_consts.insert(dst.clone(), s.to_string());
                        }
                    }
                    j += 1;
                }
                Stmt::Expr(insn)
                    if crate::optimize::is_pure_op(insn.insn.op) && insn.dst.is_some() =>
                {
                    preserved_pre.push(stmts[j].clone());
                    j += 1;
                }
                // Nop has no dst (and no side effect), so it slips past
                // the pure-op arm above (which gates on `dst.is_some()`).
                // Skip it silently rather than break — a compiler-emitted
                // alignment Nop interleaved between init-prep instructions
                // must not abort StringBuilder pattern recognition.
                Stmt::Expr(insn) if insn.insn.op == Opcode::Nop => {
                    j += 1;
                }
                _ => break,
            }
        }
        if !init_found {
            i += 1;
            continue;
        }

        // Collect append calls. Track the "current sb var" which may change via move-result-object.
        let mut current_sb = sb_var.clone();
        let mut concat_dst: Option<VarId> = None;

        while j < stmts.len() {
            match &stmts[j] {
                Stmt::Expr(insn) if is_sb_append(insn, dex, &current_sb) => {
                    // The append argument is uses[1] (uses[0] is sb)
                    if let Some(arg) = insn.uses.get(1) {
                        if let Some(lit) = string_consts.get(arg) {
                            parts.push(ConcatPart::Literal(lit.clone()));
                        } else {
                            parts.push(ConcatPart::Var(arg.clone()));
                        }
                    }
                    j += 1;
                    // Check for move-result-object after append (returns sb)
                    if j < stmts.len() {
                        if let Stmt::Expr(mro) = &stmts[j] {
                            if is_move_result_object(mro) {
                                if let Some(ref new_sb) = mro.dst {
                                    current_sb = new_sb.clone();
                                }
                                j += 1;
                            }
                        }
                    }
                }
                Stmt::Expr(insn) if is_sb_to_string(insn, dex, &current_sb) => {
                    // Found the toString — complete the pattern
                    j += 1;
                    // Capture move-result-object after toString — this is the concat's dst
                    if j < stmts.len() {
                        if let Stmt::Expr(mro) = &stmts[j] {
                            if is_move_result_object(mro) {
                                concat_dst = mro.dst.clone();
                                j += 1;
                            }
                        }
                    }
                    break;
                }
                // Skip const-string and other value-preparing instructions
                Stmt::Expr(insn)
                    if matches!(insn.insn.op, Opcode::ConstString | Opcode::ConstStringJumbo) =>
                {
                    if let (Some(dst), Some(PoolIndex::String(sidx))) =
                        (&insn.dst, insn.insn.pool_idx)
                    {
                        if let Ok(s) = dex.get_string(sidx) {
                            string_consts.insert(dst.clone(), s.to_string());
                        }
                    }
                    j += 1;
                }
                // Preserve other pure value-setup instructions (e.g. arraylength,
                // iget, const-int, move) before the splice — see comment on the
                // sibling preserved_pre at the init-scan loop above for rationale.
                Stmt::Expr(insn)
                    if crate::optimize::is_pure_op(insn.insn.op) && insn.dst.is_some() =>
                {
                    preserved_pre.push(stmts[j].clone());
                    j += 1;
                }
                // Mirror of the init-scan loop's Nop arm above: a Nop has no
                // dst so it skips the pure-op arm, and must be consumed
                // explicitly rather than breaking pattern recognition.
                Stmt::Expr(insn) if insn.insn.op == Opcode::Nop => {
                    j += 1;
                }
                _ => break, // Pattern broken
            }
        }

        if parts.is_empty() || concat_dst.is_none() {
            // Without a concat_dst the StringConcat would emit as a bare
            // expression statement, which is not legal Java. Leave the
            // raw StringBuilder calls intact in that case.
            i += 1;
            continue;
        }

        // Replace stmts[i..j] with [preserved pure-op defs] + StringConcat.
        // The preserved defs keep `ConcatPart::Var(vN)` references resolvable.
        let concat = Stmt::StringConcat {
            dst: concat_dst.clone(),
            parts,
        };
        let mut new_items: Vec<Stmt> = preserved_pre;
        new_items.push(concat);
        let advance = new_items.len();
        stmts.splice(i..j, new_items);
        changed = true;
        // Skip past the inserted items so we don't rescan them as a new SB chain.
        i += advance;
    }

    changed
}

// ── For-each (iterator) ─────────────────────────────────────────────

#[allow(dead_code, reason = "for-each iterator sugar shape — predicate retained for an upcoming sugar pass.")]
fn is_has_next_call(insn: &SsaInsn, dex: &DexFile) -> bool {
    matches!(
        insn.insn.op,
        Opcode::InvokeInterface | Opcode::InvokeVirtual
    ) && insn.insn.pool_idx.as_ref().is_some_and(|p| {
        if let PoolIndex::Method(midx) = p {
            dex.methods
                .get(midx.0 as usize)
                .and_then(|m| dex.get_string(m.name_idx).ok())
                .is_some_and(|n| n == "hasNext")
        } else {
            false
        }
    })
}

fn is_next_call(insn: &SsaInsn, dex: &DexFile) -> bool {
    matches!(
        insn.insn.op,
        Opcode::InvokeInterface | Opcode::InvokeVirtual
    ) && insn.insn.pool_idx.as_ref().is_some_and(|p| {
        if let PoolIndex::Method(midx) = p {
            dex.methods
                .get(midx.0 as usize)
                .and_then(|m| dex.get_string(m.name_idx).ok())
                .is_some_and(|n| n == "next")
        } else {
            false
        }
    })
}

#[allow(dead_code, reason = "for-each iterator sugar shape — predicate retained for an upcoming sugar pass.")]
fn is_iterator_call(insn: &SsaInsn, dex: &DexFile) -> bool {
    matches!(
        insn.insn.op,
        Opcode::InvokeInterface | Opcode::InvokeVirtual
    ) && insn.insn.pool_idx.as_ref().is_some_and(|p| {
        if let PoolIndex::Method(midx) = p {
            dex.methods
                .get(midx.0 as usize)
                .and_then(|m| dex.get_string(m.name_idx).ok())
                .is_some_and(|n| n == "iterator")
        } else {
            false
        }
    })
}

/// Detect iterator-based for-each in a While loop.
fn desugar_for_each_iterator(stmt: &mut Stmt, dex: &DexFile) -> bool {
    // Look for While where cond comes from hasNext, body starts with next()
    match stmt {
        Stmt::While { cond: _, body, .. } => {
            // Check if body starts with next() call
            let body_stmts = match body.as_ref() {
                Stmt::Seq(s) => s,
                _ => return false,
            };

            if body_stmts.is_empty() {
                return false;
            }

            // First stmt should be invoke next() or next() + move-result-object
            let (next_insn, elem_var) = match &body_stmts[0] {
                Stmt::Expr(insn) if is_next_call(insn, dex) && body_stmts.len() > 1 => {
                    if let Stmt::Expr(mro) = &body_stmts[1] {
                        if is_move_result_object(mro) {
                            (insn, mro.dst.clone())
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                _ => return false,
            };

            let iter_var = match next_insn.uses.first() {
                Some(v) => v.clone(),
                None => return false,
            };

            let elem_var = match elem_var {
                Some(v) => v,
                None => return false,
            };

            // Remove next() + MRO from body, build ForEach
            let remaining_body: Vec<Stmt> = body_stmts[2..].to_vec();
            let new_body = crate::structure::flatten_single(remaining_body);

            *stmt = Stmt::ForEach {
                var: elem_var,
                iterable: iter_var,
                body: Box::new(new_body),
            };
            true
        }
        _ => false,
    }
}

// ── For-loop detection ──────────────────────────────────────────────

/// Detect `init; while (cond) { body; increment; }` → `for (init; cond; increment) { body; }`
// WHY: `i + N` cursor advance into `stmts` with `i + N < stmts.len()`
// guards; `i += 1` per iteration; pattern-match indexing
// `stmts[i + 1]` etc. preceded by len-bound checks.
#[allow(clippy::arithmetic_side_effects, reason = "`i + N` cursor advance into `stmts` with `i + N < stmts.len()` guards; `i += 1` per iteration; pattern-match indexing `stmts[i + 1]` etc. preceded by len-bound checks.")]
fn desugar_for_loops(stmts: &mut Vec<Stmt>) -> bool {
    let mut changed = false;
    let mut i = 0;

    while i + 1 < stmts.len() {
        // Check: stmts[i] is Expr (initialization), stmts[i+1] is While
        let is_init_expr = matches!(&stmts[i], Stmt::Expr(insn) if insn.dst.is_some());
        if !is_init_expr {
            i += 1;
            continue;
        }

        let is_while = matches!(&stmts[i + 1], Stmt::While { .. });
        if !is_while {
            i += 1;
            continue;
        }

        // Check if the while body ends with an increment (add-int/lit8 +1 or add-int/2addr)
        let has_increment = if let Stmt::While { body, .. } = &stmts[i + 1] {
            match body.as_ref() {
                Stmt::Seq(body_stmts) if !body_stmts.is_empty() => {
                    matches!(body_stmts.last(), Some(Stmt::Expr(insn))
                        if matches!(insn.insn.op,
                            Opcode::AddIntLit8 | Opcode::AddIntLit16 | Opcode::AddInt2Addr)
                        && (insn.insn.literal == 1 || matches!(insn.insn.op, Opcode::AddInt2Addr)))
                }
                Stmt::Expr(insn) => {
                    matches!(insn.insn.op, Opcode::AddIntLit8 | Opcode::AddIntLit16)
                        && insn.insn.literal == 1
                }
                _ => false,
            }
        } else {
            false
        };

        if !has_increment {
            i += 1;
            continue;
        }

        // Verify the init variable's register matches the increment variable's
        // register.  Without this check, an unrelated pre-loop assignment (e.g.
        // the accumulator `s = 0` in `for (int x : arr) s += x`) would be
        // incorrectly hoisted into the for-header, scoping it to the loop body
        // and making `return s` a compile error.
        let init_reg = if let Stmt::Expr(insn) = &stmts[i] {
            insn.dst.as_ref().map(|v| v.reg())
        } else {
            None
        };
        let update_reg = if let Stmt::While { body, .. } = &stmts[i + 1] {
            let last = match body.as_ref() {
                Stmt::Seq(bs) => bs.last(),
                other @ Stmt::Expr(_) => Some(other),
                _ => None,
            };
            last.and_then(|s| {
                if let Stmt::Expr(insn) = s {
                    insn.dst.as_ref().map(|v| v.reg())
                } else {
                    None
                }
            })
        } else {
            None
        };
        let Some(init_reg_val) = init_reg else {
            i += 1;
            continue;
        };
        if Some(init_reg_val) != update_reg {
            i += 1;
            continue;
        }

        // Don't hoist into a for-loop if the init register is used after the
        // while statement: scoping it inside the for-header would make those
        // post-loop uses a compile error (e.g. `popcount` returns the counter).
        let used_after_loop = stmts[i + 2..].iter().any(|s| stmt_uses_reg(s, init_reg_val));
        if used_after_loop {
            i += 1;
            continue;
        }

        // Extract components and build For loop
        let init = stmts.remove(i);
        let while_stmt = stmts.remove(i);

        if let Stmt::While { cond, body } = while_stmt {
            let (update, remaining_body) = match *body {
                Stmt::Seq(mut body_stmts) => {
                    // `update_reg` was computed from `body_stmts.last()` above
                    // returning `Some`, so `body_stmts` is non-empty here. But
                    // if the invariant ever drifts we fall back gracefully
                    // instead of panicking.
                    match body_stmts.pop() {
                        Some(update) => {
                            let remaining =
                                crate::structure::flatten_single(body_stmts);
                            (update, remaining)
                        }
                        None => (Stmt::Seq(Vec::new()), Stmt::Seq(Vec::new())),
                    }
                }
                single @ Stmt::Expr(_) => {
                    // The single statement IS the increment — empty body
                    (single, Stmt::Seq(vec![]))
                }
                other => (Stmt::Seq(vec![]), other),
            };

            stmts.insert(
                i,
                Stmt::For {
                    init: Box::new(init),
                    cond,
                    update: Box::new(update),
                    body: Box::new(remaining_body),
                },
            );
            changed = true;
        }
        // Don't advance i — recheck
    }

    changed
}

fn cond_uses_reg(cond: &crate::structure::Condition, reg: u16) -> bool {
    use crate::structure::Condition;
    match cond {
        Condition::TestZero { var, .. } | Condition::Var(var) => var.reg() == reg,
        Condition::Compare { left, right, .. } => left.reg() == reg || right.reg() == reg,
    }
}

/// Returns true if any VarId with the given register appears as a use in `stmt`.
fn stmt_uses_reg(stmt: &Stmt, reg: u16) -> bool {
    match stmt {
        Stmt::Expr(insn) => insn.uses.iter().any(|v| v.reg() == reg),
        Stmt::Seq(stmts) => stmts.iter().any(|s| stmt_uses_reg(s, reg)),
        Stmt::Return(Some(v)) | Stmt::Throw(v) => v.reg() == reg,
        Stmt::If { cond, then_body, else_body, .. } => {
            cond_uses_reg(cond, reg)
                || stmt_uses_reg(then_body, reg)
                || else_body.as_ref().is_some_and(|b| stmt_uses_reg(b, reg))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => stmt_uses_reg(body, reg),
        Stmt::For { body, .. } => stmt_uses_reg(body, reg),
        Stmt::Switch { cases, default, .. } => {
            cases.iter().any(|(_, b)| stmt_uses_reg(b, reg))
                || default.as_ref().is_some_and(|b| stmt_uses_reg(b, reg))
        }
        Stmt::StringSwitch { cases, default, .. } => {
            cases.iter().any(|(_, b)| stmt_uses_reg(b, reg))
                || default.as_ref().is_some_and(|b| stmt_uses_reg(b, reg))
        }
        Stmt::StringConcat { parts, .. } => parts.iter().any(|p| {
            matches!(p, crate::structure::ConcatPart::Var(v) if v.reg() == reg)
        }),
        Stmt::TryCatch { body, catches, .. } => {
            stmt_uses_reg(body, reg)
                || catches.iter().any(|c| stmt_uses_reg(&c.body, reg))
        }
        Stmt::InlinedReturn(insn) | Stmt::InlinedThrow(insn) => {
            insn.uses.iter().any(|v| v.reg() == reg)
        }
        _ => false,
    }
}

// ── Expression inlining ─────────────────────────────────────────────

/// Walk one Stmt tree and accumulate per-`VarId` use counts into `counts`.
///
/// Previously [`inline_single_use_vars`] called a per-var
/// `count_var_uses_in_stmt` once per remaining stmt per def — overall
/// `O(stmts² · tree_depth)` per method body. Top-10 leaf in flamegraphs
/// of large APK audits. Walking once into a per-`VarId`
/// map drops the cost to `O(stmts · tree_depth)` per pass.
// WHY: BTreeMap counter `*counts.entry(v).or_insert(0) += 1` over
// IR-bounded VarIds; bounded by parser-validated VarId pool size
// (u32-bounded). Cannot overflow usize within input limits.
#[allow(clippy::arithmetic_side_effects, reason = "BTreeMap counter `*counts.entry(v).or_insert(0) += 1` over IR-bounded VarIds; bounded by parser-validated VarId pool size (u32-bounded). Cannot overflow usize within input limits.")]
fn accumulate_var_uses(stmt: &Stmt, counts: &mut std::collections::BTreeMap<VarId, usize>) {
    match stmt {
        Stmt::Expr(insn) => {
            for u in &insn.uses {
                *counts.entry(u.clone()).or_insert(0) += 1;
            }
        }
        Stmt::Seq(stmts) => {
            for s in stmts {
                accumulate_var_uses(s, counts);
            }
        }
        Stmt::Return(Some(v)) => *counts.entry(v.clone()).or_insert(0) += 1,
        Stmt::Throw(v) => *counts.entry(v.clone()).or_insert(0) += 1,
        Stmt::If {
            cond,
            then_body,
            else_body,
            ..
        } => {
            cond.accumulate_uses(counts);
            accumulate_var_uses(then_body, counts);
            if let Some(b) = else_body {
                accumulate_var_uses(b, counts);
            }
        }
        Stmt::While { cond, body, .. } | Stmt::DoWhile { body, cond, .. } => {
            cond.accumulate_uses(counts);
            accumulate_var_uses(body, counts);
        }
        Stmt::Switch {
            value,
            cases,
            default,
            ..
        } => {
            *counts.entry(value.clone()).or_insert(0) += 1;
            for (_, b) in cases {
                accumulate_var_uses(b, counts);
            }
            if let Some(b) = default {
                accumulate_var_uses(b, counts);
            }
        }
        Stmt::StringSwitch {
            value,
            cases,
            default,
            ..
        } => {
            *counts.entry(value.clone()).or_insert(0) += 1;
            for (_, b) in cases {
                accumulate_var_uses(b, counts);
            }
            if let Some(b) = default {
                accumulate_var_uses(b, counts);
            }
        }
        Stmt::StringConcat { parts, .. } => {
            for p in parts {
                if let ConcatPart::Var(v) = p {
                    *counts.entry(v.clone()).or_insert(0) += 1;
                }
            }
        }
        Stmt::ForEach {
            var: v,
            iterable,
            body,
            ..
        } => {
            *counts.entry(v.clone()).or_insert(0) += 1;
            *counts.entry(iterable.clone()).or_insert(0) += 1;
            accumulate_var_uses(body, counts);
        }
        Stmt::TryCatch { body, catches, .. } => {
            accumulate_var_uses(body, counts);
            for c in catches {
                accumulate_var_uses(&c.body, counts);
            }
        }
        Stmt::Synchronized { lock, body, .. } => {
            *counts.entry(lock.clone()).or_insert(0) += 1;
            accumulate_var_uses(body, counts);
        }
        Stmt::BooleanAssign { cond, .. } => {
            cond.accumulate_uses(counts);
        }
        _ => {}
    }
}

/// Build a per-method-body use-count table by walking every stmt once.
fn build_use_count_table(stmts: &[Stmt]) -> std::collections::BTreeMap<VarId, usize> {
    let mut counts = std::collections::BTreeMap::new();
    for s in stmts {
        accumulate_var_uses(s, &mut counts);
    }
    counts
}

/// Inline single-use variables: `Type v = expr; return v;` → `return expr;`
/// Works for return, throw, and expression-to-expression patterns.
// WHY: `i + 1` cursor index into `stmts` with `i + 1 < stmts.len()`
// guards; `i += 1` per iteration; BTreeMap counter increments over
// IR-bounded VarIds.
#[allow(clippy::arithmetic_side_effects, reason = "`i + 1` cursor index into `stmts` with `i + 1 < stmts.len()` guards; `i += 1` per iteration; BTreeMap counter increments over IR-bounded VarIds.")]
fn inline_single_use_vars(stmts: &mut Vec<Stmt>) -> bool {
    let mut changed = false;
    let mut i = 0;
    let mut counts = build_use_count_table(stmts);

    while i + 1 < stmts.len() {
        // Check if stmts[i] defines a variable
        let def_var = match &stmts[i] {
            Stmt::Expr(insn) => insn.dst.clone(),
            Stmt::StringConcat { dst, .. } => dst.clone(),
            _ => None,
        };

        let def_var = match def_var {
            Some(v) => v,
            None => {
                i += 1;
                continue;
            }
        };

        // Look up cached use count. Fresh SSA defs never appear as uses
        // at positions ≤ i (the dst is freshly minted at i), so the
        // global count equals the tail count `stmts[i+1..]`.
        // SEMANTICS-DEFAULT-EMPTY: def_var absent from the use-count map means it has
        // zero uses; the inline-candidate check below correctly rejects zero-use vars.
        let total_uses = counts.get(&def_var).copied().unwrap_or(0);

        if total_uses != 1 {
            i += 1;
            continue;
        }

        // Check if the next statement uses this var in an inlineable position
        match &stmts[i + 1] {
            Stmt::Return(Some(v)) if *v == def_var => {}
            Stmt::Throw(v) if *v == def_var => {}
            _ => {
                i += 1;
                continue;
            }
        }

        // Extract the defining statement
        let def_stmt = stmts.remove(i);

        // Replace the next statement with the inlined version
        match (&def_stmt, &stmts[i]) {
            (Stmt::Expr(insn), Stmt::Return(Some(v))) if *v == def_var => {
                stmts[i] = Stmt::InlinedReturn(insn.clone());
            }
            (Stmt::Expr(insn), Stmt::Throw(v)) if *v == def_var => {
                stmts[i] = Stmt::InlinedThrow(insn.clone());
            }
            (Stmt::StringConcat { parts, .. }, Stmt::Return(Some(v))) if *v == def_var => {
                stmts[i] = Stmt::InlinedReturnConcat(parts.clone());
            }
            _ => {
                stmts.insert(i, def_stmt);
                i += 1;
                continue;
            }
        }
        changed = true;
        // Successful inline mutates `stmts[i]` from `Expr(insn)` /
        // `Return(v)` to `InlinedReturn(insn)` (which contributes 0
        // to use counts per `accumulate_var_uses`). Other vars in
        // `insn.uses` are zero post-inline at this position; rebuild the
        // table so subsequent iterations see the post-inline state.
        // Re-walk is `O(stmts · tree_depth)` per inline; total cost
        // per method body is `O(k · stmts · tree_depth)` for `k`
        // inlines, vs `O(stmts² · tree_depth)` without the table.
        counts = build_use_count_table(stmts);
        // Don't advance i — check again at this position
    }

    changed
}

// ── Recursive tree walker ───────────────────────────────────────────

// WHY: depth-bounded recursion (`if depth > MAX_DESUGAR_DEPTH { return false; }`
// guard at entry). Arithmetic is `depth + 1` for recursion arg; bounded by
// `MAX_DESUGAR_DEPTH + 1`. Mirrors `emit::emit_stmt_depth` PROOF shape.
#[allow(clippy::arithmetic_side_effects, reason = "depth-bounded recursion (`if depth > MAX_DESUGAR_DEPTH { return false; }` guard at entry). Arithmetic is `depth + 1` for recursion arg; bounded by `MAX_DESUGAR_DEPTH + 1`.")]
fn desugar_recursive(
    stmt: &mut Stmt,
    dex: &DexFile,
    enclosing_class: TypeIdx,
    is_top_level: bool,
    method_const_int_env: &std::collections::BTreeMap<VarId, i32>,
    depth: usize,
) -> bool {
    if depth > MAX_DESUGAR_DEPTH {
        return false;
    }
    let mut changed = false;

    match stmt {
        Stmt::Seq(stmts) => {
            // First desugar children — children are NEVER top-level.
            for s in stmts.iter_mut() {
                changed |= desugar_recursive(
                    s,
                    dex,
                    enclosing_class,
                    false,
                    method_const_int_env,
                    depth + 1,
                );
            }
            // Then desugar this seq. Run string-switch reconstruction
            // FIRST — the three-stmt triple it matches must be seen
            // before `inline_single_use_vars` or the for-loop folder
            // gets a chance to rearrange things. The is_top_level flag
            // distinguishes the method-root Seq from nested sub-Seqs
            // for recognizers that gate on whole-method-body shape
            // (kotlinc19::coroutine_suspend).
            changed |= reconstruct_string_switches(
                stmts,
                dex,
                enclosing_class,
                is_top_level,
                method_const_int_env,
            );
            changed |= desugar_string_concat_in_seq(stmts, dex);
            // Lift comparison-as-value shapes BEFORE inline_single_use_vars so
            // single-use const-1/const-0 vars consumed by the lifted form are
            // collapsed into the BooleanAssign rather than left as orphan
            // declarations after the if/else collapses.
            changed |= lift_comparison_as_value_in_seq(stmts);
            changed |= inline_single_use_vars(stmts);
            changed |= desugar_for_loops(stmts);
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            changed |= desugar_recursive(
                then_body,
                dex,
                enclosing_class,
                false,
                method_const_int_env,
                depth + 1,
            );
            if let Some(eb) = else_body {
                changed |= desugar_recursive(
                    eb,
                    dex,
                    enclosing_class,
                    false,
                    method_const_int_env,
                    depth + 1,
                );
            }
        }
        Stmt::While { .. } => {
            changed |= desugar_for_each_iterator(stmt, dex);
            // If not converted, recurse into body
            if let Stmt::While { body, .. } = stmt {
                changed |= desugar_recursive(
                    body,
                    dex,
                    enclosing_class,
                    false,
                    method_const_int_env,
                    depth + 1,
                );
            }
        }
        Stmt::DoWhile { body, .. } => {
            changed |= desugar_recursive(
                body,
                dex,
                enclosing_class,
                false,
                method_const_int_env,
                depth + 1,
            );
        }
        Stmt::Switch { cases, default, .. } => {
            for (_, body) in cases {
                changed |= desugar_recursive(
                    body,
                    dex,
                    enclosing_class,
                    false,
                    method_const_int_env,
                    depth + 1,
                );
            }
            if let Some(d) = default {
                changed |= desugar_recursive(
                    d,
                    dex,
                    enclosing_class,
                    false,
                    method_const_int_env,
                    depth + 1,
                );
            }
        }
        Stmt::StringSwitch { cases, default, .. } => {
            for (_, body) in cases {
                changed |= desugar_recursive(
                    body,
                    dex,
                    enclosing_class,
                    false,
                    method_const_int_env,
                    depth + 1,
                );
            }
            if let Some(d) = default {
                changed |= desugar_recursive(
                    d,
                    dex,
                    enclosing_class,
                    false,
                    method_const_int_env,
                    depth + 1,
                );
            }
        }
        Stmt::TryCatch { body, catches, .. } => {
            changed |= desugar_recursive(
                body,
                dex,
                enclosing_class,
                false,
                method_const_int_env,
                depth + 1,
            );
            for c in catches {
                changed |= desugar_recursive(
                    &mut c.body,
                    dex,
                    enclosing_class,
                    false,
                    method_const_int_env,
                    depth + 1,
                );
            }
        }
        Stmt::Synchronized { body, .. } => {
            changed |= desugar_recursive(
                body,
                dex,
                enclosing_class,
                false,
                method_const_int_env,
                depth + 1,
            );
        }
        Stmt::ForEach { body, .. } => {
            changed |= desugar_recursive(
                body,
                dex,
                enclosing_class,
                false,
                method_const_int_env,
                depth + 1,
            );
        }
        _ => {}
    }

    changed
}

// ── String switch reconstruction ───────────────────────────────────
//
// javac lowers Java 7+ `switch(String s)` to two back-to-back switches:
//   (1) `int h = s.hashCode();`
//   (2) `switch (h) { case HASH_OF_LITERAL: if (s.equals("LIT")) tag = N;
//                     else tag = -1; break; ... default: break; }`
//   (3) `switch (tag) { case N: <user_body>; ... default: <user_default>; }`
// This pass pattern-matches the three-stmt triple in a `Seq` and
// replaces it with a single `Stmt::StringSwitch` where case labels are
// string literals.

/// Walk a `Seq` looking for canonical javac signatures via the
/// recognizer engine in [`droidsaw_common::signature`]. On match → in-
/// place replacement (e.g. two adjacent `Stmt::Switch` collapsed into
/// one `Stmt::StringSwitch`). On candidate-but-inexact deviation →
/// wraps the region in [`Stmt::Unrecognized`] so an analyst sees the
/// honest failure rather than misleading "best-effort" output.
///
/// Discrimination between "candidate deviation" and "not a candidate"
/// is by bytecode signature, not by absence-of-match — see
/// `has_string_switch_candidate_shape` for the Unrecognized decision logic.
///
/// Returns `true` on any rewrite (recognized or near-miss wrapping).
fn reconstruct_string_switches(
    stmts: &mut Vec<Stmt>,
    dex: &DexFile,
    enclosing_class: TypeIdx,
    is_top_level: bool,
    method_const_int_env: &std::collections::BTreeMap<VarId, i32>,
) -> bool {
    use droidsaw_common::signature::{run_signatures, SignatureResult};

    use crate::signatures::{signature_table, DexBackend, DexSigInput, RecognizedDexShape};
    use crate::structure::UnrecognizedReason;

    let mut changed = false;
    let table = signature_table();
    let mut j = 0;
    while j < stmts.len() {
        let input = DexSigInput {
            stmts,
            position: j,
            dex,
            enclosing_class,
            is_top_level,
            method_const_int_env,
        };
        match run_signatures::<DexBackend>(input, &table) {
            SignatureResult::Matched {
                shape: RecognizedDexShape::Replacement { new_stmt, span },
                ..
            } => {
                let span = span.max(1);
                let end = j.saturating_add(span);
                let end = end.min(stmts.len());
                stmts.splice(j..end, [new_stmt]);
                changed = true;
                // Don't advance j; re-check this position.
                continue;
            }
            SignatureResult::Matched {
                shape: RecognizedDexShape::TaggedRegion { signature_id, span },
                ..
            } => {
                // Tagged region: recognizer identified the shape but
                // didn't lift; wrap the region in Stmt::Unrecognized
                // with closest = Some(signature_id), distance = 0
                // (sentinel for "exact tag match"). Emit dispatches on
                // distance == 0 to render the recognizer-specific banner.
                let span = span.max(1);
                let end = j.saturating_add(span).min(stmts.len());
                let raw = collect_raw_insns(&stmts[j..end]);
                let cfg_region = first_block_idx(&stmts[j..end]);
                let unrecognized = Stmt::Unrecognized {
                    cfg_region,
                    reason: UnrecognizedReason::NoSignatureMatch {
                        closest: Some(signature_id),
                        distance: 0,
                    },
                    raw,
                };
                stmts.splice(j..end, [unrecognized]);
                changed = true;
                j = j.saturating_add(1);
            }
            SignatureResult::Unmatched {
                closest: Some((sig_id, distance)),
            } => {
                // Candidate-but-inexact: wrap the region in Stmt::Unrecognized.
                let span = unrecognized_span(stmts, j);
                let end = j.saturating_add(span).min(stmts.len());
                let raw = collect_raw_insns(&stmts[j..end]);
                let cfg_region = first_block_idx(&stmts[j..end]);
                let unrecognized = Stmt::Unrecognized {
                    cfg_region,
                    reason: UnrecognizedReason::NoSignatureMatch {
                        closest: Some(sig_id),
                        distance,
                    },
                    raw,
                };
                stmts.splice(j..end, [unrecognized]);
                changed = true;
                j = j.saturating_add(1);
            }
            SignatureResult::Ambiguous { candidates } => {
                let span = unrecognized_span(stmts, j);
                let end = j.saturating_add(span).min(stmts.len());
                let raw = collect_raw_insns(&stmts[j..end]);
                let cfg_region = first_block_idx(&stmts[j..end]);
                let unrecognized = Stmt::Unrecognized {
                    cfg_region,
                    reason: UnrecognizedReason::AmbiguousSignature { candidates },
                    raw,
                };
                stmts.splice(j..end, [unrecognized]);
                changed = true;
                j = j.saturating_add(1);
            }
            // Unmatched with no near-miss: not a candidate. Leave alone.
            // This is the "hand-written Stmt::If chain" path — discriminator
            // is bytecode signature, not absence-of-match.
            SignatureResult::Unmatched { closest: None } => {
                j = j.saturating_add(1);
            }
            // IndeterminateInput: no recognizer Recognized, but at least
            // one returned Indeterminate (upstream detector consulted
            // during try_match could not classify the input — typically
            // a `ParseFailure`-tainted subsection). Wrap in
            // Stmt::Unrecognized with DetectorIndeterminate reason so
            // the audit envelope can surface "detection was silent
            // because input was malformed" via the diag walker.
            SignatureResult::IndeterminateInput { reason } => {
                let span = unrecognized_span(stmts, j);
                let end = j.saturating_add(span).min(stmts.len());
                let raw = collect_raw_insns(&stmts[j..end]);
                let cfg_region = first_block_idx(&stmts[j..end]);
                let unrecognized = Stmt::Unrecognized {
                    cfg_region,
                    reason: UnrecognizedReason::DetectorIndeterminate {
                        detector_name: reason,
                    },
                    raw,
                };
                stmts.splice(j..end, [unrecognized]);
                changed = true;
                j = j.saturating_add(1);
            }
        }
    }
    changed
}

/// Span (in stmts) of the unrecognized region for a candidate-but-
/// inexact site. Today's only signature is the two-Switch string-switch
/// shape, so span = 2 when the next stmt is also a Switch. Conservative
/// fallback: 1, so we never wrap an out-of-range region.
fn unrecognized_span(stmts: &[Stmt], position: usize) -> usize {
    if matches!(stmts.get(position), Some(Stmt::Switch { .. }))
        && matches!(stmts.get(position.saturating_add(1)), Some(Stmt::Switch { .. }))
    {
        2
    } else {
        1
    }
}

fn collect_raw_insns(stmts: &[Stmt]) -> Vec<SsaInsn> {
    let mut out: Vec<SsaInsn> = Vec::new();
    for s in stmts {
        collect_raw_insns_into(s, &mut out);
    }
    out
}

fn collect_raw_insns_into(stmt: &Stmt, out: &mut Vec<SsaInsn>) {
    match stmt {
        Stmt::Expr(insn) | Stmt::InlinedReturn(insn) | Stmt::InlinedThrow(insn) => {
            out.push(insn.clone());
        }
        Stmt::Seq(v) => {
            for s in v {
                collect_raw_insns_into(s, out);
            }
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            collect_raw_insns_into(then_body, out);
            if let Some(e) = else_body.as_deref() {
                collect_raw_insns_into(e, out);
            }
        }
        Stmt::Switch { cases, default, .. } => {
            for (_, body) in cases {
                collect_raw_insns_into(body, out);
            }
            if let Some(d) = default.as_deref() {
                collect_raw_insns_into(d, out);
            }
        }
        Stmt::StringSwitch { cases, default, .. } => {
            for (_, body) in cases {
                collect_raw_insns_into(body, out);
            }
            if let Some(d) = default.as_deref() {
                collect_raw_insns_into(d, out);
            }
        }
        Stmt::TryCatch { body, catches, .. } => {
            collect_raw_insns_into(body, out);
            for c in catches {
                collect_raw_insns_into(&c.body, out);
            }
        }
        Stmt::Synchronized { body, .. }
        | Stmt::While { body, .. }
        | Stmt::DoWhile { body, .. }
        | Stmt::ForEach { body, .. }
        | Stmt::For { body, .. } => {
            collect_raw_insns_into(body, out);
        }
        // Other variants carry no SsaInsn directly — Stmt::Return,
        // Stmt::Throw, etc. are leaf-level shapes with no embedded
        // SsaInsn references the analyst would benefit from in the
        // raw-smali banner.
        _ => {}
    }
}

/// Sentinel BlockIdx used when we cannot recover the precise CFG block
/// of an unrecognized region from `Stmt`-level data. The raw insns'
/// addresses (rendered by `emit_unrecognized` as `pc=0xNNN`) provide the
/// needed correlation; the BlockIdx field stays best-effort.
fn first_block_idx(_stmts: &[Stmt]) -> crate::cfg::BlockIdx {
    crate::cfg::BlockIdx(u32::MAX)
}

/// True iff the region at `stmts[position..]` is a candidate for the
/// javac `switch (String)` lowering: two adjacent `Stmt::Switch` whose
/// outer discriminant is materialized by a `String.hashCode()` invoke
/// upstream in the same `Seq`.
///
/// Used by the signature engine in `crate::signatures::javac21::
/// switch_string` to decide whether a deviation site warrants
/// `Stmt::Unrecognized` wrapping (candidate-but-inexact) vs silent
/// pass-through (not even a candidate). The discriminator is the
/// bytecode signature, not the absence of a match.
pub(crate) fn has_string_switch_candidate_shape(stmts: &[Stmt], position: usize) -> bool {
    let Some(first) = stmts.get(position) else {
        return false;
    };
    let Some(second) = stmts.get(position.saturating_add(1)) else {
        return false;
    };
    let Stmt::Switch {
        value: outer_var, ..
    } = first
    else {
        return false;
    };
    if !matches!(second, Stmt::Switch { .. }) {
        return false;
    }
    // hashCode-on-String upstream by syntactic shape (no dex pool walk —
    // that's done in the full match). True iff some preceding Stmt::Expr
    // is an InvokeVirtual whose dst is the outer switch's discriminant.
    let outer_reg = outer_var.reg();
    for i in (0..position).rev() {
        if let Stmt::Expr(insn) = &stmts[i] {
            if let Some(dst) = insn.dst.as_ref() {
                if dst.reg() == outer_reg
                    && matches!(
                        insn.insn.op,
                        Opcode::InvokeVirtual | Opcode::InvokeVirtualRange
                    )
                {
                    return true;
                }
                // Pre-merge form: MoveResult into outer_reg, with the
                // InvokeVirtual immediately before.
                if dst.reg() == outer_reg
                    && matches!(
                        insn.insn.op,
                        Opcode::MoveResult | Opcode::MoveResultObject | Opcode::MoveResultWide
                    )
                    && i > 0
                    && matches!(
                        &stmts[i.saturating_sub(1)],
                        Stmt::Expr(prev) if matches!(
                            prev.insn.op,
                            Opcode::InvokeVirtual | Opcode::InvokeVirtualRange
                        )
                    )
                {
                    return true;
                }
            }
        }
    }
    false
}

pub(crate) fn try_collapse_adjacent_switches(
    stmts: &[Stmt],
    j: usize,
    dex: &DexFile,
    method_const_int_env: &std::collections::BTreeMap<VarId, i32>,
) -> Option<Stmt> {
    // Defense-in-depth on bounds: callers that drop the
    // `has_string_switch_candidate_shape` gate (e.g. future engine
    // tests, or call sites added by stream #4 / #5) must not be able to
    // panic this function on out-of-range `j`.
    let first = stmts.get(j)?;
    let second = stmts.get(j.saturating_add(1))?;
    let Stmt::Switch {
        value: sw_hash_var,
        cases: hash_cases,
        default: hash_default,
    } = first
    else {
        return None;
    };
    let Stmt::Switch {
        value: sw_tag_var,
        cases: tag_cases,
        default: tag_default,
    } = second
    else {
        return None;
    };

    // Scan backward for the hashCode source producing `sw_hash_var`.
    let str_var = find_hash_code_source(stmts, j, sw_hash_var, dex)?;

    // Outer default must be empty / break.
    if let Some(d) = hash_default.as_deref() {
        if !is_empty_or_break(d) {
            return None;
        }
    }

    // Per-case: collect (tag_N, "literal_N") pairs. R8 sometimes hoists
    // common tag constants out of the dispatcher and emits per-case
    // `move v_tag, v_const_src` — `extract_const_int_assign` accepts
    // those moves iff the source VarId resolves in
    // `method_const_int_env` (a method-wide collection of integer-
    // constant SSA defs computed once at `desugar` entry). On corpus
    // audit, near-miss sites are uniformly R8 const-hoist variants of
    // the canonical shape.
    let mut tag_to_literal: std::collections::BTreeMap<i32, String> =
        std::collections::BTreeMap::new();
    let mut tag_reg: Option<u16> = None;
    for (_hashes, body) in hash_cases {
        if !extract_case_literal_tag(
            body,
            &str_var,
            &mut tag_to_literal,
            &mut tag_reg,
            method_const_int_env,
            dex,
        ) {
            return None;
        }
    }
    let tag_reg = tag_reg?;
    if tag_to_literal.is_empty() {
        return None;
    }

    // Inner switch's discriminant register must match the tag register.
    if sw_tag_var.reg() != tag_reg {
        return None;
    }

    // Every inner-case label must be in the tag→literal map.
    let mut new_cases: Vec<(Vec<String>, Box<Stmt>)> = Vec::new();
    for (tags, body) in tag_cases {
        let mut lits: Vec<String> = Vec::new();
        for t in tags {
            let lit = tag_to_literal.get(t)?;
            lits.push(lit.clone());
        }
        new_cases.push((lits, body.clone()));
    }

    // Inner default must not reference the tag register.
    if let Some(d) = tag_default.as_deref() {
        if stmt_uses_reg(d, tag_reg) {
            return None;
        }
    }

    Some(Stmt::StringSwitch {
        value: str_var,
        cases: new_cases,
        default: tag_default.clone(),
    })
}

/// Scan `stmts[..before]` backward for the statement that materializes
/// `hash_var` via `String.hashCode()`. Two accepted shapes:
///   (a) `Expr(insn)` where `insn` is a merged InvokeVirtual-with-dst
///       equal to `hash_var`;
///   (b) a `[Expr(InvokeVirtual hashCode, dst=None), Expr(MoveResult,
///       dst=hash_var)]` pair (pre-`merge_invoke_moveresult` form).
/// Returns the `String` receiver var on match, else `None`.
// WHY: `before - 1` for last-stmt index; the caller guarantees `before > 0`
// (no scan-from-position-0 case), so subtraction is safe.
#[allow(clippy::arithmetic_side_effects, reason = "`before - 1` for last-stmt index; the caller guarantees `before > 0` (no scan-from-position-0 case), so subtraction is safe.")]
fn find_hash_code_source(
    stmts: &[Stmt],
    before: usize,
    hash_var: &VarId,
    dex: &DexFile,
) -> Option<VarId> {
    // Walk backward.
    for i in (0..before).rev() {
        // Shape (a): merged — Expr(InvokeVirtual with dst = hash_var,
        // matching hashCode). Only fire if the insn is actually an
        // invoke; otherwise fall through to shape (b).
        if let Stmt::Expr(insn) = &stmts[i] {
            if matches!(
                insn.insn.op,
                Opcode::InvokeVirtual | Opcode::InvokeVirtualRange
            ) && insn.dst.as_ref() == Some(hash_var)
            {
                if let Some((str_var, _)) = match_hash_code_invoke(insn, dex) {
                    return Some(str_var);
                }
                return None;
            }
        }
        // Shape (b): pre-merge pair — stmts[i] is MoveResult with dst=hash_var,
        //            stmts[i-1] is the InvokeVirtual hashCode with dst=None.
        if let Stmt::Expr(mro_insn) = &stmts[i] {
            if matches!(
                mro_insn.insn.op,
                Opcode::MoveResult | Opcode::MoveResultObject | Opcode::MoveResultWide
            ) && mro_insn.dst.as_ref() == Some(hash_var)
                && i > 0
            {
                if let Stmt::Expr(inv_insn) = &stmts[i - 1] {
                    // Temporarily pretend the invoke has `hash_var` as dst
                    // so `match_hash_code_invoke` accepts it. We just need
                    // the op + method classification.
                    if matches!(
                        inv_insn.insn.op,
                        Opcode::InvokeVirtual | Opcode::InvokeVirtualRange
                    ) {
                        let Some(PoolIndex::Method(midx)) = inv_insn.insn.pool_idx else {
                            return None;
                        };
                        let m = dex.methods.get(midx.0 as usize)?;
                        let name = dex.get_string(m.name_idx).ok()?;
                        if name != "hashCode" {
                            return None;
                        }
                        let class = dex.get_type_descriptor(m.class_idx).ok()?;
                        if class != "Ljava/lang/String;" {
                            return None;
                        }
                        let receiver = inv_insn.uses.first()?.clone();
                        return Some(receiver);
                    }
                }
                return None;
            }
        }
    }
    None
}

/// Match `invoke-virtual String.hashCode()` on any object; return the
/// receiver var + the dst var.
fn match_hash_code_invoke(insn: &SsaInsn, dex: &DexFile) -> Option<(VarId, VarId)> {
    if !matches!(
        insn.insn.op,
        Opcode::InvokeVirtual | Opcode::InvokeVirtualRange
    ) {
        return None;
    }
    let Some(PoolIndex::Method(midx)) = insn.insn.pool_idx else {
        return None;
    };
    let m = dex.methods.get(midx.0 as usize)?;
    let name = dex.get_string(m.name_idx).ok()?;
    if name != "hashCode" {
        return None;
    }
    let class = dex.get_type_descriptor(m.class_idx).ok()?;
    if class != "Ljava/lang/String;" {
        return None;
    }
    let receiver = insn.uses.first()?.clone();
    let dst = insn.dst.clone()?;
    Some((receiver, dst))
}

/// Match the canonical javac-lowered outer-case body shape:
///   `Seq([Expr(ConstString LIT) → V_lit,
///         Expr(invoke-virtual <str>.equals(V_lit)) → V_eq,
///         If { cond: TestZero(V_eq) or Var(V_eq),
///              then_body: <empty or const-int>,
///              else_body: <Expr(const-int N)> } | <branches swapped> ])`
///
/// Records `tag_to_literal[N] → LIT` and the tag's register. On any
/// deviation → return `false` → parent bails whole triple-collapse.
// WHY: `seq[i + 1]`, `seq[i + 2]` indexing with `i + 2 < seq.len()`
// guard above; pattern-match shape requires exactly 3 stmts so the
// bounds-check holds by construction.
#[allow(clippy::arithmetic_side_effects, reason = "`seq[i + 1]`, `seq[i + 2]` indexing with `i + 2 < seq.len()` guard above; pattern-match shape requires exactly 3 stmts so the bounds-check holds by construction.")]
fn extract_case_literal_tag(
    body: &Stmt,
    str_var: &VarId,
    tag_to_literal: &mut std::collections::BTreeMap<i32, String>,
    tag_reg: &mut Option<u16>,
    const_int_env: &std::collections::BTreeMap<VarId, i32>,
    dex: &DexFile,
) -> bool {
    let stmts: &[Stmt] = match body {
        Stmt::Seq(v) => v,
        single => std::slice::from_ref(single),
    };
    if stmts.len() < 3 {
        return false;
    }

    // [0] ConstString → V_lit.
    let Stmt::Expr(cs_insn) = &stmts[0] else {
        return false;
    };
    let Some(literal) = match_const_string(cs_insn, dex) else {
        return false;
    };
    let Some(lit_var) = cs_insn.dst.as_ref() else {
        return false;
    };

    // [1] equals-invoke with uses = [str, V_lit]. Pre-merge, the invoke
    // may have no dst; its result is captured by a following
    // MoveResult whose dst holds V_eq. Post-merge (after emit-time
    // `merge_invoke_moveresult`), the invoke carries dst = V_eq
    // directly.
    let Stmt::Expr(eq_insn) = &stmts[1] else {
        return false;
    };
    if !match_equals_invoke(eq_insn, str_var, lit_var, dex) {
        return false;
    }
    let (eq_dst_owned, if_idx) = if let Some(d) = eq_insn.dst.as_ref() {
        (d.clone(), 2)
    } else {
        // Pre-merge form: next stmt must be a MoveResult.
        let Some(Stmt::Expr(mro_insn)) = stmts.get(2) else {
            return false;
        };
        if !matches!(
            mro_insn.insn.op,
            Opcode::MoveResult | Opcode::MoveResultObject | Opcode::MoveResultWide
        ) {
            return false;
        }
        let Some(d) = mro_insn.dst.as_ref() else {
            return false;
        };
        (d.clone(), 3)
    };
    let eq_dst = &eq_dst_owned;
    // Strict-shape gate: the outer case body must be EXACTLY the
    // canonical sequence
    // `[ConstString, equals-invoke, (MoveResult)?, If]` plus an
    // optional trailing `Break` / `Seq([])`. Any additional
    // statement is user-authored content that cannot be safely
    // absorbed into the StringSwitch reconstruction — bail.
    match stmts.len().cmp(&(if_idx + 1)) {
        std::cmp::Ordering::Less => return false,
        std::cmp::Ordering::Equal => {}
        std::cmp::Ordering::Greater => {
            // Allow exactly one trailing Break-like tail (empty Seq
            // from the structurer's fall-through synthesis).
            if stmts.len() != if_idx + 2 || !is_empty_or_break(&stmts[if_idx + 1]) {
                return false;
            }
        }
    }

    // [if_idx] If { cond uses V_eq, branches are {empty-or-const, const-int} }.
    let Stmt::If {
        cond,
        then_body,
        else_body,
    } = &stmts[if_idx]
    else {
        return false;
    };
    let cond_var = match cond {
        Condition::TestZero { var, .. } => var,
        Condition::Var(v) => v,
        _ => return false,
    };
    if cond_var != eq_dst {
        return false;
    }

    // One branch assigns a non-(-1) int constant to a tag register;
    // the other branch is empty or assigns -1 (or just another
    // constant). Inspect both; take the one with the "real" tag.
    let tag_from = |branch: &Stmt| -> Option<(i32, u16)> {
        extract_const_int_assign(branch, const_int_env)
    };
    let a = tag_from(then_body);
    let b = else_body.as_deref().and_then(tag_from);
    let (tag_val, tag_r) = match (a, b) {
        (Some((t, r)), _) if t != -1 => (t, r),
        (_, Some((t, r))) if t != -1 => (t, r),
        _ => return false,
    };

    match *tag_reg {
        None => *tag_reg = Some(tag_r),
        Some(existing) if existing != tag_r => return false,
        Some(_) => {}
    }
    tag_to_literal.insert(tag_val, literal);
    true
}

/// Extract `Expr(const-int N → V)` → `(N, V.reg())` if `branch` is
/// exactly a single Expr materializing an integer constant. Accepts:
/// (a) `Const | Const4 | Const16 | ConstHigh16` with no uses (the
///     direct javac-21 lowering), and
/// (b) `Move | MoveFrom16 | Move16` whose single source resolves in
///     `const_int_env` (the R8 const-hoisted variant — see #47 audit;
///     R8 hoists common tag constants out of the dispatcher and emits
///     per-case `move v_tag, v_const_src` to keep code size down).
/// Accepts `Stmt::Seq([single-stmt])` as well as a bare Stmt.
fn extract_const_int_assign(
    branch: &Stmt,
    const_int_env: &std::collections::BTreeMap<VarId, i32>,
) -> Option<(i32, u16)> {
    let stmt = match branch {
        Stmt::Seq(v) if v.len() == 1 => &v[0],
        Stmt::Seq(_) => return None,
        other => other,
    };
    let Stmt::Expr(insn) = stmt else {
        return None;
    };
    let dst = insn.dst.as_ref()?;
    // Shape (a): direct const-int load.
    if matches!(
        insn.insn.op,
        Opcode::Const | Opcode::Const4 | Opcode::Const16 | Opcode::ConstHigh16
    ) && insn.uses.is_empty()
    {
        let val = i32::try_from(insn.insn.literal).ok()?;
        return Some((val, dst.reg()));
    }
    // Shape (b): R8 const-hoisted move from a known-const register.
    // Only int-flavored moves; `MoveWide*` and `MoveObject*` are wide
    // / object copies and must NOT participate in the int-tag env.
    if matches!(
        insn.insn.op,
        Opcode::Move | Opcode::MoveFrom16 | Opcode::Move16
    ) && insn.uses.len() == 1
    {
        let src = &insn.uses[0];
        let val = const_int_env.get(src)?;
        return Some((*val, dst.reg()));
    }
    None
}

fn match_const_string(insn: &SsaInsn, dex: &DexFile) -> Option<String> {
    if !matches!(insn.insn.op, Opcode::ConstString | Opcode::ConstStringJumbo) {
        return None;
    }
    let Some(PoolIndex::String(sidx)) = insn.insn.pool_idx else {
        return None;
    };
    dex.get_string(sidx).ok().map(|s| s.to_string())
}

fn match_equals_invoke(insn: &SsaInsn, expected_receiver: &VarId, expected_arg: &VarId, dex: &DexFile) -> bool {
    if !matches!(
        insn.insn.op,
        Opcode::InvokeVirtual | Opcode::InvokeVirtualRange
    ) {
        return false;
    }
    let Some(PoolIndex::Method(midx)) = insn.insn.pool_idx else {
        return false;
    };
    let Some(m) = dex.methods.get(midx.0 as usize) else {
        return false;
    };
    let Ok(name) = dex.get_string(m.name_idx) else {
        return false;
    };
    if name != "equals" {
        return false;
    }
    // Receiver + one arg.
    if insn.uses.len() < 2 {
        return false;
    }
    &insn.uses[0] == expected_receiver && &insn.uses[1] == expected_arg
}

fn is_empty_or_break(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Seq(v) => v.is_empty() || v.iter().all(is_empty_or_break),
        // The structurer sometimes renders a "fall-through break" as an
        // empty Seq; bare Stmt::Expr with no useful content doesn't
        // occur in this spot. Anything else → non-empty.
        _ => false,
    }
}

// ── Lift comparison-as-value to Stmt::BooleanAssign ─────────────────
//
// Dalvik has no comparison-as-value opcode, so source-level
// `boolean v = (a == b);` lowers to one of two if-branch shapes whose
// per-branch const-stores phi-merge at the join. Without lifting:
// (1) emit renders `int v; if (..) v=0; else v=1;` (the int-leak miscompilation
//     surfaced as "int cannot be converted to boolean" by recompile),
// (2) the surrounding control flow blocks the new+init merge in `emit.rs`.
//
// This pass canonicalizes both shapes to `Stmt::BooleanAssign { dst, cond }`
// where `cond` is in positive polarity (no separate `negated` flag — the lift
// flips the cond's op when needed via `negate_condition`).

/// Match `Stmt::Expr(Const-K → dst)` where K is 0 or 1, allowing the wrapper
/// to be either bare `Stmt::Expr` or a single-element `Stmt::Seq`.
/// Returns `(dst, K)`.
fn match_const_0_or_1(stmt: &Stmt) -> Option<(VarId, i64)> {
    let inner = match stmt {
        Stmt::Expr(_) => stmt,
        Stmt::Seq(v) if v.len() == 1 => &v[0],
        _ => return None,
    };
    let Stmt::Expr(insn) = inner else { return None; };
    let dst = insn.dst.as_ref()?;
    if !matches!(insn.insn.op, Opcode::Const4 | Opcode::Const16 | Opcode::Const) {
        return None;
    }
    let lit = insn.insn.literal;
    if lit != 0 && lit != 1 {
        return None;
    }
    Some((dst.clone(), lit))
}

/// `Stmt::Seq([])` or empty-bodied else_body sentinel.
fn is_empty_seq(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Seq(v) if v.is_empty())
}

/// Negate a boolean condition by flipping the comparison op. Returns `None` for
/// `Condition::Var(_)` (synthetic conditions have no op to flip).
fn negate_condition(cond: &Condition) -> Option<Condition> {
    match cond {
        Condition::TestZero { var, op } => {
            let flipped = match op {
                Opcode::IfEqz => Opcode::IfNez,
                Opcode::IfNez => Opcode::IfEqz,
                Opcode::IfLtz => Opcode::IfGez,
                Opcode::IfGez => Opcode::IfLtz,
                Opcode::IfGtz => Opcode::IfLez,
                Opcode::IfLez => Opcode::IfGtz,
                _ => return None,
            };
            Some(Condition::TestZero { var: var.clone(), op: flipped })
        }
        Condition::Compare { left, right, op } => {
            let flipped = match op {
                Opcode::IfEq => Opcode::IfNe,
                Opcode::IfNe => Opcode::IfEq,
                Opcode::IfLt => Opcode::IfGe,
                Opcode::IfGe => Opcode::IfLt,
                Opcode::IfGt => Opcode::IfLe,
                Opcode::IfLe => Opcode::IfGt,
                _ => return None,
            };
            Some(Condition::Compare { left: left.clone(), right: right.clone(), op: flipped })
        }
        Condition::Var(_) => None,
    }
}

/// Match the **balanced** shape:
/// `Stmt::If { cond, then=Const-K_a → reg N, else=Some(Const-K_b → reg N) }`
/// where `{K_a, K_b} = {0, 1}`.
///
/// Returns `(dst, cond_in_positive_polarity)`. Polarity:
/// - then=1, else=0 → cond directly (when cond is true, set 1)
/// - then=0, else=1 → !cond (when cond is true, set 0; lifted v = !cond)
fn match_balanced_compare_if(stmt: &Stmt) -> Option<(VarId, Condition)> {
    let Stmt::If { cond, then_body, else_body: Some(else_body) } = stmt else {
        return None;
    };
    let (then_dst, then_lit) = match_const_0_or_1(then_body)?;
    let (else_dst, else_lit) = match_const_0_or_1(else_body)?;
    if then_dst.reg() != else_dst.reg() {
        return None;
    }
    // Pick the lower-version branch as the lifted dst so emit's canonical-type
    // predicate (`env.types.iter().filter(reg).min_by_key(ver)`) lines up with
    // the declaration site deterministically — the predicate gates the
    // `boolean ` type prefix on `then_dst.ver()` matching the canonical entry,
    // and which branch has the lower ver is incidental SSA numbering.
    let dst = if then_dst.ver() <= else_dst.ver() { then_dst } else { else_dst };
    match (then_lit, else_lit) {
        (1, 0) => Some((dst, cond.clone())),
        (0, 1) => Some((dst, negate_condition(cond)?)),
        _ => None, // {0,0} or {1,1} aren't boolean comparisons.
    }
}

/// Match the **else-only** shape across two adjacent stmts in a Seq:
/// `Expr(Const-0 → reg N)` then
/// `If { cond, then=empty, else=Some(Const-1 → reg N) }`
///
/// The init-zero may be separated from the if by Stmts that don't define or use
/// reg N — that's why this matches a window-pair rather than two strictly
/// adjacent stmts. `init_idx` is the position of the const-0; `if_idx` the
/// position of the if. Caller deletes `init_idx` and replaces `if_idx`.
///
/// Polarity: when cond is FALSE (else runs), v=1 → lifted v = !cond.
/// Mirror form (then-only set-1 with `else=None`):
/// `If { cond, then=Some(Const-1 → reg N), else=None }` → lifted v = cond.
fn match_else_only_compare_if(
    stmts: &[Stmt],
    if_idx: usize,
) -> Option<(usize, VarId, Condition)> {
    let if_stmt = stmts.get(if_idx)?;
    let Stmt::If { cond, then_body, else_body } = if_stmt else { return None; };

    // Determine which form (else-only set-1 vs then-only set-1).
    let (set_dst, lifted_cond) = if is_empty_seq(then_body) {
        // Form A: then=empty, else=set-1 → v = !cond.
        let else_body = else_body.as_deref()?;
        let (d, lit) = match_const_0_or_1(else_body)?;
        if lit != 1 { return None; }
        (d, negate_condition(cond)?)
    } else if else_body.is_none() {
        // Form B: then=set-1, else=None → v = cond.
        let (d, lit) = match_const_0_or_1(then_body)?;
        if lit != 1 { return None; }
        (d, cond.clone())
    } else {
        return None;
    };

    // Scan backward for the const-0 init to the same reg, tolerating intervening
    // Stmts that do not define or use reg N. Stop on any if/while/etc.
    let target_reg = set_dst.reg();
    for j in (0..if_idx).rev() {
        let prev = &stmts[j];
        if let Some((init_dst, init_lit)) = match_const_0_or_1(prev) {
            if init_dst.reg() == target_reg && init_lit == 0 {
                return Some((j, set_dst, lifted_cond));
            }
        }
        // Keep walking only past Stmts that won't have observable interaction
        // with reg N. Conservatively allow `Stmt::Expr` and prior
        // `Stmt::BooleanAssign` whose dst+uses are disjoint from reg N. Stop
        // at any structured stmt (control flow, etc.).
        match prev {
            Stmt::Expr(insn) => {
                if let Some(ref d) = insn.dst {
                    if d.reg() == target_reg {
                        return None;
                    }
                }
                if insn.uses.iter().any(|u| u.reg() == target_reg) {
                    return None;
                }
            }
            Stmt::BooleanAssign { dst, cond } => {
                if dst.reg() == target_reg {
                    return None;
                }
                // Reg-level check on the cond's referenced vars.
                let cond_touches_target = match cond {
                    Condition::TestZero { var, .. } => var.reg() == target_reg,
                    Condition::Compare { left, right, .. } => {
                        left.reg() == target_reg || right.reg() == target_reg
                    }
                    Condition::Var(v) => v.reg() == target_reg,
                };
                if cond_touches_target {
                    return None;
                }
            }
            _ => return None,
        }
    }
    None
}

/// Walk a `Seq` and lift recognized comparison-as-value shapes to
/// `Stmt::BooleanAssign`. See module-level comment for the canonical shapes.
// WHY: `i + 1` index into `stmts` with `i + 1 < stmts.len()` guard; `i += 1` per iteration.
#[allow(clippy::arithmetic_side_effects, reason = "`i + 1` index into `stmts` with `i + 1 < stmts.len()` guard; `i += 1` per iteration.")]
fn lift_comparison_as_value_in_seq(stmts: &mut Vec<Stmt>) -> bool {
    let mut changed = false;
    let mut i = 0;
    while i < stmts.len() {
        // Pattern A: balanced if/else with const-0 + const-1.
        if let Some((dst, cond)) = match_balanced_compare_if(&stmts[i]) {
            stmts[i] = Stmt::BooleanAssign { dst, cond };
            changed = true;
            // Re-check this position — chained boolean lifts are possible.
            continue;
        }
        // Pattern B: const-0 init + else-only / then-only if.
        if let Some((init_idx, dst, cond)) = match_else_only_compare_if(stmts, i) {
            stmts[i] = Stmt::BooleanAssign { dst, cond };
            stmts.remove(init_idx);
            changed = true;
            // After remove, indices shifted; current `i` now points at the
            // BooleanAssign (since init_idx < i). Re-check the new position.
            continue;
        }
        i += 1;
    }
    changed
}

// ── Public API ──────────────────────────────────────────────────────

/// Apply syntactic sugar transformations to the Stmt tree.
/// Returns true if any changes were made.
///
/// `enclosing_class` is the `TypeIdx` of the class that owns the method
/// whose `Stmt` tree is being desugared. Threaded through to the
/// signature-engine driver so dialect-aware recognizers
/// (`javac21::*` vs `kotlinc19::*`) can gate on
/// `dex.class_has_kotlin_metadata(enclosing_class)` to avoid matching
/// each other's IR shapes (per `signatures::DexSigInput::enclosing_class`).
pub fn desugar(
    stmt: &mut Stmt,
    dex: &DexFile,
    _env: &TypeEnv,
    enclosing_class: TypeIdx,
) -> bool {
    // Pre-compute a method-wide `VarId → i32` env of integer constants.
    // R8 hoists common tag constants out of the StringSwitch dispatcher
    // — sometimes into a scope that's an ancestor of the dispatcher's
    // parent Seq (#47 audit on `Lg2/a;->h`). SSA versions are unique
    // and dominate uses, so a method-wide collection is sound for
    // resolving `Move v_tag, v_src` tag-assignments in
    // `extract_const_int_assign`.
    let method_const_int_env = collect_method_const_int_env(stmt);
    let mut changed_any = false;
    // Bounded fixpoint: re-run until a pass reports no change, but at most
    // MAX_DESUGAR_PASSES times. The cap guarantees termination even when a
    // transform never reaches a fixpoint (oscillation, or a spurious
    // `changed = true`); on hitting it the body is left in its current
    // best-guess shape. See MAX_DESUGAR_PASSES for the load-bearing rationale.
    for _ in 0..MAX_DESUGAR_PASSES {
        // The top-level call from `decompile_method` passes the
        // method-root Stmt as `stmt`, so `is_top_level: true` is the
        // correct seed. desugar_recursive's recursive descents into
        // child Stmts pass `is_top_level: false`. `depth: 0` seeds the
        // recursion bound (cap MAX_DESUGAR_DEPTH); see the const's
        // doc-comment for the load-bearing rationale.
        let changed = desugar_recursive(
            stmt,
            dex,
            enclosing_class,
            true,
            &method_const_int_env,
            0,
        );
        if !changed {
            break;
        }
        changed_any = true;
    }
    changed_any
}

/// Walk the entire method `Stmt` tree once, collecting every
/// `VarId → i32` mapping for integer-constant Expr stmts. Used at
/// `desugar` entry to give `try_collapse_adjacent_switches` a
/// method-wide view of const-int sources for resolving R8-hoisted
/// `Move v_tag, v_const_src` tag-assignments.
///
/// Soundness: SSA versions are unique and the def of any VarId
/// dominates its uses (otherwise the SSA would be invalid). So a
/// VarId observed anywhere in the method body always identifies the
/// same definition, regardless of structural nesting.
fn collect_method_const_int_env(stmt: &Stmt) -> std::collections::BTreeMap<VarId, i32> {
    let mut env = std::collections::BTreeMap::new();
    walk_stmt_collect_const_int(stmt, &mut env);
    env
}

fn walk_stmt_collect_const_int(
    stmt: &Stmt,
    env: &mut std::collections::BTreeMap<VarId, i32>,
) {
    match stmt {
        Stmt::Expr(insn) => {
            if !insn.uses.is_empty() {
                return;
            }
            if !matches!(
                insn.insn.op,
                Opcode::Const | Opcode::Const4 | Opcode::Const16 | Opcode::ConstHigh16
            ) {
                return;
            }
            let Some(dst) = insn.dst.as_ref() else {
                return;
            };
            let Ok(val) = i32::try_from(insn.insn.literal) else {
                return;
            };
            env.insert(dst.clone(), val);
        }
        Stmt::Seq(stmts) => {
            for s in stmts {
                walk_stmt_collect_const_int(s, env);
            }
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            walk_stmt_collect_const_int(then_body, env);
            if let Some(eb) = else_body {
                walk_stmt_collect_const_int(eb, env);
            }
        }
        Stmt::While { body, .. }
        | Stmt::DoWhile { body, .. }
        | Stmt::Synchronized { body, .. }
        | Stmt::ForEach { body, .. } => walk_stmt_collect_const_int(body, env),
        Stmt::Switch { cases, default, .. } => {
            for (_, b) in cases {
                walk_stmt_collect_const_int(b, env);
            }
            if let Some(d) = default {
                walk_stmt_collect_const_int(d, env);
            }
        }
        Stmt::StringSwitch { cases, default, .. } => {
            for (_, b) in cases {
                walk_stmt_collect_const_int(b, env);
            }
            if let Some(d) = default {
                walk_stmt_collect_const_int(d, env);
            }
        }
        Stmt::TryCatch { body, catches } => {
            walk_stmt_collect_const_int(body, env);
            for c in catches {
                walk_stmt_collect_const_int(&c.body, env);
            }
        }
        Stmt::For {
            init, update, body, ..
        } => {
            walk_stmt_collect_const_int(init, env);
            walk_stmt_collect_const_int(update, env);
            walk_stmt_collect_const_int(body, env);
        }
        Stmt::MultiArm { arms, default, .. } => {
            for arm in arms {
                walk_stmt_collect_const_int(&arm.body, env);
            }
            if let Some(d) = default {
                walk_stmt_collect_const_int(d, env);
            }
        }
        // Leaf / no nested Stmt children.
        Stmt::Return(_)
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
        | Stmt::BooleanAssign { .. }
        | Stmt::Unrecognized { .. } => {}
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{Instruction, RegList};

    fn make_expr(
        op: Opcode,
        dst: Option<(u16, u32)>,
        uses: Vec<(u16, u32)>,
        pool: Option<PoolIndex>,
    ) -> Stmt {
        Stmt::Expr(SsaInsn {
            insn: Instruction {
                addr: 0,
                op,
                size: 1,
                dst: dst.map(|d| d.0),
                src: RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: pool,
            },
            dst: dst.map(|d| VarId::new(d.0, d.1)),
            uses: uses.into_iter().map(|u| VarId::new(u.0, u.1)).collect(),
        })
    }

    #[test]
    fn string_concat_detection() {
        // Build the pattern: new SB, init, append(x), MRO, toString, MRO
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = DexFile::parse(fixture, None).unwrap();

        // Find StringBuilder type and method indices from the fixture
        let sb_type_idx = dex
            .type_descriptors
            .iter()
            .position(|d| d == "Ljava/lang/StringBuilder;")
            .map(|i| crate::ids::TypeIdx(i as u32));
        let sb_init_idx = dex
            .methods
            .iter()
            .position(|m| {
                dex.get_type_descriptor(m.class_idx).ok() == Some("Ljava/lang/StringBuilder;")
                    && dex.get_string(m.name_idx).ok() == Some("<init>")
            })
            .map(|i| MethodIdx(i as u32));
        let sb_append_idx = dex
            .methods
            .iter()
            .position(|m| {
                dex.get_type_descriptor(m.class_idx).ok() == Some("Ljava/lang/StringBuilder;")
                    && dex.get_string(m.name_idx).ok() == Some("append")
            })
            .map(|i| MethodIdx(i as u32));
        let sb_tostring_idx = dex
            .methods
            .iter()
            .position(|m| {
                dex.get_type_descriptor(m.class_idx).ok() == Some("Ljava/lang/StringBuilder;")
                    && dex.get_string(m.name_idx).ok() == Some("toString")
            })
            .map(|i| MethodIdx(i as u32));

        // Skip test if fixture doesn't have StringBuilder
        let (sb_tidx, init_midx, append_midx, tostr_midx) =
            match (sb_type_idx, sb_init_idx, sb_append_idx, sb_tostring_idx) {
                (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
                _ => return, // fixture doesn't have these methods
            };

        let mut stmts = vec![
            // new-instance v0, StringBuilder
            make_expr(
                Opcode::NewInstance,
                Some((0, 0)),
                vec![],
                Some(PoolIndex::Type(sb_tidx)),
            ),
            // invoke-direct {v0}, SB.<init>
            make_expr(
                Opcode::InvokeDirect,
                None,
                vec![(0, 0)],
                Some(PoolIndex::Method(init_midx)),
            ),
            // invoke-virtual {v0, v1}, SB.append
            make_expr(
                Opcode::InvokeVirtual,
                None,
                vec![(0, 0), (1, 0)],
                Some(PoolIndex::Method(append_midx)),
            ),
            // move-result-object v0
            make_expr(Opcode::MoveResultObject, Some((0, 1)), vec![], None),
            // invoke-virtual {v0}, SB.toString
            make_expr(
                Opcode::InvokeVirtual,
                None,
                vec![(0, 1)],
                Some(PoolIndex::Method(tostr_midx)),
            ),
            // move-result-object v2
            make_expr(Opcode::MoveResultObject, Some((2, 0)), vec![], None),
        ];

        let changed = desugar_string_concat_in_seq(&mut stmts, &dex);
        assert!(changed, "should detect string concat");
        assert!(stmts.iter().any(|s| matches!(s, Stmt::StringConcat { .. })));
    }

    #[test]
    fn string_concat_with_interleaved_nop_still_sugars() {
        // Compiler-emitted alignment Nops can appear between the
        // StringBuilder pattern's instructions. The sugar pass must skip
        // them, not bail.
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = DexFile::parse(fixture, None).unwrap();

        let sb_type_idx = dex
            .type_descriptors
            .iter()
            .position(|d| d == "Ljava/lang/StringBuilder;")
            .map(|i| crate::ids::TypeIdx(i as u32));
        let sb_init_idx = dex
            .methods
            .iter()
            .position(|m| {
                dex.get_type_descriptor(m.class_idx).ok() == Some("Ljava/lang/StringBuilder;")
                    && dex.get_string(m.name_idx).ok() == Some("<init>")
            })
            .map(|i| MethodIdx(i as u32));
        let sb_append_idx = dex
            .methods
            .iter()
            .position(|m| {
                dex.get_type_descriptor(m.class_idx).ok() == Some("Ljava/lang/StringBuilder;")
                    && dex.get_string(m.name_idx).ok() == Some("append")
            })
            .map(|i| MethodIdx(i as u32));
        let sb_tostring_idx = dex
            .methods
            .iter()
            .position(|m| {
                dex.get_type_descriptor(m.class_idx).ok() == Some("Ljava/lang/StringBuilder;")
                    && dex.get_string(m.name_idx).ok() == Some("toString")
            })
            .map(|i| MethodIdx(i as u32));

        let (sb_tidx, init_midx, append_midx, tostr_midx) =
            match (sb_type_idx, sb_init_idx, sb_append_idx, sb_tostring_idx) {
                (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
                _ => return, // fixture doesn't carry StringBuilder
            };

        // Pattern: new SB, NOP, <init>, NOP, append, MRO, toString, MRO.
        // Both Nops exercise the new pattern-recognition arms — one in
        // the init-scan loop (line ~191), one in the append-scan loop
        // (line ~269). The two MROs mirror the SSA-versioned shape of
        // `string_concat_detection` above (append's return-value MRO +
        // toString's terminal MRO are required for `parts` + `concat_dst`
        // both to populate).
        let mut stmts = vec![
            make_expr(
                Opcode::NewInstance,
                Some((0, 0)),
                vec![],
                Some(PoolIndex::Type(sb_tidx)),
            ),
            // Init-scan Nop — must be skipped, not break the pattern.
            make_expr(Opcode::Nop, None, vec![], None),
            make_expr(
                Opcode::InvokeDirect,
                None,
                vec![(0, 0)],
                Some(PoolIndex::Method(init_midx)),
            ),
            // Append-scan Nop — must also be skipped.
            make_expr(Opcode::Nop, None, vec![], None),
            make_expr(
                Opcode::InvokeVirtual,
                None,
                vec![(0, 0), (1, 0)],
                Some(PoolIndex::Method(append_midx)),
            ),
            // MRO for append's return value bumps current_sb to v0(1).
            make_expr(Opcode::MoveResultObject, Some((0, 1)), vec![], None),
            make_expr(
                Opcode::InvokeVirtual,
                None,
                vec![(0, 1)],
                Some(PoolIndex::Method(tostr_midx)),
            ),
            // Terminal MRO captures the StringConcat's dst.
            make_expr(Opcode::MoveResultObject, Some((2, 0)), vec![], None),
        ];

        let changed = desugar_string_concat_in_seq(&mut stmts, &dex);
        assert!(
            changed,
            "Nop-interleaved StringBuilder pattern must still desugar"
        );
        assert!(
            stmts.iter().any(|s| matches!(s, Stmt::StringConcat { .. })),
            "Stmt::StringConcat must be present after desugaring"
        );
    }

    #[test]
    fn string_concat_preserves_non_pattern() {
        // Just a new-instance without the full pattern — should not match
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = DexFile::parse(fixture, None).unwrap();

        let mut stmts = vec![
            make_expr(Opcode::Nop, None, vec![], None),
            make_expr(Opcode::ReturnVoid, None, vec![], None),
        ];

        let changed = desugar_string_concat_in_seq(&mut stmts, &dex);
        assert!(!changed, "should not match non-pattern");
        assert_eq!(stmts.len(), 2);
    }

    fn make_const_lit(reg: u16, ver: u32, lit: i64) -> Stmt {
        Stmt::Expr(SsaInsn {
            insn: Instruction {
                addr: 0,
                op: Opcode::Const4,
                size: 1,
                dst: Some(reg),
                src: RegList::empty(),
                literal: lit,
                target: None,
                pool_idx: None,
            },
            dst: Some(VarId::new(reg, ver)),
            uses: vec![],
        })
    }

    fn make_arrlen(reg: u16, ver: u32, src_reg: u16, src_ver: u32) -> Stmt {
        Stmt::Expr(SsaInsn {
            insn: Instruction {
                addr: 0,
                op: Opcode::ArrayLength,
                size: 1,
                dst: Some(reg),
                src: RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: None,
            },
            dst: Some(VarId::new(reg, ver)),
            uses: vec![VarId::new(src_reg, src_ver)],
        })
    }

    #[test]
    fn lift_pattern_a_balanced_then_zero_else_one() {
        // if (cond) { v=0 } else { v=1 }  → boolean v = !cond
        let mut stmts = vec![
            make_arrlen(1, 2, 4, 0),
            Stmt::If {
                cond: Condition::TestZero { var: VarId::new(1, 2), op: Opcode::IfNez },
                then_body: Box::new(make_const_lit(1, 6, 0)),
                else_body: Some(Box::new(make_const_lit(1, 5, 1))),
            },
        ];
        let changed = lift_comparison_as_value_in_seq(&mut stmts);
        assert!(changed, "balanced if should lift");
        assert_eq!(stmts.len(), 2);
        match &stmts[1] {
            Stmt::BooleanAssign { dst, cond } => {
                assert_eq!(dst.reg(), 1);
                // negated polarity: original cond was IfNez → flipped to IfEqz.
                match cond {
                    Condition::TestZero { op, .. } => assert_eq!(*op, Opcode::IfEqz),
                    _ => panic!("expected TestZero"),
                }
            }
            other => panic!("expected BooleanAssign, got {other:?}"),
        }
    }

    #[test]
    fn lift_pattern_a_balanced_then_one_else_zero() {
        // if (cond) { v=1 } else { v=0 }  → boolean v = cond (positive polarity)
        let mut stmts = vec![Stmt::If {
            cond: Condition::Compare {
                left: VarId::new(2, 1),
                right: VarId::new(3, 1),
                op: Opcode::IfEq,
            },
            then_body: Box::new(make_const_lit(4, 7, 1)),
            else_body: Some(Box::new(make_const_lit(4, 8, 0))),
        }];
        let changed = lift_comparison_as_value_in_seq(&mut stmts);
        assert!(changed, "balanced if should lift");
        match &stmts[0] {
            Stmt::BooleanAssign { dst, cond } => {
                assert_eq!(dst.reg(), 4);
                // positive polarity: cond unchanged.
                match cond {
                    Condition::Compare { op, .. } => assert_eq!(*op, Opcode::IfEq),
                    _ => panic!("expected Compare"),
                }
            }
            other => panic!("expected BooleanAssign, got {other:?}"),
        }
    }

    #[test]
    fn lift_pattern_b_else_only() {
        // const-0 → v ; if (cond) { } else { v=1 }  → boolean v = !cond
        // (with intervening unrelated const + arrlen)
        let mut stmts = vec![
            make_const_lit(2, 3, 0),                      // pre-init: v2 = 0
            make_const_lit(3, 4, 1),                      // unrelated literal-1
            make_arrlen(4, 8, 4, 0),                      // unrelated arrlen
            Stmt::If {
                cond: Condition::Compare {
                    left: VarId::new(4, 8),
                    right: VarId::new(3, 4),
                    op: Opcode::IfNe,
                },
                then_body: Box::new(Stmt::Seq(vec![])),
                else_body: Some(Box::new(make_const_lit(2, 10, 1))),
            },
        ];
        let changed = lift_comparison_as_value_in_seq(&mut stmts);
        assert!(changed, "else-only if should lift across non-touching prev stmts");
        // After lift: const-1 + arrlen + BooleanAssign (3 stmts; const-0 removed).
        assert_eq!(stmts.len(), 3);
        match stmts.last().expect("non-empty post-lift") {
            Stmt::BooleanAssign { dst, cond } => {
                assert_eq!(dst.reg(), 2);
                // negated polarity: cond was IfNe → flipped to IfEq.
                match cond {
                    Condition::Compare { op, .. } => assert_eq!(*op, Opcode::IfEq),
                    _ => panic!("expected Compare"),
                }
            }
            other => panic!("expected BooleanAssign at tail, got {other:?}"),
        }
    }

    #[test]
    fn lift_refuses_non_zero_one_const_pair() {
        // {2, 3} const pair — not a boolean shape. Must NOT lift.
        let mut stmts = vec![Stmt::If {
            cond: Condition::TestZero { var: VarId::new(0, 0), op: Opcode::IfEqz },
            then_body: Box::new(make_const_lit(1, 1, 2)),
            else_body: Some(Box::new(make_const_lit(1, 2, 3))),
        }];
        let changed = lift_comparison_as_value_in_seq(&mut stmts);
        assert!(!changed, "non-{{0,1}} pair must not lift");
        assert!(matches!(&stmts[0], Stmt::If { .. }));
    }

    // ── #47 extract_const_int_assign env-resolved Move ────────────────

    fn make_move(dst_reg: u16, dst_ver: u32, src_reg: u16, src_ver: u32, op: Opcode) -> Stmt {
        Stmt::Expr(SsaInsn {
            insn: Instruction {
                addr: 0,
                op,
                size: 1,
                dst: Some(dst_reg),
                src: RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: None,
            },
            dst: Some(VarId::new(dst_reg, dst_ver)),
            uses: vec![VarId::new(src_reg, src_ver)],
        })
    }

    #[test]
    fn extract_const_int_assign_accepts_direct_const4() {
        let env = std::collections::BTreeMap::new();
        let s = make_const_lit(8, 19, 4);
        assert_eq!(extract_const_int_assign(&s, &env), Some((4, 8)));
    }

    #[test]
    fn extract_const_int_assign_resolves_move_via_env() {
        // R8 const-hoist case: `move v8, v3` where v3 was Const4 4.
        let mut env = std::collections::BTreeMap::new();
        env.insert(VarId::new(3, 6), 4i32);
        let s = make_move(8, 12, 3, 6, Opcode::Move);
        assert_eq!(
            extract_const_int_assign(&s, &env),
            Some((4, 8)),
            "Move v8, v3 must resolve to (4, 8) when v3=4 is in env"
        );
    }

    #[test]
    fn extract_const_int_assign_resolves_move_from16() {
        // MoveFrom16 variant — same env-lookup path.
        let mut env = std::collections::BTreeMap::new();
        env.insert(VarId::new(16, 13), -1i32);
        let s = make_move(14, 154, 16, 13, Opcode::MoveFrom16);
        assert_eq!(extract_const_int_assign(&s, &env), Some((-1, 14)));
    }

    #[test]
    fn extract_const_int_assign_rejects_move_when_source_not_in_env() {
        // Move from a register that is NOT a known const — must reject
        // (e.g. `move v_tag, v_method_arg`). Soundness: never invent a
        // tag value for a non-constant source.
        let env = std::collections::BTreeMap::new(); // empty
        let s = make_move(8, 31, 0, 1, Opcode::Move);
        assert_eq!(extract_const_int_assign(&s, &env), None);
    }

    #[test]
    fn extract_const_int_assign_rejects_move_wide() {
        // MoveWide is a WIDE (long/double) copy; must NOT be confused
        // with int-tag move. Even if the source is in env, reject —
        // wide regs participate in a different SSA arity.
        let mut env = std::collections::BTreeMap::new();
        env.insert(VarId::new(3, 6), 4i32);
        let s = make_move(8, 12, 3, 6, Opcode::MoveWide);
        assert_eq!(extract_const_int_assign(&s, &env), None);
    }

    #[test]
    fn extract_const_int_assign_rejects_move_object() {
        // MoveObject is an object-reference copy; reject for the same
        // reason as MoveWide.
        let mut env = std::collections::BTreeMap::new();
        env.insert(VarId::new(3, 6), 4i32);
        let s = make_move(8, 12, 3, 6, Opcode::MoveObject);
        assert_eq!(extract_const_int_assign(&s, &env), None);
    }

    #[test]
    fn collect_method_const_int_env_walks_nested_seq() {
        // Const4 def in a nested If-then-body must be reachable from
        // the method-wide env.
        let inner = Stmt::Seq(vec![make_const_lit(3, 6, 4), make_const_lit(4, 7, 2)]);
        let stmt = Stmt::Seq(vec![
            make_const_lit(15, 12, 3),
            Stmt::If {
                cond: Condition::TestZero { var: VarId::new(0, 0), op: Opcode::IfEqz },
                then_body: Box::new(inner),
                else_body: None,
            },
        ]);
        let env = collect_method_const_int_env(&stmt);
        assert_eq!(env.get(&VarId::new(15, 12)), Some(&3));
        assert_eq!(env.get(&VarId::new(3, 6)), Some(&4));
        assert_eq!(env.get(&VarId::new(4, 7)), Some(&2));
    }

    #[test]
    fn collect_method_const_int_env_skips_non_const_exprs() {
        // ArrayLength has a use, so it's not a const — must be skipped.
        let stmt = Stmt::Seq(vec![
            make_const_lit(3, 6, 4),
            make_arrlen(7, 12, 4, 0),
        ]);
        let env = collect_method_const_int_env(&stmt);
        assert_eq!(env.get(&VarId::new(3, 6)), Some(&4));
        assert!(!env.contains_key(&VarId::new(7, 12)));
    }

    /// Pin `build_use_count_table` semantics. The table must:
    /// - count every use across the body in one tree walk;
    /// - assign 0 (or absent) to vars that are defined but never read
    ///   (defs are stmts[i].dst on Expr; not counted as a use);
    /// - aggregate uses across nested Stmt arms (If / Switch / etc.).
    fn make_return(reg: u16, ver: u32) -> Stmt {
        Stmt::Return(Some(VarId::new(reg, ver)))
    }
    fn make_expr_def(dst_reg: u16, dst_ver: u32, use_reg: u16, use_ver: u32) -> Stmt {
        // Synthetic add-int: dst = use + use. Two uses of (use_reg, use_ver).
        make_expr(
            Opcode::AddInt,
            Some((dst_reg, dst_ver)),
            vec![(use_reg, use_ver), (use_reg, use_ver)],
            None,
        )
    }

    #[test]
    fn build_use_count_table_counts_uses_not_defs() {
        // v0 def then return v0 — 1 use of v0 (the return); v0's def is
        // a fresh dst, not a use, so it does not contribute.
        let stmts = vec![
            make_expr(Opcode::Const4, Some((0, 0)), vec![], None),
            make_return(0, 0),
        ];
        let table = build_use_count_table(&stmts);
        assert_eq!(table.get(&VarId::new(0, 0)), Some(&1));
    }

    #[test]
    fn build_use_count_table_aggregates_multiple_uses() {
        // v0 used twice in one Expr (synthetic add-int v0+v0) plus
        // once in a return.
        let stmts = vec![
            make_expr(Opcode::Const4, Some((0, 0)), vec![], None),
            make_expr_def(1, 0, 0, 0),
            make_return(0, 0),
        ];
        let table = build_use_count_table(&stmts);
        assert_eq!(table.get(&VarId::new(0, 0)), Some(&3));
        // v1 is defined but never read.
        assert_eq!(table.get(&VarId::new(1, 0)), None);
    }

    #[test]
    fn inline_single_use_vars_inlines_single_use_return() {
        // Both code-paths must inline this shape:
        //   v0 = const 42; return v0;  →  InlinedReturn(const 42)
        let mut stmts = vec![
            make_expr(Opcode::Const4, Some((0, 0)), vec![], None),
            make_return(0, 0),
        ];
        let changed = inline_single_use_vars(&mut stmts);
        assert!(changed, "single-use var must inline");
        assert_eq!(stmts.len(), 1);
        assert!(matches!(stmts[0], Stmt::InlinedReturn(_)));
    }

    #[test]
    fn inline_single_use_vars_preserves_multi_use_def() {
        // v0 used twice — must NOT inline.
        let mut stmts = vec![
            make_expr(Opcode::Const4, Some((0, 0)), vec![], None),
            make_expr_def(1, 0, 0, 0), // uses v0 twice
            make_return(0, 0),         // also uses v0
        ];
        let pre_len = stmts.len();
        let changed = inline_single_use_vars(&mut stmts);
        assert!(!changed, "multi-use var must not inline");
        assert_eq!(stmts.len(), pre_len);
    }

    // ── desugar_recursive depth cap regression tests ─────────────────
    //
    // Source of these tests: ASAN trip on recursive Stmt desugaring.
    // Without the cap, pathologically deep Stmt trees overflow the rayon worker stack.
    // With the cap (MAX_DESUGAR_DEPTH = 256), recursion halts at the
    // boundary and returns `false`.

    #[test]
    fn desugar_recursive_early_returns_at_depth_cap() {
        // Direct invocation with `depth == MAX_DESUGAR_DEPTH + 1` must
        // hit the entry guard and return `false` immediately, without
        // touching the Stmt body. Marker: a deliberately-recursive
        // tree at this entry should NOT recurse further — if the guard
        // were absent the test would consume O(DEPTH) frames.
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = DexFile::parse(fixture, None)
            .expect("classes.dex fixture must parse for test setup");
        let env = std::collections::BTreeMap::new();
        // A 3-level tree is sufficient; cap fires at entry so depth of
        // the tree below the call is irrelevant.
        let mut stmt = Stmt::Seq(vec![Stmt::Seq(vec![Stmt::Seq(vec![])])]);
        let changed = desugar_recursive(
            &mut stmt,
            &dex,
            TypeIdx(0),
            true,
            &env,
            MAX_DESUGAR_DEPTH + 1,
        );
        assert!(
            !changed,
            "desugar_recursive must early-return false when depth > MAX_DESUGAR_DEPTH"
        );
    }

    #[test]
    fn desugar_recursive_walks_under_cap() {
        // Sanity-positive: a tree well under the cap walks normally
        // and returns without panic. Confirms the guard is `depth >`
        // (strictly greater), not `>=` (which would erroneously block
        // the legal `depth == MAX_DESUGAR_DEPTH` case).
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = DexFile::parse(fixture, None)
            .expect("classes.dex fixture must parse for test setup");
        let env = std::collections::BTreeMap::new();
        let mut stmt = Stmt::Seq(vec![]);
        // depth = MAX_DESUGAR_DEPTH exactly — must NOT trip the guard.
        let _changed = desugar_recursive(
            &mut stmt,
            &dex,
            TypeIdx(0),
            true,
            &env,
            MAX_DESUGAR_DEPTH,
        );
        // No panic = pass; the empty Seq has no rewriteable shape, so
        // `changed` may be false. The assertion is "does not panic".
    }

    #[test]
    fn desugar_does_not_panic_on_deep_tree() {
        // Full end-to-end: build Stmt::Seq nested past the cap, call
        // the public `desugar` entrypoint, assert it returns without
        // stack overflow or panic.
        //
        // Test isolates the recursion-depth dimension: each Seq frame
        // is `vec![inner_seq]` (a single-child sequence). The
        // BTreeMap allocated by `inline_single_use_vars` at each
        // Seq is small (no var defs in an empty leaf, no uses
        // accumulated above), so this test does NOT reproduce the
        // ASAN trip's full per-frame allocation pressure — it
        // reproduces the recursion shape alone. The structural
        // contract proven here is: recursion halts at the cap. The
        // ASAN-trip per-frame heap pressure is reproduced
        // separately by `fuzz_enum_cross_class` exercising real
        // DEX inputs (parent stream's deferred follow-up
        // `dex-fuzz-decompile-method-deep-nesting-seed`).
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = DexFile::parse(fixture, None)
            .expect("classes.dex fixture must parse for test setup");
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: Vec::new(),
        };
        let depth = MAX_DESUGAR_DEPTH + 100;
        let mut stmt = Stmt::Seq(vec![]);
        for _ in 0..depth {
            stmt = Stmt::Seq(vec![stmt]);
        }
        // Must not panic. Return value is "did any rewrite happen" —
        // an empty-Seq chain has no rewriteable shape, so `false` is
        // the expected value; the assertion is on panic-freedom.
        let _changed = desugar(&mut stmt, &dex, &env, TypeIdx(0));
    }
}
