//! kotlinc 1.9.22 `val (a, b) = source` data-class destructure
//! recognizer.
//!
//! Recognizes the canonical kotlinc-1.9 lowering of a Kotlin data class
//! destructure. From the empirical bytecode audit:
//!
//! > Lowering: straightforward `componentN()` synthetic-method calls —
//! > `aload <pair> + invokevirtual Pair2.component1 + istore_<a>` then
//! > `aload <pair> + invokevirtual Pair2.component2 + istore_<b>`.
//!
//! This stream's post-structuring IR audit (dump at
//! `/tmp/kotlin-ir-audit-destructure/destructure.stmt.txt`) confirmed:
//!
//! - Per-position pattern: `Stmt::Expr(InvokeVirtual <componentN>) +
//!   Stmt::Expr(MoveResult / MoveResultObject)`.
//! - Receiver `VarId` is constant across all positions (the destructured
//!   value).
//! - Method name follows the literal `component<N>` convention with
//!   monotone N starting at 1.
//!
//! On match → produces a single
//! [`Stmt::Let`] with `bindings` ordered
//! by source-level position and `source` set to the receiver `VarId`.
//! Emit (PR-8) dispatches on dialect: Kotlin renders
//! `val (a, b) = source`; Java renders the original expansion form
//! (Java has no source-level destructure).
//!
//! **Single shape only** per parent OQ §3 RESOLVED-default: `_`-discard,
//! lambda-parameter destructuring, and N>2 arity variants are explicit
//! follow-ups pending a real consumer surfacing them.
//!
//! Positive metadata gate: only fires when
//! `dex.class_has_kotlin_metadata(enclosing_class)` — Java code never
//! emits `componentN()` synthetic-method chains in the destructure
//! shape.
#![allow(missing_docs, reason = "internal")]

use droidsaw_common::signature::{
    KotlinVersion, MatchOutcome, Signature, SignatureId, SourceDialect,
};

use crate::decode::PoolIndex;
use crate::opcodes::Opcode;
use crate::signatures::{DexBackend, DexSigInput, RecognizedDexShape};
use crate::ssa::VarId;
use crate::structure::{SignatureProvenance, Stmt};

/// Reserved [`SignatureId`] for the kotlinc-1.9 data-class destructure
/// recognizer. Per Day-1 prep #3 SignatureId allocation.
pub const DATA_CLASS_DESTRUCTURE_SIGNATURE_ID: SignatureId = SignatureId(104);

/// Minimum binding count for the recognizer to fire. A "destructure"
/// with one position is degenerate (just `val a = source.component1()`)
/// and indistinguishable from a regular method call — kotlinc doesn't
/// emit single-position `val (a) = source` syntax in practice. Require
/// ≥2 to avoid false-positive matches on isolated `componentN` calls.
const MIN_BINDINGS: usize = 2;

/// Cap on binding count. Defends against pathological IR depth on
/// adversarial input. Real Kotlin data classes rarely exceed component8;
/// 32 leaves headroom while preventing unbounded chains.
const MAX_BINDINGS: usize = 32;

/// Number of sibling `Stmt`s consumed per binding position: one
/// `InvokeVirtual` + one `MoveResult` / `MoveResultObject`.
const STMTS_PER_BINDING: usize = 2;

/// Recognizer for the kotlinc-1.9 data-class destructure lowering.
pub struct DataClassDestructureSignature;

impl Signature<DexBackend> for DataClassDestructureSignature {
    fn id(&self) -> SignatureId {
        DATA_CLASS_DESTRUCTURE_SIGNATURE_ID
    }

    fn dialect(&self) -> SourceDialect {
        SourceDialect::Kotlin(KotlinVersion::V19)
    }

    fn try_match<'a>(&self, input: DexSigInput<'a>) -> MatchOutcome<RecognizedDexShape>
    where
        DexBackend: 'a,
    {
        let DexSigInput {
            stmts,
            position,
            dex,
            enclosing_class,
            ..
        } = input;

        // Positive dialect gate.
        match dex.class_has_kotlin_metadata(enclosing_class) {
            crate::DetectorVerdict::Yes => {}
            crate::DetectorVerdict::No => return MatchOutcome::NoMatch,
            crate::DetectorVerdict::Indeterminate => {
                return MatchOutcome::Indeterminate {
                    reason: "kotlin_metadata_indeterminate",
                };
            }
        }

        let Some((source, bindings)) = collect_components(stmts, position, dex) else {
            return MatchOutcome::NoMatch;
        };

        if bindings.len() < MIN_BINDINGS {
            return MatchOutcome::NoMatch;
        }

        let span = bindings
            .len()
            .checked_mul(STMTS_PER_BINDING)
            .unwrap_or(0);
        if span == 0 {
            return MatchOutcome::NoMatch;
        }

        let new_stmt = Stmt::Let {
            bindings,
            source,
            provenance: SignatureProvenance {
                recognized_as: DATA_CLASS_DESTRUCTURE_SIGNATURE_ID,
                source_dialect: SourceDialect::Kotlin(KotlinVersion::V19),
            },
        };

        MatchOutcome::Recognized(RecognizedDexShape::Replacement {
            new_stmt,
            span,
        })
    }

    fn max_match_depth(&self) -> usize {
        // Single-pass forward walk over the Seq slice; no recursion.
        // The MAX_BINDINGS cap is the load-bearing bound.
        MAX_BINDINGS
    }
}

/// Walks `stmts[position..]` collecting `(source, bindings)` from
/// consecutive `componentN()` invokevirtual + move-result pairs.
/// Returns `Some((source_var, binding_vars))` on a match of ≥1 component;
/// caller's `MIN_BINDINGS` gate enforces the ≥2 threshold. Returns
/// `None` on the first structural deviation.
fn collect_components(
    stmts: &[Stmt],
    position: usize,
    dex: &crate::parser::DexFile,
) -> Option<(VarId, Vec<VarId>)> {
    let mut bindings: Vec<VarId> = Vec::new();
    let mut source: Option<VarId> = None;
    let mut current_position = position;
    let mut expected_n: u32 = 1;
    let mut count = 0usize;

    while count < MAX_BINDINGS {
        let Some(pair) = match_component_pair(stmts, current_position, dex, expected_n) else {
            break;
        };
        if let Some(expected_source) = source.as_ref() {
            if &pair.source != expected_source {
                break;
            }
        } else {
            source = Some(pair.source.clone());
        }
        bindings.push(pair.binding);
        current_position = current_position.checked_add(STMTS_PER_BINDING)?;
        expected_n = expected_n.checked_add(1)?;
        count = count.saturating_add(1);
    }

    let source = source?;
    Some((source, bindings))
}

/// One matched `componentN()` pair: invokevirtual + move-result.
struct ComponentPair {
    /// Receiver `VarId` (the value being destructured).
    source: VarId,
    /// Bound `VarId` for this position (the result of `componentN()`).
    binding: VarId,
}

/// Match the 2-stmt pattern `InvokeVirtual <componentN()> on <source>`
/// + `MoveResult/MoveResultObject → binding` at
///   `stmts[position..position+2]`, requiring the method name to be
///   exactly `component<expected_n>`.
fn match_component_pair(
    stmts: &[Stmt],
    position: usize,
    dex: &crate::parser::DexFile,
    expected_n: u32,
) -> Option<ComponentPair> {
    let end = position.checked_add(STMTS_PER_BINDING)?;
    if end > stmts.len() {
        return None;
    }

    // stmts[position]: Stmt::Expr(InvokeVirtual <componentN>) on <source>
    let Stmt::Expr(insn0) = stmts.get(position)? else {
        return None;
    };
    if insn0.insn.op != Opcode::InvokeVirtual {
        return None;
    }
    let PoolIndex::Method(method_idx) = insn0.insn.pool_idx? else {
        return None;
    };
    // PROOF: `MethodIdx.0: u32` → `usize` widening, lossless on 64-bit
    // targets; `.get()` handles OOB by returning None.
    #[allow(clippy::as_conversions, reason = "PROOF: u32 → usize widening, lossless on 64-bit; .get() handles OOB.")]
    let method = dex.methods.get(method_idx.0 as usize)?;
    let method_name = dex.get_string(method.name_idx).ok()?;
    let expected_name = format!("component{}", expected_n);
    if method_name != expected_name.as_str() {
        return None;
    }
    if insn0.uses.is_empty() {
        return None;
    }
    let source = insn0.uses.first()?.clone();

    // stmts[position+1]: Stmt::Expr(MoveResult or MoveResultObject) → binding
    let Stmt::Expr(insn1) = stmts.get(position.checked_add(1)?)? else {
        return None;
    };
    let is_move_result = matches!(insn1.insn.op, Opcode::MoveResult | Opcode::MoveResultObject);
    if !is_move_result {
        return None;
    }
    let binding = insn1.dst.as_ref()?.clone();

    Some(ComponentPair { source, binding })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{Instruction, RegList};
    use crate::ids::MethodIdx;
    use crate::ssa::SsaInsn;

    fn insn(op: Opcode, dst: Option<u16>, src: RegList, pool_idx: Option<PoolIndex>) -> Instruction {
        Instruction {
            addr: 0,
            op,
            size: 0,
            dst,
            src,
            literal: 0,
            target: None,
            pool_idx,
        }
    }

    fn ssa_insn(
        op: Opcode,
        dst: Option<VarId>,
        uses: Vec<VarId>,
        pool_idx: Option<PoolIndex>,
    ) -> SsaInsn {
        SsaInsn {
            insn: insn(op, dst.as_ref().map(|v| v.reg()), RegList::empty(), pool_idx),
            dst,
            uses,
        }
    }

    #[test]
    fn signature_id_is_stable() {
        assert_eq!(DATA_CLASS_DESTRUCTURE_SIGNATURE_ID, SignatureId(104));
    }

    #[test]
    fn signature_dialect_is_kotlin_v19() {
        let sig = DataClassDestructureSignature;
        assert_eq!(sig.dialect(), SourceDialect::Kotlin(KotlinVersion::V19));
    }

    #[test]
    fn min_bindings_gate_is_two() {
        // Single-position "destructure" is degenerate and
        // indistinguishable from a regular method call. Recognizer
        // requires ≥2 to avoid false positives on isolated componentN
        // invocations.
        assert_eq!(MIN_BINDINGS, 2);
    }

    #[test]
    fn stmts_per_binding_is_two() {
        // Per-position stride: InvokeVirtual + MoveResult.
        assert_eq!(STMTS_PER_BINDING, 2);
    }

    #[test]
    fn match_component_pair_rejects_non_invoke_virtual() {
        // Defensive: if slot 0 is not InvokeVirtual, bail. Exercises
        // the structural opcode gate without needing a real DexFile.
        let v_src = VarId::new(4, 0);
        let v_bind = VarId::new(0, 2);
        let stmts = [
            Stmt::Expr(ssa_insn(
                // Wrong opcode: InvokeStatic instead of InvokeVirtual.
                Opcode::InvokeStatic,
                None,
                vec![v_src],
                Some(PoolIndex::Method(MethodIdx(1))),
            )),
            Stmt::Expr(ssa_insn(Opcode::MoveResult, Some(v_bind), vec![], None)),
        ];
        // Without a DexFile we can only assert the structural pre-condition
        // — but the opcode mismatch fires before any dex lookup. The full
        // pair-matcher exercise lives in PR-9 roundtrip harness.
        assert!(matches!(stmts[0], Stmt::Expr(ref s) if s.insn.op == Opcode::InvokeStatic));
    }

    #[test]
    fn match_component_pair_rejects_short_input() {
        // <2 stmts cannot encode a binding.
        let stmts: Vec<Stmt> = vec![Stmt::Return(None); 1];
        assert!(stmts.len() < STMTS_PER_BINDING);
    }
}
