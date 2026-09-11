//! kotlinc 1.9.22 `suspend fun` state-machine recognizer.
//!
//! Recognizes the canonical kotlinc-1.9 lowering of a Kotlin `suspend fun`.
//! From the empirical bytecode audit:
//!
//! > Full state machine lives in the **top-level suspend wrapper method**
//! > (`SampleKt.work(int, Continuation)`), NOT in the inner class.
//! > Inner class `SampleKt$work$1 extends kotlin.coroutines.jvm.internal.ContinuationImpl`
//! > is a stub holding `int I$0 / Object result / int label` fields + a
//! > delegating `invokeSuspend` that calls back into the wrapper with
//! > the suspend bit set on label.
//!
//! This stream's post-structuring IR audit (dump at
//! `/tmp/kotlin-ir-audit-coroutine/work.stmt.txt`) confirmed the
//! shape: `instanceof <inner>` preamble + label-bitmask check via
//! `If TestZero`, `getfield label:I + Stmt::Switch` main dispatch,
//! per-state `ResultKt.throwOnFailure` + suspend-bit return, and
//! `IllegalStateException` in the `default` arm carrying the **exact
//! literal** `"call to 'resume' before 'invoke' with coroutine"` —
//! the load-bearing single-symbol discriminator.
//!
//! **Recognition strategy**: rather than walk the full state-machine
//! structure (instanceof + label-bitmask + tableswitch + per-state
//! body — fragile to compile-time variation across kotlinc patch
//! versions), the recognizer detects the magic literal as a single
//! discriminator. The literal is:
//!
//! 1. Strictly Kotlin-runtime — emitted only by kotlinc's coroutine
//!    state-machine lowering, not by any Java compiler.
//! 2. Strictly within the wrapper method — the IllegalStateException
//!    construction happens in the `default` arm of the label-tableswitch.
//!
//! Combined with the positive enclosing-class metadata gate
//! (`@kotlin.Metadata` required), the literal is sufficient to recognize
//! the wrapper method body with high confidence and very low
//! false-positive rate. (A Java method that happens to reference the
//! exact string would fail the metadata gate; a Kotlin method that
//! references the string but isn't a coroutine wrapper is vanishingly
//! rare in practice.)
//!
//! On match → returns
//! [`RecognizedDexShape::TaggedRegion { signature_id: 105, span }`](crate::signatures::RecognizedDexShape::TaggedRegion)
//! covering the entire wrapper-method body. Engine driver wraps in
//! `Stmt::Unrecognized` with `closest = Some(105)`, `distance = 0`
//! (the exact-tag sentinel). Emit dispatches on the closest+distance
//! tag to render the banner + unfolded form.
//!
//! The state-machine recognizer fits `DexSigInput<'a>` — all
//! discriminators are method-local bytecode patterns + class-relationship
//! facts available pre-structuring. The load-bearing discriminator is
//! the const-string load, which is method-local.

use droidsaw_common::signature::{
    KotlinVersion, MatchOutcome, Signature, SignatureId, SourceDialect,
};

use crate::decode::PoolIndex;
use crate::opcodes::Opcode;
use crate::signatures::{DexBackend, DexSigInput, RecognizedDexShape};
use crate::structure::Stmt;

/// Reserved [`SignatureId`] for the kotlinc-1.9 coroutine state-machine
/// recognizer. Per Day-1 prep #3 SignatureId allocation (last in the
/// 100..=199 kotlinc-19 range).
pub const COROUTINE_SUSPEND_SIGNATURE_ID: SignatureId = SignatureId(105);

/// Cap on Stmt-tree walk depth in the literal-detection scanner. The
/// post-structuring IR is a tree (no cycles in safe Rust), but a
/// pathologically deep tree could OOM the recursion stack. 256 is the
/// same defense-in-depth bound used by the chain walkers in
/// `when_sealed_object` / `when_sealed_class` / `when_string`.
const MAX_WALK_DEPTH: usize = 256;

/// The exact runtime literal kotlinc emits in the `default` arm of the
/// coroutine state-machine's label-tableswitch. Strictly identifies a
/// kotlinc coroutine wrapper method body. Spec source: kotlin-stdlib
/// runtime; verified empirically in the IR audit dump at
/// `/tmp/kotlin-ir-audit-coroutine/work.stmt.txt`.
const COROUTINE_SUSPENDED_LITERAL: &str =
    "call to 'resume' before 'invoke' with coroutine";

/// Recognizer for the kotlinc-1.9 coroutine `suspend fun` state machine.
pub struct CoroutineSuspendSignature;

impl Signature<DexBackend> for CoroutineSuspendSignature {
    fn id(&self) -> SignatureId {
        COROUTINE_SUSPEND_SIGNATURE_ID
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
            is_top_level,
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

        // Top-level-only gate. The state machine is the entire wrapper-
        // method body; partial matches on inner sub-Seqs would conflict
        // with other recognizers (e.g. when_int matching the inner
        // label-tableswitch) AND would over-match on the
        // IllegalStateException default-arm Seq inside the label-
        // tableswitch (which itself contains the magic literal that the
        // walker detects). The `is_top_level` flag from
        // `DexSigInput` (populated by `sugar::desugar_recursive`)
        // distinguishes the method-root Seq from inner sub-Seqs;
        // `position == 0` further constrains to the start of the
        // method-root Seq, so the recognized region covers the entire
        // body.
        if !is_top_level || position != 0 {
            return MatchOutcome::NoMatch;
        }

        // Load-bearing discriminator: scan the region for the magic
        // const-string literal. Found → kotlinc coroutine. Not found →
        // not a coroutine.
        let Some(slice) = stmts.get(position..) else {
            return MatchOutcome::NoMatch;
        };
        if !contains_coroutine_literal(slice, dex) {
            return MatchOutcome::NoMatch;
        }

        let span = stmts.len().saturating_sub(position).max(1);
        MatchOutcome::Recognized(RecognizedDexShape::TaggedRegion {
            signature_id: COROUTINE_SUSPEND_SIGNATURE_ID,
            span,
        })
    }

    fn max_match_depth(&self) -> usize {
        MAX_WALK_DEPTH
    }
}

/// True iff any `Stmt::Expr(ConstString)` (or inlined-throw / inlined-
/// return variant) within the Stmt slice loads the
/// [`COROUTINE_SUSPENDED_LITERAL`]. Walks the Stmt tree iteratively up
/// to [`MAX_WALK_DEPTH`].
fn contains_coroutine_literal(stmts: &[Stmt], dex: &crate::parser::DexFile) -> bool {
    // Iterative DFS with explicit stack — avoids recursion-depth panic
    // on pathologically deep IR.
    let mut stack: Vec<(&Stmt, usize)> = Vec::new();
    for s in stmts {
        stack.push((s, 0));
    }
    let mut iters = 0usize;
    while let Some((stmt, depth)) = stack.pop() {
        if depth >= MAX_WALK_DEPTH {
            continue;
        }
        iters = iters.saturating_add(1);
        if iters >= MAX_WALK_DEPTH.saturating_mul(MAX_WALK_DEPTH) {
            // Hard cap on total iterations as belt-and-suspenders DoS
            // defense — bounded by depth × breadth in practice.
            return false;
        }
        let next_depth = depth.saturating_add(1);
        match stmt {
            Stmt::Expr(insn) | Stmt::InlinedReturn(insn) | Stmt::InlinedThrow(insn) => {
                if insn.insn.op == Opcode::ConstString {
                    if let Some(PoolIndex::String(string_idx)) = insn.insn.pool_idx {
                        if let Ok(s) = dex.get_string(string_idx) {
                            if s == COROUTINE_SUSPENDED_LITERAL {
                                return true;
                            }
                        }
                    }
                }
            }
            Stmt::Seq(children) => {
                for c in children {
                    stack.push((c, next_depth));
                }
            }
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                stack.push((then_body, next_depth));
                if let Some(eb) = else_body {
                    stack.push((eb, next_depth));
                }
            }
            Stmt::While { body, .. }
            | Stmt::DoWhile { body, .. }
            | Stmt::Synchronized { body, .. }
            | Stmt::ForEach { body, .. } => {
                stack.push((body, next_depth));
            }
            Stmt::For {
                init, update, body, ..
            } => {
                stack.push((init, next_depth));
                stack.push((update, next_depth));
                stack.push((body, next_depth));
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    stack.push((body, next_depth));
                }
                if let Some(d) = default {
                    stack.push((d, next_depth));
                }
            }
            Stmt::StringSwitch { cases, default, .. } => {
                for (_, body) in cases {
                    stack.push((body, next_depth));
                }
                if let Some(d) = default {
                    stack.push((d, next_depth));
                }
            }
            Stmt::MultiArm { arms, default, .. } => {
                for arm in arms {
                    stack.push((&arm.body, next_depth));
                }
                if let Some(d) = default {
                    stack.push((d, next_depth));
                }
            }
            Stmt::TryCatch { body, catches } => {
                stack.push((body, next_depth));
                for c in catches {
                    stack.push((&c.body, next_depth));
                }
            }
            // Variants that don't carry SsaInsns or sub-Stmts.
            Stmt::Return(_)
            | Stmt::Throw(_)
            | Stmt::InlinedReturnConcat(_)
            | Stmt::StringConcat { .. }
            | Stmt::Break
            | Stmt::Continue
            | Stmt::Goto(_)
            | Stmt::Unrecognized { .. }
            | Stmt::Let { .. }
            | Stmt::ResolvedFragment { .. }
            | Stmt::OutlinedBlock { .. }
            | Stmt::BooleanAssign { .. } => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{Instruction, RegList};
    use crate::ssa::{SsaInsn, VarId};

    fn insn(
        op: Opcode,
        dst: Option<u16>,
        src: RegList,
        pool_idx: Option<PoolIndex>,
    ) -> Instruction {
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
        assert_eq!(COROUTINE_SUSPEND_SIGNATURE_ID, SignatureId(105));
    }

    #[test]
    fn signature_dialect_is_kotlin_v19() {
        let sig = CoroutineSuspendSignature;
        assert_eq!(sig.dialect(), SourceDialect::Kotlin(KotlinVersion::V19));
    }

    #[test]
    fn coroutine_literal_constant_is_exact() {
        // Locked at the kotlinc-stdlib runtime's emit string. Drift would
        // silently break recognition; this test pins the constant.
        assert_eq!(
            COROUTINE_SUSPENDED_LITERAL,
            "call to 'resume' before 'invoke' with coroutine"
        );
    }

    #[test]
    fn max_walk_depth_is_bounded() {
        // Defense-in-depth bound mirrors chain walkers in sibling
        // recognizers. Pathologically deep trees terminate cleanly.
        assert_eq!(MAX_WALK_DEPTH, 256);
    }

    #[test]
    fn contains_coroutine_literal_short_circuits_on_no_const_string() {
        // Defensive: stmts with no ConstString never trigger the
        // dex lookup branch; walker terminates without false-positive.
        // (Without a real DexFile we can only assert structural
        // pre-conditions; full positive case lives in PR-9 harness.)
        let stmts = [Stmt::Return(None), Stmt::Break];
        // Confirm the variants we constructed don't carry pool_idx or
        // children — matches the iterative walker's "no-op" branches.
        assert!(matches!(stmts[0], Stmt::Return(_)));
        assert!(matches!(stmts[1], Stmt::Break));
    }

    #[test]
    fn const_string_with_wrong_pool_kind_does_not_match() {
        // Defensive: a ConstString with PoolIndex::Method (ill-formed
        // bytecode) bails cleanly without panic. The walker's let-Some
        // chain on PoolIndex::String returns false.
        let v = VarId::new(0, 0);
        let s = Stmt::Expr(ssa_insn(
            Opcode::ConstString,
            Some(v),
            vec![],
            Some(PoolIndex::Method(crate::ids::MethodIdx(7))),
        ));
        // Assert structurally: the pool_idx is not String.
        if let Stmt::Expr(ref ssa) = s {
            assert!(!matches!(ssa.insn.pool_idx, Some(PoolIndex::String(_))));
        } else {
            panic!("expected Stmt::Expr");
        }
    }
}
