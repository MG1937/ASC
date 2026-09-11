//! kotlinc 1.9.22 `when (x) { is Sub1 -> ...; is Sub2 -> ... }` over a
//! sealed root with **subclass** subtypes (mirror of `when_sealed_object`
//! for the non-`object`-singleton case).
//!
//! Recognizes the canonical kotlinc-1.9 lowering of a sealed-CLASS
//! `when` chain. From the empirical bytecode audit and post-structuring
//! IR audit on
//! `tests/corpus/clean/kotlinc-1.9/when_sealed_class/05arms.kt`
//! (dump at `/tmp/kotlin-ir-audit-class/05arms.stmt.txt`), the lowering
//! produces a nested `Stmt::If` chain whose per-arm test pattern is
//! exactly **two** sibling `Stmt`s in the parent `Seq`:
//!
//! 1. `Stmt::Expr(InstanceOf<Sub> uses=[disc] dst=v_r)` — the dex
//!    `instance-of` opcode is single-instruction (writes its boolean
//!    result directly to a register, no `MoveResult` needed). The pool
//!    index carries the subtype `TypeIdx`.
//! 2. `Stmt::If { cond: TestZero { var: v_r, op: IfEqz }, then_body, else_body }`
//!    where `then_body` is a `Stmt::Seq` carrying either the next 2-stmt
//!    arm-test tower or the throw-terminus block, and `else_body` is the
//!    arm body. Bytecode-preserved condition form: `IfEqz` jumps to
//!    `then_body` (next test) when `instanceof` returned false.
//!
//! Chain terminus (deepest nested `then_body`) is **identical to
//! when_sealed_object**:
//!
//! - `Stmt::Expr(NewInstance Lkotlin/NoWhenBranchMatchedException;)` → `v_ex`
//! - `Stmt::Expr(InvokeDirect <init> on v_ex)`
//! - `Stmt::Throw(v_ex)`
//!
//! On match → produces a single
//! [`Stmt::MultiArm`] with
//! [`Discriminant::SealedSubtype { var, sealed_root }`](crate::structure::Discriminant::SealedSubtype)
//! and per-arm
//! [`ArmPattern::SealedTypeIs(sub)`](crate::structure::ArmPattern::SealedTypeIs)
//! (NOT `SealedObjectIs` — sealed-CLASS arms render as `is X.Sub ->` at
//! the Kotlin source level, sealed-OBJECT arms render as bare
//! `X.Sub ->`; emit dispatches on the variant per parent PR-2a's IR
//! split).
//!
//! Same gates as when_sealed_object per parent OQ §6 RESOLVED-default:
//! min-arm ≥ 3 + sealed-root carries `@kotlin.Metadata`. Both gates
//! protect the recognizer from false-positive matches on Java
//! hand-written `instanceof` chains.
#![allow(missing_docs, reason = "internal")]

use droidsaw_common::signature::{
    KotlinVersion, MatchOutcome, Signature, SignatureId, SourceDialect,
};

use crate::decode::PoolIndex;
use crate::ids::TypeIdx;
use crate::opcodes::Opcode;
use crate::signatures::{DexBackend, DexSigInput, RecognizedDexShape};
use crate::ssa::VarId;
use crate::structure::{
    ArmPattern, Condition, Discriminant, MultiArm as MultiArmCase, SignatureProvenance, Stmt,
};

/// Reserved [`SignatureId`] for the kotlinc-1.9 sealed-CLASS `when`
/// recognizer. Adjacent to `WHEN_SEALED_OBJECT_SIGNATURE_ID = 100` per
/// Day-1 prep #3 — the two sealed-when variants get adjacent IDs so
/// emit dispatch + diagnostic banners can group them.
pub const WHEN_SEALED_CLASS_SIGNATURE_ID: SignatureId = SignatureId(101);

/// Minimum arm count for the recognizer to fire.
///
/// **Lowered from 3 → 2 in PR-9e.1 of #41b** for parity with
/// `when_sealed_object`'s relax. Java hand-written `instanceof` chains
/// are common at 2 arms — but the metadata gate is the discriminator,
/// not the arm count. This recognizer requires
/// `dex.class_has_kotlin_metadata(sealed_root)` to be true (and
/// `sealed_root` to be the LCA across all arm subtypes); a 2-arm Java
/// `if (x instanceof Foo) ... else if (x instanceof Bar) ...` either
/// has no shared sealed_root (Foo + Bar are unrelated → `sealed_root_lca`
/// returns None → NearMiss) or shares only `java.lang.Object` (excluded
/// by `sealed_root_lca`) or some other ancestor that doesn't carry
/// `@kotlin.Metadata`. So the metadata gate alone closes the
/// false-positive risk. MIN_ARMS=2 is just the smallest source-level
/// `when` arm count (1-arm is degenerate; kotlinc rejects).
const MIN_ARMS: usize = 2;

/// Cap on chain-walk depth. Defends against pathological IR depth on
/// adversarial input. Same value as when_sealed_object — real kotlinc
/// chains are bounded by source-level arm count.
const MAX_CHAIN_DEPTH: usize = 256;

/// JVM type descriptor for `kotlin.NoWhenBranchMatchedException` — the
/// exception kotlinc throws at the chain terminus to signal an
/// unreachable arm (exhaustiveness fall-through). Identical to
/// when_sealed_object's terminus type.
const NWBME_DESCRIPTOR: &str = "Lkotlin/NoWhenBranchMatchedException;";

/// Number of sibling `Stmt`s consumed at the recognizer's entry
/// position (`InstanceOf` + `If`). Smaller than when_sealed_object's
/// stride of 4 because `instance-of` is a single-instruction primitive
/// (no `SgetObject`/`InvokeStatic`/`MoveResult` triplet preceding the
/// `If`).
const ARM_TEST_STRIDE: usize = 2;

/// Recognizer for the kotlinc-1.9 sealed-CLASS `when` lowering.
pub struct WhenSealedClassSignature;

impl Signature<DexBackend> for WhenSealedClassSignature {
    fn id(&self) -> SignatureId {
        WHEN_SEALED_CLASS_SIGNATURE_ID
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
            ..
        } = input;

        // Walk the chain. Returns Some((discriminant, arms)) on full match
        // up through the throw terminus; None on shape failure.
        let Some((discriminant, arms)) = collect_arms(stmts, position, dex) else {
            return MatchOutcome::NoMatch;
        };

        // Min-arm gate (parent OQ §6).
        if arms.len() < MIN_ARMS {
            return MatchOutcome::NoMatch;
        }

        // Metadata gate (parent OQ §6): require shared sealed root + that
        // root must carry @kotlin.Metadata. NearMiss when shape-matched but
        // gate fails — the engine surfaces that as a closest-hint banner
        // instead of silently returning to the next signature.
        let arm_subtypes: Vec<TypeIdx> = arms.iter().map(|(t, _)| *t).collect();
        let Some(sealed_root) = dex.sealed_root_lca(&arm_subtypes) else {
            return MatchOutcome::NearMiss { distance: arms.len() };
        };
        match dex.class_has_kotlin_metadata(sealed_root) {
            crate::DetectorVerdict::Yes => {}
            crate::DetectorVerdict::No => return MatchOutcome::NearMiss { distance: arms.len() },
            crate::DetectorVerdict::Indeterminate => {
                return MatchOutcome::Indeterminate {
                    reason: "kotlin_metadata_indeterminate",
                };
            }
        }

        let multiarm = Stmt::MultiArm {
            discriminant: Discriminant::SealedSubtype {
                var: discriminant,
                sealed_root,
            },
            arms: arms
                .into_iter()
                .map(|(sub, body)| MultiArmCase {
                    pattern: ArmPattern::SealedTypeIs(sub),
                    body,
                })
                .collect(),
            default: None,
            provenance: SignatureProvenance {
                recognized_as: WHEN_SEALED_CLASS_SIGNATURE_ID,
                source_dialect: SourceDialect::Kotlin(KotlinVersion::V19),
            },
        };

        MatchOutcome::Recognized(RecognizedDexShape::Replacement {
            new_stmt: multiarm,
            span: ARM_TEST_STRIDE,
        })
    }

    fn max_match_depth(&self) -> usize {
        // Recurses through the nested If chain; cap mirrors MAX_CHAIN_DEPTH
        // to give the engine a consistent view of the recursive bound.
        MAX_CHAIN_DEPTH
    }
}

/// Walks the nested If chain starting at `stmts[position]`, collecting
/// `(sub_type, arm_body)` pairs. Returns `Some((discriminant_var, arms))`
/// when the chain reaches a `throw NoWhenBranchMatchedException` terminus
/// at its deepest level; returns `None` on any structural deviation.
///
/// Mirrors [`crate::signatures::kotlinc19::when_sealed_object::collect_arms`]
/// but with the sealed-CLASS per-arm matcher (`InstanceOf` + `If` instead
/// of `SgetObject` + `InvokeStatic areEqual` + `MoveResult` + `If`). Kept
/// recognizer-local rather than shared because the per-arm matcher is the
/// only meaningful difference between the two recognizers; duplication is
/// favored until a third caller surfaces.
fn collect_arms(
    stmts: &[Stmt],
    position: usize,
    dex: &crate::parser::DexFile,
) -> Option<(VarId, Vec<(TypeIdx, Stmt)>)> {
    let mut arms: Vec<(TypeIdx, Stmt)> = Vec::new();
    let mut current_stmts: &[Stmt] = stmts;
    let mut current_position = position;
    let mut discriminant: Option<VarId> = None;
    let mut depth = 0usize;

    loop {
        if depth >= MAX_CHAIN_DEPTH {
            return None;
        }

        // Try to match a 2-stmt arm test at the current position.
        if let Some(arm) = match_arm_test(current_stmts, current_position) {
            // Discriminant must be consistent across arms.
            if let Some(expected) = discriminant.as_ref() {
                if &arm.disc_var != expected {
                    return None;
                }
            } else {
                discriminant = Some(arm.disc_var.clone());
            }
            arms.push((arm.sub_type, arm.arm_body.clone()));
            current_stmts = arm.next_seq;
            current_position = 0;
            depth = depth.saturating_add(1);
            continue;
        }

        // Not an arm test. Check whether the current position is an
        // already-lifted sibling sealed-CLASS `Stmt::MultiArm` from a
        // prior recognizer pass on a deeper Seq. Inside-out desugar
        // ordering means the engine fires on the deepest sub-Seq first
        // (e.g. arms 3+4+5 of a 5-arm chain) and lifts to MultiArm
        // before the outer pass sees the chain. Without this absorption
        // step, the outer chain walker would only see arms 1+2
        // followed by `[MultiArm]` — fail the structural shape check
        // and bail. PR-9e of #41b.
        //
        // **Critical termination invariant**: only absorb when at
        // least one outer arm has already been collected
        // (`!arms.is_empty()`). See the matching comment in
        // `when_sealed_object::collect_arms` for the rationale —
        // without this gate the engine self-recurses on a just-lifted
        // MultiArm and infinite-loops.
        if !arms.is_empty() {
            if let Some(absorbed) = match_embedded_multiarm(current_stmts, current_position) {
                // Discriminant must match the chain's. Every absorbed arm
                // is from a prior lift on the same chain by definition, so
                // this is a tightness check rather than a real risk gate.
                if let Some(expected) = discriminant.as_ref() {
                    if &absorbed.disc_var != expected {
                        return None;
                    }
                } else {
                    discriminant = Some(absorbed.disc_var.clone());
                }
                arms.extend(absorbed.arms);
                return Some((discriminant?, arms));
            }
        }

        // Not an arm test. Check for the throw terminus.
        let remaining = current_stmts.get(current_position..)?;
        if matches_throw_terminus(remaining, dex) {
            return Some((discriminant?, arms));
        }

        // Neither arm-test nor throw-terminus shape — not a sealed-when chain.
        return None;
    }
}

/// One absorbed embedded `Stmt::MultiArm`. The arms are extracted from
/// the inner-pass's lift output and re-projected as `(TypeIdx, Stmt)`
/// pairs ready for the outer chain walker's accumulator. Returned only
/// when the embedded shape is provably from this same recognizer
/// (sealed-CLASS, `SignatureId(101)`) — chain-merge with a foreign
/// recognizer's lift would be unsound.
struct EmbeddedMultiArm {
    /// Discriminant variable carried in the absorbed MultiArm. Must
    /// equal the outer chain's discriminant for a valid merge.
    disc_var: VarId,
    /// Already-lifted arms in source-position order. Each arm's
    /// `pattern` was `ArmPattern::SealedTypeIs(sub)`; we drop the
    /// outer wrapping and surface `(sub, body)` for the outer walker.
    arms: Vec<(TypeIdx, Stmt)>,
}

/// Try to absorb a sibling-recognizer's already-lifted `Stmt::MultiArm`
/// at `stmts[position]` as a sequence of completed sealed-CLASS arms.
///
/// Mirrors the sealed-OBJECT helper of the same name in
/// [`when_sealed_object`](super::when_sealed_object) — the only
/// per-recognizer differences are the gated `SignatureId` and the
/// gated `ArmPattern` variant. Soundness conditions documented there
/// apply identically here.
fn match_embedded_multiarm(stmts: &[Stmt], position: usize) -> Option<EmbeddedMultiArm> {
    let stmt = stmts.get(position)?;
    let Stmt::MultiArm {
        discriminant,
        arms,
        default,
        provenance,
    } = stmt
    else {
        return None;
    };
    if provenance.recognized_as != WHEN_SEALED_CLASS_SIGNATURE_ID {
        return None;
    }
    if default.is_some() {
        return None;
    }
    let Discriminant::SealedSubtype { var, .. } = discriminant else {
        return None;
    };
    let mut absorbed_arms: Vec<(TypeIdx, Stmt)> = Vec::with_capacity(arms.len());
    for case in arms {
        let ArmPattern::SealedTypeIs(sub) = case.pattern else {
            return None;
        };
        absorbed_arms.push((sub, case.body.clone()));
    }
    Some(EmbeddedMultiArm {
        disc_var: var.clone(),
        arms: absorbed_arms,
    })
}

/// One matched arm test. Borrows from the parent `stmts` slice.
struct ArmTest<'a> {
    /// The Kotlin subtype this arm matches against — recovered from the
    /// `instance-of` instruction's pool index.
    sub_type: TypeIdx,
    /// Discriminant variable (the `when` subject) — first/only `use` of
    /// the `instance-of` instruction.
    disc_var: VarId,
    /// Arm body — the `else_body` of the `Stmt::If` (executes when
    /// `instance-of` returned true, i.e. the bytecode `ifeq` did NOT
    /// branch).
    arm_body: &'a Stmt,
    /// Sub-Seq inside the `Stmt::If`'s `then_body` — caller recurses into
    /// this to match the next arm test (or the throw terminus).
    next_seq: &'a [Stmt],
}

/// Match the 2-stmt arm-test pattern at `stmts[position..position+2]`.
/// Returns `Some(ArmTest)` on full structural match. Pure structural
/// (no `DexFile` dependency) — the `sub_type` is recovered directly from
/// the `instance-of`'s pool index, which is a `TypeIdx` and needs no
/// name-side verification (unlike sealed-OBJECT's `INSTANCE` field
/// indirection).
fn match_arm_test(stmts: &[Stmt], position: usize) -> Option<ArmTest<'_>> {
    let end = position.checked_add(ARM_TEST_STRIDE)?;
    if end > stmts.len() {
        return None;
    }

    // stmts[position]: Stmt::Expr(InstanceOf <Sub>) → v_r, uses=[disc]
    let Stmt::Expr(insn0) = stmts.get(position)? else {
        return None;
    };
    if insn0.insn.op != Opcode::InstanceOf {
        return None;
    }
    let PoolIndex::Type(sub_type) = insn0.insn.pool_idx? else {
        return None;
    };
    let v_r = insn0.dst.as_ref()?;
    if insn0.uses.len() != 1 {
        return None;
    }
    let disc_var = insn0.uses.first()?.clone();

    // stmts[position+1]: Stmt::If { cond: TestZero(v_r, IfEqz), then_body: Seq, else_body: Some(arm) }
    let Stmt::If {
        cond,
        then_body,
        else_body,
    } = stmts.get(position.checked_add(1)?)?
    else {
        return None;
    };
    let Condition::TestZero { var: cond_var, op } = cond else {
        return None;
    };
    if cond_var != v_r {
        return None;
    }
    if *op != Opcode::IfEqz {
        return None;
    }
    let arm_body = else_body.as_ref()?.as_ref();
    let Stmt::Seq(next_seq) = then_body.as_ref() else {
        return None;
    };

    Some(ArmTest {
        sub_type,
        disc_var,
        arm_body,
        next_seq: next_seq.as_slice(),
    })
}

/// True iff `stmts` starts with the 3-stmt
/// `throw NoWhenBranchMatchedException` terminus block:
/// `NewInstance + InvokeDirect + Throw`. Identical to
/// when_sealed_object's terminus matcher (kotlinc emits the same throw
/// shape regardless of sealed-OBJECT vs sealed-CLASS lowering).
fn matches_throw_terminus(stmts: &[Stmt], dex: &crate::parser::DexFile) -> bool {
    let Some(shape) = matches_throw_terminus_shape(stmts) else {
        return false;
    };
    let Ok(desc) = dex.get_type_descriptor(TypeIdx(shape.exception_type_idx)) else {
        return false;
    };
    desc == NWBME_DESCRIPTOR
}

/// Pure structural Stmt match for the throw terminus — returns the
/// exception type index for the dex-side caller to verify against
/// `Lkotlin/NoWhenBranchMatchedException;`.
struct ThrowTerminusShape {
    exception_type_idx: u32,
}

fn matches_throw_terminus_shape(stmts: &[Stmt]) -> Option<ThrowTerminusShape> {
    if stmts.len() < 3 {
        return None;
    }
    // stmts[0]: Stmt::Expr(NewInstance <ExceptionType>) → v_ex
    let Stmt::Expr(insn0) = stmts.first()? else {
        return None;
    };
    if insn0.insn.op != Opcode::NewInstance {
        return None;
    }
    let PoolIndex::Type(type_idx) = insn0.insn.pool_idx? else {
        return None;
    };
    let v_ex = insn0.dst.as_ref()?;

    // stmts[1]: Stmt::Expr(InvokeDirect <init>) on v_ex
    let Stmt::Expr(insn1) = stmts.get(1)? else {
        return None;
    };
    if insn1.insn.op != Opcode::InvokeDirect {
        return None;
    }
    if insn1.uses.first() != Some(v_ex) {
        return None;
    }

    // stmts[2]: Stmt::Throw(v_ex)
    let Stmt::Throw(thrown_var) = stmts.get(2)? else {
        return None;
    };
    if thrown_var != v_ex {
        return None;
    }

    Some(ThrowTerminusShape {
        exception_type_idx: type_idx.0,
    })
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

    fn arm_test_stmts(
        v_disc: VarId,
        v_r: VarId,
        sub_type: TypeIdx,
        next_seq: Vec<Stmt>,
        arm_body: Stmt,
    ) -> Vec<Stmt> {
        vec![
            Stmt::Expr(ssa_insn(
                Opcode::InstanceOf,
                Some(v_r.clone()),
                vec![v_disc],
                Some(PoolIndex::Type(sub_type)),
            )),
            Stmt::If {
                cond: Condition::TestZero {
                    var: v_r,
                    op: Opcode::IfEqz,
                },
                then_body: Box::new(Stmt::Seq(next_seq)),
                else_body: Some(Box::new(arm_body)),
            },
        ]
    }

    #[test]
    fn signature_id_is_stable() {
        assert_eq!(WHEN_SEALED_CLASS_SIGNATURE_ID, SignatureId(101));
    }

    #[test]
    fn signature_dialect_is_kotlin_v19() {
        let sig = WhenSealedClassSignature;
        assert_eq!(sig.dialect(), SourceDialect::Kotlin(KotlinVersion::V19));
    }

    #[test]
    fn min_arm_gate_is_two() {
        // Lowered from 3 → 2 in PR-9e.1 of #41b for parity with
        // when_sealed_object's relax. The metadata gate
        // (`@kotlin.Metadata` on sealed_root) closes the
        // false-positive risk on Java hand-written `instanceof` chains
        // — the metadata is structurally absent on Java code.
        assert_eq!(MIN_ARMS, 2);
    }

    #[test]
    fn arm_test_stride_is_two() {
        // Recognizer consumes 2 sibling stmts at entry: InstanceOf + If.
        // Distinct from when_sealed_object's stride of 4 — instance-of
        // is single-instruction (no SgetObject/InvokeStatic/MoveResult
        // triplet preceding the If).
        assert_eq!(ARM_TEST_STRIDE, 2);
    }

    #[test]
    fn match_arm_test_recognizes_canonical_pattern() {
        let v_disc = VarId::new(2, 0);
        let v_r = VarId::new(0, 2);
        let sub = TypeIdx(7);
        let stmts = arm_test_stmts(v_disc.clone(), v_r, sub, vec![], Stmt::Return(None));
        let arm = match_arm_test(&stmts, 0).expect("canonical shape must match");
        assert_eq!(arm.sub_type, sub);
        assert_eq!(arm.disc_var, v_disc);
        assert!(matches!(arm.arm_body, Stmt::Return(None)));
    }

    #[test]
    fn match_arm_test_rejects_when_else_body_missing() {
        // Source-natural sealed-when always carries the arm body in
        // else_body; absence means this isn't a sealed-when arm.
        let mut stmts = arm_test_stmts(
            VarId::new(2, 0),
            VarId::new(0, 2),
            TypeIdx(7),
            vec![],
            Stmt::Return(None),
        );
        if let Stmt::If { else_body, .. } = &mut stmts[1] {
            *else_body = None;
        }
        assert!(match_arm_test(&stmts, 0).is_none());
    }

    #[test]
    fn match_arm_test_rejects_wrong_test_zero_op() {
        // kotlinc emits IfEqz; IfNez would mean a structurer flip not
        // observed in the empirical IR audit.
        let mut stmts = arm_test_stmts(
            VarId::new(2, 0),
            VarId::new(0, 2),
            TypeIdx(7),
            vec![],
            Stmt::Return(None),
        );
        if let Stmt::If { cond: Condition::TestZero { op, .. }, .. } = &mut stmts[1] {
            *op = Opcode::IfNez;
        }
        assert!(match_arm_test(&stmts, 0).is_none());
    }

    #[test]
    fn match_arm_test_rejects_wrong_pool_kind() {
        // Pool index must be PoolIndex::Type (the subtype TypeIdx); a
        // PoolIndex::Method (e.g. an unrelated InstanceOf opcode misuse)
        // would mean the bytecode is ill-formed but recognizer should
        // bail cleanly without panic.
        let mut stmts = arm_test_stmts(
            VarId::new(2, 0),
            VarId::new(0, 2),
            TypeIdx(7),
            vec![],
            Stmt::Return(None),
        );
        if let Stmt::Expr(ref mut ssa) = stmts[0] {
            ssa.insn.pool_idx = Some(PoolIndex::Method(MethodIdx(7)));
        }
        assert!(match_arm_test(&stmts, 0).is_none());
    }

    #[test]
    fn match_arm_test_rejects_short_input() {
        // <2 stmts cannot encode an arm test.
        let stmts: Vec<Stmt> = vec![Stmt::Return(None); 1];
        assert!(match_arm_test(&stmts, 0).is_none());
    }

    #[test]
    fn matches_throw_terminus_shape_recognizes_canonical_pattern() {
        let v_ex = VarId::new(0, 18);
        let stmts = vec![
            Stmt::Expr(ssa_insn(
                Opcode::NewInstance,
                Some(v_ex.clone()),
                vec![],
                Some(PoolIndex::Type(TypeIdx(13))),
            )),
            Stmt::Expr(ssa_insn(
                Opcode::InvokeDirect,
                None,
                vec![v_ex.clone()],
                Some(PoolIndex::Method(MethodIdx(14))),
            )),
            Stmt::Throw(v_ex),
        ];
        let shape =
            matches_throw_terminus_shape(&stmts).expect("canonical throw terminus must match");
        assert_eq!(shape.exception_type_idx, 13);
    }

    #[test]
    fn matches_throw_terminus_shape_rejects_throw_var_mismatch() {
        // The throw must refer to the SAME var that NewInstance defined.
        // A mismatch indicates an unrelated throw (e.g. some preceding
        // exception construction smuggled in), not the chain terminus.
        // Mirrors when_sealed_object's parity test — same failure mode,
        // same defensive check at matches_throw_terminus_shape's tail.
        let v_ex = VarId::new(0, 18);
        let v_other = VarId::new(0, 99);
        let stmts = vec![
            Stmt::Expr(ssa_insn(
                Opcode::NewInstance,
                Some(v_ex.clone()),
                vec![],
                Some(PoolIndex::Type(TypeIdx(13))),
            )),
            Stmt::Expr(ssa_insn(
                Opcode::InvokeDirect,
                None,
                vec![v_ex],
                Some(PoolIndex::Method(MethodIdx(14))),
            )),
            Stmt::Throw(v_other),
        ];
        assert!(matches_throw_terminus_shape(&stmts).is_none());
    }

    #[test]
    fn matches_throw_terminus_shape_rejects_short_input() {
        let stmts: Vec<Stmt> = vec![Stmt::Return(None); 2];
        assert!(matches_throw_terminus_shape(&stmts).is_none());
    }
}
