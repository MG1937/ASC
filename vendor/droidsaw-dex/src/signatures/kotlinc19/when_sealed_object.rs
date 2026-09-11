//! kotlinc 1.9.22 `when (x) { Sub1 -> ...; Sub2 -> ... }` over a sealed
//! root with `object` subtypes.
//!
//! Recognizes the canonical kotlinc-1.9 lowering of a sealed-OBJECT
//! `when` chain. From the empirical bytecode audit and post-structuring
//! IR audit, the lowering produces a nested `Stmt::If` chain whose
//! per-arm test pattern
//! is exactly four sibling `Stmt`s in the parent `Seq`:
//!
//! 1. `Stmt::Expr(SgetObject <Sub>.INSTANCE)` → `v_inst`
//! 2. `Stmt::Expr(InvokeStatic Lkotlin/jvm/internal/Intrinsics;.areEqual(<disc>, v_inst))`
//! 3. `Stmt::Expr(MoveResult)` → `v_r`
//! 4. `Stmt::If { cond: TestZero { var: v_r, op: IfEqz }, then_body, else_body }`
//!    where `then_body` is a `Stmt::Seq` carrying either the next 4-stmt
//!    arm-test tower or the throw-terminus block, and `else_body` is the
//!    arm body. (`IfEqz` semantics: branch into `then_body` when areEqual
//!    returned false; fall through to `else_body` when it returned true.
//!    Bytecode-preserved form, not source-natural.)
//!
//! Chain terminus (deepest nested `then_body`):
//!
//! - `Stmt::Expr(NewInstance Lkotlin/NoWhenBranchMatchedException;)` → `v_ex`
//! - `Stmt::Expr(InvokeDirect <init> on v_ex)`
//! - `Stmt::Throw(v_ex)`
//!
//! On match → produces a single
//! [`Stmt::MultiArm`] with
//! [`Discriminant::SealedSubtype { var, sealed_root }`](crate::structure::Discriminant::SealedSubtype)
//! and per-arm
//! [`ArmPattern::SealedObjectIs(sub)`](crate::structure::ArmPattern::SealedObjectIs).
//! `default: None` because `NoWhenBranchMatchedException` is the
//! exhaustiveness fall-through, not a Kotlin `else ->` arm.
//!
//! Two gates:
//!
//! 1. **Min-arm**: chain length ≥ 3. Rejects 2-arm shapes — false-positive
//!    risk on Java hand-written `instanceof` chains is too high.
//! 2. **Metadata**: the recovered sealed root must carry
//!    `@kotlin.Metadata` (RuntimeVisible). Java code never carries this
//!    annotation, so the gate closes the false-positive risk.
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

/// Reserved [`SignatureId`] for the kotlinc-1.9 sealed-OBJECT `when`
/// recognizer. Range `100..=199` is reserved for kotlinc-1.9 signatures
/// (per `javac21::switch_string` doc-comment).
pub const WHEN_SEALED_OBJECT_SIGNATURE_ID: SignatureId = SignatureId(100);

/// Minimum arm count for the recognizer to fire.
///
/// **Lowered from 3 → 2 in PR-9e.1 of #41b**. The original parent-OQ §6
/// default of 3 was chosen as defense-in-depth against Java hand-written
/// `instanceof` / `equals` chains potentially looking like a 2-arm
/// sealed-when. Empirical analysis during PR-9e shows the metadata
/// gate already provides full coverage: this recognizer requires
/// `dex.class_has_kotlin_metadata(sealed_root)` to be true — a property
/// Java code structurally cannot have. So the additional MIN_ARMS=3
/// floor was overkill. Lowering to 2 unlocks
/// `when_sealed_object/02arms` round-trip without admitting
/// false positives on Java code.
///
/// Sealed-OBJECT specifically uses `Intrinsics.areEqual` — a kotlinc-
/// runtime-only method. Java source never emits this call. Metadata
/// gate alone is the load-bearing discriminator; MIN_ARMS=2 just sets
/// the floor at the smallest source-level `when` arm count (1-arm
/// `when` is degenerate and kotlinc rejects).
const MIN_ARMS: usize = 2;

/// Cap on chain-walk depth. Defends against pathological IR depth on
/// adversarial input (real kotlinc chains are bounded by source-level
/// arm count, typically ≤50; 256 leaves headroom even for the 130-arm
/// fixture).
const MAX_CHAIN_DEPTH: usize = 256;

/// JVM type descriptor for `kotlin.jvm.internal.Intrinsics`. The static
/// holder for `areEqual` and `checkNotNullParameter` — kotlinc emits a
/// call into this class at every `==` and method-entry.
const INTRINSICS_CLASS_DESCRIPTOR: &str = "Lkotlin/jvm/internal/Intrinsics;";

/// Method name for the per-arm equality call.
const AREEQUAL_METHOD_NAME: &str = "areEqual";

/// Field name of the singleton holder on every Kotlin `object`. kotlinc
/// emits `<Sub>.INSTANCE` for every `object Sub : SealedRoot()` declaration.
const INSTANCE_FIELD_NAME: &str = "INSTANCE";

/// JVM type descriptor for `kotlin.NoWhenBranchMatchedException` — the
/// exception kotlinc throws at the chain terminus to signal an
/// unreachable arm (exhaustiveness fall-through).
const NWBME_DESCRIPTOR: &str = "Lkotlin/NoWhenBranchMatchedException;";

/// Recognizer for the kotlinc-1.9 sealed-OBJECT `when` lowering.
pub struct WhenSealedObjectSignature;

impl Signature<DexBackend> for WhenSealedObjectSignature {
    fn id(&self) -> SignatureId {
        WHEN_SEALED_OBJECT_SIGNATURE_ID
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
                    pattern: ArmPattern::SealedObjectIs(sub),
                    body,
                })
                .collect(),
            default: None,
            provenance: SignatureProvenance {
                recognized_as: WHEN_SEALED_OBJECT_SIGNATURE_ID,
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

/// Number of sibling `Stmt`s consumed at the recognizer's entry position
/// (`SgetObject` + `InvokeStatic` + `MoveResult` + `If`). Same stride
/// applies at every nesting level inside `then_body` Seqs; only the
/// outermost stride matters for the engine's `span`.
const ARM_TEST_STRIDE: usize = 4;

/// Walks the nested If chain starting at `stmts[position]`, collecting
/// `(sub_type, arm_body)` pairs. Returns `Some((discriminant_var, arms))`
/// when the chain reaches a `throw NoWhenBranchMatchedException` terminus
/// at its deepest level; returns `None` on any structural deviation.
///
/// The discriminant variable must be the same `VarId` across every arm —
/// kotlinc emits the `when` subject as a single SSA-defined value used
/// uniformly. Discriminant divergence is treated as "not a kotlinc
/// sealed-when chain" rather than NearMiss (the candidate predicate
/// `match_arm_test_shape` will fail on the next arm anyway, and a
/// genuine sealed-when chain never has divergent discriminants).
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

        // Try to match a 4-stmt arm test at the current position.
        if let Some(arm) = match_arm_test(current_stmts, current_position, dex) {
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
        // already-lifted sibling sealed-OBJECT `Stmt::MultiArm` from a
        // prior recognizer pass on a deeper Seq. Inside-out desugar
        // ordering means the engine fires on the deepest sub-Seq first
        // (e.g. arms 3+4+5 of a 5-arm chain) and lifts to MultiArm
        // before the outer pass sees the chain. Without this absorption
        // step, the outer chain walker would only see arms 1+2
        // followed by `[MultiArm]` — fail the structural shape check
        // and bail. PR-9e of #41b.
        //
        // **Critical termination invariant**: only absorb when at
        // least one outer arm has already been collected (`!arms.is_empty()`).
        // Without this gate, the engine would re-enter `try_match` on
        // the just-lifted MultiArm at position 0 of a Seq, the absorb
        // would fire on the same MultiArm, the engine would splice the
        // identical lift back into place, set `changed=true`, and
        // re-loop forever. The gate ensures absorbtion is strictly
        // chain-EXTENSION (outer-then-inner), never chain-IDENTITY
        // (just-the-inner-MultiArm).
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
/// (sealed-OBJECT, `SignatureId(100)`) — chain-merge with a foreign
/// recognizer's lift would be unsound.
struct EmbeddedMultiArm {
    /// Discriminant variable carried in the absorbed MultiArm. Must
    /// equal the outer chain's discriminant for a valid merge.
    disc_var: VarId,
    /// Already-lifted arms in source-position order. Each arm's
    /// `pattern` was `ArmPattern::SealedObjectIs(sub)`; we drop the
    /// outer wrapping and surface `(sub, body)` for the outer walker.
    arms: Vec<(TypeIdx, Stmt)>,
}

/// Try to absorb a sibling-recognizer's already-lifted `Stmt::MultiArm`
/// at `stmts[position]` as a sequence of completed sealed-OBJECT arms.
///
/// **Soundness conditions** (all must hold; any failure → `None`):
/// 1. The stmt at `position` is `Stmt::MultiArm`.
/// 2. SignatureProvenance `recognized_as` equals this signature's id —
///    cross-recognizer merging would corrupt arm semantics.
/// 3. Discriminant is `Discriminant::SealedSubtype { var, .. }` —
///    other discriminants belong to other recognizers.
/// 4. `default` is `None` — kotlinc emits the throw terminus inline
///    after the chain; a non-None default means the inner lift came
///    from a different shape (explicit `else ->` arm) and we must
///    not silently drop it.
/// 5. Every arm pattern is `ArmPattern::SealedObjectIs(sub)`. Mixed
///    patterns (e.g. one `SealedTypeIs`) indicate a sealed-CLASS lift
///    encroached, which is impossible by construction (different
///    recognizer) but worth gating defensively.
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
    if provenance.recognized_as != WHEN_SEALED_OBJECT_SIGNATURE_ID {
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
        let ArmPattern::SealedObjectIs(sub) = case.pattern else {
            return None;
        };
        absorbed_arms.push((sub, case.body.clone()));
    }
    Some(EmbeddedMultiArm {
        disc_var: var.clone(),
        arms: absorbed_arms,
    })
}

/// One matched arm test. Borrows from the parent `stmts` slice; the
/// caller clones `arm_body` and chases `next_seq` for the next level.
struct ArmTest<'a> {
    /// The Kotlin `object` subtype this arm matches against — recovered
    /// from the `getstatic <Sub>.INSTANCE` field's owning class.
    sub_type: TypeIdx,
    /// Discriminant variable (the `when` subject) — first arg to areEqual.
    disc_var: VarId,
    /// Arm body — the `else_body` of the `Stmt::If` (executes when
    /// areEqual returned true, i.e. the bytecode `ifeq` did NOT branch).
    arm_body: &'a Stmt,
    /// Sub-Seq inside the `Stmt::If`'s `then_body` — caller recurses into
    /// this to match the next arm test (or the throw terminus).
    next_seq: &'a [Stmt],
}

/// Match the 4-stmt arm-test pattern at `stmts[position..position+4]`.
/// Returns `Some(ArmTest)` on full structural + dex-side match;
/// `None` otherwise. Pure boolean shape-match split out into
/// [`match_arm_test_shape`] for unit testing without a `DexFile`.
fn match_arm_test<'a>(
    stmts: &'a [Stmt],
    position: usize,
    dex: &crate::parser::DexFile,
) -> Option<ArmTest<'a>> {
    let shape = match_arm_test_shape(stmts, position)?;

    // Verify the SgetObject's field is named "INSTANCE" and resolve the
    // owning Sub type.
    // PROOF: pool indices (u32) → usize widening, lossless on 64-bit;
    // `.get()` handles OOB by returning None.
    #[allow(clippy::as_conversions, reason = "PROOF: u32 → usize widening, lossless on 64-bit; .get() handles OOB.")]
    let field = dex.fields.get(shape.sub_field_idx as usize)?;
    let field_name = dex.get_string(field.name_idx).ok()?;
    if field_name != INSTANCE_FIELD_NAME {
        return None;
    }
    let sub_type = field.class_idx;

    // Verify the InvokeStatic targets `Lkotlin/jvm/internal/Intrinsics;.areEqual`.
    #[allow(clippy::as_conversions, reason = "PROOF: u32 → usize widening, lossless on 64-bit; .get() handles OOB.")]
    let method = dex.methods.get(shape.areequal_method_idx as usize)?;
    let method_name = dex.get_string(method.name_idx).ok()?;
    if method_name != AREEQUAL_METHOD_NAME {
        return None;
    }
    let class_desc = dex.get_type_descriptor(method.class_idx).ok()?;
    if class_desc != INTRINSICS_CLASS_DESCRIPTOR {
        return None;
    }

    Some(ArmTest {
        sub_type,
        disc_var: shape.disc_var,
        arm_body: shape.arm_body,
        next_seq: shape.next_seq,
    })
}

/// Pure structural Stmt match for the arm-test pattern — no `DexFile`
/// dependency. Returns the extracted pool indices + var IDs for the
/// dex-side caller to verify field/method names.
struct ArmTestShape<'a> {
    /// `field_idx.0` of the `SgetObject` instruction (loads `<Sub>.INSTANCE`).
    sub_field_idx: u32,
    /// `method_idx.0` of the `InvokeStatic` instruction (calls `areEqual`).
    areequal_method_idx: u32,
    /// First argument to `areEqual` — the discriminant variable.
    disc_var: VarId,
    /// Arm body (`else_body` of the `Stmt::If`).
    arm_body: &'a Stmt,
    /// Sub-Seq inside the `Stmt::If`'s `then_body`.
    next_seq: &'a [Stmt],
}

fn match_arm_test_shape(stmts: &[Stmt], position: usize) -> Option<ArmTestShape<'_>> {
    let end = position.checked_add(ARM_TEST_STRIDE)?;
    if end > stmts.len() {
        return None;
    }

    // stmts[position]: Stmt::Expr(SgetObject) → v_inst
    let Stmt::Expr(insn0) = stmts.get(position)? else {
        return None;
    };
    if insn0.insn.op != Opcode::SgetObject {
        return None;
    }
    let PoolIndex::Field(field_idx) = insn0.insn.pool_idx? else {
        return None;
    };
    let v_inst = insn0.dst.as_ref()?;

    // stmts[position+1]: Stmt::Expr(InvokeStatic areEqual)
    let Stmt::Expr(insn1) = stmts.get(position.checked_add(1)?)? else {
        return None;
    };
    if insn1.insn.op != Opcode::InvokeStatic {
        return None;
    }
    let PoolIndex::Method(method_idx) = insn1.insn.pool_idx? else {
        return None;
    };
    if insn1.uses.len() != 2 {
        return None;
    }
    // Args: [disc, v_inst]. Verify second arg is the v_inst we just loaded.
    let disc_var = insn1.uses.first()?.clone();
    if insn1.uses.get(1)? != v_inst {
        return None;
    }

    // stmts[position+2]: Stmt::Expr(MoveResult) → v_r
    let Stmt::Expr(insn2) = stmts.get(position.checked_add(2)?)? else {
        return None;
    };
    if insn2.insn.op != Opcode::MoveResult {
        return None;
    }
    let v_r = insn2.dst.as_ref()?;

    // stmts[position+3]: Stmt::If { cond: TestZero(v_r, IfEqz), then_body, else_body }
    let Stmt::If {
        cond,
        then_body,
        else_body,
    } = stmts.get(position.checked_add(3)?)?
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

    Some(ArmTestShape {
        sub_field_idx: field_idx.0,
        areequal_method_idx: method_idx.0,
        disc_var,
        arm_body,
        next_seq: next_seq.as_slice(),
    })
}

/// True iff `stmts` starts with the 3-stmt
/// `throw NoWhenBranchMatchedException` terminus block:
/// `NewInstance + InvokeDirect + Throw`.
fn matches_throw_terminus(stmts: &[Stmt], dex: &crate::parser::DexFile) -> bool {
    let Some(shape) = matches_throw_terminus_shape(stmts) else {
        return false;
    };
    // Verify the NewInstance type is Lkotlin/NoWhenBranchMatchedException;
    let Ok(desc) = dex.get_type_descriptor(TypeIdx(shape.exception_type_idx)) else {
        return false;
    };
    desc == NWBME_DESCRIPTOR
}

/// Pure structural Stmt match for the throw terminus — no `DexFile`
/// dependency. Returns the exception type index for the dex-side caller
/// to verify against `Lkotlin/NoWhenBranchMatchedException;`.
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
    use crate::ids::{FieldIdx, MethodIdx};
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
        v_inst: VarId,
        v_r: VarId,
        v_disc: VarId,
        sub_field_idx: FieldIdx,
        areequal_method_idx: MethodIdx,
        next_seq: Vec<Stmt>,
        arm_body: Stmt,
    ) -> Vec<Stmt> {
        vec![
            Stmt::Expr(ssa_insn(
                Opcode::SgetObject,
                Some(v_inst.clone()),
                vec![],
                Some(PoolIndex::Field(sub_field_idx)),
            )),
            Stmt::Expr(ssa_insn(
                Opcode::InvokeStatic,
                None,
                vec![v_disc, v_inst.clone()],
                Some(PoolIndex::Method(areequal_method_idx)),
            )),
            Stmt::Expr(ssa_insn(Opcode::MoveResult, Some(v_r.clone()), vec![], None)),
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
        assert_eq!(WHEN_SEALED_OBJECT_SIGNATURE_ID, SignatureId(100));
    }

    #[test]
    fn signature_dialect_is_kotlin_v19() {
        let sig = WhenSealedObjectSignature;
        assert_eq!(sig.dialect(), SourceDialect::Kotlin(KotlinVersion::V19));
    }

    #[test]
    fn min_arm_gate_is_two() {
        // Lowered from 3 → 2 in PR-9e.1 of #41b. The metadata gate
        // (`@kotlin.Metadata` on sealed_root) is sufficient on its own
        // for false-positive safety on Java code; the additional
        // 3-arm floor was overkill. 2 is the smallest source-level
        // `when` arm count — 1-arm `when` is degenerate.
        assert_eq!(MIN_ARMS, 2);
    }

    #[test]
    fn match_arm_test_shape_recognizes_canonical_pattern() {
        let v_disc = VarId::new(1, 0);
        let v_inst = VarId::new(0, 2);
        let v_r = VarId::new(0, 3);
        let stmts = arm_test_stmts(
            v_inst.clone(),
            v_r,
            v_disc.clone(),
            FieldIdx(7),
            MethodIdx(15),
            vec![],
            Stmt::Return(None),
        );
        let shape = match_arm_test_shape(&stmts, 0).expect("canonical shape must match");
        assert_eq!(shape.sub_field_idx, 7);
        assert_eq!(shape.areequal_method_idx, 15);
        assert_eq!(shape.disc_var, v_disc);
        assert!(matches!(shape.arm_body, Stmt::Return(None)));
    }

    #[test]
    fn match_arm_test_shape_rejects_when_else_body_missing() {
        // Source-natural Kotlin sealed-when always carries an arm body
        // in else_body; absence means this isn't a sealed-when arm.
        let mut stmts = arm_test_stmts(
            VarId::new(0, 2),
            VarId::new(0, 3),
            VarId::new(1, 0),
            FieldIdx(7),
            MethodIdx(15),
            vec![],
            Stmt::Return(None),
        );
        if let Stmt::If { else_body, .. } = &mut stmts[3] {
            *else_body = None;
        }
        assert!(match_arm_test_shape(&stmts, 0).is_none());
    }

    #[test]
    fn match_arm_test_shape_rejects_wrong_test_zero_op() {
        // kotlinc emits IfEqz (jump-if-zero = jump-if-false). IfNez
        // would mean the structurer flipped the condition source-natural,
        // which empirical audit confirmed is NOT what kotlinc-1.9 does.
        let mut stmts = arm_test_stmts(
            VarId::new(0, 2),
            VarId::new(0, 3),
            VarId::new(1, 0),
            FieldIdx(7),
            MethodIdx(15),
            vec![],
            Stmt::Return(None),
        );
        if let Stmt::If { cond: Condition::TestZero { op, .. }, .. } = &mut stmts[3] {
            *op = Opcode::IfNez;
        }
        assert!(match_arm_test_shape(&stmts, 0).is_none());
    }

    #[test]
    fn match_arm_test_shape_rejects_short_input() {
        // <4 stmts cannot encode an arm test.
        let stmts: Vec<Stmt> = vec![Stmt::Return(None); 3];
        assert!(match_arm_test_shape(&stmts, 0).is_none());
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
        // A mismatch indicates an unrelated throw, not the chain terminus.
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
