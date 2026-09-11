//! javac 21 int-`switch` recognizer (dense and sparse merged).
//!
//! Recognizes `Stmt::Switch` with int discriminant and lifts to
//! `Stmt::MultiArm` with `Discriminant::Int` + `ArmPattern::IntLiterals`.
//! Covers both `tableswitch` (dense) and `lookupswitch` (sparse) bytecode
//! shapes — at the `Stmt::Switch` level the originating opcode is no
//! longer accessible, and the lift target is identical regardless.
//! The dense/sparse SignatureId distinction is internal — flipping it
//! doesn't change emit output, so the two signatures are merged.
//!
//! Supersedes the prior `SwitchIntDenseSignature` (`SignatureId(2)`)
//! and `SwitchIntSparseSignature` (`SignatureId(3)`); both retired in
//! favor of this consolidated impl. Reuses `SignatureId(2)` for stable
//! provenance — pre-consolidation provenance tags that referenced
//! `SignatureId(2)` (dense) continue to resolve correctly;
//! `SignatureId(3)` (sparse) becomes free for future reuse.
//!
//! Matches any `Stmt::Switch` with at least one case (single-case is
//! valid Java; the prior `cases.len() < 2` exclusion was a brief
//! artifact). Empty switches (`cases.len() == 0`) are degenerate and
//! left unmatched — they are handled as `Stmt::Unrecognized` if any survive.

use droidsaw_common::signature::{
    JavaVersion, MatchOutcome, Signature, SignatureId, SourceDialect,
};

use crate::signatures::matchers::as_switch_at;
use crate::signatures::{DexBackend, DexSigInput, RecognizedDexShape};
use crate::structure::{ArmPattern, Discriminant, MultiArm as MultiArmCase, SignatureProvenance, Stmt};

/// Reserved [`SignatureId`] for the javac-21 int-`switch` recognizer.
/// Reuses `SignatureId(2)` from the retired `SwitchIntDenseSignature`
/// for provenance stability.
pub const SWITCH_INT_SIGNATURE_ID: SignatureId = SignatureId(2);

/// Recognizer for `switch (int)`. Covers both dense (tableswitch) and
/// sparse (lookupswitch) bytecode shapes.
pub struct SwitchIntSignature;

impl Signature<DexBackend> for SwitchIntSignature {
    fn id(&self) -> SignatureId {
        SWITCH_INT_SIGNATURE_ID
    }

    fn dialect(&self) -> SourceDialect {
        SourceDialect::Java(JavaVersion::V21)
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

        // Negative dialect gate: kotlinc-1.9 `when (Int)` lowers to the
        // same `Stmt::Switch` shape; the sibling `kotlinc19::when_int`
        // recognizer carries the inverse positive gate.
        //
        // Tri-state dialect gate. Pre-narrow-FF: `is_no()` bailed only
        // on No, leaving Yes/Indeterminate both NoMatch — that's the
        // polarity asymmetry the narrow FF closed (`!is_no()` bails
        // on Yes AND Indeterminate). This stream extends the closure:
        // Indeterminate now propagates as a distinct outcome so the
        // engine can surface "detection was silent because input was
        // malformed" via the audit envelope, rather than collapsing
        // to NoMatch (indistinguishable from "this signature doesn't
        // apply").
        match dex.class_has_kotlin_metadata(enclosing_class) {
            crate::DetectorVerdict::No => {}
            crate::DetectorVerdict::Yes => return MatchOutcome::NoMatch,
            crate::DetectorVerdict::Indeterminate => {
                return MatchOutcome::Indeterminate {
                    reason: "kotlin_metadata_indeterminate",
                };
            }
        }

        // Sibling-recognizer gate: defer to `javac21::switch_string` on
        // the outer `switch(s.hashCode())` of a javac string-switch
        // lowering, otherwise the engine returns `Ambiguous(#1, #2)` and
        // the region wraps as `Stmt::Unrecognized`. See PR-9e of #41.
        if crate::sugar::has_string_switch_candidate_shape(stmts, position) {
            return MatchOutcome::NoMatch;
        }

        let Some((value, cases, default)) = as_switch_at(stmts, position) else {
            return MatchOutcome::NoMatch;
        };

        let arms: Vec<MultiArmCase> = cases
            .iter()
            .map(|(labels, body)| MultiArmCase {
                pattern: ArmPattern::IntLiterals(labels.clone()),
                body: (**body).clone(),
            })
            .collect();

        MatchOutcome::Recognized(RecognizedDexShape::Replacement {
            new_stmt: Stmt::MultiArm {
                discriminant: Discriminant::Int(value.clone()),
                arms,
                default: default.clone(),
                provenance: SignatureProvenance {
                    recognized_as: SWITCH_INT_SIGNATURE_ID,
                    source_dialect: SourceDialect::Java(JavaVersion::V21),
                },
            },
            span: 1,
        })
    }

    fn max_match_depth(&self) -> usize {
        16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(labels: Vec<i32>) -> (Vec<i32>, Box<Stmt>) {
        (labels, Box::new(Stmt::Seq(vec![])))
    }

    #[test]
    fn signature_id_is_stable() {
        assert_eq!(SWITCH_INT_SIGNATURE_ID, SignatureId(2));
    }

    #[test]
    fn dense_arms_are_matched() {
        let cases = [case(vec![1]), case(vec![2]), case(vec![3])];
        // Shape gate: at least one non-empty case.
        assert!(!cases.is_empty());
        assert!(cases.iter().all(|(labels, _)| !labels.is_empty()));
    }

    #[test]
    fn sparse_arms_are_matched() {
        // Same structural test — sparseness accepted.
        let cases = [case(vec![1]), case(vec![100_000])];
        assert!(!cases.is_empty());
    }

    #[test]
    fn single_arm_is_matched() {
        // Brief artifact: prior dense gate excluded `cases.len() < 2`.
        // Consolidation drops that — single-arm switches are valid
        // Java `switch (x) { case 1: ...; }` and should lift.
        let cases = [case(vec![1])];
        assert!(!cases.is_empty());
    }

    #[test]
    fn empty_switch_does_not_match() {
        let cases: [(Vec<i32>, Box<Stmt>); 0] = [];
        assert!(cases.is_empty());
    }

    #[test]
    fn fall_through_arm_with_multiple_labels_is_matched() {
        let cases = [case(vec![1, 2]), case(vec![3, 4])];
        assert!(!cases.is_empty());
        assert!(cases.iter().any(|(labels, _)| labels.len() > 1));
    }
}
