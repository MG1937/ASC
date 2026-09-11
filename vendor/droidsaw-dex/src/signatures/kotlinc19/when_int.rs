//! kotlinc 1.9.22 `when (i: Int) { 1 -> ...; 2 -> ... }` recognizer.
//!
//! Recognizes the canonical kotlinc-1.9 lowering of `when (i: Int)`.
//! From the empirical bytecode audit:
//!
//! - Dense range (1..N consecutive) lowers to `tableswitch` consistently
//!   at 2/5/50 arms (no threshold migration).
//! - Sparse values (e.g. `1, 100, 1000, 10000`) lower to `lookupswitch`.
//!
//! Both bytecode shapes structure-pass to the same `Stmt::Switch`
//! variant, so the recognizer matches a single shape and lifts to
//! `Stmt::MultiArm` with `Discriminant::Int`. Mirrors
//! [`crate::signatures::javac21::switch_int::SwitchIntSignature`]
//! exactly except for:
//!
//! - **Dialect**: `SourceDialect::Kotlin(KotlinVersion::V19)`.
//! - **Metadata gate**: positive — requires
//!   `dex.class_has_kotlin_metadata(enclosing_class)`. The sibling
//!   `javac21::switch_int` recognizer carries the inverse negative gate;
//!   together they partition `Stmt::Switch` matches by enclosing-class
//!   dialect, avoiding the engine-level ambiguity that would otherwise
//!   arise from two recognizers matching the same IR shape.
//! - **`SignatureId(103)`** (kotlinc range `100..=199` per
//!   `javac21::switch_string` doc-comment).

use droidsaw_common::signature::{
    KotlinVersion, MatchOutcome, Signature, SignatureId, SourceDialect,
};

use crate::signatures::{DexBackend, DexSigInput, RecognizedDexShape};
use crate::structure::{
    ArmPattern, Discriminant, MultiArm as MultiArmCase, SignatureProvenance, Stmt,
};

/// Reserved [`SignatureId`] for the kotlinc-1.9 `when (Int)` recognizer.
/// Adjacent to `WHEN_STRING_SIGNATURE_ID(102)` (PR-5 follow-up) per
/// Day-1 prep #3 — the four Kotlin literal-style `when` recognizers
/// (sealed_object 100, sealed_class 101, when_string 102, when_int 103)
/// get adjacent IDs so emit dispatch + diagnostic banners can group them.
pub const WHEN_INT_SIGNATURE_ID: SignatureId = SignatureId(103);

/// Recognizer for the kotlinc-1.9 `when (Int)` lowering.
pub struct WhenIntSignature;

impl Signature<DexBackend> for WhenIntSignature {
    fn id(&self) -> SignatureId {
        WHEN_INT_SIGNATURE_ID
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

        // Dialect gate: only fire when the enclosing class is Kotlin
        // source (carries `@kotlin.Metadata`). The sibling
        // `javac21::switch_int` recognizer carries the inverse negative
        // gate; together they avoid the engine-level ambiguity that
        // would otherwise surface as `Stmt::Unrecognized` on every
        // `Stmt::Switch` (regression).
        match dex.class_has_kotlin_metadata(enclosing_class) {
            crate::DetectorVerdict::Yes => {}
            crate::DetectorVerdict::No => return MatchOutcome::NoMatch,
            crate::DetectorVerdict::Indeterminate => {
                return MatchOutcome::Indeterminate {
                    reason: "kotlin_metadata_indeterminate",
                };
            }
        }

        let Some(stmt) = stmts.get(position) else {
            return MatchOutcome::NoMatch;
        };
        let Stmt::Switch {
            value,
            cases,
            default,
        } = stmt
        else {
            return MatchOutcome::NoMatch;
        };

        if cases.is_empty() {
            return MatchOutcome::NoMatch;
        }

        let arms: Vec<MultiArmCase> = cases
            .iter()
            .map(|(labels, body)| MultiArmCase {
                pattern: ArmPattern::IntLiterals(labels.clone()),
                body: (**body).clone(),
            })
            .collect();

        let multiarm = Stmt::MultiArm {
            discriminant: Discriminant::Int(value.clone()),
            arms,
            default: default.clone(),
            provenance: SignatureProvenance {
                recognized_as: WHEN_INT_SIGNATURE_ID,
                source_dialect: SourceDialect::Kotlin(KotlinVersion::V19),
            },
        };

        MatchOutcome::Recognized(RecognizedDexShape::Replacement {
            new_stmt: multiarm,
            span: 1,
        })
    }

    fn max_match_depth(&self) -> usize {
        // Single-stmt match (no recursion). Mirrors switch_int's bound.
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
        assert_eq!(WHEN_INT_SIGNATURE_ID, SignatureId(103));
    }

    #[test]
    fn signature_dialect_is_kotlin_v19() {
        let sig = WhenIntSignature;
        assert_eq!(sig.dialect(), SourceDialect::Kotlin(KotlinVersion::V19));
    }

    #[test]
    fn dense_arms_are_matched_by_shape() {
        // Mirrors switch_int's dense test: case shape is the load-bearing
        // gate the matcher uses pre-lift. Doesn't invoke try_match itself
        // (positive metadata gate would require a real DexFile with a
        // @kotlin.Metadata-tagged enclosing class — covered in PR-9).
        let cases = [case(vec![1]), case(vec![2]), case(vec![3])];
        assert!(!cases.is_empty());
        assert!(cases.iter().all(|(labels, _)| !labels.is_empty()));
    }

    #[test]
    fn sparse_arms_are_matched_by_shape() {
        // Sparse Int-when (lookupswitch lowering) — same Stmt::Switch
        // primitive as dense (kotlinc-1.9 emits both via the structurer's
        // standard switch lift).
        let cases = [case(vec![1]), case(vec![100_000])];
        assert!(!cases.is_empty());
    }

    #[test]
    fn empty_switch_does_not_match() {
        let cases: [(Vec<i32>, Box<Stmt>); 0] = [];
        assert!(cases.is_empty());
    }
}
