//! javac 21 `switch (String)` recognizer.
//!
//! Recognizes the canonical javac lowering of `switch (String s)`:
//!
//! 1. `int h = s.hashCode();`
//! 2. `switch (h) { case HASH_OF_LITERAL: if (s.equals("LIT")) tag = N;
//!                  else tag = -1; break; ... default: break; }`
//! 3. `switch (tag) { case N: <user_body>; ... default: <user_default>; }`
//!
//! On match → produces a single
//! [`crate::structure::Stmt::StringSwitch`].
//! On deviation (candidate-but-inexact) → returns
//! [`MatchOutcome::NearMiss`] so the caller wraps the region in
//! [`crate::structure::Stmt::Unrecognized`].
//!
//! The pattern-match logic is shared with the legacy `sugar.rs`
//! reconstruct-pass entry point — see the private
//! `crate::sugar::try_collapse_adjacent_switches` for the verbatim
//! recognizer body. This module is the engine-shaped facade only.
#![allow(missing_docs, reason = "internal")]

use droidsaw_common::signature::{
    JavaVersion, MatchOutcome, Signature, SignatureId, SourceDialect,
};

use crate::signatures::{DexBackend, DexSigInput, RecognizedDexShape};
use crate::structure::{
    ArmPattern, Discriminant, MultiArm as MultiArmCase, SignatureProvenance, Stmt,
};
use crate::sugar::{
    has_string_switch_candidate_shape, try_collapse_adjacent_switches,
};

/// Reserved [`SignatureId`] for the javac-21 `switch (String)` recognizer.
/// Range `1..=99` is reserved for javac-21 signatures (`#4`); kotlinc
/// signatures (`#5`) get `100..=199`; protector signatures (`#9`) get
/// `1000..=1999`.
pub const STRING_SWITCH_SIGNATURE_ID: SignatureId = SignatureId(1);

/// Recognizer for the canonical javac 21 `switch (String)` lowering.
pub struct StringSwitchSignature;

impl Signature<DexBackend> for StringSwitchSignature {
    fn id(&self) -> SignatureId {
        STRING_SWITCH_SIGNATURE_ID
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
            method_const_int_env,
            ..
        } = input;

        // Dialect gate: skip if the enclosing class is Kotlin source.
        // The kotlinc-1.9 `when (String)` lowering at ≥5 arms produces
        // the same hashCode+tableswitch shape (recognizer finding #7);
        // the sibling `kotlinc19::when_string` recognizer matches it with
        // the inverse positive gate. Without this discriminator both
        // signatures would match every `String.hashCode()`-based two-
        // switch and the engine would surface `Ambiguous` →
        // `Unrecognized` on every Kotlin string-switch fixture (regression).
        // Mirrors the partition pattern landed in PR-4 of #41b
        // (DexSigInput.enclosing_class + javac21::switch_int's gate).
        //
        // Tri-state dialect gate. See switch_int.rs's gate for the
        // dialect-attribution symmetry argument + the post-narrow-FF
        // Indeterminate-propagation rationale.
        match dex.class_has_kotlin_metadata(enclosing_class) {
            crate::DetectorVerdict::No => {}
            crate::DetectorVerdict::Yes => return MatchOutcome::NoMatch,
            crate::DetectorVerdict::Indeterminate => {
                return MatchOutcome::Indeterminate {
                    reason: "kotlin_metadata_indeterminate",
                };
            }
        }

        // Candidate-shape gate: this signature only considers regions
        // that look like a two-switch javac lowering. Anything else is
        // `NoMatch` (silent — the caller doesn't wrap unrelated regions
        // in `Stmt::Unrecognized`).
        if !has_string_switch_candidate_shape(stmts, position) {
            return MatchOutcome::NoMatch;
        }

        // Try the verbatim recognizer. On full match, the helper
        // returns `Stmt::StringSwitch` (the legacy variant). Re-wrap it
        // as `Stmt::MultiArm` with `Discriminant::String` per the
        // consolidation program — `Stmt::MultiArm` is the canonical
        // recognized shape; `Stmt::StringSwitch` is retired.
        match try_collapse_adjacent_switches(stmts, position, dex, method_const_int_env) {
            Some(Stmt::StringSwitch {
                value,
                cases,
                default,
            }) => {
                let arms: Vec<MultiArmCase> = cases
                    .into_iter()
                    .map(|(literals, body)| MultiArmCase {
                        pattern: ArmPattern::StringLiterals(literals),
                        body: *body,
                    })
                    .collect();
                let multiarm = Stmt::MultiArm {
                    discriminant: Discriminant::String(value),
                    arms,
                    default,
                    provenance: SignatureProvenance {
                        recognized_as: STRING_SWITCH_SIGNATURE_ID,
                        source_dialect: SourceDialect::Java(JavaVersion::V21),
                    },
                };
                MatchOutcome::Recognized(RecognizedDexShape::Replacement {
                    new_stmt: multiarm,
                    span: 2,
                })
            }
            // Helper currently always returns `Stmt::StringSwitch` on
            // `Some(_)`; defensive fall-through for future shape drift.
            Some(_) => MatchOutcome::NoMatch,
            // Candidate shape but precise pattern deviated. Caller wraps
            // the region in `Stmt::Unrecognized`. `distance` carries the
            // best-effort hint — for now, a single-step bound; future
            // refinement of the recognizer can thread back the actual
            // edit-distance from the failing inner predicate.
            None => MatchOutcome::NearMiss { distance: 1 },
        }
    }

    fn max_match_depth(&self) -> usize {
        // The recognizer scans backward up to one Seq slot for the
        // `hashCode()` source and inspects per-case bodies up to the
        // canonical 4-stmt shape (`ConstString, equals, MoveResult?,
        // If`). No deep recursion — the bounded-depth invariant is
        // structural, not value-driven.
        16
    }
}

