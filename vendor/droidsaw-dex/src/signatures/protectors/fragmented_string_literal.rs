//! Fragmented-string-literal recognizer.
//!
//! Recognizes the pattern: a string constant fragmented across N≥2
//! source-level literals and reassembled at runtime via
//! `StringBuilder.append` / `invokedynamic StringConcatFactory`. The
//! fragmentation is an IOC-grep evasion technique — javac would
//! constant-fold `"a" + "b"` into a single literal, but author-side
//! tricks (separate-statement assignment, intermediate locals, certain
//! ternary forms) bypass folding so the bytecode contains separate
//! `const-string` instructions that get concat'd at runtime.
//!
//! ## Bytecode shape
//!
//! After `sugar::desugar_string_concat_in_seq` (StringBuilder peephole)
//! or `javac21::string_concat_indy` (invokedynamic recognizer) lifts the
//! lower-level concat machinery to [`Stmt::StringConcat`], the parts
//! vector encodes the source-level pieces:
//!
//! ```ignore
//! Stmt::StringConcat {
//!     dst: Some(v),
//!     parts: vec![
//!         ConcatPart::Literal("admin@cerb".into()),
//!         ConcatPart::Literal("erusapp.com".into()),
//!     ],
//! }
//! ```
//!
//! The recognizer matches when **every part is `ConcatPart::Literal`**
//! AND there are **at least 2 parts** (single-part is just a
//! `const-string`; matching it would be a false positive on plain
//! literals). Mixed `Literal + Var` patterns are real runtime concats
//! (e.g., `"hello " + name`) — those stay as `Stmt::StringConcat`.
//!
//! ## SignatureProvenance
//!
//! Observed at `com.surebrec.U2.U1:2982` in the Cerberus stalkerware
//! Play Store APK (v1.4.9; SHA-256 `b43e7b16841e2058017a75fb2a211fe2dc2e7f442d244e47d16559ad801ce7a1`):
//!
//! - `"admin@cerb" + "erusapp.com"` → `admin@cerberusapp.com`
//! - `"support@cer" + "berusapp.com"` → `support@cerberusapp.com`
//! - `"https://cerb" + "erusapp.com" + "/download/version"` → OTA self-update URL
//!
//! The LSDroid author chose to fragment exactly
//! the IOC-grep targets (support emails + OTA endpoint); everything
//! else (33 C2 URLs, 41 FCM verbs, Firebase project id) ships as plain
//! literals. The recognizer's job is to recover the resolved literal
//! so the analyst's IOC-grep workflow finds these strings.
//!
//! ## False-positive discipline (Directive 3 of #45)
//!
//! Plain `"copyright " + " 2026"` fragmentation in normal Java code
//! also matches this pattern — that's not malicious, just unfortunate.
//! The recognizer DOES match it; the resulting `ResolvedFragment` IR +
//! emit banner-comment is correct for both cases (resolved literal
//! recovered + fragmentation evidence preserved). The semantic
//! interpretation ("is this evasion?") is left to the analyst — the
//! recognizer only attests "this string was reassembled from fragments
//! at runtime", not "this is malicious". Fail-closed on ambiguity is
//! satisfied by structural-only recognition.

use droidsaw_common::signature::{
    JavaVersion, MatchOutcome, Signature, SignatureId, SourceDialect,
};

use crate::signatures::{DexBackend, DexSigInput, RecognizedDexShape};
use crate::structure::{ConcatPart, Stmt};

/// Reserved [`SignatureId`] for the fragmented-string-literal recognizer.
pub const FRAGMENTED_STRING_LITERAL_SIGNATURE_ID: SignatureId = SignatureId(200);

/// Minimum number of `ConcatPart::Literal` parts to recognize as a
/// fragmented literal. `< 2` is a single-literal `Stmt::StringConcat`
/// (i.e., effectively a `const-string`); recognizing it would be a
/// false positive on plain literals.
const MIN_FRAGMENT_COUNT: usize = 2;

/// Recognizer for fragmented-source-literal compile-time concatenation.
pub struct FragmentedStringLiteralSignature;

impl Signature<DexBackend> for FragmentedStringLiteralSignature {
    fn id(&self) -> SignatureId {
        FRAGMENTED_STRING_LITERAL_SIGNATURE_ID
    }

    fn dialect(&self) -> SourceDialect {
        // Dialect-agnostic: the fragmentation pattern produces the
        // same `Stmt::StringConcat` IR shape from javac (any version
        // 8+) and kotlinc. Tag as Java/V21 by convention; the emitted
        // banner does not depend on dialect.
        SourceDialect::Java(JavaVersion::V21)
    }

    fn try_match<'a>(&self, input: DexSigInput<'a>) -> MatchOutcome<RecognizedDexShape>
    where
        DexBackend: 'a,
    {
        let DexSigInput {
            stmts, position, ..
        } = input;

        let Some(stmt) = stmts.get(position) else {
            return MatchOutcome::NoMatch;
        };

        match try_recognize_stmt(stmt) {
            Some(new_stmt) => MatchOutcome::Recognized(RecognizedDexShape::Replacement {
                new_stmt,
                span: 1,
            }),
            None => MatchOutcome::NoMatch,
        }
    }

    fn max_match_depth(&self) -> usize {
        // Single-stmt structural match; no recursion involved.
        4
    }

    fn wildcard_tolerance(&self) -> usize {
        // Strict structural match — the StringConcat IR is the
        // recognized shape; no padding/noise insns to skip.
        0
    }
}

/// Pure-function matcher: returns `Some(new_stmt)` on a fragmented
/// literal, `None` otherwise. Extracted from [`try_match`] so unit
/// tests can exercise the recognition logic without constructing a
/// full `DexSigInput` (which requires a `DexFile`).
fn try_recognize_stmt(stmt: &Stmt) -> Option<Stmt> {
    let (dst, parts) = match stmt {
        Stmt::StringConcat { dst, parts } => (dst, parts),
        _ => return None,
    };

    // Bail if any part references a runtime variable — that's a real
    // `"prefix " + name` concat, not a fragmented literal.
    if parts.iter().any(|p| matches!(p, ConcatPart::Var(_))) {
        return None;
    }

    // Below MIN_FRAGMENT_COUNT is a single-literal StringConcat —
    // cosmetic IR, not fragmentation.
    if parts.len() < MIN_FRAGMENT_COUNT {
        return None;
    }

    // Materialize the resolved literal + the original fragments.
    let mut resolved = String::new();
    let mut fragments: Vec<String> = Vec::with_capacity(parts.len());
    for part in parts {
        if let ConcatPart::Literal(s) = part {
            resolved.push_str(s);
            fragments.push(s.clone());
        } else {
            // Defense-in-depth — the Var check above already rejected
            // this case. Belt-and-suspenders.
            return None;
        }
    }

    Some(Stmt::ResolvedFragment {
        dst: dst.clone(),
        resolved,
        fragments,
        signature_id: FRAGMENTED_STRING_LITERAL_SIGNATURE_ID,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(s: &str) -> ConcatPart {
        ConcatPart::Literal(s.to_string())
    }

    fn varid() -> crate::ssa::VarId {
        // Test-only synthesized VarId. The recognizer doesn't inspect
        // VarId fields; only the Some/None presence.
        crate::ssa::VarId::new(0, 0)
    }

    #[test]
    fn two_literal_parts_recognized() {
        let stmt = Stmt::StringConcat {
            dst: Some(varid()),
            parts: vec![lit("admin@cerb"), lit("erusapp.com")],
        };
        let out = try_recognize_stmt(&stmt).expect("Some");
        match out {
            Stmt::ResolvedFragment {
                resolved,
                fragments,
                signature_id,
                ..
            } => {
                assert_eq!(resolved, "admin@cerberusapp.com");
                assert_eq!(fragments, vec!["admin@cerb", "erusapp.com"]);
                assert_eq!(signature_id, FRAGMENTED_STRING_LITERAL_SIGNATURE_ID);
            }
            _ => panic!("expected ResolvedFragment"),
        }
    }

    #[test]
    fn three_literal_parts_recognized() {
        // Mirrors the Cerberus OTA URL site:
        // "https://cerb" + "erusapp.com" + "/download/version"
        let stmt = Stmt::StringConcat {
            dst: Some(varid()),
            parts: vec![
                lit("https://cerb"),
                lit("erusapp.com"),
                lit("/download/version"),
            ],
        };
        let out = try_recognize_stmt(&stmt).expect("Some");
        match out {
            Stmt::ResolvedFragment { resolved, .. } => {
                assert_eq!(resolved, "https://cerberusapp.com/download/version");
            }
            _ => panic!("expected ResolvedFragment"),
        }
    }

    #[test]
    fn single_part_no_match() {
        // Single-literal StringConcat — cosmetic IR, not a fragmented
        // literal. Recognizer must NOT fire (would be a false positive
        // on plain const-string lowering).
        let stmt = Stmt::StringConcat {
            dst: Some(varid()),
            parts: vec![lit("admin@cerberusapp.com")],
        };
        assert!(try_recognize_stmt(&stmt).is_none());
    }

    #[test]
    fn mixed_literal_var_no_match() {
        // Real runtime concat (`"hello " + name`) — NOT a fragmented
        // literal. Recognizer must NOT fire.
        let stmt = Stmt::StringConcat {
            dst: Some(varid()),
            parts: vec![lit("hello "), ConcatPart::Var(varid())],
        };
        assert!(try_recognize_stmt(&stmt).is_none());
    }

    #[test]
    fn non_string_concat_no_match() {
        // Any other Stmt variant — not a candidate.
        let stmt = Stmt::Break;
        assert!(try_recognize_stmt(&stmt).is_none());
    }

    #[test]
    fn empty_parts_no_match() {
        // Pathological empty StringConcat — defense-in-depth on
        // upstream IR shape.
        let stmt = Stmt::StringConcat {
            dst: Some(varid()),
            parts: vec![],
        };
        assert!(try_recognize_stmt(&stmt).is_none());
    }

    #[test]
    fn dst_none_recognized_inline() {
        // Inline-use form (StringConcat with dst=None — used directly
        // as a method argument). Recognizer fires; emit handles the
        // None-dst case with an inline-literal form per the IR doc.
        let stmt = Stmt::StringConcat {
            dst: None,
            parts: vec![lit("a"), lit("b")],
        };
        let out = try_recognize_stmt(&stmt).expect("Some");
        match out {
            Stmt::ResolvedFragment { dst, resolved, .. } => {
                assert!(dst.is_none());
                assert_eq!(resolved, "ab");
            }
            _ => panic!("expected ResolvedFragment"),
        }
    }

    #[test]
    fn signature_metadata() {
        let sig = FragmentedStringLiteralSignature;
        assert_eq!(sig.id(), FRAGMENTED_STRING_LITERAL_SIGNATURE_ID);
        assert_eq!(sig.id().0, 200);
        assert_eq!(sig.wildcard_tolerance(), 0);
        assert_eq!(sig.max_match_depth(), 4);
    }
}
