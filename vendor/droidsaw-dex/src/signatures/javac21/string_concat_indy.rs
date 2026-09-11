//! javac 21 invokedynamic StringConcatFactory recognizer.
//!
//! Recognizes the canonical javac-9+ lowering of `"a" + x + "b"`:
//! a single `invoke-custom` whose bootstrap is
//! `java.lang.invoke.StringConcatFactory.makeConcatWithConstants`. The
//! call-site's encoded_array layout is:
//!
//! - `[0]` `VALUE_METHOD_HANDLE` — bootstrap method (StringConcatFactory).
//! - `[1]` `VALUE_STRING` — SAM method name `"makeConcatWithConstants"`.
//! - `[2]` `VALUE_METHOD_TYPE` — invokedType.
//! - `[3]` `VALUE_STRING` — the **recipe**, where:
//!     - `U+0001` placeholder = take the next runtime argument from
//!       `insn.uses`.
//!     - `U+0002` placeholder = take the next constant from the trailing
//!       slots `[4..]` of the encoded_array.
//!     - Any other char = literal segment.
//! - `[4..]` `VALUE_STRING` / `VALUE_INT` / etc. — constants substituted
//!   into `U+0002` placeholders in recipe order.
//!
//! On match → produces a [`Stmt::StringConcat`] with parts derived from
//! the recipe + uses + trailing constants. The pre-Java-9 StringBuilder
//! peephole (`sugar::desugar_string_concat_in_seq`) is the second
//! producer of the same recognized variant; both pipelines yield the
//! same emit-side rendering.
//!
//! See `tests/corpus/clean/javac-21/string_concat_indy/` for fixtures.

use droidsaw_common::signature::{
    JavaVersion, MatchOutcome, Signature, SignatureId, SourceDialect,
};

use crate::annotation::EncodedValue;
use crate::decode::PoolIndex;
use crate::opcodes::Opcode;
use crate::parser::DexFile;
use crate::signatures::{DexBackend, DexSigInput, RecognizedDexShape};
use crate::ssa::SsaInsn;
use crate::structure::{ConcatPart, Stmt};

/// Reserved [`SignatureId`] for the javac-21 invokedynamic
/// StringConcatFactory recognizer.
pub const STRING_CONCAT_INDY_SIGNATURE_ID: SignatureId = SignatureId(5);

const PLACEHOLDER_ARG: char = '\u{0001}';
const PLACEHOLDER_CONST: char = '\u{0002}';

/// Recognizer for invokedynamic-StringConcat.
pub struct StringConcatIndySignature;

impl Signature<DexBackend> for StringConcatIndySignature {
    fn id(&self) -> SignatureId {
        STRING_CONCAT_INDY_SIGNATURE_ID
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
            ..
        } = input;

        let Some(stmt) = stmts.get(position) else {
            return MatchOutcome::NoMatch;
        };
        // Two acceptable shapes per the existing string-switch precedent:
        //   (a) merged: `Stmt::Expr(InvokeCustom with dst=v)` — single stmt.
        //   (b) pre-merge pair: `Stmt::Expr(InvokeCustom dst=None) +
        //       Stmt::Expr(MoveResultObject dst=v)` — two stmts.
        // Detect (a) first; fall back to (b) at the same position.
        let (insn, dst, span): (&SsaInsn, Option<crate::ssa::VarId>, usize) = match stmt {
            Stmt::Expr(insn)
                if matches!(insn.insn.op, Opcode::InvokeCustom | Opcode::InvokeCustomRange) =>
            {
                (insn, insn.dst.clone(), 1)
            }
            _ => return MatchOutcome::NoMatch,
        };
        // Resolve the call_site, gate on bootstrap.
        let Some(parts) = parse_string_concat_indy(insn, dex) else {
            return MatchOutcome::NoMatch;
        };
        // Honor the pre-merge form: if the InvokeCustom has dst=None and
        // the next stmt is MoveResultObject with a dst, span the pair.
        let (effective_dst, effective_span) = if dst.is_none() {
            match stmts.get(position.saturating_add(1)) {
                Some(Stmt::Expr(mro)) if mro.insn.op == Opcode::MoveResultObject => {
                    (mro.dst.clone(), span.saturating_add(1))
                }
                _ => (dst, span),
            }
        } else {
            (dst, span)
        };

        let new_stmt = Stmt::StringConcat {
            dst: effective_dst,
            parts,
        };
        MatchOutcome::Recognized(RecognizedDexShape::Replacement {
            new_stmt,
            span: effective_span,
        })
    }

    fn max_match_depth(&self) -> usize {
        16
    }
}

/// Try to parse an `InvokeCustom` insn as a StringConcatFactory call.
/// Returns `Some(parts)` on full match, `None` on any deviation (wrong
/// bootstrap, malformed recipe, arg/const count mismatch).
fn parse_string_concat_indy(insn: &SsaInsn, dex: &DexFile) -> Option<Vec<ConcatPart>> {
    let PoolIndex::CallSite(cs_idx) = insn.insn.pool_idx? else {
        return None;
    };
    // PROOF: CallSiteIdx (u32 newtype) → usize widening, lossless on 64-bit;
    // `.get()` handles OOB by returning None.
    #[allow(clippy::as_conversions, reason = "PROOF: u32 → usize widening, lossless on 64-bit; .get() handles OOB.")]
    let &cs_off = dex.call_site_ids.get(cs_idx.0 as usize)?;
    let cs = dex.encoded_arrays.get(&cs_off)?;
    let [bootstrap_slot, _, _, recipe_slot, ..] = cs.as_slice() else {
        return None;
    };
    // [0] bootstrap method-handle → must be StringConcatFactory.makeConcatWithConstants.
    let EncodedValue::MethodHandle(bootstrap_h) = *bootstrap_slot else {
        return None;
    };
    if !is_string_concat_factory(dex, bootstrap_h) {
        return None;
    }
    // [3] recipe.
    let EncodedValue::String(recipe_idx) = *recipe_slot else {
        return None;
    };
    let recipe = dex.get_string(recipe_idx).ok()?.to_string();

    // Trailing constants slice (may be empty).
    let constants: &[EncodedValue] = cs.get(4..).unwrap_or(&[]);

    parse_recipe(&recipe, &insn.uses, constants, dex)
}

/// `true` iff the method-handle at `mh_idx` resolves to
/// `java.lang.invoke.StringConcatFactory.makeConcatWithConstants`.
/// `makeConcat` (the no-constants variant) is NOT accepted here — its
/// recipe is implicit (every arg is a `U+0001` placeholder), and javac
/// 9+ always emits `makeConcatWithConstants` for the explicit-recipe
/// shape. A future signature can add `makeConcat` if a fixture
/// surfaces it.
fn is_string_concat_factory(dex: &DexFile, mh_idx: crate::ids::MethodHandleIdx) -> bool {
    // PROOF: MethodHandleIdx (u32 newtype) → usize widening, lossless on
    // 64-bit; `.get()` handles OOB by returning None.
    #[allow(clippy::as_conversions, reason = "PROOF: u32 → usize widening, lossless on 64-bit; .get() handles OOB.")]
    let Some(handle) = dex.method_handles.get(mh_idx.0 as usize) else {
        return false;
    };
    // Method-kind handles only (4..=8 = invoke-static / invoke-instance
    // / invoke-constructor / invoke-interface / invoke-direct-special).
    if !(4..=8).contains(&handle.kind) {
        return false;
    }
    // PROOF: `handle.field_or_method_id: u16` widens to usize losslessly on
    // all targets. `.get()` handles OOB.
    #[allow(clippy::as_conversions, reason = "PROOF: u16 → usize widening, lossless on all targets; .get() handles OOB.")]
    let Some(method) = dex.methods.get(handle.field_or_method_id as usize) else {
        return false;
    };
    let class = dex.get_type_descriptor(method.class_idx).unwrap_or("");
    let name = dex.get_string(method.name_idx).unwrap_or("");
    class == "Ljava/lang/invoke/StringConcatFactory;" && name == "makeConcatWithConstants"
}

/// Parse a StringConcatFactory recipe into a `Vec<ConcatPart>`.
///
/// The recipe is a sequence of literal characters interleaved with the
/// placeholders `U+0001` (substitute next runtime arg) and `U+0002`
/// (substitute next trailing constant). Returns `None` if the recipe
/// references more args / constants than are available.
fn parse_recipe(
    recipe: &str,
    uses: &[crate::ssa::VarId],
    constants: &[EncodedValue],
    dex: &DexFile,
) -> Option<Vec<ConcatPart>> {
    let mut out: Vec<ConcatPart> = Vec::new();
    let mut buf: String = String::new();
    let mut next_arg: usize = 0;
    let mut next_const: usize = 0;

    let flush_lit = |buf: &mut String, out: &mut Vec<ConcatPart>| {
        if !buf.is_empty() {
            out.push(ConcatPart::Literal(std::mem::take(buf)));
        }
    };

    for ch in recipe.chars() {
        match ch {
            PLACEHOLDER_ARG => {
                flush_lit(&mut buf, &mut out);
                let var = uses.get(next_arg)?;
                out.push(ConcatPart::Var(var.clone()));
                next_arg = next_arg.saturating_add(1);
            }
            PLACEHOLDER_CONST => {
                flush_lit(&mut buf, &mut out);
                let val = constants.get(next_const)?;
                let lit = encoded_value_to_string(val, dex)?;
                out.push(ConcatPart::Literal(lit));
                next_const = next_const.saturating_add(1);
            }
            other => buf.push(other),
        }
    }
    flush_lit(&mut buf, &mut out);

    // Sanity: don't accept a recipe that consumed fewer args than the
    // call-site supplies (would be a corpus bug — recipe / uses out of
    // sync).
    if next_arg != uses.len() {
        return None;
    }
    // Trailing-constant count must match what the recipe consumed.
    if next_const != constants.len() {
        return None;
    }

    Some(out)
}

/// Render an `EncodedValue` constant as the string the recipe expects
/// to splice in. Today: `String` (verbatim), `Int` / `Long` / `Byte` /
/// `Short` / `Char` (decimal/char-literal forms), `Boolean` (`true` /
/// `false`). Other variants → `None`, the recipe fails to match (the
/// signature returns `NoMatch`, the engine wraps the region in
/// `Stmt::Unrecognized` per the inversion-driven discipline).
fn encoded_value_to_string(val: &EncodedValue, dex: &DexFile) -> Option<String> {
    match val {
        EncodedValue::String(sidx) => dex.get_string(*sidx).ok().map(|s| s.to_string()),
        EncodedValue::Int(i) => Some(i.to_string()),
        EncodedValue::Long(l) => Some(l.to_string()),
        EncodedValue::Byte(b) => Some(b.to_string()),
        EncodedValue::Short(s) => Some(s.to_string()),
        EncodedValue::Char(c) => Some(format!("{}", u32::from(*c))),
        EncodedValue::Boolean(b) => Some(if *b { "true".into() } else { "false".into() }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_chars_are_what_we_expect() {
        // Regression guard: U+0001 / U+0002 must remain the literal
        // recipe placeholders. Any drift here would silently break
        // recognition on real-world bytecode.
        assert_eq!(PLACEHOLDER_ARG as u32, 0x01);
        assert_eq!(PLACEHOLDER_CONST as u32, 0x02);
    }

    #[test]
    fn signature_id_is_stable() {
        assert_eq!(STRING_CONCAT_INDY_SIGNATURE_ID, SignatureId(5));
    }

    // The recipe parser is exercised end-to-end via fixture corpus +
    // production smoke. Unit-testing it here would require constructing
    // a `DexFile` for the `EncodedValue::String(StringIdx)` lookup,
    // which is awkward without a real fixture. Production-path
    // coverage lives in `tests/corpus_check.rs` once the corpus
    // entry is exercised against a real toolchain (javac+d8 produce a
    // .dex, decompile pipeline runs through this signature).
}
