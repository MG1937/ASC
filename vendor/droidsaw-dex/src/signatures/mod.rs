//! Per-opcode signature implementations for inversion-driven decompilation.
//!
//! The signature engine itself lives in
//! [`droidsaw_common::signature`]; this module hosts the dex-specific
//! [`SignatureBackend`] adapter, the input view recognizers consume, the
//! lifted IR shape recognizers produce, and the per-dialect recognizer
//! tables (see [`javac21`]).
//!
//! Recognizer tables populate this directory: javac-21 signatures,
//! kotlinc-1.9 signatures, and protector-shape signatures.
#![allow(missing_docs, reason = "internal")]

pub mod javac21;
pub mod kotlinc19;
pub mod matchers;
pub mod protectors;

use droidsaw_common::signature::{Signature, SignatureBackend};

use crate::ids::TypeIdx;
use crate::parser::DexFile;
use crate::structure::Stmt;

/// View of a candidate region a recognizer pattern-matches against.
///
/// The `Stmt` slice is the parent `Stmt::Seq` body; `position` is the
/// index of the first stmt in the candidate region. Recognizers walk
/// forward from `position` and may scan backward for upstream context
/// (e.g. `String.hashCode()` materialization preceding the outer switch).
#[derive(Clone, Copy)]
pub struct DexSigInput<'a> {
    /// Parent `Seq` body the recognizer is scanning.
    pub stmts: &'a [Stmt],
    /// Index of the first stmt in the candidate region.
    pub position: usize,
    /// String/method/type-pool lookup table for opcode classification.
    pub dex: &'a DexFile,
    /// `TypeIdx` of the class enclosing the method whose Seq this is.
    /// Recognizers gate dialect-specific matches on
    /// `dex.class_has_kotlin_metadata(enclosing_class)` to avoid
    /// engine-level ambiguity between javac and kotlinc lowerings of
    /// the same IR shape (e.g. `Stmt::Switch` matched by both
    /// `javac21::switch_int` and `kotlinc19::when_int`). The driver in
    /// `sugar.rs::reconstruct_string_switches` populates this from the
    /// `class_def.class_idx` of the enclosing method's `decompile_method`
    /// caller frame.
    pub enclosing_class: TypeIdx,
    /// True iff `stmts` is the method-root `Stmt::Seq` (the immediate
    /// body of `decompile_method`'s `structure::structure(...)` output)
    /// rather than a nested sub-Seq (Switch case, If then-body,
    /// loop body, etc.). Recognizers that target whole-method-body
    /// shapes — e.g. `kotlinc19::coroutine_suspend` — gate on this flag
    /// to avoid over-matching on inner sub-Seqs that
    /// happen to share a structural fingerprint (e.g. the
    /// IllegalStateException default-arm of the coroutine state-machine's
    /// label-tableswitch).
    ///
    /// Driver-side population: `sugar::desugar_recursive` passes
    /// `is_top_level: true` only on its FIRST call (from `sugar::desugar`,
    /// which receives the method-root); all recursive descents into
    /// child `Stmt`s pass `is_top_level: false`. Engine-driver
    /// `reconstruct_string_switches` threads the flag into every
    /// `DexSigInput` it constructs.
    pub is_top_level: bool,
    /// Method-wide `VarId → i32` env of integer-constant SSA defs.
    /// Pre-computed once at `sugar::desugar` entry by walking the
    /// method's `Stmt` tree. Recognizers that need to resolve
    /// `Move v_dst, v_src` to its underlying constant value (e.g.
    /// `javac21::switch_string` accepting R8-hoisted tag-assignments
    /// per #47) look up `v_src` in this map. SSA versions are unique
    /// and dominate uses, so a method-wide collection is sound
    /// regardless of structural nesting.
    pub method_const_int_env: &'a std::collections::BTreeMap<crate::ssa::VarId, i32>,
}

/// Lifted IR fragment a recognizer returns on match.
///
/// `Replacement` carries the new statement plus the in-place `span`: the
/// caller does `stmts.splice(position..position+span, [new_stmt])`.
pub enum RecognizedDexShape {
    /// In-place replacement of `stmts[position..position+span]` with a
    /// single recognized statement.
    Replacement {
        /// The recognized lifted IR shape.
        new_stmt: Stmt,
        /// Number of original stmts the replacement covers.
        span: usize,
    },
    /// Recognized region without a lifted-IR replacement — the
    /// recognizer identifies the SHAPE but doesn't produce a
    /// source-level lift; emit handles the rendering on its own.
    ///
    /// The engine driver wraps the tagged region in
    /// [`crate::structure::Stmt::Unrecognized`]
    /// with `closest = Some(signature_id)`, `distance = 0` (the sentinel
    /// for "exact tag match" — distinguishes from genuine near-misses
    /// which carry positive distance). Emit (PR-8 or follow-up) dispatches
    /// on `closest + distance == 0` to render the recognizer-specific
    /// banner + unfolded form.
    ///
    /// Used by recognizers whose source-level recovery is intentionally
    /// limited (e.g. `kotlinc19::coroutine_suspend` — recognizes the
    /// state-machine shape but doesn't lift back to
    /// `suspend fun` syntax; emit produces a banner + unfolded form
    /// instead).
    TaggedRegion {
        /// Identifier of the recognizing signature. Engine driver copies
        /// into `Stmt::Unrecognized.reason.closest`.
        signature_id: droidsaw_common::signature::SignatureId,
        /// Number of original stmts the tagged region covers.
        span: usize,
    },
}

/// Bundle-side adapter naming the input view + recognized shape used by
/// dex signatures.
pub struct DexBackend;

impl SignatureBackend for DexBackend {
    type Input<'a>
        = DexSigInput<'a>
    where
        Self: 'a;
    type Recognized = RecognizedDexShape;
}

/// All registered dex signatures, in stable id order.
///
/// Subsequent recognizer additions extend this table. Six kotlinc-1.9
/// recognizers in total: when_sealed_object, when_sealed_class,
/// when_string, when_int, data_class_destructure, coroutine_suspend.
pub fn signature_table() -> [&'static dyn Signature<DexBackend>; 11] {
    [
        // javac-21 (range 1..=99)
        &javac21::switch_string::StringSwitchSignature,
        &javac21::switch_int::SwitchIntSignature,
        &javac21::string_concat_indy::StringConcatIndySignature,
        // kotlinc-1.9 (range 100..=199)
        &kotlinc19::when_sealed_object::WhenSealedObjectSignature,
        &kotlinc19::when_sealed_class::WhenSealedClassSignature,
        &kotlinc19::when_string::WhenStringSignature,
        &kotlinc19::when_int::WhenIntSignature,
        &kotlinc19::data_class_destructure::DataClassDestructureSignature,
        &kotlinc19::coroutine_suspend::CoroutineSuspendSignature,
        // protectors (range 200..=299)
        &protectors::fragmented_string_literal::FragmentedStringLiteralSignature,
        &protectors::reflective_invoke_stub::ReflectiveInvokeStubSignature,
    ]
}
