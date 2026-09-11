//! R8 inversion pass — skeleton.
//!
//! This module is the entry point for the dex decompile pipeline's R8
//! inversion stage. It recognises the structural source-to-source
//! transformations that R8 / Proguard apply during shrinking +
//! optimization (block outlining, method inlining, `Enum.values()`
//! caching, dead-code elision artifacts, inner-class flattening,
//! …) and inverts them where the bytecode carries enough information
//! to recover semantic identity, or annotates them where the
//! transformation is lossy by construction (e.g. method inlining
//! without an `--mapping-file`).
//!
//! Pipeline placement: this pass runs in `decompile_method` AFTER
//! [`crate::structure::wrap_try_catch`] (so the IR is fully
//! structured) and BEFORE [`crate::sugar::desugar`] (so sugar
//! operates on the post-inversion IR rather than the raw R8 output).
//!
//! # Wave 1A status (this commit)
//!
//! This file is the SKELETON. It publishes:
//!
//! - The [`R8Origin`] annotation type that future recognizer
//!   sub-streams attach to transformed IR nodes.
//! - The [`R8Transform`] enum that names the recognised
//!   transformations. The enum is `#[non_exhaustive]` and currently
//!   has NO variants — Wave 2 sub-streams (`dex-r8-signatures`,
//!   `dex-r8-inner-class-promotion-back`) add variants as their
//!   recognisers land.
//! - The [`apply`] function whose signature mirrors
//!   [`crate::sugar::desugar`]'s shape. The body is a no-op
//!   pass-through today; Wave 2 wires recognisers into it.
//!
//! # Wave 2 contract (forward reference)
//!
//! Recognisers land as additions to:
//!
//! 1. New variants on [`R8Transform`] (this file).
//! 2. New variants on [`crate::structure::Stmt`] that EMBED an
//!    [`R8Origin`] field, OR an `Option<R8Origin>` annotation on
//!    existing variants — Wave 2 picks the cardinality.
//! 3. Recogniser logic in [`apply`] that walks `stmt`, matches a
//!    transformation shape, and rewrites the matched subtree to a
//!    canonical inverted form with an [`R8Origin`] tag.

use std::collections::BTreeMap;

use crate::cfg;
use crate::decode::PoolIndex;
use crate::ids::{FieldIdx, MethodIdx, TypeIdx};
use crate::opcodes::Opcode;
use crate::parser::{DexFile, ParseFailureKind};
use crate::structure::Stmt;
use crate::types::TypeEnv;

/// Subsection-clean gate for every R8 recognizer that walks
/// `dex.class_datas` or `dex.code_items` via index lookup.
///
/// Without the guard: each `dex.class_datas.get(&off)?` / `dex.code_items.get(&off)?`
/// silently returned `None` when the parser tolerantly recorded a
/// `ParseFailureKind::ClassData` or `ParseFailureKind::CodeItem`
/// failure for that offset. An attacker who planted a ClassData
/// failure on an R8-outlined synthetic class's `class_data_off` got
/// the recognizer to return `None` → class treated as user-defined
/// → R8 inversion silently skipped → operator sees an unrewound
/// outlined block as developer-written. The R8-inversion silent-
/// bypass primitive.
///
/// With the guard: every recognizer that consults class_datas/code_items
/// gates on this helper at function entry. When either subsection
/// has a tolerantly-recorded failure, the whole dex is in an
/// Indeterminate state w.r.t. R8 inversion — the recognizer bails
/// to `None`. The global Indeterminate signal is already surfaced
/// by `diag::collect_detector_indeterminate_findings`, so the operator
/// sees the taint via the standard audit-envelope Finding stream.
///
/// Conservative trade-off: when ANY ClassData or CodeItem failure
/// exists, EVERY R8 recognizer call returns None (coarse). Without
/// the guard, behavior was finer (only the specific failed offsets bailed),
/// but coarser-but-uniformly-defensive is the correct discipline
/// for adversarial input.
#[inline]
fn r8_subsection_clean_check(dex: &DexFile) -> Option<()> {
    if dex.subsection_clean(&[
        ParseFailureKind::ClassData,
        ParseFailureKind::CodeItem,
    ]) {
        Some(())
    } else {
        None
    }
}

/// Named R8 / Proguard transformations that the inversion pass
/// recognises. `#[non_exhaustive]` so Wave 2 sub-streams add
/// variants without an ABI break. Empty in Wave 1A — the type is
/// published as a contract surface.
///
/// Each variant names a specific source-to-source transformation R8
/// applies during shrinking + optimization. The variant's
/// presence on an [`R8Origin`] tag means the inversion pass
/// recognised that shape at the tagged IR node. Wave 2 sub-streams
/// will add (per the umbrella Brief):
///
/// - `BlockOutlined` — R8 hoisted a repeated bytecode block into a
///   synthetic helper method; the inversion pass inlines the helper
///   back at each call site.
/// - `MethodInlined` — R8 inlined a small leaf method at its call
///   sites; without an `--mapping-file` the original name can't be
///   recovered, so this variant is annotation-only.
/// - `EnumValuesCached` — R8 lifted a `MyEnum.values()` call into a
///   static field; the inversion pass rewrites uses of the static
///   field back to a `.values()` call.
/// - `DeadBranchStripped` — R8 stripped an `if (false) { … }`
///   constant-condition branch; structural cues sometimes survive
///   (orphan SSA defs, unreachable-block remnants) — annotation-
///   only.
/// - `InnerClassFlattened` — R8 promoted `Outer$Inner` inner
///   classes to top-level renamed classes; the inversion pass
///   detects the bidirectional-reference shape and re-nests `Inner`
///   inside `Outer` at emit time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[non_exhaustive]
pub enum R8Transform {
    /// Helper-side of R8 block-outlining where MAPPING confirms the
    /// helper is R8-outlined. Emitted only when the recogniser is
    /// fed an [`OutlineOracle`] AND the helper class+method is in
    /// the oracle's outline-annotation set.
    ///
    /// `mapping_confirmed: true` is the strong claim: the bytecode
    /// shape matches AND R8's own mapping declares the method
    /// outlined. `mapping_confirmed: false` is reserved for the
    /// disagreement case (recogniser fires, oracle present, oracle
    /// says NOT outlined) — emitted only when an allowlist policy
    /// tolerates the divergence; otherwise the harness fails hard.
    ///
    /// Production code paths run WITHOUT an oracle (mapping is
    /// unavailable on real APKs by design) and therefore never emit
    /// this variant — they emit [`Self::StructurallyOutlineLike`]
    /// instead.
    BlockOutlinedHelper {
        /// True when the recogniser was paired with an
        /// [`OutlineOracle`] and the oracle confirms the helper is
        /// in R8's mapping outline-annotation set. False is reserved
        /// for the allowlisted-disagreement case (oracle says NOT
        /// outlined, harness tolerates the FP via an explicit
        /// allowlist). Never set from bytecode alone — see
        /// [`Self::StructurallyOutlineLike`] for the no-oracle path.
        mapping_confirmed: bool,
    },

    /// Bytecode-only match for the R8 block-outline helper shape.
    /// The recogniser saw a structurally-outline-like helper method
    /// (every gate in I3-I13 satisfied, with at least 2 distinct
    /// callers), but NO mapping was available to confirm that the
    /// transformation came from R8's outliner.
    ///
    /// This is the production-emit variant (mapping is unavailable
    /// on real APKs). Analyst output reads "looks like outline, no
    /// mapping to confirm" — distinguishable from the high-trust
    /// [`Self::BlockOutlinedHelper`] `mapping_confirmed: true` case
    /// that test harnesses can elevate to when paired with mapping.
    ///
    /// The earlier shape — emitting `BlockOutlinedHelper` at
    /// confidence=100 from bytecode alone — labelled the wrong axis
    /// (callsite density, not mapping confirmation) and surfaced a
    /// deployment-blocker FP rate on horizontal-merge bridges.
    StructurallyOutlineLike,

    /// R8 lifted a repeated `MyEnum.values()` call into a single
    /// static field initialised once in the holder class's `<clinit>`.
    /// Every subsequent use becomes an `sget-object` of that field
    /// instead of a fresh `invoke-static MyEnum;->values()` call.
    /// The recogniser marks methods whose body reads such a cached
    /// field; emit surfaces this as evidence that the field-read site
    /// is morally a `MyEnum.values()` call.
    ///
    /// Detected by [`recognise_enum_values_cache_use`]. The
    /// associated [`R8Origin::synthetic_helper`] carries the original
    /// `Enum.values()` `MethodIdx` (the R8 transformation's
    /// SOURCE — what the field replaces); [`R8Origin::source_pc`]
    /// carries the first `sget-object` PC in the recognised method;
    /// [`R8Origin::caller_count`] carries the count of field-read
    /// sites for this field across the whole DEX (call-site count
    /// semantic — unlike the `BlockOutlinedHelper` variant, which uses
    /// the distinct-caller-method count).
    ///
    /// # Empirical caveat
    ///
    /// On the synthetic Wave 1B `enum_values_cache` fixture, R8 9.0
    /// did NOT produce a values-cache field — it OUTLINED the
    /// `values()` call into a `La;::a(int)` helper (already detected
    /// by [`Self::BlockOutlinedHelper`]). The values-cache shape this
    /// variant recognises is the one the Brief specifies and the one
    /// production R8 produces under different keep rules / optimizer
    /// passes (notably when the holder class is kept and the
    /// `values()` array survives shrinking). The recogniser is
    /// implemented per the Brief's specced shape; production corpora
    /// will exercise it as values-cached shapes surface.
    EnumValuesCached,

    /// R8 inlined a small leaf helper method at its call site. Once
    /// inlining eliminates every call site the helper is removed from
    /// the DEX entirely; only the EXPANDED body survives in the
    /// caller. Without an `--mapping-file` the original helper name is
    /// unrecoverable — this variant is annotation-only, marking the
    /// suspected inline site rather than re-introducing the helper.
    ///
    /// **Structural reality.** R8 9.0 fully inlines `clamp(x, 0, 100)`
    /// into the caller body. After inlining the resulting bytecode is
    /// indistinguishable from source that was hand-written inline:
    /// register-mapping is folded into the surrounding allocation,
    /// arg-shuffles are coalesced with the host's, and the helper's
    /// internal branches are renumbered into the host's PC space.
    /// **No load-bearing signal survives in the bytecode alone.**
    ///
    /// Documented impossibility for in-DEX recognition; see
    /// [`recognise_method_inlined`] for the empirical refutation. The
    /// variant remains as a contract surface for an external oracle
    /// (R8 mapping file, debug-info attribution) — those have access
    /// to the helper-name + call-site evidence in-DEX has lost. The
    /// in-DEX dispatcher in [`apply`] does NOT route to this variant;
    /// production callers that want it must construct it from oracle
    /// evidence directly.
    MethodInlined,

    /// R8 stripped an `if (CONST) { ... }` branch under a constant
    /// condition. Annotation-only marker — there is no way to
    /// recover the stripped text from post-DCE bytecode, and in the
    /// fully-stripped case (R8 9.0 default behaviour observed on the
    /// `dce_unreachable_branch` fixture) there is no surviving cue
    /// either: R8 removes the conditioning field, its writer, and
    /// the branch in one pass.
    ///
    /// **Recogniser status: documented impossibility.** The dispatcher
    /// in [`apply`] does NOT route to this variant; see
    /// [`recognise_dead_branch_stripped`] for the three candidate
    /// detectors enumerated and rejected on empirical grounds (R8 9.0
    /// on the `dce_unreachable_branch` fixture strips field +
    /// initialiser + branch in one pass, leaving no orphan / no
    /// unreachable block / no single-edge conditional). The variant
    /// is published as a contract surface for an external oracle
    /// (R8 mapping file, debug-info) once one is wired in.
    ///
    /// **Candidate signals deferred pending empirical study** (none
    /// implemented):
    ///
    /// - **Orphan static field** — a `static final` written in
    ///   `<clinit>` but never read elsewhere in the DEX. Would
    ///   require class-level cross-method analysis (today's
    ///   [`apply`] is per-method) and risks conflating legitimate
    ///   API constants with DCE artifacts. Confidence 60 framing on
    ///   a class-level signal does not justify the FP rate.
    /// - **Orphan SSA def** — a computed value with zero uses. The
    ///   pipeline already runs [`crate::optimize::optimize`] before
    ///   `apply`, so true orphans on R8-fed input are rare; non-
    ///   orphans (computed-then-discarded values in legitimate code)
    ///   are common. The marker would surface as confidence-60
    ///   noise.
    /// - **Single-edge conditional** — a CFG node with a conditional
    ///   opcode but only one outgoing edge. The CFG already prunes
    ///   structurally-unreachable edges; surviving artifacts require
    ///   partial-stripping which R8 9.0 does not produce on the
    ///   fixture.
    ///
    /// The framing of "orphan SSA defs / unreachable-block
    /// remnants" presupposes partial stripping. R8 9.0 on the
    /// `dce_unreachable_branch` fixture fully strips the conditioning
    /// field, its initializer method, and the dead branch — leaving
    /// only the live arithmetic-and-return with no surviving
    /// structural cue. The recogniser stays a stub until a
    /// production-corpus partial-stripping shape is documented.
    DeadBranchStripped,
}

/// Per-IR-node R8 transformation provenance tag. Attached to a
/// recognised node by [`apply`] (or by an IR variant introduced by
/// a Wave 2 sub-stream that EMBEDS the field).
///
/// Fields:
///
/// - `variant`: which [`R8Transform`] shape was recognised.
/// - `confidence`: recogniser confidence in `0..=100`. `100` is
///   "structural — the recogniser is the inverse of a known R8
///   transformation and the match is mechanical." Lower confidences
///   surface when the recogniser uses heuristics (e.g. shape-based
///   pattern matching that could fire on hand-crafted bytecode that
///   isn't actually R8 output).
/// - `source_pc`: bytecode program-counter of the originating
///   instruction in the input DEX, when known. Optional because some
///   transformations (e.g. inner-class flattening) operate at the
///   class level, not at a specific bytecode site.
/// - `synthetic_helper`: pool index of R8's synthetic helper method
///   when the transformation involved one (e.g. block outlining
///   produces a synthetic helper at a known method-id). Optional;
///   only some transformations carry this.
///
/// Construction is gated by [`R8Transform`] having at least one
/// variant. In Wave 1A the enum is empty, so no value of this
/// struct can be constructed; the type is published as a contract
/// surface only. Wave 2 sub-streams add the first variants and the
/// first constructions.
#[derive(Debug, Clone, serde::Serialize)]
pub struct R8Origin {
    /// Recognised transformation.
    pub variant: R8Transform,
    /// **Caller-count tier label, NOT a precision percentage.**
    ///
    /// The integer in `0..=100` maps to a discrete admission tier
    /// derived from `OutlineOptions.threshold`-style structural
    /// gates (for `BlockOutlinedHelper` / `StructurallyOutlineLike`:
    /// ≥ 20 distinct callers → 100, ≥ 5 → 70, ≥ 2 → 40, below floor
    /// → no marker). Reading the number as "X% chance the recogniser
    /// is right" conflates a ladder label with an empirical
    /// precision claim — they are different axes.
    ///
    /// Empirical precision is calibrated against a validation corpus.
    /// Wilson lower bound on precision at p=0.95 requires n ≥ 100
    /// mapping-paired observations to clear the ≥ 0.95 contract; the
    /// only public corpus available today is n=45, informative-only.
    /// The in-tree custom fixture under
    /// `tests/fixtures/r8/block_outlining/` is the planned exact-
    /// ground-truth anchor once its artifacts are regenerated.
    pub confidence: u8,
    /// Bytecode PC of the originating instruction, when known.
    pub source_pc: Option<u32>,
    /// Pool index of R8's synthetic helper method, when the
    /// transformation involved one.
    pub synthetic_helper: Option<MethodIdx>,
    /// Audit-trail count published with the marker. The exact
    /// semantic depends on the [`Self::variant`]:
    ///
    /// - [`R8Transform::BlockOutlinedHelper`]: number of DISTINCT
    ///   caller methods invoking [`Self::synthetic_helper`] across the
    ///   whole DEX (dedup by caller method, not by call site). The
    ///   recogniser fires only when this count is ≥ 2 (repetition
    ///   gate); the threshold ladder runs against this distinct count
    ///   so a single caller with many invoke-static sites cannot
    ///   inflate the confidence.
    /// - [`R8Transform::EnumValuesCached`]: number of `sget-object`
    ///   read sites for the cached field across the whole DEX
    ///   (call-site count semantic — read sites, not distinct reading
    ///   methods).
    /// - Other variants: `0` when the transformation does not carry a
    ///   meaningful caller count.
    ///
    /// Surfacing this in the marker lets the analyst sanity-check the
    /// recogniser's evidence without re-running the cross-method scan.
    pub caller_count: usize,
}

/// Apply the R8 inversion pass to the structured IR of one method.
///
/// Signature mirrors [`crate::sugar::desugar`] so the call site in
/// `decompile_method` reads symmetrically. Returns `true` when the
/// pass made any change to `stmt`, `false` otherwise. Wave 2
/// recognisers convert the no-op skeleton into a real walker; today
/// the body is `false`.
///
/// # Wave 1A contract (this commit)
///
/// No-op. Any call site can invoke this and observe no behavioural
/// change. Existing fixture goldens, the `corpus_emit_smoke`
/// roundtrip harness, the `v1_corpus_roundtrip` env-gated harness,
/// and every lib-test all stay byte-identical.
///
/// # Parameters
///
/// `stmt` is the method-root Stmt tree as built by
/// [`crate::structure::structure`] + [`crate::structure::wrap_try_catch`].
/// Wave 2 recognisers will walk this tree in place.
///
/// `dex` is the parsed [`DexFile`] — recognisers need it to resolve
/// method-id / type-id pool references in matched patterns.
///
/// `_env` is the per-method [`TypeEnv`] from `infer_types`.
/// Underscored in the skeleton because no recogniser uses it yet;
/// Wave 2 (specifically `EnumValuesCached` recognition) will read
/// enum-type info from it.
///
/// `_enclosing_class` is the [`TypeIdx`] of the class containing
/// the method being processed. Underscored in the skeleton.
/// `InnerClassFlattened` recognition in Wave 2 uses it to detect the
/// outer-class-of-inner pattern.
/// Cross-method state the inversion pass needs to validate
/// recogniser claims that span the whole DEX. Computed once per DEX
/// (typically at `decompile_class_impl` entry, above the per-method
/// loop) and threaded into every [`apply`] call.
///
/// Fields are deliberately scoped to "what the recognisers ACTUALLY
/// verify" — no speculative pre-computation. The BlockOutlined gate
/// reads both fields; future recognisers (`EnumValuesCached`,
/// `InnerClassFlattened`) add their own pre-pass into this struct or
/// sibling structs.
///
/// **Why a census struct rather than walking inside `apply`:**
///
/// `apply` runs per-method. The repetition-count gate needs to know
/// how many distinct invoke-static call sites in the WHOLE DEX target
/// the helper. Computing that on every `apply` call would be
/// O(methods × invocations); computing it once per DEX is O(methods).
/// The shared-state pattern is the same one `r8_identity::collect`
/// uses for per-class identity hints.
#[derive(Debug, Default, Clone)]
pub struct TrampolineCensus {
    /// For each `MethodIdx` that is the target of any `invoke-static`
    /// in this DEX, the list of caller `MethodIdx` values containing
    /// those call sites. Multiple invoke-static sites from the same
    /// caller produce multiple entries (the helper-side
    /// caller-shape check de-duplicates as needed). Used by the
    /// BlockOutlined recogniser's repetition + caller-shape gates.
    invoke_static_callers: BTreeMap<MethodIdx, Vec<MethodIdx>>,
    /// `MethodIdx → code_off` lookup so the helper-body-shape check
    /// can reach the helper's bytecode without re-scanning all
    /// `class_datas`. Populated alongside `invoke_static_callers`.
    method_code_off: BTreeMap<MethodIdx, u32>,
    /// `MethodIdx → class_data_off` lookup so the source-derived
    /// outliner recogniser can reach the containing class's
    /// `ClassData` (instance/static fields, sibling direct/virtual
    /// methods) via `dex.class_datas.get(&off)`. The DEX has
    /// `class_datas` keyed on `class_data_off`; storing the
    /// per-method back-pointer avoids a per-call O(class_defs) scan.
    method_class_data_off: BTreeMap<MethodIdx, u32>,
    /// `class_data_off → index into `dex.class_defs`` for the canonical
    /// outline class_def at that offset. The per-method linear
    /// `class_defs` scan in the outline recogniser is memoized to an
    /// O(log C) lookup here. The canonical row for a given
    /// `class_data_off` is the FIRST `ACC_SYNTHETIC` (0x1000) row if one
    /// exists, else the FIRST row overall — matching
    /// `resolve_outline_class_def_canonical` exactly (including the
    /// collision case where rows share a `class_data_off`).
    canonical_class_def_by_data_off: BTreeMap<u32, usize>,
}

impl TrampolineCensus {
    /// Number of invoke-static **call sites** referencing `target`.
    /// Each call site contributes one — a single caller method that
    /// invokes the target 20 times contributes 20 to this count.
    /// Returns `0` if no call sites exist (the helper is either
    /// orphaned or lives outside this DEX).
    ///
    /// Contrast with [`Self::distinct_caller_count`], which dedups by
    /// caller method. The R8 outliner's repetition gate uses the
    /// distinct-caller semantic — a single attacker-controlled caller
    /// emitting 20 dummy invoke-static instructions to one helper must
    /// not, by itself, satisfy the threshold. This method is retained
    /// for recognisers / diagnostics that genuinely want the call-site
    /// count (e.g. caller-shape audits that examine every site).
    #[must_use]
    pub fn invoke_static_count(&self, target: MethodIdx) -> usize {
        self.invoke_static_callers
            .get(&target)
            .map(Vec::len)
            .unwrap_or(0)
    }

    /// Number of **distinct caller methods** invoking `target` via
    /// `invoke-static`. Dedups the underlying `Vec<MethodIdx>` so a
    /// caller that invokes the target N times contributes 1 (not N) to
    /// this count. Returns `0` if `target` has no callers in this DEX.
    ///
    /// This is the count the BlockOutlined confidence ladder consumes:
    /// R8's outliner runs the OutlineOptions.threshold gate over
    /// distinct caller methods, so the inversion pass's caller-count
    /// gate must mirror that semantic. Using
    /// [`Self::invoke_static_count`] there would let a single caller
    /// method with 20 dummy invoke-static instructions hit
    /// `confidence: 100`.
    #[must_use]
    pub fn distinct_caller_count(&self, target: MethodIdx) -> usize {
        let Some(callers) = self.invoke_static_callers.get(&target) else {
            return 0;
        };
        callers
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<MethodIdx>>()
            .len()
    }

    /// Caller method indices of every invoke-static site targeting
    /// `target`. Duplicates are NOT de-duplicated — a caller invoking
    /// the target multiple times appears once per call site. Empty
    /// slice if `target` has no callers in this DEX.
    #[must_use]
    pub fn callers_of(&self, target: MethodIdx) -> &[MethodIdx] {
        self.invoke_static_callers
            .get(&target)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Index into `dex.class_defs` of the canonical outline class_def
    /// for `class_data_off`, or `None` if no class_def at this offset.
    /// The canonical row is the first `ACC_SYNTHETIC` row at the offset
    /// if any exists, else the first row overall — identical to
    /// `resolve_outline_class_def_canonical`. The returned index is into
    /// the `dex.class_defs` the census was built from; callers resolve
    /// it with `dex.class_defs.get(idx)`.
    #[must_use]
    pub fn canonical_class_def_idx(&self, class_data_off: u32) -> Option<usize> {
        self.canonical_class_def_by_data_off
            .get(&class_data_off)
            .copied()
    }
}

/// Build the [`TrampolineCensus`] for `dex` by walking every
/// instruction in every `code_item` once. Linear in total instruction
/// count.
///
/// Two passes folded into one walk:
///
/// 1. Tally `invoke-static{,/range}` references per `MethodIdx`.
/// 2. Build the `method_idx → code_off` lookup by iterating
///    `dex.class_datas` (EncodedMethod entries carry both fields).
#[must_use]
pub fn build_trampoline_census(dex: &DexFile) -> TrampolineCensus {
    // First pass: build a code_off → method_idx reverse map so the
    // second pass can attribute each invoke-static call site to its
    // owning method. Also builds the forward method_idx → code_off
    // lookup (used later by the helper-body-shape check) and the
    // method_idx → class_data_off back-pointer (used by the
    // source-derived recogniser to reach the containing ClassData).
    let mut method_code_off: BTreeMap<MethodIdx, u32> = BTreeMap::new();
    let mut method_class_data_off: BTreeMap<MethodIdx, u32> = BTreeMap::new();
    let mut code_off_to_owner: BTreeMap<u32, MethodIdx> = BTreeMap::new();
    for (class_data_off, class_data) in &dex.class_datas {
        for em in class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
        {
            method_class_data_off
                .entry(em.method_idx)
                .or_insert(*class_data_off);
            if em.code_off == 0 {
                continue;
            }
            method_code_off.entry(em.method_idx).or_insert(em.code_off);
            code_off_to_owner.entry(em.code_off).or_insert(em.method_idx);
        }
    }
    // Second pass: tally invoke-static call sites per target,
    // attributing each call site to its owning method.
    let mut callers: BTreeMap<MethodIdx, Vec<MethodIdx>> = BTreeMap::new();
    for (code_off, code) in &dex.code_items {
        let Some(&owner) = code_off_to_owner.get(code_off) else {
            // code_item not owned by any EncodedMethod — unusual but
            // not fatal; skip.
            continue;
        };
        for insn in &code.instructions {
            if !matches!(
                insn.op,
                Opcode::InvokeStatic | Opcode::InvokeStaticRange
            ) {
                continue;
            }
            let Some(PoolIndex::Method(m)) = insn.pool_idx else {
                continue;
            };
            callers.entry(m).or_default().push(owner);
        }
    }
    // Precompute the canonical outline class_def per `class_data_off` in
    // ONE O(C) pass. The per-method scan in the outline recogniser would
    // otherwise re-resolve this linearly per concrete method. The rule
    // matches `resolve_outline_class_def_canonical`: the canonical for an
    // offset is the first ACC_SYNTHETIC (0x1000) row if any exists, else
    // the first row overall. `class_data_off == 0` is included like any
    // other offset so the map equals the linear resolver for every off.
    let mut canonical_class_def_by_data_off: BTreeMap<u32, usize> = BTreeMap::new();
    for (i, cd) in dex.class_defs.iter().enumerate() {
        let off = cd.class_data_off;
        let is_syn = (cd.access_flags & 0x1000) != 0;
        match canonical_class_def_by_data_off.get(&off).copied() {
            None => {
                canonical_class_def_by_data_off.insert(off, i);
            }
            Some(incumbent) => {
                let incumbent_is_syn = dex
                    .class_defs
                    .get(incumbent)
                    .is_some_and(|c| (c.access_flags & 0x1000) != 0);
                if !incumbent_is_syn && is_syn {
                    // Upgrade to the first ACC_SYNTHETIC row at this off.
                    canonical_class_def_by_data_off.insert(off, i);
                }
            }
        }
    }
    TrampolineCensus {
        invoke_static_callers: callers,
        method_code_off,
        method_class_data_off,
        canonical_class_def_by_data_off,
    }
}

/// Apply the R8 inversion pass to one method's structured IR.
///
/// Helper-side detection only ([`recognise_outline_helper_v2`]):
/// fires when the CURRENT method IS a synthetic helper R8's
/// outliner extracted a repeated bytecode block into. Marks the
/// helper's body so the analyst sees the outlined block at its
/// source. Tags with [`R8Transform::BlockOutlinedHelper`].
///
/// `census` carries DEX-wide state the recognisers need to verify
/// their claims — see [`TrampolineCensus`] for what's pre-computed
/// and why. Pass an empty `TrampolineCensus::default()` to opt out
/// of recognition (e.g. enum-subclass inlining; tests).
///
/// `current_method` identifies the method whose `stmt` is being
/// walked. The recogniser asks the census how many call sites
/// reference `current_method`.
#[must_use = "return value indicates whether the pass changed the IR"]
pub fn apply(
    stmt: &mut Stmt,
    dex: &DexFile,
    _env: &TypeEnv,
    _enclosing_class: TypeIdx,
    current_method: MethodIdx,
    census: &TrampolineCensus,
) -> bool {
    let mut changed = false;
    // Source-derived helper-side recogniser. Replaces the prior
    // (renamed-namespace + repetition + single-BB body +
    // trampoline-shape callers) gate sequence — those gates were
    // Meta-dialect-narrow and missed AGP-default R8 entirely. The
    // v2 predicates are derived from R8's `OutlinerImpl` source.
    // Trampoline-side recognition is dropped: the trampoline call
    // shape is NOT an outliner invariant (R8 team Q&A confirmation;
    // the helper body mirrors the extracted sequence, not a single
    // invoke + return).
    if let Some(origin) = recognise_outline_helper_v2(dex, current_method, census) {
        prepend_outlined_block_marker(stmt, origin);
        changed = true;
    } else if let Some(origin) = recognise_enum_values_cache_use(dex, current_method, census) {
        prepend_outlined_block_marker(stmt, origin);
        changed = true;
    }
    // [`R8Transform::MethodInlined`] and [`R8Transform::DeadBranchStripped`]
    // intentionally have NO arm in this dispatcher. Both transformations
    // erase every in-DEX signal at apply time (R8's inliner folds the
    // helper into the caller; R8's DCE strips conditioning field +
    // writer + branch in one pass). Empirical study of R8 9.0 on the
    // `method_inlining/` and `dce_unreachable_branch/` fixtures
    // confirms no surviving structural cue. The variants remain as
    // contract surface for an EXTERNAL oracle (R8 mapping file,
    // debug-info attribution) — see [`recognise_method_inlined`] and
    // [`recognise_dead_branch_stripped`] for the documented-impossibility
    // analysis and the rejected candidate detectors.
    changed
}

/// Walk a structured Stmt tree and collect every `R8Origin`
/// recogniser marker prepended by [`apply`]. Returned in
/// depth-first order; nested control-flow constructs (If, While,
/// Switch, TryCatch, etc.) are descended.
///
/// Used by the test-time R8 oracle ratchet
/// (`tests/r8_oracle_ratchet.rs`) so it can inspect markers as IR
/// data rather than parsing them out of the rendered decompile
/// text. Text-level extraction is forgeable — a method name or
/// string literal in the input DEX can carry an
/// `@droidsaw R8Origin(...)` substring that would survive into the
/// emit output; IR-level inspection is not.
#[must_use]
pub fn collect_r8_origins(stmt: &Stmt) -> Vec<R8Origin> {
    let mut out = Vec::new();
    walk_collect_origins(stmt, &mut out);
    out
}

fn walk_collect_origins(stmt: &Stmt, out: &mut Vec<R8Origin>) {
    match stmt {
        Stmt::OutlinedBlock { origin, .. } => out.push(origin.clone()),
        Stmt::Seq(stmts) => {
            for s in stmts {
                walk_collect_origins(s, out);
            }
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            walk_collect_origins(then_body, out);
            if let Some(eb) = else_body {
                walk_collect_origins(eb, out);
            }
        }
        Stmt::While { body, .. }
        | Stmt::DoWhile { body, .. }
        | Stmt::Synchronized { body, .. }
        | Stmt::ForEach { body, .. }
        | Stmt::TryCatch { body, .. } => walk_collect_origins(body, out),
        Stmt::For {
            init, body, update, ..
        } => {
            walk_collect_origins(init, out);
            walk_collect_origins(body, out);
            walk_collect_origins(update, out);
        }
        Stmt::Switch { cases, default, .. } => {
            for (_, b) in cases {
                walk_collect_origins(b, out);
            }
            if let Some(d) = default {
                walk_collect_origins(d, out);
            }
        }
        Stmt::StringSwitch { cases, default, .. } => {
            for (_, b) in cases {
                walk_collect_origins(b, out);
            }
            if let Some(d) = default {
                walk_collect_origins(d, out);
            }
        }
        Stmt::MultiArm { arms, default, .. } => {
            for arm in arms {
                walk_collect_origins(&arm.body, out);
            }
            if let Some(d) = default {
                walk_collect_origins(d, out);
            }
        }
        // Leaf variants — no nested Stmt children, no origin.
        Stmt::Expr(_)
        | Stmt::Return(_)
        | Stmt::InlinedReturn(_)
        | Stmt::InlinedReturnConcat(_)
        | Stmt::Throw(_)
        | Stmt::InlinedThrow(_)
        | Stmt::Break
        | Stmt::Continue
        | Stmt::Goto(_)
        | Stmt::StringConcat { .. }
        | Stmt::Unrecognized { .. }
        | Stmt::Let { .. }
        | Stmt::ResolvedFragment { .. }
        | Stmt::BooleanAssign { .. } => {}
    }
}

/// Method-inlined recogniser — documented impossibility for in-DEX
/// detection. Always returns `None`. Not wired into [`apply`]'s
/// dispatcher (see the dispatcher comment).
///
/// Kept as evidence-anchor: the unit tests below pin "stub returns
/// None on these structural shapes" so any future arm that claims to
/// detect MethodInlined from in-DEX bytecode must first explain why
/// those shapes don't FP-fire it.
///
/// R8 inlines small leaf methods at every call site. When all call
/// sites are inlined the helper is removed from the DEX entirely. The
/// resulting bytecode in each caller is indistinguishable from
/// hand-written inline source: R8's inliner renumbers the helper's
/// register allocation into the caller's, folds the helper's internal
/// branches into the caller's PC space, and discards every artefact
/// (debug-info name, line-number table, parameter-shuffle prologue)
/// that an in-DEX recogniser could pivot on. With no signal in the
/// bytecode alone, any heuristic ("method body is long", "body
/// contains nested conditionals that look like an inlined `clamp`")
/// fires on hand-written code at the same rate as on inlined
/// helpers.
#[allow(
    dead_code,
    reason = "Permanent evidence-anchor stub. Not wired into apply()'s dispatcher (see the dispatcher comment around `R8Transform::MethodInlined intentionally has no arm`). Called only by #[cfg(test)] unit tests that pin the stub-returns-None contract on the structural shapes the docstring above rejects. Removal would lose the test-anchored guard against a future arm that tries to detect MethodInlined from in-DEX bytecode alone."
)]
fn recognise_method_inlined(
    _stmt: &Stmt,
    _dex: &DexFile,
    _current_method: MethodIdx,
    _census: &TrampolineCensus,
) -> Option<R8Origin> {
    None
}

/// DeadBranchStripped recogniser — **documented impossibility** for
/// in-DEX detection. Always returns `None`. Not wired into [`apply`]'s
/// dispatcher (see the dispatcher comment).
///
/// Kept as evidence-anchor: the three candidate detectors enumerated
/// below were rejected on empirical grounds; the unit tests pin "stub
/// returns None on these structural shapes" so any future arm that
/// claims to detect DeadBranchStripped from in-DEX bytecode must
/// first explain why those shapes don't FP-fire it.
///
/// The Brief (`R8Transform::DeadBranchStripped`) admits the
/// transformation is lossy and proposes confidence 60 over
/// "orphan SSA defs / unreachable-block remnants" as the surviving
/// cue. Empirical study of R8 9.0 on the `dce_unreachable_branch`
/// fixture refutes that proposal: R8 fully strips the conditioning
/// static field, its `<clinit>` writer, AND the dead branch in one
/// pass. The post-DCE method body is the live arithmetic and a
/// return — there is no orphan, no unreachable block, no single-
/// edge conditional. There is no signal.
///
/// Three candidate detectors were enumerated and rejected at design
/// time:
///
/// 1. **Orphan static field** (class-level scan for `static final`
///    fields written in `<clinit>` but read nowhere). Requires
///    cross-method analysis that today's per-method [`apply`] does
///    not have a hook for, and would mark legitimate API constants
///    (sentinel values, default-config flags) as DCE artifacts.
///    Confidence 60 does not justify the FP rate.
/// 2. **Orphan SSA def** (method-level scan for SSA defs with zero
///    uses). The pipeline runs [`crate::optimize::optimize`] before
///    `apply`, which already prunes dead SSA defs on input the
///    upstream stack produces. Non-orphan computed-then-discarded
///    values in real code (e.g. side-effecting calls whose return
///    is discarded) are common; the marker would fire on those.
/// 3. **Single-edge conditional** (CFG node with a conditional
///    opcode but only one outgoing edge). The CFG already drops
///    structurally-unreachable successors; partial-stripping
///    artifacts would require R8 to leave a half-stripped branch,
///    which R8 9.0 does not do on the fixture.
///
/// The arguments are not against the variant itself — it remains a
/// useful contract surface — but against any of the proposed
/// detectors firing without a documented production-corpus signal.
///
/// Parameters are accepted because the unit tests below call this
/// stub with them; the stub body uses none of them.
#[must_use]
#[allow(
    dead_code,
    reason = "Permanent evidence-anchor stub. Not wired into apply()'s dispatcher (see the dispatcher comment around `R8Transform::DeadBranchStripped intentionally has no arm`). Called only by #[cfg(test)] unit tests that pin the stub-returns-None contract on the three candidate detector shapes the docstring above rejects (orphan static field, orphan SSA def, single-edge conditional). Removal would lose the test-anchored guard against a future arm that tries to detect DeadBranchStripped from in-DEX bytecode alone."
)]
fn recognise_dead_branch_stripped(
    _stmt: &Stmt,
    _dex: &DexFile,
    _current_method: MethodIdx,
    _census: &TrampolineCensus,
) -> Option<R8Origin> {
    // Structural stub. See variant docstring for the empirical gap.
    None
}


/// Source-derived BlockOutlined helper recogniser.
///
/// The new design keys on invariants R8's `OutlinerImpl` establishes
/// by construction (pinned against r8.googlesource.com `Outliner`
/// pass at the time of writing):
///
/// - **No class-name patterns.** R8 reserves the right to rename
///   synthetic classes; matching on `LX/<short>;` or
///   `$$ExternalSyntheticOutline$<id>` would re-narrow the recogniser
///   to one dialect and break the next time R8 changes its naming
///   convention.
///
/// - **Containing class structure** (R8 `SyntheticItems` invariant):
///   exactly one static method, no instance/static fields, no
///   `<clinit>`, default no-arg `<init>` only. The synthetic outline
///   class is a single-method bag.
///
/// - **Method signature** (`OutlinerImpl` constructor):
///   `ACC_PUBLIC | ACC_STATIC`, parameter arity ≤ 5 (`MAX_IN_SIZE`).
///
/// - **Method body** (`OutlinerImpl` eligibility predicate):
///   straight-line opcodes only — `invoke*`, `new-instance`,
///   arithmetic binops, return/move-result. No branches, switches,
///   loops, monitor, move-exception. Body size 1-100 instructions
///   (R8 source: `OutlineOptions.minSize=3, maxSize=99` bytes plus
///   emit-side overhead admitting 1-100 insns at the recogniser).
///
/// - **Caller count** (`OutlineOptions.threshold=20`):
///   confidence ladder rather than hard floor — R8's threshold is
///   the emit-time floor on the producer side, but consumer-side
///   measurements may see fewer callers if downstream passes
///   pruned. Confidence: ≥20 → 100, ≥5 → 70, ≥2 → 40, else None.
///
/// Returns `None` when any predicate declines. Returns
/// `Some(R8Origin { variant: BlockOutlinedHelper, .. })` with the
/// recorded confidence when all predicates pass.
/// Resolve the canonical `class_def_item` for an R8 outline helper given
/// a `class_data_off`. Closes the `class_data_off` collision evasion at
/// the previous bare-`.find()` shape: an attacker can plant two
/// `class_def_item` rows with DIFFERENT `class_idx` but the SAME
/// `class_data_off` pointing at a legit R8 outline `class_data`; if the
/// first row lacks `ACC_SYNTHETIC` the gate at the call site short-
/// circuits and outline detection is silently suppressed. Prefers the
/// `ACC_SYNTHETIC`-bearing canonical row; falls back to first match
/// (so non-attacker bundles continue to resolve as before).
///
/// The collision itself surfaces as `DEX_CLASS_DATA_OFF_COLLISION` via
/// `diag::collect_class_data_off_collision_findings`; this helper just
/// performs the canonical resolution.
///
/// Production resolves the canonical class_def through the
/// `TrampolineCensus` memoization (`canonical_class_def_idx`), which is
/// built in one O(C) pass. This linear resolver is retained `#[cfg(test)]`
/// as the independent equivalence oracle the census map is verified
/// against.
#[cfg(test)]
fn resolve_outline_class_def_canonical(
    dex: &DexFile,
    class_data_off: u32,
) -> Option<&crate::ids::ClassDefItem> {
    dex.class_defs
        .iter()
        .filter(|cd| cd.class_data_off == class_data_off)
        .find(|cd| cd.access_flags & 0x1000 != 0)
        .or_else(|| {
            dex.class_defs
                .iter()
                .find(|cd| cd.class_data_off == class_data_off)
        })
}

fn recognise_outline_helper_v2(
    dex: &DexFile,
    current_method: MethodIdx,
    census: &TrampolineCensus,
) -> Option<R8Origin> {
    // Defensive gate against tolerantly-recorded ClassData / CodeItem
    // parse failures. See r8_subsection_clean_check for the
    // R8-inversion silent-bypass primitive this closes.
    r8_subsection_clean_check(dex)?;

    // ── Containing-class ACC_SYNTHETIC requirement ──
    // R8's SyntheticItems sets ACC_SYNTHETIC (0x1000) on every
    // class it synthesizes. Developer-written code that happens
    // to satisfy the structural predicates below (single static
    // method, no fields, etc.) does NOT carry this flag. This is
    // the difference between catching outline helpers and catching
    // every utility class that looks like one structurally.
    let class_data_off = census.method_class_data_off.get(&current_method).copied()?;
    // Canonical (ACC_SYNTHETIC-preferring) resolution memoized in the
    // census; equivalent to `resolve_outline_class_def_canonical` but
    // O(log C) instead of a per-method linear `class_defs` scan.
    let class_def = dex
        .class_defs
        .get(census.canonical_class_def_idx(class_data_off)?)?;
    if (class_def.access_flags & 0x1000) == 0 {
        return None;
    }

    // ── D8 desugar synthetic namespace discrimination ──
    // Both R8's outliner AND D8's desugar pipeline emit classes
    // using the `$$ExternalSynthetic` / `$$InternalSynthetic`
    // infix convention. The PREVIOUS implementation excluded
    // ANY class containing `$$ExternalSynthetic`, intending to
    // skip D8 backports — but this also excluded R8 outline
    // helpers when R8 preserved synthetic names in the DEX.
    //
    // Real-world empirical data: in some R8 versions, outlined helper
    // classes named `*$$ExternalSyntheticOutline0` in the DEX are
    // excluded by the substring exclusion, requiring special care in
    // the recognizer.
    //
    // Discrimination via descriptor after the infix. R8 outline
    // emit kinds (per R8 source `synthesis/SyntheticNaming.java`):
    //   - Outline, CovariantOutline, ApiModelOutline,
    //     NonStartupInStartupOutline, BUOutline, ObjectCloneOutline
    // D8 desugar kinds (NOT outliner output) emit classes with
    // descriptors NOT in that allow-list:
    //   - Lambda, Backport, Record, ServiceLoadable, etc.
    //
    // If the descriptor after `$$ExternalSynthetic` matches an R8
    // outline kind → fall through to the structural recogniser
    // (it should fire). Otherwise → skip (D8 artifact).
    //
    // `$$InternalSynthetic` is D8-internal-only at this writing
    // (no R8 outline emit path uses it), so the bare-substring
    // exclusion stays.
    let class_desc = dex
        .type_descriptors
        .get({
            #[allow(
                clippy::as_conversions,
                reason = "PROOF: u32 → usize widening, lossless on 64-bit; `.get()` bounds-checks before slice access."
            )]
            {
                class_def.class_idx.0 as usize
            }
        })
        .map(String::as_str)
        .unwrap_or("");
    if class_desc.contains("$$InternalSynthetic") {
        return None;
    }
    // Tracks whether this class is BUOutline (R8 bottom-up outliner
    // for exception-throw sequences). BU bodies legitimately end in
    // `Throw` and may have zero params (caller pushes nothing). Set
    // from the descriptor-allow-list check below so downstream body /
    // arity gates can relax for this kind without losing precision on
    // basic Outline.
    let mut is_bu_outline = false;
    if let Some(suffix) = class_desc.split("$$ExternalSynthetic").nth(1) {
        // Suffix is everything after the FIRST `$$ExternalSynthetic`
        // occurrence; for a class like
        // `Lcom/foo/Bar$$ExternalSyntheticOutline0;` the suffix is
        // `Outline0;`. Take the longest leading ASCII-alphabetic run
        // as the descriptor; rejects empty-descriptor crafted input
        // (`$$ExternalSynthetic0`).
        let descriptor_len = suffix
            .bytes()
            .take_while(|b| b.is_ascii_alphabetic())
            .count();
        let descriptor = suffix.get(..descriptor_len).unwrap_or("");
        if !matches!(
            descriptor,
            "Outline"
                | "CovariantOutline"
                | "ApiModelOutline"
                | "NonStartupInStartupOutline"
                | "BUOutline"
                | "ObjectCloneOutline"
        ) {
            return None;
        }
        is_bu_outline = descriptor == "BUOutline";
        // R8 outline descriptor — fall through, recogniser fires.
    }
    // Note: the `Lj$/` namespace (D8 java.* desugar) is NOT
    // excluded here. R8 has been observed to outline methods
    // FROM inside `Lj$/time/` classes (the outliner runs over
    // D8-desugar-emitted code as a normal optimization input).
    // Excluding the namespace would drop real outline targets.

    // ── Kotlin compiler synthetic-accessor exclusion ──
    // Kotlin emits `access$<original_name>` static methods to
    // bridge `internal`/`private`-visibility members across
    // compilation units. These survive R8 with a single static
    // method per class (no fields, straight-line body) — same
    // structural shape as an outline helper. The `access$` method
    // prefix is a documented Kotlin compiler convention, stable
    // across Kotlin versions.
    //
    // The method-name check has to happen later (after we have
    // `current_method` resolved); this gate is here so the
    // namespace-exclusion comment block stays together.

    // ── Containing-class structural predicate (I5) ──
    let class_data = dex.class_datas.get(&class_data_off)?;
    if !class_data.instance_fields.is_empty() {
        return None;
    }
    // Static-fields gate: structurally the basic Outliner-emit
    // shape is a single static helper in a field-free synthetic
    // class. R8's ApiModelOutliner is observed to emit helpers
    // into a synthetic class that ALSO hosts static fields (likely
    // SDK-version constants or compile-time-resolved API-level
    // metadata that the SDK-branching helpers reference). Empirical
    // anchor: Phase 1.5 harness-side FN walker (Phase 2.5 sweep at
    // n=31) bucketed 46 of 50 (92%) API_MODEL_OUTLINE FN cases as
    // `has_static_fields` rejections, concentrated in 2 R8-renamed
    // classes (one project across 2 release versions, 23 outlined
    // methods each). Class flags on every one of the 46:
    // `0x1401 = ACC_PUBLIC | ACC_ABSTRACT | ACC_SYNTHETIC`.
    //
    // Relaxation: admit when the containing class is
    // `ACC_PUBLIC + ACC_ABSTRACT + ACC_SYNTHETIC` simultaneously.
    // This flag combination is descriptor-name-agnostic (works on
    // classes where R8 stripped the synthetic infix at release) and
    // structurally narrow: ACC_SYNTHETIC is compiler-emitted-only
    // (developer source cannot produce it), and the simultaneous
    // ABSTRACT + PUBLIC + SYNTHETIC combo on a class that meets the
    // remaining outline-helper structural predicate (no instance
    // fields, no virtual methods, single non-static direct, etc.)
    // is a tight enough trigger to keep developer-written utility
    // classes out.
    let class_is_abstract_synthetic_public = (class_def.access_flags & 0x1401) == 0x1401;
    if !class_data.static_fields.is_empty() && !class_is_abstract_synthetic_public {
        return None;
    }
    if !class_data.virtual_methods.is_empty() {
        return None;
    }
    // Non-static direct methods: at most ONE (the default no-arg
    // <init> R8 emits on every synthesized class). R8 9.x packs
    // multiple outline methods into one synthetic class — the
    // count of STATIC direct methods is not bounded by 1 (the
    // earlier SyntheticItems Q&A framing of "single synthetic
    // method per class" did not match observed output).
    let non_static_direct = class_data
        .direct_methods
        .iter()
        .filter(|em| (em.access_flags & 0x0008) == 0)
        .count();
    if non_static_direct > 1 {
        return None;
    }
    // Verify the CURRENT method is in this class and is static.
    let helper = class_data
        .direct_methods
        .iter()
        .find(|em| em.method_idx == current_method)?;
    if (helper.access_flags & 0x0008) == 0 {
        return None;
    }

    // ── Method-signature predicate (I4 + I8) ──
    // I4: ACC_PUBLIC | ACC_STATIC. Bit values per DEX spec.
    if (helper.access_flags & 0x0001) == 0 {
        return None;
    }
    // I8: parameter arity ≤ 5. The DEX proto's parameter_count
    // includes the receiver only for instance methods; static
    // methods carry exactly their declared arity.
    #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; method_idx.0 and proto_idx.0 bounded < dex.methods.len()/dex.protos.len() by parser validation of method_ids/proto_ids pools.")]
    let method_id = dex.methods.get(current_method.0 as usize)?;
    // Kotlin synthetic-accessor exclusion: method names starting
    // with `access$` are Kotlin compiler bridges for
    // internal-/private-visibility members, NOT R8 outliner
    // output. Stable Kotlin compiler emit-contract.
    let method_name = dex.get_string(method_id.name_idx).unwrap_or("");
    if method_name.starts_with("access$") {
        return None;
    }
    #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; proto_idx.0 bounded < dex.protos.len() by parser validation of proto_ids pool.")]
    let proto = dex.protos.get(method_id.proto_idx.0 as usize)?;
    // R8 outlines parameterize the extracted code; a zero-arity
    // outline would just hoist a constant expression, which R8
    // does not bother synthesizing for the basic Outliner — but
    // BUOutline (R8 BottomUpOutliner) DOES emit zero-arity helpers
    // that construct + throw an exception with no caller-supplied
    // inputs (e.g. `throw new IllegalStateException()` extracted
    // from many sites). Allow param_count == 0 ONLY for BUOutline.
    let param_count = if proto.parameters_off == 0 {
        0
    } else {
        dex.type_lists
            .get(&proto.parameters_off)
            .map(Vec::len)
            .unwrap_or(0)
    };
    if param_count > 5 {
        return None;
    }
    if param_count == 0 && !is_bu_outline {
        return None;
    }

    // ── Body predicate (I6 + I7) ──
    let code_off = census.method_code_off.get(&current_method).copied()?;
    let code = dex.code_items.get(&code_off)?;
    if !code.tries.is_empty() {
        return None;
    }
    // I7: instruction-count bound. Maps the byte bound (3-99 bytes,
    // ~1-50 16-bit code units) plus emit-side overhead onto a
    // permissive insn-count range.
    let insn_count = code.instructions.len();
    if insn_count == 0 || insn_count > 100 {
        return None;
    }
    // A body that is a single bare Return-family opcode extracted no
    // bytecode: this is an R8 horizontal-class-merge empty bridge (a
    // synthetic static stub), not an extracted outline body. The
    // outliner exists to hoist repeated non-trivial bytecode, so a
    // sole-return shape is structurally impossible as an outline.
    // Reject regardless of caller count / kind.
    if insn_count == 1
        && code.instructions.first().is_some_and(|i| {
            matches!(
                i.op,
                Opcode::ReturnVoid
                    | Opcode::Return
                    | Opcode::ReturnWide
                    | Opcode::ReturnObject
            )
        })
    {
        return None;
    }
    // I6: every opcode must be outline-eligible. BUOutline bodies
    // legitimately terminate in `Throw` (the whole point of the BU
    // outliner is to extract exception-construction-and-throw
    // sequences); for that kind, swap in the BU-aware predicate
    // which admits `Throw` as a body opcode. Other kinds keep the
    // strict predicate (`Throw` would FP-fire on developer-written
    // synthetic-static throw helpers).
    let body_ok = if is_bu_outline {
        body_is_outline_eligible_bu(code)
    } else {
        body_is_outline_eligible(code)
    };
    if !body_ok {
        return None;
    }

    // ── Caller-count confidence ladder (I9) ──
    // Uses DISTINCT caller methods (not call sites) so a single
    // attacker-controlled caller emitting many invoke-static
    // instructions to one helper cannot inflate the ladder. R8's
    // OutlineOptions.threshold is itself defined over distinct
    // callers; the recogniser mirrors that semantic.
    let caller_count = census.distinct_caller_count(current_method);
    // Two outline-emit shapes admit at a lower distinct-caller
    // threshold than the basic Outliner's
    // `OutlineOptions.threshold=20`:
    //
    // - BU outliner: empirically as few as 1 distinct caller (slot07
    //   `Platform$$ExternalSyntheticBUOutline0.m`, mapping-confirmed).
    //   Descriptor-named (`$$ExternalSyntheticBUOutline`) so gated on
    //   `is_bu_outline`.
    //
    // - ApiModelOutline emit in R8-renamed classes (synthetic infix
    //   stripped by release optimization): empirically 1 distinct
    //   caller per outlined method in partially-obfuscated androidx
    //   helpers (slot17 + slot18 paired-corpus FN walker observation:
    //   3 mapping-annotated `Build.VERSION.SDK_INT`-routing methods
    //   with `class_access=0x1401 = ACC_PUBLIC|ACC_ABSTRACT|
    //   ACC_SYNTHETIC` and `caller_count=1`). The descriptor name is
    //   gone post-rename so gated on the same structural flag-mask
    //   that gates the `has_static_fields` relaxation —
    //   `class_is_abstract_synthetic_public`.
    //
    // Each kind has its own ladder so the relaxations can be tuned
    // independently as paired-corpus data grows.
    let confidence = if is_bu_outline {
        bu_outlined_ladder_confidence(caller_count)?
    } else if class_is_abstract_synthetic_public {
        abstract_synthetic_outlined_ladder_confidence(caller_count)?
    } else {
        block_outlined_ladder_confidence(caller_count)?
    };

    // Production recognition is bytecode-shape only — no mapping
    // available. The high-trust [`R8Transform::BlockOutlinedHelper`]
    // variant is emitted only when a paired-mapping caller elevates
    // this marker via [`elevate_with_oracle`]; this production path
    // emits [`R8Transform::StructurallyOutlineLike`].
    Some(R8Origin {
        variant: R8Transform::StructurallyOutlineLike,
        confidence,
        source_pc: None,
        synthetic_helper: Some(current_method),
        caller_count,
    })
}

/// Oracle that maps `(obfuscated_class, obfuscated_method)` tuples
/// to "R8 outlined this method" verdicts. Backed by R8's own
/// `mapping.txt` in test contexts; production code does not have
/// access to a mapping by design (real APKs ship without one), so
/// production callers never wire one in.
///
/// The trait is the bridge between the bytecode-only recogniser
/// (which emits [`R8Transform::StructurallyOutlineLike`]) and the
/// mapping-confirmed variant
/// [`R8Transform::BlockOutlinedHelper`]: a harness with a paired
/// mapping calls [`elevate_with_oracle`] on each recogniser output
/// to upgrade or downgrade the variant.
pub trait OutlineOracle {
    /// Mapping-key class name (`a.b`) — descriptor without `L`/`;`
    /// wrappers, `/` replaced by `.`.
    fn is_outlined(&self, mapping_key_class: &str, method: &str) -> bool;
}

/// Verdict produced by [`elevate_with_oracle`] for one marker under
/// a paired-mapping oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleVerdict {
    /// Oracle confirms the marker; variant is now
    /// [`R8Transform::BlockOutlinedHelper`] with `mapping_confirmed: true`.
    Confirmed,
    /// Oracle disagrees: recogniser fired but mapping says NOT
    /// outlined. The mapping-paired harness must either fail or
    /// allowlist this descriptor; the marker variant is set to
    /// [`R8Transform::BlockOutlinedHelper`] with `mapping_confirmed: false`
    /// so the disagreement survives in the marker text.
    Disagreed,
}

/// Reclassify a recogniser-emitted [`R8Origin`] using a paired
/// mapping oracle. Operates on the
/// [`R8Transform::StructurallyOutlineLike`] variant (the
/// production-emit shape); other variants pass through unchanged.
///
/// Returns the updated origin + an [`OracleVerdict`] for the caller
/// to act on (assert allowlisted, fail the test, log, etc.). The
/// `mapping_key_class` argument is the helper class's mapping-key
/// form (descriptor → key via
/// `tests/common/r8_canonical_marker::descriptor_to_mapping_key`);
/// `helper_method` is the obfuscated method name.
#[must_use]
pub fn elevate_with_oracle<O: OutlineOracle + ?Sized>(
    origin: R8Origin,
    oracle: &O,
    mapping_key_class: &str,
    helper_method: &str,
) -> (R8Origin, Option<OracleVerdict>) {
    if !matches!(origin.variant, R8Transform::StructurallyOutlineLike) {
        return (origin, None);
    }
    let confirmed = oracle.is_outlined(mapping_key_class, helper_method);
    let verdict = if confirmed {
        OracleVerdict::Confirmed
    } else {
        OracleVerdict::Disagreed
    };
    let elevated = R8Origin {
        variant: R8Transform::BlockOutlinedHelper {
            mapping_confirmed: confirmed,
        },
        ..origin
    };
    (elevated, Some(verdict))
}

/// Confidence ladder for the BlockOutlined recogniser, factored out so
/// the recogniser-level test path and the regression test exercise the
/// same constants. Returns `None` when the distinct-caller count is
/// below the admission floor (≥ 2); otherwise the confidence tier.
///
/// The thresholds match R8's `OutlineOptions.threshold = 20` (the
/// emit-time outline threshold) and a confidence ladder below it. A
/// regression that drops the ladder floor — e.g. allowing `>= 1` —
/// surfaces in `block_outlined_recogniser_rejects_call_site_inflation`
/// without needing to thread a real `DexFile` through the test
/// harness.
///
/// # The returned integer is a tier label, not a precision percentage
///
/// `Some(100)` is "≥ 20 distinct callers cleared R8's emit threshold",
/// not "100% likely to be a real R8 outline". The empirical precision
/// of the recogniser at a given tier requires mapping-paired evidence
/// against a corpus of ≥ 100 outline annotations (Wilson lower bound
/// at p=0.95) — see [`R8Origin::confidence`] for the calibration state. Today's available evidence
/// (n=45) is informative-only; in-tree exact ground truth lives in
/// `tests/fixtures/r8/block_outlining/` when its artifacts are
/// regenerated.
#[must_use]
pub(crate) fn block_outlined_ladder_confidence(distinct: usize) -> Option<u8> {
    match distinct {
        c if c >= 20 => Some(100),
        c if c >= 5 => Some(70),
        c if c >= 2 => Some(40),
        _ => None,
    }
}

/// Ladder for outlined helpers whose containing class carries the
/// `ACC_PUBLIC | ACC_ABSTRACT | ACC_SYNTHETIC` (`0x1401`) flag
/// conjunction. R8's ApiModelOutliner is observed to emit
/// `Build.VERSION.SDK_INT`-routing helpers at per-call-site
/// granularity (one outlined method per SDK branch in the source),
/// with one caller each, in classes where R8 stripped the
/// `$$ExternalSyntheticApiModelOutline` infix at release. Empirical
/// anchor: Phase 1.5 harness-side FN walker observed 3 mapping-
/// confirmed API_MODEL_OUTLINE methods in slot17 (`androidx.compose.
/// ui.text.input.r.L`, `r.O`) + slot18 (`y.s`) with
/// `class_access=0x1401` and `caller_count=1`.
///
/// Admits the 1-caller case at the lowest confidence tier (`20`) and
/// rejoins the main ladder for ≥ 2, identical shape to
/// [`bu_outlined_ladder_confidence`]. The 0-caller case stays
/// rejected: "called by nothing" weakens the outline interpretation
/// since R8's outliner exists to share extracted code.
///
/// The relaxation is structurally gated upstream by
/// `class_is_abstract_synthetic_public` (same bool the
/// `has_static_fields` Phase 3.5 relaxation uses) — non-0x1401
/// outline candidates keep the strict ≥ 2 floor, preserving precision
/// against developer-written single-caller static helpers.
#[must_use]
pub(crate) fn abstract_synthetic_outlined_ladder_confidence(distinct: usize) -> Option<u8> {
    match distinct {
        c if c >= 20 => Some(100),
        c if c >= 5 => Some(70),
        c if c >= 2 => Some(40),
        1 => Some(20),
        _ => None,
    }
}

/// BU-specific confidence ladder. R8's BottomUpOutliner is observed
/// to emit outlines with as few as 1 distinct caller (empirical
/// anchor: slot07 `Platform$$ExternalSyntheticBUOutline0.m`,
/// caller_count=1, mapping confirms outline annotation). Admits the
/// 1-caller case at the lowest confidence tier (`20`) and rejoins the
/// main ladder for ≥ 2.
///
/// The relaxation is descriptor-gated upstream — only classes whose
/// descriptor explicitly contains `BUOutline` (per R8's
/// `SyntheticNaming`) reach this ladder. Non-BU outline kinds keep
/// the strict ≥ 2 floor, preserving precision against developer-
/// written single-caller static helpers that aren't outlines.
#[must_use]
pub(crate) fn bu_outlined_ladder_confidence(distinct: usize) -> Option<u8> {
    match distinct {
        c if c >= 20 => Some(100),
        c if c >= 5 => Some(70),
        c if c >= 2 => Some(40),
        1 => Some(20),
        _ => None,
    }
}

/// I6 predicate: returns `true` iff `code`'s body has straight-line
/// control flow — no branches, switches, loops, monitor-enter/exit,
/// throw, or move-exception opcodes.
///
/// Outline bodies are an arbitrary instruction sequence R8's
/// outliner extracted from caller-side code. The R8 source's
/// extraction-eligibility predicate is narrower than the emitted
/// body (the outliner may add register-shuffle / move-result /
/// const-class setup during emit). For the recogniser, the only
/// reliable structural predicate is "no control flow" — outline
/// bodies are by definition extractable contiguous sequences with
/// a single entry and exit.
///
/// Field access (iget/iput/sget/sput), array access (aget/aput),
/// type casts (check-cast), and arithmetic are all admitted because
/// real outline bodies contain them.
fn body_is_outline_eligible(code: &crate::decode::CodeItem) -> bool {
    for insn in &code.instructions {
        if !opcode_is_outline_eligible(insn.op) {
            return false;
        }
    }
    true
}

/// BU-specific body eligibility: same as [`body_is_outline_eligible`]
/// except `Throw` is admitted. R8 BottomUpOutliner extracts
/// exception-construction-and-throw sequences from many call sites,
/// and the extracted body therefore ends in `Throw`. `MoveException`
/// is NOT admitted: that opcode appears at exception-handler entries,
/// not in outline bodies (an outline is a callee with no try/catch).
fn body_is_outline_eligible_bu(code: &crate::decode::CodeItem) -> bool {
    for insn in &code.instructions {
        if matches!(insn.op, Opcode::Throw) {
            continue;
        }
        if !opcode_is_outline_eligible(insn.op) {
            return false;
        }
    }
    true
}

/// Returns `false` for opcodes that introduce control flow or
/// exception semantics — those cannot appear in an outlined body.
/// Returns `true` for everything else.
fn opcode_is_outline_eligible(op: Opcode) -> bool {
    use Opcode::*;
    if cfg::is_branch(op) {
        return false;
    }
    !matches!(
        op,
        // Exception-class opcodes: outline bodies have a single
        // entry and a single exit (return*); throw/move-exception
        // introduce non-local control flow.
        Throw
            | MoveException
            // Monitor opcodes: synchronization spans an entire
            // method, not a sub-sequence; outliner does not extract.
            | MonitorEnter
            | MonitorExit
            // Switch payloads: would split a single-BB body.
            | PackedSwitch | SparseSwitch
            // Fill-array-data: data payload; treats body as
            // multi-section, not single straight-line.
            | FillArrayData
    )
}


/// EnumValuesCached recogniser — detects methods that READ a cached
/// `MyEnum.values()` static field that R8 introduced.
///
/// # Design
///
/// The Brief specifies the shape as: R8 lifts `MyEnum.values()` into
/// a static field initialised once by the holder class's `<clinit>`
/// (the typical pattern is a `$VALUES` field on the enum class itself
/// or a synthetic `$cached-values`-style field on a holder). Every
/// subsequent use becomes `sget-object <field>` instead of a fresh
/// `invoke-static <Enum>.values()`.
///
/// This recogniser fires on a method that **reads** such a field. It
/// returns `Some(R8Origin)` when ALL of:
///
/// - The current method has a `code_item` resolvable through
///   `census.method_code_off` (cross-DEX / native / abstract methods
///   are conservatively skipped).
/// - The body contains at least one `sget-object` whose pool index
///   resolves to a field of type `[L<EnumType>;` (array of an enum
///   subtype — `EnumType.superclass == Ljava/lang/Enum;`).
/// - The field's declaring class's `<clinit>` writes the field via
///   the canonical `invoke-static <EnumType>.values()` →
///   `move-result-object` → `sput-object <field>` sequence (with no
///   other writers anywhere in the DEX).
/// - Across the whole DEX, the field is read at ≥ 2 `sget-object`
///   sites (repetition gate — a single read is not a "cached" use,
///   it's just a normal field access).
///
/// On a match, [`R8Origin::synthetic_helper`] carries the
/// `MethodIdx` of the original `Enum.values()` call R8 replaced
/// (the recogniser identifies it from the `<clinit>` write
/// pattern); [`R8Origin::source_pc`] carries the bytecode PC of the
/// first `sget-object` read site in the current method;
/// [`R8Origin::caller_count`] carries the DEX-wide read-site count.
///
/// # Why "synthetic_helper" carries the values() method
///
/// The [`Stmt::OutlinedBlock`] IR variant's `synthetic_target` field
/// is named for block-outlining but semantically means "the
/// `MethodIdx` the R8 transformation referenced as its source". For
/// EnumValuesCached, that source IS `MyEnum.values()` — the call R8
/// replaced with a field read. Reusing the field gives emit a
/// uniform doc-comment shape across all R8 variants without
/// introducing a parallel IR variant.
///
/// # Why this is pure-on-dex (no extra census parameter)
///
/// The recogniser does its own per-method walk over the
/// candidate-field's `<clinit>` and over the DEX-wide read sites.
/// Wave 2A.1 introduced [`TrampolineCensus`] specifically because
/// the BlockOutlined gates need DEX-wide repetition counts of
/// `invoke-static` targets — and those counts are inherently a
/// cross-method aggregation that would be O(N×M) recomputed
/// per-method. Here, the recogniser walks the current method's
/// instructions ONCE looking for `sget-object` and then verifies
/// each candidate field locally — bounded by the candidate field's
/// owner's `<clinit>` length, which is small. The signature stays
/// compatible with parallel Wave 2A streams.
fn recognise_enum_values_cache_use(
    dex: &DexFile,
    current_method: MethodIdx,
    census: &TrampolineCensus,
) -> Option<R8Origin> {
    // Defensive gate (see r8_subsection_clean_check).
    r8_subsection_clean_check(dex)?;

    // Look up the current method's code_item. If it has none (native /
    // abstract / cross-DEX), bail — there are no instructions to
    // inspect.
    let code_off = *census.method_code_off.get(&current_method)?;
    let code = dex.code_items.get(&code_off)?;

    // Walk the current method's body looking for the first
    // sget-object whose FieldIdx survives the values-cache
    // verification (try_recognise_values_cache_field). The recogniser
    // surfaces ONE marker per method even if multiple cached fields
    // are read — the first PC-ordered match wins, which keeps
    // [`R8Origin::source_pc`] deterministic.
    for insn in &code.instructions {
        if !matches!(insn.op, Opcode::SgetObject) {
            continue;
        }
        let Some(PoolIndex::Field(field_idx)) = insn.pool_idx else {
            continue;
        };
        if let Some(origin) = try_recognise_values_cache_field(dex, field_idx, insn.addr) {
            return Some(origin);
        }
    }
    None
}

/// Verifies that `field_idx` names an R8 enum-values cache field, and
/// if so returns the populated [`R8Origin`].
///
/// Verification gates:
///
/// 1. Field type is `[L<X>;` (array-of-reference shape).
/// 2. `<X>`'s declaring `class_def`'s superclass descriptor equals
///    `Ljava/lang/Enum;` (the element is an enum subtype).
/// 3. The field's declaring class's `<clinit>` writes the field via
///    `invoke-static <X>.values()` + `move-result-object` +
///    `sput-object <field>` (the canonical R8 cache-init sequence).
/// 4. Across all `code_items` in the DEX, the field has ≥ 2
///    `sget-object` read sites.
///
/// `pc` is the PC of the originating `sget-object` in the caller —
/// passed through as [`R8Origin::source_pc`] for the analyst's audit
/// trail.
fn try_recognise_values_cache_field(
    dex: &DexFile,
    field_idx: FieldIdx,
    pc: u32,
) -> Option<R8Origin> {
    // Field-pool bounds checked via `.get()` on all indices.
    let field_pos = usize::try_from(field_idx.0).ok()?;
    let field = dex.fields.get(field_pos)?;

    // Gate 1: field type is `[L<X>;`.
    let field_type_pos = usize::try_from(field.type_idx.0).ok()?;
    let field_type_desc = dex.type_descriptors.get(field_type_pos)?;
    let element_descriptor = field_type_desc.strip_prefix('[')?;
    if !element_descriptor.starts_with('L') || !element_descriptor.ends_with(';') {
        return None;
    }

    // Gate 2: the element class has `Ljava/lang/Enum;` as its
    // superclass. The recogniser walks `class_defs` looking for a
    // class_def whose `class_idx`'s descriptor equals
    // `element_descriptor` and whose superclass descriptor is
    // `Ljava/lang/Enum;`.
    let element_type_idx = find_type_idx_for_descriptor(dex, element_descriptor)?;
    if !class_def_extends_enum(dex, element_type_idx) {
        return None;
    }

    // Gate 3: field's declaring class's `<clinit>` writes the field
    // via the canonical sequence, AND that's the ONLY writer DEX-wide.
    // The Brief's "static field of enum-array type initialised once in
    // <clinit>" wording is load-bearing — any other writer means the
    // field isn't a true cache.
    let values_method_idx =
        find_clinit_values_writer(dex, field.class_idx, field_idx, element_type_idx)?;
    if has_extra_writers_outside_clinit(dex, field.class_idx, field_idx) {
        return None;
    }

    // Gate 4: ≥ 2 sget-object read sites for this field across the DEX.
    let read_count = count_sget_object_read_sites(dex, field_idx);
    if read_count < 2 {
        return None;
    }

    Some(R8Origin {
        variant: R8Transform::EnumValuesCached,
        confidence: 100,
        source_pc: Some(pc),
        synthetic_helper: Some(values_method_idx),
        caller_count: read_count,
    })
}

/// Returns the `TypeIdx` whose descriptor equals `descriptor`, or
/// `None` if no such type exists. Linear scan over
/// `dex.type_descriptors`; acceptable because this is called only for
/// a candidate field's element type (bounded by the number of distinct
/// enum-values cache candidate fields in the current method, typically
/// 1).
fn find_type_idx_for_descriptor(dex: &DexFile, descriptor: &str) -> Option<TypeIdx> {
    for (i, d) in dex.type_descriptors.iter().enumerate() {
        if d == descriptor {
            return Some(TypeIdx(u32::try_from(i).ok()?));
        }
    }
    None
}

/// Returns `true` iff `class_type_idx`'s `class_def` has
/// `Ljava/lang/Enum;` as its superclass descriptor. Returns `false`
/// if the class_def cannot be resolved (cross-DEX class) — conservative
/// refusal-to-claim.
fn class_def_extends_enum(dex: &DexFile, class_type_idx: TypeIdx) -> bool {
    for cd in &dex.class_defs {
        if cd.class_idx != class_type_idx {
            continue;
        }
        let Some(super_idx) = cd.superclass_idx else {
            return false;
        };
        let Ok(super_pos) = usize::try_from(super_idx.0) else {
            return false;
        };
        let Some(super_desc) = dex.type_descriptors.get(super_pos) else {
            return false;
        };
        return super_desc == "Ljava/lang/Enum;";
    }
    false
}

/// Scans the holder class's `<clinit>` body for the canonical R8
/// cache-init sequence `invoke-static <element_type>.values()` +
/// `move-result-object` + `sput-object <field>`. Returns the
/// `MethodIdx` of the `values()` call on a match, `None` otherwise.
///
/// The match is order-tolerant within the instruction stream — the
/// recogniser scans for an `invoke-static` of `<element_type>.values()`
/// and verifies a subsequent `sput-object` of `field_idx` follows it
/// (with at most one intervening `move-result-object`). R8 typically
/// emits the three instructions contiguously, but tolerance lets the
/// recogniser survive minor reordering (e.g. interleaved const-loads
/// for other fields).
fn find_clinit_values_writer(
    dex: &DexFile,
    holder_class_idx: TypeIdx,
    field_idx: FieldIdx,
    element_type_idx: TypeIdx,
) -> Option<MethodIdx> {
    // Defensive gate (see r8_subsection_clean_check).
    r8_subsection_clean_check(dex)?;

    // Locate the holder's class_data and find `<clinit>`. <clinit> is
    // a direct, static method with name "<clinit>".
    let clinit_method_idx = find_clinit_method_idx(dex, holder_class_idx)?;
    let clinit_pos = usize::try_from(clinit_method_idx.0).ok()?;
    let _clinit_method = dex.methods.get(clinit_pos)?;
    // Resolve `<clinit>`'s code_off via the class_data lookup. The
    // method_code_off census exists for this same lookup but is
    // optional here — scanning the holder's class_data directly keeps
    // the recogniser self-contained.
    let class_data = find_class_data_for_class(dex, holder_class_idx)?;
    let clinit_code_off = class_data
        .direct_methods
        .iter()
        .find(|em| em.method_idx == clinit_method_idx)
        .map(|em| em.code_off)?;
    if clinit_code_off == 0 {
        return None;
    }
    let code = dex.code_items.get(&clinit_code_off)?;
    // Scan for invoke-static <element>.values() ... sput-object field.
    let insns = code.instructions.as_slice();
    let mut pending_values_method: Option<MethodIdx> = None;
    for insn in insns {
        match insn.op {
            Opcode::InvokeStatic | Opcode::InvokeStaticRange => {
                let Some(PoolIndex::Method(m)) = insn.pool_idx else {
                    continue;
                };
                if invoke_is_enum_values_call(dex, m, element_type_idx) {
                    pending_values_method = Some(m);
                }
            }
            Opcode::SputObject => {
                if let (Some(PoolIndex::Field(f)), Some(values_m)) =
                    (insn.pool_idx, pending_values_method)
                {
                    if f == field_idx {
                        return Some(values_m);
                    }
                }
            }
            // Reset pending on intervening method calls that aren't
            // values(); preserves the "values() result feeds the
            // sput-object" invariant.
            _ => {}
        }
    }
    None
}

/// Returns `true` if `method_idx` refers to a `<element_type>.values()`
/// method — i.e. its declaring class is `element_type_idx`, its name
/// is `"values"`, and its prototype has zero parameters returning a
/// `[L<element_type>;` array. Pure-bounds-checked lookup.
fn invoke_is_enum_values_call(
    dex: &DexFile,
    method_idx: MethodIdx,
    element_type_idx: TypeIdx,
) -> bool {
    let Ok(method_pos) = usize::try_from(method_idx.0) else {
        return false;
    };
    let Some(method) = dex.methods.get(method_pos) else {
        return false;
    };
    if method.class_idx != element_type_idx {
        return false;
    }
    let Ok(name_pos) = usize::try_from(method.name_idx.0) else {
        return false;
    };
    let Some(name) = dex.strings.get(name_pos) else {
        return false;
    };
    if name.as_str_lossy() != "values" {
        return false;
    }
    let Ok(proto_pos) = usize::try_from(method.proto_idx.0) else {
        return false;
    };
    let Some(proto) = dex.protos.get(proto_pos) else {
        return false;
    };
    let Ok(ret_pos) = usize::try_from(proto.return_type_idx.0) else {
        return false;
    };
    let Some(ret_desc) = dex.type_descriptors.get(ret_pos) else {
        return false;
    };
    let Ok(elem_pos) = usize::try_from(element_type_idx.0) else {
        return false;
    };
    let Some(elem_desc) = dex.type_descriptors.get(elem_pos) else {
        return false;
    };
    // Return type should be `[<element-descriptor>` (array of the
    // enum subtype). The values() method on java.lang.Enum returns
    // `T[]` where T is the concrete enum subtype.
    let expected_ret = format!("[{elem_desc}");
    ret_desc == &expected_ret
}

/// Returns the `MethodIdx` of the `<clinit>` method on
/// `holder_class_idx`, or `None` if the class has no `<clinit>` or
/// its class_data can't be resolved.
fn find_clinit_method_idx(dex: &DexFile, holder_class_idx: TypeIdx) -> Option<MethodIdx> {
    let class_data = find_class_data_for_class(dex, holder_class_idx)?;
    for em in &class_data.direct_methods {
        // Resolve the method to check its name.
        let method_pos = usize::try_from(em.method_idx.0).ok()?;
        let method = dex.methods.get(method_pos)?;
        let name_pos = usize::try_from(method.name_idx.0).ok()?;
        let name = dex.strings.get(name_pos)?;
        if name.as_str_lossy() == "<clinit>" {
            return Some(em.method_idx);
        }
    }
    None
}

/// Returns the [`crate::decode::ClassData`] for `holder_class_idx`,
/// or `None` if the class has no class_data (e.g. interfaces with no
/// methods) or the class_def is not in this DEX.
fn find_class_data_for_class(
    dex: &DexFile,
    holder_class_idx: TypeIdx,
) -> Option<&crate::decode::ClassData> {
    // Defensive gate (see r8_subsection_clean_check).
    r8_subsection_clean_check(dex)?;

    // Find the class_def_off via the parser's `class_defs` slot.
    let class_def = dex
        .class_defs
        .iter()
        .find(|cd| cd.class_idx == holder_class_idx)?;
    dex.class_datas.get(&class_def.class_data_off)
}

/// Counts the number of `sget-object <field_idx>` read sites across
/// the entire DEX. Linear in total instruction count, but each
/// invocation is bounded — the recogniser only calls this for fields
/// that have already passed the type + clinit-writer gates, which
/// rules out most fields up front.
fn count_sget_object_read_sites(dex: &DexFile, field_idx: FieldIdx) -> usize {
    let mut count = 0usize;
    for code in dex.code_items.values() {
        for insn in &code.instructions {
            if !matches!(insn.op, Opcode::SgetObject) {
                continue;
            }
            if matches!(insn.pool_idx, Some(PoolIndex::Field(f)) if f == field_idx) {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

/// Returns `true` if any `sput-object` writer of `field_idx` exists
/// OUTSIDE the holder class's `<clinit>`. The cache-shape claim
/// requires `<clinit>` to be the sole writer; a second writer
/// disqualifies the field.
fn has_extra_writers_outside_clinit(
    dex: &DexFile,
    holder_class_idx: TypeIdx,
    field_idx: FieldIdx,
) -> bool {
    let Some(clinit_method_idx) = find_clinit_method_idx(dex, holder_class_idx) else {
        return false;
    };
    let Some(class_data) = find_class_data_for_class(dex, holder_class_idx) else {
        return false;
    };
    let clinit_code_off = class_data
        .direct_methods
        .iter()
        .find(|em| em.method_idx == clinit_method_idx)
        .map(|em| em.code_off)
        .unwrap_or(0);
    for (code_off, code) in &dex.code_items {
        if *code_off == clinit_code_off {
            continue;
        }
        for insn in &code.instructions {
            if !matches!(insn.op, Opcode::SputObject) {
                continue;
            }
            if matches!(insn.pool_idx, Some(PoolIndex::Field(f)) if f == field_idx) {
                return true;
            }
        }
    }
    false
}

/// Prepend a `Stmt::OutlinedBlock` marker to the method-body `Seq`.
/// Called after a recogniser returns `Some`; if `stmt` is not a
/// `Stmt::Seq`, this wraps the existing body in one with the marker
/// at the head.
fn prepend_outlined_block_marker(stmt: &mut Stmt, origin: R8Origin) {
    let Some(synthetic_target) = origin.synthetic_helper else {
        return;
    };
    let marker = Stmt::OutlinedBlock {
        synthetic_target,
        origin,
    };
    // If the method body is already a Seq, prepend in place. Otherwise
    // wrap the existing root Stmt in a new Seq with the marker first.
    // This handles short straight-line methods whose root is a single
    // Expr / InlinedReturn / Return — common for outlined helpers.
    match stmt {
        Stmt::Seq(stmts) => {
            stmts.insert(0, marker);
        }
        _ => {
            let owned = std::mem::replace(stmt, Stmt::Break);
            *stmt = Stmt::Seq(vec![marker, owned]);
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests focus on the pure pattern-matchers
    //! ([`extract_trampoline_target`], [`invoke_target_method`],
    //! [`prepend_outlined_block_marker`]) so they don't need a parsed
    //! `DexFile` to stand up. The end-to-end gate — recogniser +
    //! renamed-namespace check + emit-rendered output — is covered by
    //! the [`tests/corpus/clean/r8-9.0-release/block_outlining/`]
    //! fixture pipeline ([`tests/corpus_r8_check.rs`]).

    use super::*;
    use crate::decode::{Instruction, RegList};
    use crate::ids::MethodIdx;
    use crate::ssa::{SsaInsn, VarId};
    use crate::structure::Stmt;

    fn invoke_static_insn(method_idx: u32, addr: u32) -> SsaInsn {
        SsaInsn {
            insn: Instruction {
                addr,
                op: Opcode::InvokeStatic,
                size: 3,
                dst: None,
                src: RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: Some(PoolIndex::Method(MethodIdx(method_idx))),
            },
            dst: Some(VarId::new(1, 0)),
            uses: vec![],
        }
    }

    #[test]
    fn trampoline_census_count_returns_zero_for_unknown_target() {
        let census = TrampolineCensus::default();
        assert_eq!(census.invoke_static_count(MethodIdx(42)), 0);
        assert!(census.callers_of(MethodIdx(42)).is_empty());
    }

    #[test]
    fn distinct_caller_count_returns_zero_for_unknown_target() {
        // Symmetric to `trampoline_census_count_returns_zero_for_unknown_target`:
        // an empty census reports 0 distinct callers for any target.
        let census = TrampolineCensus::default();
        assert_eq!(census.distinct_caller_count(MethodIdx(42)), 0);
    }

    #[test]
    fn distinct_caller_count_dedups_callers() {
        // Attack C shape: one attacker-controlled caller method
        // emits 20 invoke-static instructions to the same helper.
        // `invoke_static_count` reflects all 20 call sites;
        // `distinct_caller_count` collapses them to the single
        // distinct caller. The recogniser's threshold ladder reads
        // the distinct count and must therefore see 1, falling below
        // the floor of 2.
        let mut census = TrampolineCensus::default();
        let target = MethodIdx(100);
        let attacker = MethodIdx(7);
        let sites: Vec<MethodIdx> = std::iter::repeat_n(attacker, 20).collect();
        census.invoke_static_callers.insert(target, sites);
        assert_eq!(census.invoke_static_count(target), 20);
        assert_eq!(census.distinct_caller_count(target), 1);

        // Sanity-check the dedup against a mixed shape: 3 distinct
        // callers with varying repetition counts collapse to 3.
        let mixed_target = MethodIdx(101);
        let mixed = vec![
            MethodIdx(1),
            MethodIdx(1),
            MethodIdx(1),
            MethodIdx(2),
            MethodIdx(2),
            MethodIdx(3),
        ];
        census.invoke_static_callers.insert(mixed_target, mixed);
        assert_eq!(census.invoke_static_count(mixed_target), 6);
        assert_eq!(census.distinct_caller_count(mixed_target), 3);
    }

    #[test]
    fn block_outlined_recogniser_rejects_call_site_inflation() {
        // Attack C end-to-end at the census-level mock: even with 20
        // invoke-static call sites recorded against a candidate
        // helper, the recogniser must refuse to fire when all 20 sites
        // come from one caller. The structural predicates upstream of
        // the ladder are NOT exercised here — they would reject this
        // synthetic input anyway because we never populate
        // `method_class_data_off`, `class_defs`, or `class_datas`.
        // The test pins the ladder semantic: distinct_caller_count
        // returns 1 for the inflated shape, which is below the floor
        // of 2, so the recogniser short-circuits before it would
        // declare a confidence-100 / 70 / 40 BlockOutlinedHelper.
        let mut census = TrampolineCensus::default();
        let helper = MethodIdx(100);
        let attacker = MethodIdx(7);
        let sites: Vec<MethodIdx> = std::iter::repeat_n(attacker, 20).collect();
        census.invoke_static_callers.insert(helper, sites);
        // The structural-gate refusal alone gives `None`, but the
        // load-bearing assertion is that the LADDER would refuse on
        // distinct_caller_count == 1 even if structural gates passed.
        // Call through the production ladder helper rather than
        // mirroring the match — if a future edit drops the floor
        // (e.g. `>= 1` admission) this test catches it without
        // requiring a parallel update.
        let distinct = census.distinct_caller_count(helper);
        assert_eq!(distinct, 1, "20 sites from 1 caller → 1 distinct");
        assert!(
            block_outlined_ladder_confidence(distinct).is_none(),
            "ladder must reject single-caller inflation; got {:?}",
            block_outlined_ladder_confidence(distinct),
        );

        // And confirm the end-to-end recogniser call also returns None
        // on this census (the structural gates short-circuit first,
        // but the call-site verification is what we care about).
        let dex = make_minimal_dexfile();
        assert!(recognise_outline_helper_v2(&dex, helper, &census).is_none());
    }

    #[test]
    fn abstract_synthetic_public_flag_mask_admits_class_with_static_fields() {
        // Pin the exact bitmask the static-fields relaxation uses. R8
        // ApiModelOutliner emits helpers into classes with these three
        // flags simultaneously when the class hosts SDK-version
        // constants the helpers reference. Empirical anchor: Phase
        // 2.5 paired-corpus sweep observed every API_MODEL_OUTLINE
        // FN whose containing class had static fields carried this
        // exact flag combination (`0x1401`).
        //
        // Regression that drops one of the three flag bits — or that
        // shifts the mask to a different combination — surfaces here
        // without depending on the end-to-end recogniser path.
        const ACC_PUBLIC: u32 = 0x0001;
        const ACC_ABSTRACT: u32 = 0x0400;
        const ACC_SYNTHETIC: u32 = 0x1000;
        let target_mask = ACC_PUBLIC | ACC_ABSTRACT | ACC_SYNTHETIC;
        assert_eq!(target_mask, 0x1401, "mask drift would un-fix Phase 3.5 cases");

        // Missing ACC_SYNTHETIC → no trigger (developer-source abstract
        // class with statics must continue to be rejected as a
        // non-outline-helper).
        assert_ne!(
            (ACC_PUBLIC | ACC_ABSTRACT) & target_mask,
            target_mask,
        );
        // Missing ACC_ABSTRACT → no trigger (basic Outliner / BU /
        // other R8-synthetic kinds whose helper class isn't abstract
        // stay on the strict static-fields gate; their precision
        // floor is preserved by the conjunction).
        assert_ne!(
            (ACC_PUBLIC | ACC_SYNTHETIC) & target_mask,
            target_mask,
        );
        // Missing ACC_PUBLIC → no trigger.
        assert_ne!(
            (ACC_ABSTRACT | ACC_SYNTHETIC) & target_mask,
            target_mask,
        );
        // Real-world observed flag value from the FN walker emit:
        // `class_access=0x1401` on 46/46 has_static_fields rejections.
        assert_eq!(0x1401u32 & target_mask, target_mask);
        // ACC_INTERFACE (0x0200) does NOT change the trigger when
        // the three required bits are all set. Interfaces with
        // ACC_PUBLIC + ACC_ABSTRACT + ACC_SYNTHETIC are not the
        // observed shape, but the predicate is conjunctive so an
        // additional bit doesn't break it.
        assert_eq!(0x1601u32 & target_mask, target_mask);
    }

    #[test]
    fn static_fields_gate_admits_iff_static_fields_empty_or_class_is_0x1401() {
        // Pin the gate EXPRESSION's truth-table (not just the bitmask
        // constants). The production gate at recognise_outline_helper_v2
        // line ~982 reads:
        //
        //   if !class_data.static_fields.is_empty()
        //      && !class_is_abstract_synthetic_public {
        //       return None;
        //   }
        //
        // Equivalently: admit IFF (static_fields_empty) OR (0x1401-class).
        //
        // A regression that swaps `&&` for `||`, drops the negation, or
        // shifts which operand is the bitmask check surfaces here
        // without depending on full DexFile construction. Mirrors the
        // boolean-logic shape rather than the bitmask constant
        // (which `abstract_synthetic_public_flag_mask_admits_…` covers).
        let admits = |flags: u32, static_empty: bool| {
            static_empty || (flags & 0x1401) == 0x1401
        };
        // static_fields empty → always admit, regardless of flags.
        assert!(admits(0x0000, true));
        assert!(admits(0x1401, true));
        // static_fields present + non-0x1401 flags → reject (strict path).
        assert!(!admits(0x0000, false));
        assert!(!admits(0x1000, false), "ACC_SYNTHETIC alone insufficient");
        assert!(!admits(0x0001, false), "ACC_PUBLIC alone insufficient");
        assert!(
            !admits(0x0400 | 0x0001, false),
            "ACC_ABSTRACT+PUBLIC without SYNTHETIC stays rejected"
        );
        // static_fields present + 0x1401 → admit (Phase 3.5 relaxation).
        assert!(admits(0x1401, false));
        assert!(
            admits(0x1401 | 0x0020, false),
            "0x1401 conjunction still fires with extra bits set"
        );
    }

    #[test]
    fn body_eligibility_bu_admits_throw_strict_rejects_it() {
        // Pins the only structural difference between the two body
        // predicates: BU admits Throw (BottomUpOutliner extracts
        // exception-throw sequences); strict rejects Throw to keep
        // precision on developer-written synthetic throw helpers.
        let body = code_item_of(vec![
            Instruction {
                addr: 0,
                op: Opcode::NewInstance,
                size: 2,
                dst: Some(0),
                src: crate::decode::RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: None,
            },
            Instruction {
                addr: 2,
                op: Opcode::InvokeDirect,
                size: 3,
                dst: None,
                src: crate::decode::RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: None,
            },
            Instruction {
                addr: 5,
                op: Opcode::Throw,
                size: 1,
                dst: None,
                src: crate::decode::RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: None,
            },
        ]);
        assert!(body_is_outline_eligible_bu(&body));
        assert!(!body_is_outline_eligible(&body));
    }

    #[test]
    fn body_eligibility_bu_still_rejects_monitor_and_branches() {
        // BU relaxation is Throw-only — `MonitorEnter` is still out
        // (synchronization spans a whole method, not a fragment) and
        // branches still split the body.
        let with_monitor = code_item_of(vec![Instruction {
            addr: 0,
            op: Opcode::MonitorEnter,
            size: 1,
            dst: None,
            src: crate::decode::RegList::empty(),
            literal: 0,
            target: None,
            pool_idx: None,
        }]);
        assert!(!body_is_outline_eligible_bu(&with_monitor));
    }

    #[test]
    fn block_outlined_ladder_confidence_tiers() {
        // Pin the ladder constants explicitly so a regression that
        // shifts a threshold lands a unit-test failure here without
        // depending on the end-to-end recogniser path.
        assert_eq!(block_outlined_ladder_confidence(0), None);
        assert_eq!(block_outlined_ladder_confidence(1), None);
        assert_eq!(block_outlined_ladder_confidence(2), Some(40));
        assert_eq!(block_outlined_ladder_confidence(4), Some(40));
        assert_eq!(block_outlined_ladder_confidence(5), Some(70));
        assert_eq!(block_outlined_ladder_confidence(19), Some(70));
        assert_eq!(block_outlined_ladder_confidence(20), Some(100));
        assert_eq!(block_outlined_ladder_confidence(1_000), Some(100));
    }

    #[test]
    fn bu_outlined_ladder_admits_one_caller_at_lowest_tier() {
        // BU ladder differs from the basic ladder only at distinct == 1
        // — that case yields Some(20) instead of None. The upper tiers
        // match exactly. A regression that drops the 1-caller arm
        // surfaces here.
        assert_eq!(bu_outlined_ladder_confidence(0), None);
        assert_eq!(bu_outlined_ladder_confidence(1), Some(20));
        assert_eq!(bu_outlined_ladder_confidence(2), Some(40));
        assert_eq!(bu_outlined_ladder_confidence(5), Some(70));
        assert_eq!(bu_outlined_ladder_confidence(20), Some(100));
    }

    #[test]
    fn abstract_synthetic_outlined_ladder_admits_one_caller_at_lowest_tier() {
        // 0x1401-gated ladder mirrors BU's relaxed shape: admits 1
        // distinct caller at the lowest confidence tier (Some(20)),
        // rejoins the main ladder at >= 2. The 0-caller case stays
        // rejected — admitting 0 risks precision-floor breach on
        // zero-caller developer-written static helpers that happen to
        // carry the ACC_PUBLIC|ACC_ABSTRACT|ACC_SYNTHETIC flag combo.
        assert_eq!(abstract_synthetic_outlined_ladder_confidence(0), None);
        assert_eq!(abstract_synthetic_outlined_ladder_confidence(1), Some(20));
        assert_eq!(abstract_synthetic_outlined_ladder_confidence(2), Some(40));
        assert_eq!(abstract_synthetic_outlined_ladder_confidence(5), Some(70));
        assert_eq!(abstract_synthetic_outlined_ladder_confidence(20), Some(100));
    }

    #[test]
    fn abstract_synthetic_outlined_ladder_shape_matches_bu_ladder() {
        // The two relaxed ladders are currently identical in shape.
        // Pin this so a future per-trigger divergence (e.g. tightening
        // the 0x1401 ladder's 1-caller arm without touching BU) is an
        // explicit, single-site change rather than a silent skew.
        for n in [0usize, 1, 2, 4, 5, 19, 20, 1_000] {
            assert_eq!(
                abstract_synthetic_outlined_ladder_confidence(n),
                bu_outlined_ladder_confidence(n),
                "0x1401 and BU ladders drifted at distinct={n}",
            );
        }
    }

    #[test]
    fn caller_ladder_dispatch_picks_relaxed_for_0x1401_class() {
        // Pin the dispatch EXPRESSION at recognise_outline_helper_v2's
        // caller-ladder selection site:
        //
        //   let confidence = if is_bu_outline {
        //       bu_outlined_ladder_confidence(caller_count)?
        //   } else if class_is_abstract_synthetic_public {
        //       abstract_synthetic_outlined_ladder_confidence(caller_count)?
        //   } else {
        //       block_outlined_ladder_confidence(caller_count)?
        //   };
        //
        // Three-way dispatch shape — a regression that re-orders the
        // arms (BU and 0x1401 are mutually exclusive in practice but
        // the if/else-if ordering is load-bearing for precision under
        // a hypothetical class flagged both ways), or that swaps which
        // ladder a branch calls, surfaces here.
        let select = |is_bu: bool, is_0x1401: bool, caller_count: usize| -> Option<u8> {
            if is_bu {
                bu_outlined_ladder_confidence(caller_count)
            } else if is_0x1401 {
                abstract_synthetic_outlined_ladder_confidence(caller_count)
            } else {
                block_outlined_ladder_confidence(caller_count)
            }
        };
        // Neither flag → basic ladder (rejects 1-caller).
        assert_eq!(select(false, false, 1), None);
        assert_eq!(select(false, false, 2), Some(40));
        // 0x1401 flag → relaxed ladder (admits 1-caller).
        assert_eq!(select(false, true, 1), Some(20));
        assert_eq!(select(false, true, 0), None);
        // BU flag → BU ladder (admits 1-caller).
        assert_eq!(select(true, false, 1), Some(20));
        // BU + 0x1401 → BU wins (BU is the first arm; arm order
        // codifies that BU's descriptor-name evidence is stronger
        // than the structural-flag-only signal).
        assert_eq!(select(true, true, 1), Some(20));
    }

    fn code_item_of(insns: Vec<Instruction>) -> crate::decode::CodeItem {
        crate::decode::CodeItem {
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            debug_info_off: 0,
            instructions: insns,
            tries: vec![],
            catch_handlers: vec![],
            payloads: std::collections::BTreeMap::new(),
            invariant_violations: vec![],
        }
    }
    fn make_minimal_dexfile() -> crate::parser::DexFile {
        use crate::header::DexHeader;
        let mut magic = [0u8; 8];
        magic[..4].copy_from_slice(b"dex\n");
        magic[4..7].copy_from_slice(b"035");
        crate::parser::DexFile {
            string_data_offs: Vec::new(),
            header: DexHeader {
                magic,
                checksum: 0,
                signature: [0u8; 20],
                file_size: 0,
                header_size: 112,
                endian_tag: 0x1234_5678,
                link_size: 0,
                link_off: 0,
                map_off: 0,
                string_ids_size: 0,
                string_ids_off: 0,
                type_ids_size: 0,
                type_ids_off: 0,
                proto_ids_size: 0,
                proto_ids_off: 0,
                field_ids_size: 0,
                field_ids_off: 0,
                method_ids_size: 0,
                method_ids_off: 0,
                class_defs_size: 0,
                class_defs_off: 0,
                data_size: 0,
                data_off: 0,
            },
            strings: Vec::new(),
            type_descriptors: Vec::new(),
            protos: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            class_defs: Vec::new(),
            annotations: std::collections::BTreeMap::new(),
            type_lists: std::collections::BTreeMap::new(),
            class_datas: std::collections::BTreeMap::new(),
            raw_class_data_bytes: std::collections::BTreeMap::new(),
            code_items: std::collections::BTreeMap::new(),
            annotation_sets: std::collections::BTreeMap::new(),
            annotation_set_ref_lists: std::collections::BTreeMap::new(),
            annotation_items: std::collections::BTreeMap::new(),
            annotation_item_widths: std::collections::BTreeMap::new(),
            encoded_arrays: std::collections::BTreeMap::new(),
            encoded_array_widths: std::collections::BTreeMap::new(),
            method_handles: Vec::new(),
            call_site_ids: Vec::new(),
            map_entries: Vec::new(),
            debug_infos: std::collections::BTreeMap::new(),
            debug_info_raw_bytes: std::collections::BTreeMap::new(),
            debug_info_section_layout: Vec::new(),
            annotation_set_section_layout: Vec::new(),
            input_checksums_canonical: true,
            parse_errors: Vec::new(),
            class_def_index: Vec::new(),
        }
    }


    #[test]
    fn method_inlined_recogniser_returns_none_on_empty_seq() {
        // The MethodInlined recogniser is a documented stub: it never
        // returns Some, because no in-DEX signal survives R8 method
        // inlining. This test pins that contract — if a future commit
        // wires up a real recogniser it MUST also delete or rewrite
        // this test (and amend the variant doc-comment); the test is
        // the gauge that prevents an unannounced behaviour change.
        let dex = make_minimal_dexfile();
        let census = TrampolineCensus::default();
        let stmt = Stmt::Seq(vec![]);
        assert!(recognise_method_inlined(&stmt, &dex, MethodIdx(0), &census).is_none());
    }

    #[test]
    fn method_inlined_recogniser_returns_none_on_blockoutlined_shape() {
        // The trampoline-shaped Stmt (a known-good R8 shape) ALSO
        // returns None from the MethodInlined recogniser. This is the
        // load-bearing claim: the stub does NOT fire on shapes that
        // belong to other recognisers. If a future heuristic version
        // accidentally pattern-matches trampoline-shaped Stmts as
        // "inlined", this test catches it.
        let dex = make_minimal_dexfile();
        let census = TrampolineCensus::default();
        let stmt = Stmt::Seq(vec![Stmt::InlinedReturn(invoke_static_insn(3, 0x42))]);
        assert!(recognise_method_inlined(&stmt, &dex, MethodIdx(0), &census).is_none());
    }

    #[test]
    fn method_inlined_recogniser_returns_none_on_richer_body() {
        // A method body with multiple statements (the post-inlining
        // shape the fixture's `expected-after-inversion.java` describes:
        // const-load + arithmetic + conditional branches). The stub
        // returns None — confirming the recogniser does NOT speculate
        // about "expanded-looking" bodies.
        let dex = make_minimal_dexfile();
        let census = TrampolineCensus::default();
        let stmt = Stmt::Seq(vec![
            Stmt::Expr(invoke_static_insn(3, 0x10)),
            Stmt::Expr(invoke_static_insn(4, 0x12)),
            Stmt::Expr(invoke_static_insn(5, 0x14)),
            Stmt::Return(None),
        ]);
        assert!(recognise_method_inlined(&stmt, &dex, MethodIdx(0), &census).is_none());
    }

    #[test]
    fn method_inlined_variant_is_distinct_from_blockoutlined_helper() {
        // Compile-time + structural check that the variant join is
        // safe: MethodInlined sits alongside the BlockOutlined
        // recogniser as a distinct enum tag. Downstream consumers
        // (e.g. emit's variant_name match) can dispatch on the
        // variant alone.
        let helper = R8Transform::StructurallyOutlineLike;
        let inlined = R8Transform::MethodInlined;
        assert_ne!(inlined, helper);
    }

    #[test]
    fn method_inlined_origin_is_constructible_for_oracle_path() {
        // Loading R8 mapping file evidence (out of scope) could construct
        // a MethodInlined R8Origin from
        // external evidence. This test pins that the type admits the
        // construction — `synthetic_helper: None` and the
        // `confidence: 80` shape called for by the fixture's
        // signature.toml. The construction itself proves the
        // architecture admits the annotation-only variant; the
        // recogniser body remaining a stub (above tests) proves we
        // don't fabricate that evidence from bytecode alone.
        let origin = R8Origin {
            variant: R8Transform::MethodInlined,
            confidence: 80,
            source_pc: Some(0x42),
            synthetic_helper: None,
            caller_count: 0,
        };
        assert!(matches!(origin.variant, R8Transform::MethodInlined));
        assert_eq!(origin.confidence, 80);
        assert!(origin.synthetic_helper.is_none());
        assert!(origin.source_pc.is_some());
    }

    #[test]
    fn prepend_marker_inserts_at_front_and_preserves_tail() {
        let origin = R8Origin {
            variant: R8Transform::StructurallyOutlineLike,
            confidence: 100,
            source_pc: Some(0x10),
            synthetic_helper: Some(MethodIdx(5)),
            caller_count: 3,
        };
        let mut stmt = Stmt::Seq(vec![Stmt::InlinedReturn(invoke_static_insn(5, 0x10))]);
        prepend_outlined_block_marker(&mut stmt, origin);
        let Stmt::Seq(seq) = &stmt else {
            panic!("apply() should preserve top-level Seq shape");
        };
        assert_eq!(seq.len(), 2);
        match &seq[0] {
            Stmt::OutlinedBlock {
                synthetic_target,
                origin,
            } => {
                assert_eq!(*synthetic_target, MethodIdx(5));
                assert!(matches!(
                    origin.variant,
                    R8Transform::StructurallyOutlineLike
                ));
                assert_eq!(origin.confidence, 100);
                assert_eq!(origin.caller_count, 3);
            }
            other => panic!("expected OutlinedBlock marker, got {other:?}"),
        }
        assert!(matches!(seq[1], Stmt::InlinedReturn(_)));
    }

    // ── EnumValuesCached recogniser tests ──────────────────────────
    //
    // These tests hand-build a minimal DexFile with the shape:
    //   Type 0: Ljava/lang/Object;
    //   Type 1: Ljava/lang/Enum;
    //   Type 2: LSimple$Color;         (the enum subtype)
    //   Type 3: [LSimple$Color;        (enum-array element type)
    //   Type 4: LSimple;               (holder class)
    //
    //   Field 0: LSimple;->$VALUES_CACHE:[LSimple$Color;
    //
    //   Method 0: LSimple$Color;->values()[LSimple$Color;   (the source values() call)
    //   Method 1: LSimple;-><clinit>()V                     (writes the cache)
    //   Method 2: LSimple;->countRed()I                     (reads the cache)
    //   Method 3: LSimple;->countGreen()I                   (also reads the cache, for the
    //                                                        repetition gate)
    //
    // The harness builders below populate just enough of the DexFile
    // pools to make the recogniser's lookups succeed; emitter / SSA
    // / structurer paths are NOT exercised here — the unit gate is
    // the recogniser's per-method match logic alone.

    use crate::dex_string::DexString;
    use crate::ids::{
        ClassDefItem, FieldIdItem, FieldIdx, MethodIdItem, ProtoIdItem, StringIdx, TypeIdx,
    };
    use crate::ids::ProtoIdx;

    fn s(d: &str) -> DexString {
        DexString::from_decoded_str(d)
    }

    /// Build the values-cache fixture DEX. Returns the DexFile plus
    /// the MethodIdx of `countRed` (one of the cache-reading methods).
    /// The DEX is "valid enough" for the recogniser — its bytecode
    /// pools resolve, but its header sections are zeroed and parser-
    /// or emit-side validators would reject it.
    fn values_cache_dex() -> (crate::parser::DexFile, MethodIdx) {
        let mut dex = make_minimal_dexfile();

        // Strings.
        dex.strings = vec![
            s("Ljava/lang/Object;"),      // 0
            s("Ljava/lang/Enum;"),        // 1
            s("LSimple$Color;"),          // 2
            s("[LSimple$Color;"),         // 3
            s("LSimple;"),                // 4
            s("values"),                  // 5: Color.values() method name
            s("<clinit>"),                // 6: Simple.<clinit> method name
            s("countRed"),                // 7: Simple.countRed method name
            s("countGreen"),              // 8: Simple.countGreen method name
            s("$VALUES_CACHE"),           // 9: cached-values field name
            s("V"),                       // 10: void return shorty/descriptor
            s("I"),                       // 11: int return descriptor
        ];

        // Type descriptors mirror strings 0..=4 by index.
        dex.type_descriptors = vec![
            String::from("Ljava/lang/Object;"),
            String::from("Ljava/lang/Enum;"),
            String::from("LSimple$Color;"),
            String::from("[LSimple$Color;"),
            String::from("LSimple;"),
            // Extra type descriptors needed for prototypes.
            String::from("V"),
            String::from("I"),
        ];
        // Convenient TypeIdx constants.
        let _ty_object = TypeIdx(0);
        let _ty_enum = TypeIdx(1);
        let ty_color = TypeIdx(2);
        let _ty_color_array = TypeIdx(3);
        let ty_simple = TypeIdx(4);
        let ty_void = TypeIdx(5);
        let ty_int = TypeIdx(6);

        // Protos:
        //  0: ()[LSimple$Color;    (values())
        //  1: ()V                  (<clinit>)
        //  2: ()I                  (countRed / countGreen)
        dex.protos = vec![
            ProtoIdItem {
                shorty_idx: StringIdx(3), // shorty unused by recogniser
                return_type_idx: TypeIdx(3),
                parameters_off: 0,
            },
            ProtoIdItem {
                shorty_idx: StringIdx(10),
                return_type_idx: ty_void,
                parameters_off: 0,
            },
            ProtoIdItem {
                shorty_idx: StringIdx(11),
                return_type_idx: ty_int,
                parameters_off: 0,
            },
        ];

        // Fields:
        //  0: LSimple;->$VALUES_CACHE:[LSimple$Color;
        dex.fields = vec![FieldIdItem {
            class_idx: ty_simple,
            type_idx: TypeIdx(3),
            name_idx: StringIdx(9),
        }];

        // Methods.
        // 0: LSimple$Color;->values()[LSimple$Color;
        // 1: LSimple;-><clinit>()V
        // 2: LSimple;->countRed()I
        // 3: LSimple;->countGreen()I
        dex.methods = vec![
            MethodIdItem {
                class_idx: ty_color,
                proto_idx: ProtoIdx(0),
                name_idx: StringIdx(5),
            },
            MethodIdItem {
                class_idx: ty_simple,
                proto_idx: ProtoIdx(1),
                name_idx: StringIdx(6),
            },
            MethodIdItem {
                class_idx: ty_simple,
                proto_idx: ProtoIdx(2),
                name_idx: StringIdx(7),
            },
            MethodIdItem {
                class_idx: ty_simple,
                proto_idx: ProtoIdx(2),
                name_idx: StringIdx(8),
            },
        ];

        // Class defs:
        //  - LSimple$Color; extends Ljava/lang/Enum;
        //  - LSimple;       extends Ljava/lang/Object;
        dex.class_defs = vec![
            ClassDefItem {
                class_idx: ty_color,
                access_flags: 0,
                superclass_idx: Some(TypeIdx(1)),
                interfaces_off: 0,
                source_file_idx: None,
                annotations_off: 0,
                class_data_off: 0,
                static_values_off: 0,
            },
            ClassDefItem {
                class_idx: ty_simple,
                access_flags: 0,
                superclass_idx: Some(TypeIdx(0)),
                interfaces_off: 0,
                source_file_idx: None,
                annotations_off: 0,
                class_data_off: 0x1000, // arbitrary distinct value
                static_values_off: 0,
            },
        ];

        // class_data for LSimple; — holds <clinit> + countRed +
        // countGreen as direct methods. The recogniser scans
        // direct_methods looking for the "<clinit>" entry by name.
        dex.class_datas.insert(
            0x1000,
            crate::decode::ClassData {
                static_fields: Vec::new(),
                instance_fields: Vec::new(),
                direct_methods: vec![
                    crate::decode::EncodedMethod {
                        method_idx: MethodIdx(1), // <clinit>
                        access_flags: 0x0008,     // ACC_STATIC
                        code_off: 0x2000,
                    },
                    crate::decode::EncodedMethod {
                        method_idx: MethodIdx(2), // countRed
                        access_flags: 0x0009,     // ACC_PUBLIC | ACC_STATIC
                        code_off: 0x2100,
                    },
                    crate::decode::EncodedMethod {
                        method_idx: MethodIdx(3), // countGreen
                        access_flags: 0x0009,
                        code_off: 0x2200,
                    },
                ],
                virtual_methods: Vec::new(),
            },
        );

        // <clinit> body: invoke-static Color.values() ; move-result-object ; sput-object $VALUES_CACHE.
        dex.code_items.insert(
            0x2000,
            code_item_of(vec![
                crate::decode::Instruction {
                    addr: 0,
                    op: Opcode::InvokeStatic,
                    size: 3,
                    dst: None,
                    src: crate::decode::RegList::empty(),
                    literal: 0,
                    target: None,
                    pool_idx: Some(PoolIndex::Method(MethodIdx(0))),
                },
                crate::decode::Instruction {
                    addr: 3,
                    op: Opcode::MoveResultObject,
                    size: 1,
                    dst: Some(0),
                    src: crate::decode::RegList::empty(),
                    literal: 0,
                    target: None,
                    pool_idx: None,
                },
                crate::decode::Instruction {
                    addr: 4,
                    op: Opcode::SputObject,
                    size: 2,
                    dst: None,
                    src: crate::decode::RegList::empty(),
                    literal: 0,
                    target: None,
                    pool_idx: Some(PoolIndex::Field(FieldIdx(0))),
                },
                crate::decode::Instruction {
                    addr: 6,
                    op: Opcode::ReturnVoid,
                    size: 1,
                    dst: None,
                    src: crate::decode::RegList::empty(),
                    literal: 0,
                    target: None,
                    pool_idx: None,
                },
            ]),
        );

        // countRed body: sget-object $VALUES_CACHE ; return.
        dex.code_items.insert(
            0x2100,
            code_item_of(vec![
                crate::decode::Instruction {
                    addr: 0x20,
                    op: Opcode::SgetObject,
                    size: 2,
                    dst: Some(0),
                    src: crate::decode::RegList::empty(),
                    literal: 0,
                    target: None,
                    pool_idx: Some(PoolIndex::Field(FieldIdx(0))),
                },
                crate::decode::Instruction {
                    addr: 0x22,
                    op: Opcode::Return,
                    size: 1,
                    dst: Some(0),
                    src: crate::decode::RegList::empty(),
                    literal: 0,
                    target: None,
                    pool_idx: None,
                },
            ]),
        );

        // countGreen body: sget-object $VALUES_CACHE ; return.
        dex.code_items.insert(
            0x2200,
            code_item_of(vec![
                crate::decode::Instruction {
                    addr: 0x30,
                    op: Opcode::SgetObject,
                    size: 2,
                    dst: Some(0),
                    src: crate::decode::RegList::empty(),
                    literal: 0,
                    target: None,
                    pool_idx: Some(PoolIndex::Field(FieldIdx(0))),
                },
                crate::decode::Instruction {
                    addr: 0x32,
                    op: Opcode::Return,
                    size: 1,
                    dst: Some(0),
                    src: crate::decode::RegList::empty(),
                    literal: 0,
                    target: None,
                    pool_idx: None,
                },
            ]),
        );

        (dex, MethodIdx(2))
    }

    /// Build the census for the values-cache fixture: maps method
    /// indices 1..=3 to their code offsets so the recogniser's
    /// `census.method_code_off` lookup resolves.
    fn values_cache_census() -> TrampolineCensus {
        let mut c = TrampolineCensus::default();
        c.method_code_off.insert(MethodIdx(1), 0x2000);
        c.method_code_off.insert(MethodIdx(2), 0x2100);
        c.method_code_off.insert(MethodIdx(3), 0x2200);
        c
    }

    #[test]
    fn enum_values_cache_recogniser_fires_on_canonical_shape() {
        let (dex, count_red) = values_cache_dex();
        let census = values_cache_census();
        let origin = recognise_enum_values_cache_use(&dex, count_red, &census)
            .expect("canonical values-cache shape should match");
        assert!(matches!(origin.variant, R8Transform::EnumValuesCached));
        assert_eq!(origin.confidence, 100);
        // synthetic_helper points at the original Color.values() method
        // (MethodIdx(0) in our fixture).
        assert_eq!(origin.synthetic_helper, Some(MethodIdx(0)));
        // source_pc is the PC of the sget-object in countRed (0x20).
        assert_eq!(origin.source_pc, Some(0x20));
        // caller_count is the cross-DEX read-site count: countRed +
        // countGreen = 2.
        assert_eq!(origin.caller_count, 2);
    }

    #[test]
    fn enum_values_cache_recogniser_rejects_when_no_clinit_writer() {
        // Drop the <clinit> code_item — without the canonical writer
        // sequence, the field is not a cache.
        let (mut dex, count_red) = values_cache_dex();
        dex.code_items.remove(&0x2000);
        let census = values_cache_census();
        assert!(
            recognise_enum_values_cache_use(&dex, count_red, &census).is_none(),
            "missing <clinit> writer → no cache claim"
        );
    }

    // ── DeadBranchStripped stub tests ───────────────────────────────
    //
    // Wave 2A.4 ships the recogniser as a structural stub: the
    // variant is published, the apply-dispatcher wires the call,
    // and the recogniser body unconditionally returns `None`. These
    // tests pin the stub contract so it can't silently drift into
    // firing on arbitrary input, and so a future implementer
    // landing an empirical signal touches them explicitly when the
    // stub becomes live.

    #[test]
    fn dead_branch_stripped_variant_is_distinct_from_block_outlined() {
        // Variant identity is the contract surface — downstream
        // consumers dispatch on this rather than on R8Origin fields.
        let dbs = R8Origin {
            variant: R8Transform::DeadBranchStripped,
            confidence: 60,
            source_pc: None,
            synthetic_helper: None,
            caller_count: 0,
        };
        assert_ne!(dbs.variant, R8Transform::StructurallyOutlineLike);
        assert_ne!(
            dbs.variant,
            R8Transform::BlockOutlinedHelper {
                mapping_confirmed: true
            }
        );
        assert_ne!(dbs.variant, R8Transform::MethodInlined);
    }

    #[test]
    fn recognise_dead_branch_stripped_returns_none_on_empty_body() {
        // Stub contract: the recogniser MUST return None until an
        // empirical production-corpus signal is identified. Empty
        // body is the trivial input.
        let dex = make_minimal_dexfile();
        let census = TrampolineCensus::default();
        let stmt = Stmt::Seq(vec![]);
        let got = recognise_dead_branch_stripped(&stmt, &dex, MethodIdx(0), &census);
        assert!(
            got.is_none(),
            "stub must not fire — empirical signal not yet identified"
        );
    }

    #[test]
    fn enum_values_cache_recogniser_rejects_when_element_not_enum() {
        // Mutate Color's superclass to Object — then the array-element
        // gate `class_def_extends_enum` returns false.
        let (mut dex, count_red) = values_cache_dex();
        for cd in &mut dex.class_defs {
            if cd.class_idx == TypeIdx(2) {
                cd.superclass_idx = Some(TypeIdx(0)); // Object instead of Enum
            }
        }
        let census = values_cache_census();
        assert!(
            recognise_enum_values_cache_use(&dex, count_red, &census).is_none(),
            "non-enum element type → no cache claim"
        );
    }

    #[test]
    fn recognise_dead_branch_stripped_returns_none_on_trampoline_shape() {
        // Sanity: the stub doesn't accidentally fire on a body
        // that the BlockOutlined recogniser CAN fire on. If a future
        // implementer wires DeadBranchStripped detection that
        // overlaps with BlockOutlined the apply()-dispatcher's
        // priority order matters — pinning the stub here makes the
        // overlap explicit at refactor time.
        let dex = make_minimal_dexfile();
        let census = TrampolineCensus::default();
        let stmt = Stmt::Seq(vec![Stmt::InlinedReturn(invoke_static_insn(7, 0x10))]);
        let got = recognise_dead_branch_stripped(&stmt, &dex, MethodIdx(0), &census);
        assert!(got.is_none());
    }

    #[test]
    fn recognise_dead_branch_stripped_returns_none_on_arithmetic_return() {
        // Shape from the dce_unreachable_branch fixture after R8 9.0
        // fully strips: just `return x * 2;`. Empirical reality —
        // there's no surviving cue, so no recogniser can fire.
        // Pins the honesty claim in the variant docstring.
        let arith = SsaInsn {
            insn: Instruction {
                addr: 0,
                op: Opcode::MulIntLit8,
                size: 2,
                dst: Some(0),
                src: RegList::empty(),
                literal: 2,
                target: None,
                pool_idx: None,
            },
            dst: Some(VarId::new(0, 1)),
            uses: vec![],
        };
        let dex = make_minimal_dexfile();
        let census = TrampolineCensus::default();
        let stmt = Stmt::Seq(vec![Stmt::Expr(arith), Stmt::Return(Some(VarId::new(0, 1)))]);
        let got = recognise_dead_branch_stripped(&stmt, &dex, MethodIdx(0), &census);
        assert!(
            got.is_none(),
            "fully-stripped R8 output leaves no cue — the stub must not invent one"
        );
    }

    #[test]
    fn enum_values_cache_recogniser_rejects_below_repetition_gate() {
        // Drop countGreen's code_item — now only countRed reads the
        // field (1 site, below the ≥ 2 threshold).
        let (mut dex, count_red) = values_cache_dex();
        dex.code_items.remove(&0x2200);
        let census = values_cache_census();
        assert!(
            recognise_enum_values_cache_use(&dex, count_red, &census).is_none(),
            "<2 read sites → no cache claim (repetition gate)"
        );
    }

    #[test]
    fn enum_values_cache_recogniser_rejects_when_field_has_extra_writer() {
        // Add a stray sput-object of the cached field OUTSIDE
        // <clinit>. The "only writer is <clinit>" gate disqualifies
        // the field.
        let (mut dex, count_red) = values_cache_dex();
        // Add an extra method that writes the field outside <clinit>.
        dex.code_items.insert(
            0x3000,
            code_item_of(vec![
                crate::decode::Instruction {
                    addr: 0,
                    op: Opcode::SputObject,
                    size: 2,
                    dst: None,
                    src: crate::decode::RegList::empty(),
                    literal: 0,
                    target: None,
                    pool_idx: Some(PoolIndex::Field(FieldIdx(0))),
                },
                crate::decode::Instruction {
                    addr: 2,
                    op: Opcode::ReturnVoid,
                    size: 1,
                    dst: None,
                    src: crate::decode::RegList::empty(),
                    literal: 0,
                    target: None,
                    pool_idx: None,
                },
            ]),
        );
        let census = values_cache_census();
        assert!(
            recognise_enum_values_cache_use(&dex, count_red, &census).is_none(),
            "extra writer outside <clinit> → no cache claim"
        );
    }

    #[test]
    fn enum_values_cache_recogniser_skips_method_with_no_code() {
        let (dex, _) = values_cache_dex();
        let census = values_cache_census();
        // MethodIdx(99) isn't in census.method_code_off → recogniser
        // bails immediately. No panic, no false positive.
        assert!(recognise_enum_values_cache_use(&dex, MethodIdx(99), &census).is_none());
    }

    #[test]
    fn enum_values_cache_marker_emits_with_correct_variant() {
        // End-to-end: run apply() and verify the prepended marker
        // carries R8Transform::EnumValuesCached.
        let (dex, count_red) = values_cache_dex();
        let census = values_cache_census();
        // Synthesize a minimal Stmt body — a single Return suffices;
        // the recogniser ignores stmt content (it works off the
        // bytecode-level code_item).
        let mut stmt = Stmt::Seq(vec![Stmt::Return(None)]);
        let env = TypeEnv {
            types: Default::default(),
            casts: Vec::new(),
        };
        let changed = apply(&mut stmt, &dex, &env, TypeIdx(4), count_red, &census);
        assert!(changed, "recogniser should mark the cache-reading method");
        let Stmt::Seq(seq) = &stmt else {
            panic!("expected Stmt::Seq, got {stmt:?}");
        };
        assert!(seq.len() >= 2);
        match &seq[0] {
            Stmt::OutlinedBlock {
                synthetic_target,
                origin,
            } => {
                assert!(matches!(origin.variant, R8Transform::EnumValuesCached));
                assert_eq!(*synthetic_target, MethodIdx(0));
                assert_eq!(origin.confidence, 100);
                assert_eq!(origin.caller_count, 2);
            }
            other => panic!("expected OutlinedBlock marker, got {other:?}"),
        }
    }

    #[test]
    fn apply_does_not_emit_dead_branch_stripped_marker() {
        // End-to-end stub gate: apply() must NOT prepend a
        // DeadBranchStripped marker on any input today. If a
        // change to apply() ever wires a non-stub recogniser, this
        // test fails and forces the implementer to update the gate
        // intentionally.
        use crate::types::TypeEnv;
        let dex = make_minimal_dexfile();
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: Vec::new(),
        };
        let census = TrampolineCensus::default();
        // Trivial input that no BlockOutlined arm matches either
        // (no Seq, no invoke-static, no renamed-namespace target).
        let mut stmt = Stmt::Return(None);
        let _ = apply(
            &mut stmt,
            &dex,
            &env,
            TypeIdx(0),
            MethodIdx(0),
            &census,
        );
        // The stub never emits any marker — the body stays the
        // input shape.
        assert!(matches!(stmt, Stmt::Return(None)));
    }

    #[test]
    fn r8_subsection_clean_check_passes_on_clean_dex() {
        let dex = make_minimal_dexfile();
        assert_eq!(
            super::r8_subsection_clean_check(&dex),
            Some(()),
            "clean dex (no parse_errors) must pass the R8 subsection gate"
        );
    }

    #[test]
    fn r8_subsection_clean_check_bails_on_planted_class_data_failure() {
        // Audit BLOCK-3 regression: attacker plants
        // ParseFailureKind::ClassData. Every R8 recognizer that walks
        // class_datas / code_items must bail to None rather than
        // silently treating the affected offsets as "no R8 origin."
        let mut dex = make_minimal_dexfile();
        dex.parse_errors.push(crate::parser::ParseFailure {
            kind: crate::parser::ParseFailureKind::ClassData,
            offset: 0x1000,
        });
        assert_eq!(
            super::r8_subsection_clean_check(&dex),
            None,
            "planted ClassData ParseFailure must short-circuit the R8 subsection gate to None"
        );
    }

    #[test]
    fn r8_subsection_clean_check_bails_on_planted_code_item_failure() {
        let mut dex = make_minimal_dexfile();
        dex.parse_errors.push(crate::parser::ParseFailure {
            kind: crate::parser::ParseFailureKind::CodeItem,
            offset: 0x2000,
        });
        assert_eq!(
            super::r8_subsection_clean_check(&dex),
            None,
            "planted CodeItem ParseFailure must short-circuit the R8 subsection gate to None"
        );
    }

    #[test]
    fn r8_subsection_clean_check_admits_unrelated_parse_failure_kinds() {
        // Sanity: parse failures in subsections the R8 recognizers do
        // NOT consult (e.g., AnnotationItem) must NOT trip the R8 gate.
        // Only ClassData and CodeItem failures matter for R8 inversion;
        // overly-coarse gating would false-bail on legitimate fixtures
        // with unrelated annotation taint.
        let mut dex = make_minimal_dexfile();
        dex.parse_errors.push(crate::parser::ParseFailure {
            kind: crate::parser::ParseFailureKind::AnnotationItem,
            offset: 0x3000,
        });
        assert_eq!(
            super::r8_subsection_clean_check(&dex),
            Some(()),
            "AnnotationItem failure must NOT trip the R8 subsection gate (only ClassData + CodeItem do)"
        );
    }

    // ── Lens 4 PoC closure: class_data_off collision evasion ────────────
    //
    // Attacker plants two class_def_item rows with DIFFERENT class_idx
    // but SAME class_data_off. Pre-fix, `.find()` returns the first row
    // — if that's the non-ACC_SYNTHETIC decoy, the gate at
    // `(class_def.access_flags & 0x1000) == 0` returns None and R8
    // outline detection is silently suppressed. Post-fix,
    // `resolve_outline_class_def_canonical` prefers the ACC_SYNTHETIC-
    // bearing canonical row.

    fn class_def_with(class_idx: TypeIdx, access_flags: u32, class_data_off: u32) -> ClassDefItem {
        ClassDefItem {
            class_idx,
            access_flags,
            superclass_idx: None,
            interfaces_off: 0,
            source_file_idx: None,
            annotations_off: 0,
            class_data_off,
            static_values_off: 0,
        }
    }

    #[test]
    fn resolve_outline_class_def_canonical_prefers_acc_synthetic_on_collision() {
        // Lens 4 PoC byte shape:
        //   item[0]: class_idx=T2 (decoy), access_flags=0x0001 (no ACC_SYNTHETIC), class_data_off=0xABCD
        //   item[1]: class_idx=T1 (legit R8 outline), access_flags=0x1001 (ACC_SYNTHETIC), class_data_off=0xABCD
        // Pre-fix: `.find()` returns item[0] → gate at (access_flags & 0x1000) == 0 → None.
        // Post-fix: resolver prefers item[1] (ACC_SYNTHETIC) → gate passes.
        let mut dex = make_minimal_dexfile();
        dex.class_defs = vec![
            class_def_with(TypeIdx(2), 0x0001, 0xABCD),  // decoy, no ACC_SYNTHETIC
            class_def_with(TypeIdx(1), 0x1001, 0xABCD),  // canonical R8 outline
        ];
        let resolved = super::resolve_outline_class_def_canonical(&dex, 0xABCD)
            .expect("resolver finds at least one match");
        assert_eq!(
            resolved.class_idx, TypeIdx(1),
            "resolver must prefer ACC_SYNTHETIC-bearing row; got class_idx={}",
            resolved.class_idx.0
        );
        assert_ne!(
            resolved.access_flags & 0x1000, 0,
            "resolved row must carry ACC_SYNTHETIC for the downstream gate to pass"
        );
    }

    #[test]
    fn resolve_outline_class_def_canonical_falls_back_to_first_when_no_acc_synthetic() {
        // Degenerate: no rows have ACC_SYNTHETIC. Resolver falls back to
        // first match (matches pre-fix behavior for non-attacker bundles).
        // Downstream gate will return None — but the resolver itself
        // returns Some, so the call site can apply its gate uniformly.
        let mut dex = make_minimal_dexfile();
        dex.class_defs = vec![
            class_def_with(TypeIdx(2), 0x0001, 0xABCD),
            class_def_with(TypeIdx(1), 0x0001, 0xABCD),
        ];
        let resolved = super::resolve_outline_class_def_canonical(&dex, 0xABCD)
            .expect("resolver finds match even without ACC_SYNTHETIC");
        assert_eq!(
            resolved.class_idx, TypeIdx(2),
            "first-match fallback when no row has ACC_SYNTHETIC"
        );
    }

    #[test]
    fn resolve_outline_class_def_canonical_returns_none_on_no_match() {
        let mut dex = make_minimal_dexfile();
        dex.class_defs = vec![
            class_def_with(TypeIdx(1), 0x1001, 0x1000),
        ];
        assert!(
            super::resolve_outline_class_def_canonical(&dex, 0xABCD).is_none(),
            "no class_def matches the given class_data_off → None"
        );
    }

    #[test]
    fn resolve_outline_class_def_canonical_unique_row_returned_unchanged() {
        // Non-attacker case: single row at the offset; resolver returns it
        // regardless of ACC_SYNTHETIC. Matches pre-fix behavior — this is
        // the production happy path.
        let mut dex = make_minimal_dexfile();
        dex.class_defs = vec![
            class_def_with(TypeIdx(1), 0x1001, 0xABCD),
        ];
        let resolved = super::resolve_outline_class_def_canonical(&dex, 0xABCD)
            .expect("single matching row");
        assert_eq!(resolved.class_idx, TypeIdx(1));
    }

    /// For `dex`, assert the census canonical-class_def map resolves
    /// IDENTICALLY to the linear `resolve_outline_class_def_canonical`
    /// oracle for every distinct `class_data_off` present in
    /// `dex.class_defs` (plus a known-absent offset → both `None`).
    /// Identity is compared by `(class_idx, access_flags)` of the
    /// resolved row, which pins the ACC_SYNTHETIC-preferring choice and
    /// the first-fallback choice including the collision case.
    fn assert_census_matches_oracle(dex: &crate::parser::DexFile) {
        let census = build_trampoline_census(dex);
        let mut offs: Vec<u32> = dex.class_defs.iter().map(|cd| cd.class_data_off).collect();
        offs.push(0xDEAD_BEEF); // known-absent: both sides must be None
        offs.sort_unstable();
        offs.dedup();
        for off in offs {
            let oracle = super::resolve_outline_class_def_canonical(dex, off);
            let via_census = census
                .canonical_class_def_idx(off)
                .and_then(|i| dex.class_defs.get(i));
            match (oracle, via_census) {
                (None, None) => {}
                (Some(o), Some(c)) => {
                    assert_eq!(
                        (o.class_idx, o.access_flags),
                        (c.class_idx, c.access_flags),
                        "census diverges from linear oracle at class_data_off={off:#x}"
                    );
                    assert!(
                        std::ptr::eq(o, c),
                        "census must resolve to the SAME class_def row as the oracle \
                         at class_data_off={off:#x}"
                    );
                }
                (o, c) => panic!(
                    "census/oracle disagree on presence at class_data_off={off:#x}: \
                     oracle={:?}, census={:?}",
                    o.map(|cd| cd.class_idx),
                    c.map(|cd| cd.class_idx),
                ),
            }
        }
    }

    #[test]
    fn census_canonical_resolution_equals_linear_oracle_all_scenarios() {
        // Equivalence safety net: the memoized census map MUST resolve
        // identically to the linear `resolve_outline_class_def_canonical`
        // for every class_data_off across the collision scenarios the
        // oracle's own unit tests build (prefer-synthetic on collision,
        // first-fallback when no row is synthetic, single unique row),
        // plus a mixed multi-offset DEX. This pins the security-sensitive
        // ACC_SYNTHETIC-preferring decision through the new path.

        // Scenario 1: collision, decoy-first then ACC_SYNTHETIC canonical.
        let mut dex = make_minimal_dexfile();
        dex.class_defs = vec![
            class_def_with(TypeIdx(2), 0x0001, 0xABCD), // decoy, no ACC_SYNTHETIC
            class_def_with(TypeIdx(1), 0x1001, 0xABCD), // canonical R8 outline
        ];
        assert_census_matches_oracle(&dex);

        // Scenario 1b: ACC_SYNTHETIC row FIRST, decoy second — canonical
        // is still the synthetic (and the first one); pins "first
        // synthetic wins" rather than "last".
        let mut dex = make_minimal_dexfile();
        dex.class_defs = vec![
            class_def_with(TypeIdx(1), 0x1001, 0xABCD), // canonical R8 outline (first)
            class_def_with(TypeIdx(2), 0x0001, 0xABCD), // decoy after
        ];
        assert_census_matches_oracle(&dex);

        // Scenario 1c: two ACC_SYNTHETIC rows at the same offset — the
        // FIRST synthetic wins (oracle's `.find()` short-circuits).
        let mut dex = make_minimal_dexfile();
        dex.class_defs = vec![
            class_def_with(TypeIdx(2), 0x0001, 0xABCD), // non-synthetic first
            class_def_with(TypeIdx(3), 0x1001, 0xABCD), // first synthetic — canonical
            class_def_with(TypeIdx(4), 0x1001, 0xABCD), // second synthetic — NOT chosen
        ];
        assert_census_matches_oracle(&dex);

        // Scenario 2: collision, NO row has ACC_SYNTHETIC → first-match
        // fallback (the resolved row's gate downstream returns None, but
        // the resolver/map must still agree on WHICH row).
        let mut dex = make_minimal_dexfile();
        dex.class_defs = vec![
            class_def_with(TypeIdx(2), 0x0001, 0xABCD),
            class_def_with(TypeIdx(1), 0x0001, 0xABCD),
        ];
        assert_census_matches_oracle(&dex);

        // Scenario 3: single unique row (production happy path).
        let mut dex = make_minimal_dexfile();
        dex.class_defs = vec![class_def_with(TypeIdx(1), 0x1001, 0xABCD)];
        assert_census_matches_oracle(&dex);

        // Scenario 4: mixed DEX — multiple distinct offsets, one with a
        // collision, one unique, plus class_data_off == 0 (not special-
        // cased) so the map equals the oracle for the zero offset too.
        let mut dex = make_minimal_dexfile();
        dex.class_defs = vec![
            class_def_with(TypeIdx(0), 0x0001, 0),      // off 0, non-synthetic first
            class_def_with(TypeIdx(5), 0x1001, 0),      // off 0, synthetic — canonical for 0
            class_def_with(TypeIdx(2), 0x0001, 0x1000), // off 0x1000 collision decoy
            class_def_with(TypeIdx(1), 0x1001, 0x1000), // off 0x1000 collision canonical
            class_def_with(TypeIdx(6), 0x0009, 0x2000), // off 0x2000 unique, non-synthetic
        ];
        assert_census_matches_oracle(&dex);
    }

    #[test]
    fn outline_helper_v2_fires_through_census_on_collision_dex() {
        // End-to-end collision-defense preservation: a DEX with a
        // class_data_off collision where the decoy (non-ACC_SYNTHETIC)
        // row is FIRST and the canonical ACC_SYNTHETIC outline row is
        // second. The recogniser resolves the containing class via the
        // census lookup; the canonical row must be the synthetic one so
        // the (access_flags & 0x1000) gate passes and the recogniser
        // fires. If the census picked the decoy, the gate would return
        // None and the marker decision would silently flip — the
        // evasion. A two-instruction body keeps the single-bare-return
        // floor satisfied so firing is attributable to the resolution.
        let (mut dex, helper, _census) = abstract_synthetic_helper_dex(vec![
            Instruction {
                addr: 0,
                op: Opcode::SgetObject,
                size: 2,
                dst: Some(0),
                src: RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: None,
            },
            Instruction {
                addr: 2,
                op: Opcode::ReturnObject,
                size: 1,
                dst: Some(0),
                src: RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: None,
            },
        ]);
        // The builder put one ACC_SYNTHETIC class_def at class_data_off
        // 0x5000. Plant a non-synthetic decoy at the SAME offset BEFORE
        // it so a naive `.find()` / first-match would pick the decoy.
        let canonical = dex.class_defs.remove(0);
        let decoy_class_idx = TypeIdx(99);
        dex.class_defs = vec![
            class_def_with(decoy_class_idx, 0x0001, canonical.class_data_off),
            canonical,
        ];
        // Rebuild the census from the now-collision-bearing class_defs so
        // its canonical map reflects the planted decoy + canonical.
        let mut census = build_trampoline_census(&dex);
        census
            .method_class_data_off
            .insert(helper, dex.class_defs[1].class_data_off);
        census.method_code_off.insert(helper, 0x6000);
        census
            .invoke_static_callers
            .insert(helper, vec![MethodIdx(10), MethodIdx(11)]);

        // Sanity: the census canonical for this offset is the synthetic
        // (second) row, not the decoy.
        let canon_idx = census
            .canonical_class_def_idx(dex.class_defs[1].class_data_off)
            .expect("census resolves the collision offset");
        assert_eq!(
            canon_idx, 1,
            "census must pick the ACC_SYNTHETIC canonical (index 1), not the decoy (index 0)"
        );

        let origin = recognise_outline_helper_v2(&dex, helper, &census).expect(
            "recogniser must still fire on the collision DEX — the census canonical \
             resolution preserves the ACC_SYNTHETIC defense",
        );
        assert!(matches!(origin.variant, R8Transform::StructurallyOutlineLike));
        assert_eq!(origin.confidence, 40);
        assert_eq!(origin.caller_count, 2);
    }

    // ── Single-bare-return horizontal-merge-bridge suppression ──────
    //
    // R8's horizontal class merger emits synthetic static stubs whose
    // entire body is one bare Return-family opcode (e.g. the empty
    // `public static return-void` bridges packed into a
    // `0x1401 = ACC_PUBLIC|ACC_ABSTRACT|ACC_SYNTHETIC` class). These
    // satisfy every structural outline predicate AND the
    // abstract-synthetic caller-ladder relaxation, so without a floor
    // they fire as StructurallyOutlineLike at confidence 40 with two
    // distinct callers. A bare return extracts no bytecode, so it is
    // structurally impossible to be an extracted outline; the floor
    // rejects it. The positive-control twin proves the floor is
    // recall-neutral: a multi-instruction body in the same class /
    // caller configuration still fires.

    /// Build a `0x1401` (ACC_PUBLIC|ACC_ABSTRACT|ACC_SYNTHETIC) class
    /// with a single `public static` helper method whose body is the
    /// supplied instruction sequence, wired with two distinct
    /// invoke-static callers. Returns the `DexFile`, the helper's
    /// `MethodIdx`, and a census whose `method_class_data_off` /
    /// `method_code_off` / `invoke_static_callers` resolve for the
    /// recogniser. The helper takes one parameter (arity 1, in range,
    /// non-zero so the non-BU arity gate admits it).
    fn abstract_synthetic_helper_dex(
        body: Vec<crate::decode::Instruction>,
    ) -> (crate::parser::DexFile, MethodIdx, TrampolineCensus) {
        let mut dex = make_minimal_dexfile();

        // Strings: class descriptor, method name, one shorty, the
        // param + return type descriptors.
        dex.strings = vec![
            s("Lh/synth;"),  // 0: synthetic merge-bridge class
            s("m"),          // 1: helper method name
            s("LI"),         // 2: shorty (unused by recogniser)
            s("I"),          // 3: param/return type descriptor
        ];
        dex.type_descriptors = vec![
            String::from("Lh/synth;"), // TypeIdx(0): the helper's class
            String::from("I"),         // TypeIdx(1): param/return type
        ];

        // One type-list holding a single param type, keyed at a
        // non-zero offset so `proto.parameters_off != 0` resolves to
        // param_count == 1.
        let params_off = 0x4000u32;
        dex.type_lists.insert(params_off, vec![TypeIdx(1)]);

        // Proto: (I)I — one param, arity 1.
        dex.protos = vec![ProtoIdItem {
            shorty_idx: StringIdx(2),
            return_type_idx: TypeIdx(1),
            parameters_off: params_off,
        }];

        // One method: Lh/synth;->m(I)I
        dex.methods = vec![MethodIdItem {
            class_idx: TypeIdx(0),
            proto_idx: ProtoIdx(0),
            name_idx: StringIdx(1),
        }];

        // Class def: 0x1401 = ACC_PUBLIC|ACC_ABSTRACT|ACC_SYNTHETIC.
        let class_data_off = 0x5000u32;
        dex.class_defs = vec![ClassDefItem {
            class_idx: TypeIdx(0),
            access_flags: 0x1401,
            superclass_idx: Some(TypeIdx(0)),
            interfaces_off: 0,
            source_file_idx: None,
            annotations_off: 0,
            class_data_off,
            static_values_off: 0,
        }];

        // class_data: the single static helper, no fields, no virtual
        // methods.
        let code_off = 0x6000u32;
        dex.class_datas.insert(
            class_data_off,
            crate::decode::ClassData {
                static_fields: Vec::new(),
                instance_fields: Vec::new(),
                direct_methods: vec![crate::decode::EncodedMethod {
                    method_idx: MethodIdx(0),
                    access_flags: 0x0009, // ACC_PUBLIC | ACC_STATIC
                    code_off,
                }],
                virtual_methods: Vec::new(),
            },
        );
        dex.code_items.insert(code_off, code_item_of(body));

        // Census: back-pointers + two distinct callers so the
        // abstract-synthetic ladder admits at confidence 40. Build the
        // canonical class_def map from `dex.class_defs` exactly as
        // production does so the recogniser's census lookup resolves.
        let mut census = build_trampoline_census(&dex);
        census.method_class_data_off.insert(MethodIdx(0), class_data_off);
        census.method_code_off.insert(MethodIdx(0), code_off);
        census
            .invoke_static_callers
            .insert(MethodIdx(0), vec![MethodIdx(10), MethodIdx(11)]);

        (dex, MethodIdx(0), census)
    }

    #[test]
    fn outline_helper_v2_rejects_single_bare_return_void_bridge() {
        // FP-suppression: a single `return-void` body in a 0x1401
        // class with two distinct callers WOULD fire at confidence 40
        // without the floor. The floor rejects it as a horizontal-
        // merge empty bridge.
        let (dex, helper, census) = abstract_synthetic_helper_dex(vec![Instruction {
            addr: 0,
            op: Opcode::ReturnVoid,
            size: 1,
            dst: None,
            src: RegList::empty(),
            literal: 0,
            target: None,
            pool_idx: None,
        }]);
        assert!(
            recognise_outline_helper_v2(&dex, helper, &census).is_none(),
            "single bare return-void in a 0x1401 synthetic class is a horizontal-merge \
             empty bridge, not an outline — the recogniser must decline"
        );
    }

    #[test]
    fn outline_helper_v2_rejects_each_single_bare_return_family_opcode() {
        // The floor covers every Return-family opcode, not just
        // return-void: return / return-wide / return-object bridges
        // are equally bytecode-free.
        for op in [Opcode::Return, Opcode::ReturnWide, Opcode::ReturnObject] {
            let (dex, helper, census) = abstract_synthetic_helper_dex(vec![Instruction {
                addr: 0,
                op,
                size: 1,
                dst: Some(0),
                src: RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: None,
            }]);
            assert!(
                recognise_outline_helper_v2(&dex, helper, &census).is_none(),
                "single bare {op:?} must be rejected as a merge bridge"
            );
        }
    }

    #[test]
    fn outline_helper_v2_still_fires_on_multi_insn_body() {
        // Positive control (no recall loss): the SAME 0x1401 class +
        // two-distinct-caller configuration, but a two-instruction
        // body (sget-object ; return-object). This is NOT a bare
        // return — `insn_count == 1` is false — so the floor does not
        // apply and the recogniser fires at confidence 40, proving the
        // floor suppresses ONLY the single-bare-return shape.
        let (dex, helper, census) = abstract_synthetic_helper_dex(vec![
            Instruction {
                addr: 0,
                op: Opcode::SgetObject,
                size: 2,
                dst: Some(0),
                src: RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: None,
            },
            Instruction {
                addr: 2,
                op: Opcode::ReturnObject,
                size: 1,
                dst: Some(0),
                src: RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: None,
            },
        ]);
        let origin = recognise_outline_helper_v2(&dex, helper, &census)
            .expect("multi-instruction outline body must still fire");
        assert!(matches!(
            origin.variant,
            R8Transform::StructurallyOutlineLike
        ));
        assert_eq!(
            origin.confidence, 40,
            "two distinct callers on the abstract-synthetic ladder → confidence 40"
        );
        assert_eq!(origin.caller_count, 2);
    }
}
