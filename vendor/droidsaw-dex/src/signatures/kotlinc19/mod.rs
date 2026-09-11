//! kotlinc 1.9 lowering recognizers.
//!
//! Each submodule holds one [`Signature`](droidsaw_common::signature::Signature)
//! impl matching one canonical lowering produced by `kotlinc-1.9.22`.
//! Submodules are added per-PR as the `dex-signatures-kotlinc-recognizers`
//! stream lands constructs.
//!
//! Currently:
//!
//! - [`when_sealed_object`] — Kotlin `when (x) { Sub1 -> ...; Sub2 -> ... }`
//!   over a sealed root whose subtypes are Kotlin `object` singletons.
//!   kotlinc-1.9.22 lowers this to a linear
//!   `Intrinsics.areEqual(<v>, <Sub>.INSTANCE)` if-chain ending in
//!   `throw NoWhenBranchMatchedException`. Lifts to
//!   [`Stmt::MultiArm`](crate::structure::Stmt::MultiArm) with
//!   [`ArmPattern::SealedObjectIs`](crate::structure::ArmPattern::SealedObjectIs)
//!   arms. Highest-priority kotlinc recognizer (the MYB.A00 advisory-probe
//!   shape).
//! - [`when_sealed_class`] — Kotlin `when (x) { is Sub1 -> ...; is Sub2 -> ... }`
//!   over a sealed root whose subtypes are non-`object` subclasses.
//!   Mirror of `when_sealed_object` but matches the simpler `instance-of`
//!   primitive (single dex op writing directly to a register, no
//!   `MoveResult` triplet) — 2-stmt arm-test stride instead of 4. Lifts
//!   to [`Stmt::MultiArm`](crate::structure::Stmt::MultiArm) with
//!   [`ArmPattern::SealedTypeIs`](crate::structure::ArmPattern::SealedTypeIs)
//!   arms (emit renders as `is X.Sub ->`, distinct from sealed-OBJECT's
//!   bare `X.Sub ->`).
//! - [`when_int`] — Kotlin `when (i: Int) { 1 -> ...; 2 -> ... }` over
//!   the dense (`tableswitch`) and sparse (`lookupswitch`) int-switch
//!   lowerings. Mirrors `javac21::switch_int` exactly except for the
//!   dialect tag and the dialect-aware metadata gate: `when_int` fires
//!   only when the enclosing class carries `@kotlin.Metadata`;
//!   `switch_int` carries the inverse negative gate. Together they
//!   partition `Stmt::Switch` matches by enclosing-class dialect,
//!   avoiding engine-level ambiguity that would otherwise surface as
//!   `Stmt::Unrecognized`.
//! - [`when_string`] — Kotlin `when (s: String) { "x" -> ...; "y" -> ... }`
//!   covering all THREE kotlinc-1.9 sub-strategies via internal shape
//!   dispatch: ≤2-arm linear `Intrinsics.areEqual` chain (shape-shared
//!   with sealed-OBJECT but `ConstString` in slot 0 instead of
//!   `SgetObject`); ≥5-arm `String.hashCode() + tableswitch` (dense);
//!   sparse `String.hashCode() + lookupswitch`. Sub-strategy A matches
//!   the areEqual chain directly. Sub-strategy B/C delegates to
//!   `sugar::try_collapse_adjacent_switches` (shared with
//!   `javac21::switch_string`) and re-tags as Kotlin dialect. Sibling
//!   `javac21::switch_string` carries the inverse negative metadata gate
//!   (added in this PR), partitioning hashCode+switch matches by
//!   enclosing-class dialect.
//! - [`data_class_destructure`] — Kotlin `val (a, b) = source` data-class
//!   destructure. Matches consecutive `componentN()` `InvokeVirtual` +
//!   `MoveResult` pairs on the same receiver with monotone N from 1.
//!   Lifts to the [`Stmt::Let`](crate::structure::Stmt::Let) IR variant
//!   (added in this PR) carrying the bindings + source + provenance for
//!   PR-8 emit's source-level destructure rendering.
//! - [`coroutine_suspend`] — Kotlin `suspend fun` state-machine recognizer.
//!   Detects the load-bearing const-string literal `"call to 'resume'
//!   before 'invoke' with coroutine"` that kotlinc emits in the
//!   `default` arm of the wrapper-method's label-tableswitch. Returns
//!   the new
//!   [`RecognizedDexShape::TaggedRegion`](crate::signatures::RecognizedDexShape::TaggedRegion)
//!   variant; the engine driver wraps the region in
//!   `Stmt::Unrecognized` with `closest = Some(105), distance = 0`
//!   (the exact-tag sentinel). Emit dispatches on the tag to render a
//!   banner + unfolded form (no full lift to `suspend fun` source
//!   syntax).
//!
//! `SignatureId` allocations within the kotlinc range `100..=199` (per
//! `javac21::switch_string` doc-comment): see the `*_SIGNATURE_ID`
//! constant in each submodule.

pub mod coroutine_suspend;
pub mod data_class_destructure;
pub mod when_int;
pub mod when_sealed_class;
pub mod when_sealed_object;
pub mod when_string;
