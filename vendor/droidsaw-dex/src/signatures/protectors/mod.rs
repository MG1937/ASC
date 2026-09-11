//! Adversarial-toolchain signatures.
//!
//! Recognizers for shapes produced by code obfuscators / protectors:
//! DexGuard (synthetic — deferred when a real sample is in scope),
//! ProGuard (name mangling baseline), and custom stalkerware patterns
//! observed in the field.
//!
//! ## SignatureId namespace `200..=299`
//!
//! Per `signatures::mod.rs` allocation discipline (javac21 = 1..=99,
//! kotlinc-1.9 = 100..=199), protectors take 200..=299. Current
//! allocations:
//!
//! | Id | Module | What it recognizes | SignatureProvenance |
//! |----|--------|---------------------|------------|
//! | 200 | [`fragmented_string_literal`] | `StringConcat` with all-`Literal` parts that compile-time-concat-evaded an IOC literal | Cerberus `com.surebrec.U2.U1:2982` (3 sites: support emails + OTA URL) |
//! | 201 | (PR-3 of #45) `reflective_invoke_stub` | `Class.forName + Class.getMethod + Method.invoke` chain on hidden Android binder stubs (NearMiss; def-use binding pending) | Cerberus `com.surebrec.SuCommands.main` (8 binder stubs from RE doc line 654) |
//! | 202 | (PR-4 of #45) `fcm_command_dispatch` | `RemoteMessage.getData().get("command")` → 41-verb `StringSwitch` | Cerberus FCM command table (RE doc line 239–274) |
//! | 203 | (PR-5 of #45) `proguard_baseline_no_op` | Mangled-name baseline — confirms recognizers do NOT fire on plain mangled-name code | ProGuard-stripped APKs across the `corpus/apks/` set |
//!
//! ## Discipline (per #45 Brief Directives 3 + 6)
//!
//! - **False positives are worse than false negatives.** A wrong-confidence
//!   claim ("this looks like clean Java, here's the source") on a
//!   protector-emitted region misleads the analyst. Recognizers here MUST
//!   prefer `MatchOutcome::NearMiss` over `MatchOutcome::Recognized` when
//!   the shape is ambiguous; raise gates rather than relax them.
//!
//! - **SignatureProvenance is non-negotiable.** Every recognizer carries a
//!   doc-comment naming the observed-in APK (SHA-256 + class.method),
//!   plus a corpus fixture under `tests/corpus/protectors/<family>/`.
//!   Regressions in matching behavior are caught by the per-APK ratchet
//!   in `tests/unrecognized_ratchet.rs`.
//!
//! - **Fail closed on ambiguity.** Engine's existing
//!   [`SignatureResult::Ambiguous`](droidsaw_common::signature::SignatureResult)
//!   handling deterministically picks lowest id; do NOT add a "best-of"
//!   override that silently re-classifies.

pub mod fragmented_string_literal;
pub mod reflective_invoke_stub;
