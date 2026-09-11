//! Reflective-invoke-stub recognizer.
//!
//! Recognizes the pattern of reflection-mediated access to hidden
//! Android binder stubs:
//!
//! ```ignore
//! Class<?> stub = Class.forName("android.content.pm.IPackageManager$Stub");
//! Method m = stub.getMethod("grantRuntimePermission", argTypes);
//! Object result = m.invoke(target, args);
//! ```
//!
//! The recognizer fires (as [`MatchOutcome::NearMiss`]) when:
//! - The candidate `Stmt::Expr(insn)` is an `invoke-virtual` /
//!   `invoke-virtual/range` whose method reference is
//!   `Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;`.
//! - **AND** an upstream `const-string` (within the same `Stmt::Seq`
//!   slice, scanning backward from `position`) carries a class-name
//!   string in the [`KNOWN_BINDER_STUBS`] allowlist.
//!
//! Both gates are mandatory. The reflective invoke path alone is plain
//! Java reflection (legal, common, lots of false positives); the
//! upstream binder-stub literal pins the *adversarial* shape — code
//! that reflects into hidden Android system services the manifest
//! never declares it uses.
//!
//! ## Why NearMiss, not Recognized
//!
//! The two gates are **shape-only**: there is no SSA def-use binding
//! verifying that the binder-stub literal actually feeds
//! `Class.forName` whose result feeds `getMethod` whose result is the
//! receiver of the matched `Method.invoke`. Counter-example: a method
//! body containing one legitimate
//! `Class.forName("android.content.pm.IPackageManager$Stub")` (vendor
//! sample, framework probe) plus any unrelated `Method.invoke` within
//! the 32-stmt window would mis-fire as `Recognized` if we promoted
//! the shape match to high confidence.
//!
//! Per the recognizer-discipline rule "emit `NearMiss` not `Recognized`
//! when in doubt", the recognizer returns [`MatchOutcome::NearMiss`]
//! with `distance: 1`. Promotion to
//! `Recognized` requires backfilling SSA def-use binding (literal →
//! `Class.forName` → `getMethod` → `Method.invoke`); that work is
//! tracked as a follow-up. The shape match still surfaces in
//! `UNRECOGNIZED_REGION` findings via `closest = #201`, giving the
//! analyst an accurate "candidate, unverified" signal.
//!
//! ## SignatureProvenance
//!
//! Observed at `com.surebrec.SuCommands.main` in the Cerberus
//! stalkerware Play Store APK (v1.4.9; SHA-256
//! `b43e7b16841e2058017a75fb2a211fe2dc2e7f442d244e47d16559ad801ce7a1`).
//! The SuCommands code reflects on exactly the
//! 8 binder stubs in [`KNOWN_BINDER_STUBS`] to silently grant 17
//! `dangerous`-protection-level permissions, programmatically whitelist
//! itself from background-data restrictions, and disable status bar /
//! lock screen / notification system APIs the manifest never declares.
//! The HiddenApiBypass dependency lifts the client-side hidden-API
//! block; reflection access on these stubs is the load-bearing
//! mechanism (RE doc §"How Cerberus got back on Play").
//!
//! ## False-positive discipline
//!
//! Plain Java reflection (`Class.forName("com.example.Foo").getMethod(...).invoke(...)`)
//! is legal, common, and not adversarial. The recognizer's strict
//! gate-on-binder-stub-allowlist narrows the candidate surface to
//! class names in the 8-entry list. Adding new stub names requires a
//! corpus fixture documenting the observation — never widen the
//! allowlist speculatively.
//!
//! Without SSA def-use binding (see "Why NearMiss" above), the
//! shape-only allowlist gate cannot eliminate the false-positive
//! surface entirely; the recognizer therefore emits `NearMiss` rather
//! than `Recognized`, and the engine surfaces the candidate as an
//! `UNRECOGNIZED_REGION` finding with `closest = #201` instead of
//! suppressing it as a tagged region. The analyst sees an accurate
//! "candidate near-miss" signal.

use droidsaw_common::signature::{
    JavaVersion, MatchOutcome, Signature, SignatureId, SourceDialect,
};

use crate::decode::PoolIndex;
use crate::opcodes::Opcode;
use crate::parser::DexFile;
use crate::signatures::{DexBackend, DexSigInput, RecognizedDexShape};
use crate::ssa::SsaInsn;
use crate::structure::Stmt;

/// Reserved [`SignatureId`] for the reflective-invoke-stub recognizer.
pub const REFLECTIVE_INVOKE_STUB_SIGNATURE_ID: SignatureId = SignatureId(201);

/// Hidden Android binder-stub class names that the recognizer's
/// upstream-scan gate accepts. Each is a fully-qualified class name as
/// it appears in a `const-string` literal feeding `Class.forName(...)`.
///
/// Adding entries requires a corpus fixture documenting the observation
/// in another APK.
pub const KNOWN_BINDER_STUBS: &[&str] = &[
    "android.content.pm.IPackageManager$Stub",
    "android.permission.IPermissionManager$Stub",
    "com.android.internal.statusbar.IStatusBarService$Stub",
    "android.os.IPowerManager$Stub",
    "com.android.internal.widget.ILockSettings$Stub",
    "android.app.admin.IDevicePolicyManager$Stub",
    "android.app.INotificationManager$Stub",
    "android.net.INetworkPolicyManager$Stub",
];

/// `Method.invoke(Object, Object[]) -> Object` fully-qualified target.
const METHOD_INVOKE_CLASS: &str = "Ljava/lang/reflect/Method;";
const METHOD_INVOKE_NAME: &str = "invoke";

/// How far backward to scan from a `Method.invoke` site looking for
/// the upstream binder-stub literal. Per the Cerberus shape (RE doc
/// line 654), the chain is at most ~10 stmts in compact form, plus
/// allow some padding for d8 layout drift. Set to a generous-but-
/// bounded value to avoid pathological scans.
const MAX_UPSTREAM_SCAN: usize = 32;

/// Recognizer for reflection-mediated hidden-binder-stub calls.
pub struct ReflectiveInvokeStubSignature;

impl Signature<DexBackend> for ReflectiveInvokeStubSignature {
    fn id(&self) -> SignatureId {
        REFLECTIVE_INVOKE_STUB_SIGNATURE_ID
    }

    fn dialect(&self) -> SourceDialect {
        // Dialect-agnostic — adversarial recognizer on a Java/JVM
        // shape; works regardless of source compiler.
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

        // Gate 1: candidate stmt is `invoke-virtual Method.invoke(...)`.
        let Some(stmt) = stmts.get(position) else {
            return MatchOutcome::NoMatch;
        };
        let invoke_insn = match stmt {
            Stmt::Expr(insn) => insn,
            _ => return MatchOutcome::NoMatch,
        };
        if !is_reflective_method_invoke(invoke_insn, dex) {
            return MatchOutcome::NoMatch;
        }

        // Gate 2: scan backward for an upstream `const-string` literal
        // matching one of the 8 known binder stubs. The driver's
        // recursive walk passes the parent Seq slice; we walk
        // backward from position-1, bounded by MAX_UPSTREAM_SCAN.
        let upstream_match = scan_upstream_for_binder_stub(stmts, position, dex);

        if upstream_match.is_none() {
            return MatchOutcome::NoMatch;
        }

        // Both shape gates passed but def-use binding is unverified
        // (see module doc-comment "Why NearMiss"). Per Directive 3
        // ("emit NearMiss not Recognized when in doubt"), emit a
        // near-miss with distance 1 — the engine wraps the region in
        // Stmt::Unrecognized with closest = #201, distance = 1 so
        // diag::format_detail surfaces the candidate as an analyst
        // signal without claiming high confidence.
        MatchOutcome::NearMiss { distance: 1 }
    }

    fn max_match_depth(&self) -> usize {
        // Single-stmt structural match at the invoke site; the
        // upstream-scan is bounded by MAX_UPSTREAM_SCAN, not by
        // recursion.
        4
    }

    fn wildcard_tolerance(&self) -> usize {
        // The upstream-scan already absorbs intervening insns
        // (parameter array build, intermediate locals) — that's the
        // wildcard slack for this recognizer. The trait-level
        // tolerance stays at 0 since no padding-skip is needed at the
        // anchor stmt itself.
        0
    }
}

/// True iff `insn` is `invoke-virtual` / `invoke-virtual/range` whose
/// method reference resolves to
/// `Ljava/lang/reflect/Method;->invoke(...)`.
fn is_reflective_method_invoke(insn: &SsaInsn, dex: &DexFile) -> bool {
    if !matches!(
        insn.insn.op,
        Opcode::InvokeVirtual | Opcode::InvokeVirtualRange
    ) {
        return false;
    }
    let method_idx = match insn.insn.pool_idx {
        Some(PoolIndex::Method(m)) => m,
        Some(PoolIndex::MethodAndProto(m, _)) => m,
        _ => return false,
    };
    // PROOF: `MethodIdx.0: u32` → `usize` widening, lossless on 64-bit
    // targets (droidsaw's supported set); `.get()` bound-checks against
    // `dex.methods.len()` so out-of-range indices return `None` gracefully.
    #[allow(clippy::as_conversions, reason = "PROOF: u32 → usize widening, lossless on 64-bit; .get() handles OOB.")]
    let Some(method) = dex.methods.get(method_idx.0 as usize) else {
        return false;
    };
    let class = dex.get_type_descriptor(method.class_idx).unwrap_or("");
    let name = dex.get_string(method.name_idx).unwrap_or("");
    class == METHOD_INVOKE_CLASS && name == METHOD_INVOKE_NAME
}

/// Scan backward from `start_position - 1` (bounded by
/// [`MAX_UPSTREAM_SCAN`]) looking for a `Stmt::Expr(insn)` where
/// `insn.op == ConstString` and the literal is in
/// [`KNOWN_BINDER_STUBS`]. Returns the matching stub class name on
/// success; `None` if the scan exhausts without a hit.
fn scan_upstream_for_binder_stub<'a>(
    stmts: &'a [Stmt],
    start_position: usize,
    dex: &'a DexFile,
) -> Option<&'a str> {
    if start_position == 0 {
        return None;
    }
    let scan_start = start_position.saturating_sub(1);
    let scan_end = start_position.saturating_sub(MAX_UPSTREAM_SCAN);
    let mut i = scan_start;
    loop {
        if let Some(Stmt::Expr(insn)) = stmts.get(i) {
            if insn.insn.op == Opcode::ConstString
                || insn.insn.op == Opcode::ConstStringJumbo
            {
                if let Some(PoolIndex::String(string_idx)) = insn.insn.pool_idx {
                    if let Ok(s) = dex.get_string(string_idx) {
                        if KNOWN_BINDER_STUBS.contains(&s) {
                            return Some(s);
                        }
                    }
                }
            }
        }
        if i == scan_end {
            break;
        }
        match i.checked_sub(1) {
            Some(prev) => i = prev,
            None => break,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_has_eight_stubs() {
        // Per RE doc line 654 — exactly 8. Adding entries requires a
        // corpus fixture documenting another observation.
        assert_eq!(KNOWN_BINDER_STUBS.len(), 8);
    }

    #[test]
    fn allowlist_contains_packagemanager_stub() {
        // SuCommands' grant_permissions reflective call target.
        assert!(KNOWN_BINDER_STUBS.contains(&"android.content.pm.IPackageManager$Stub"));
    }

    #[test]
    fn allowlist_contains_networkpolicymanager_stub() {
        // Per RE doc — the most operationally meaningful stub
        // (programmatic background-data whitelist bypass).
        assert!(KNOWN_BINDER_STUBS.contains(&"android.net.INetworkPolicyManager$Stub"));
    }

    #[test]
    fn signature_metadata() {
        let sig = ReflectiveInvokeStubSignature;
        assert_eq!(sig.id(), REFLECTIVE_INVOKE_STUB_SIGNATURE_ID);
        assert_eq!(sig.id().0, 201);
        assert_eq!(sig.wildcard_tolerance(), 0);
        assert_eq!(sig.max_match_depth(), 4);
    }

    #[test]
    fn invoke_class_and_name_constants_match_jvm_form() {
        // Defensive — the strings are JVM-internal descriptor form
        // (`L...;`), not source-level form (`java.lang.reflect.Method`).
        // A typo here would silently fail every match.
        assert_eq!(METHOD_INVOKE_CLASS, "Ljava/lang/reflect/Method;");
        assert_eq!(METHOD_INVOKE_NAME, "invoke");
    }
}
