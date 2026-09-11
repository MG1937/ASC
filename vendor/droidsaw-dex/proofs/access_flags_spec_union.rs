// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proofs — `access_flags` spec-union validation at
//! `droidsaw_dex::access_flags::validate` for each of the 3 scopes
//! (Class / Field / Method) per DEX format §3.4.1.
//!
//! Proves the IR-coherence + roundtrip-byte-equality invariants of the
//! per-scope mask gate. Without the gate, the parser pushes raw u32
//! access_flags verbatim into the IR, letting `access_flags =
//! 0xFFFFFFFF` evaluate truthy on every bit-test simultaneously (a
//! method becomes static+abstract+native+private+public+ACC_ENUM at
//! once). With it, any bit outside the per-scope spec union surfaces
//! as `DexError::InvalidAccessFlags { raw, scope }`.
//!
//! Concrete claims (× 3 scopes):
//!
//! 1. For every `raw: u32` with `raw & !scope.mask() != 0`,
//!    `validate(raw, scope)` returns `Err(InvalidAccessFlags { raw,
//!    scope })`.
//! 2. For every `raw: u32` with `raw & !scope.mask() == 0`,
//!    `validate(raw, scope)` returns `Ok(raw)` (no narrowing or loss).
//!
//! **What this proof verifies (production-code gauge):**
//! - Target: `droidsaw_dex::access_flags::validate`. Called directly;
//!   if production has a bug, the proof fails.
//! - Oracle: pure structural assertion on the returned `Result`. No
//!   re-derivation of the mask constants inside the proof body — the
//!   production `if raw & !MASK != 0 { return Err(...) }` is the spec.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unwrap_used)]

use crate::access_flags::{validate, AccessFlagScope};
use crate::error::DexError;

// ── Sub-proof 1: Class scope rejects every out-of-mask raw ─────────────

#[kani::proof]
#[kani::unwind(4)]
fn class_scope_rejects_out_of_mask() {
    let raw: u32 = kani::any();
    kani::assume(raw & !AccessFlagScope::Class.mask() != 0);
    let r = validate(raw, AccessFlagScope::Class);
    match r {
        Err(DexError::InvalidAccessFlags { raw: r2, scope }) => {
            kani::assert(r2 == raw, "InvalidAccessFlags must carry raw verbatim");
            kani::assert(scope == AccessFlagScope::Class, "scope must match");
        }
        _ => kani::assert(false, "out-of-mask raw must surface as InvalidAccessFlags"),
    }
}

// ── Sub-proof 2: Field scope rejects every out-of-mask raw ─────────────

#[kani::proof]
#[kani::unwind(4)]
fn field_scope_rejects_out_of_mask() {
    let raw: u32 = kani::any();
    kani::assume(raw & !AccessFlagScope::Field.mask() != 0);
    let r = validate(raw, AccessFlagScope::Field);
    match r {
        Err(DexError::InvalidAccessFlags { raw: r2, scope }) => {
            kani::assert(r2 == raw, "InvalidAccessFlags must carry raw verbatim");
            kani::assert(scope == AccessFlagScope::Field, "scope must match");
        }
        _ => kani::assert(false, "out-of-mask raw must surface as InvalidAccessFlags"),
    }
}

// ── Sub-proof 3: Method scope rejects every out-of-mask raw ────────────

#[kani::proof]
#[kani::unwind(4)]
fn method_scope_rejects_out_of_mask() {
    let raw: u32 = kani::any();
    kani::assume(raw & !AccessFlagScope::Method.mask() != 0);
    let r = validate(raw, AccessFlagScope::Method);
    match r {
        Err(DexError::InvalidAccessFlags { raw: r2, scope }) => {
            kani::assert(r2 == raw, "InvalidAccessFlags must carry raw verbatim");
            kani::assert(scope == AccessFlagScope::Method, "scope must match");
        }
        _ => kani::assert(false, "out-of-mask raw must surface as InvalidAccessFlags"),
    }
}

// ── Sub-proof 4: in-mask raw accepted for every scope, value preserved ─

#[kani::proof]
#[kani::unwind(4)]
fn in_mask_raw_accepted_and_preserved_class() {
    let raw: u32 = kani::any();
    kani::assume(raw & !AccessFlagScope::Class.mask() == 0);
    let r = validate(raw, AccessFlagScope::Class);
    let Ok(returned) = r else {
        kani::assert(false, "in-mask raw must be accepted");
        return;
    };
    kani::assert(returned == raw, "in-mask raw must be returned verbatim");
}

#[kani::proof]
#[kani::unwind(4)]
fn in_mask_raw_accepted_and_preserved_field() {
    let raw: u32 = kani::any();
    kani::assume(raw & !AccessFlagScope::Field.mask() == 0);
    let r = validate(raw, AccessFlagScope::Field);
    let Ok(returned) = r else {
        kani::assert(false, "in-mask raw must be accepted");
        return;
    };
    kani::assert(returned == raw, "in-mask raw must be returned verbatim");
}

#[kani::proof]
#[kani::unwind(4)]
fn in_mask_raw_accepted_and_preserved_method() {
    let raw: u32 = kani::any();
    kani::assume(raw & !AccessFlagScope::Method.mask() == 0);
    let r = validate(raw, AccessFlagScope::Method);
    let Ok(returned) = r else {
        kani::assert(false, "in-mask raw must be accepted");
        return;
    };
    kani::assert(returned == raw, "in-mask raw must be returned verbatim");
}
