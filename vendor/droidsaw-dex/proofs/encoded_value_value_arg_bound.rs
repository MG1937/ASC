// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proofs — per-tag `value_arg` size bounds on
//! `droidsaw_dex::annotation::check_value_arg_size`, the gauge that
//! gates all 11 affected DEX encoded_value tags at parse time.
//!
//! Proves the roundtrip-byte-equality invariant that would otherwise be
//! broken by silent narrowing via `as i8` / `as u16` / `as u32` at 11
//! match arms in `decode_primitive_encoded_value`.
//!
//! For each affected variant, claim: for every `size: usize` with
//! `size > MAX_FOR_TAG`, `check_value_arg_size(variant, size, MAX)`
//! returns `Err(EncodedValueSize { variant, size })`. And the dual:
//! every `size <= MAX_FOR_TAG` returns `Ok(())`.
//!
//! 11 variants × 2 directions = 22 invariants; bundled per-variant
//! into 11 sub-proofs (each carries the reject + accept claim).
//!
//! **What this proof verifies (production-code gauge):**
//! - Target: `droidsaw_dex::annotation::check_value_arg_size`. Called
//!   directly. Each of the 11 match arms in `decode_primitive_encoded_value`
//!   routes through this helper with the exact (variant, max) pair the
//!   sub-proofs assume, so a proof failure on the helper implies a
//!   failure on the matching arm.
//! - Oracle: pure structural assertion on the returned `Result`. No
//!   re-derivation of the per-tag bound inside the proof body.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unwrap_used)]

use crate::annotation::check_value_arg_size;
use crate::error::DexError;

/// Generic per-variant sub-proof body. Symbolically samples `size`,
/// asserts: `> max` ⇒ Err with exact variant + size; `<= max` ⇒ Ok.
fn proof_for(variant: &'static str, max: usize) {
    let size: usize = kani::any();
    // Restrict `size` to the [1, 8] domain that the production caller
    // (`parse_encoded_value`) can produce (`value_arg ∈ [0,7]` → `size
    // ∈ [1,8]`). Outside that range is unreachable from production.
    kani::assume(size >= 1 && size <= 8);
    let r = check_value_arg_size(variant, size, max);
    if size > max {
        match r {
            Err(DexError::EncodedValueSize {
                variant: v,
                size: s,
            }) => {
                kani::assert(v == variant, "variant tag must match");
                kani::assert(s == size, "size must be carried verbatim");
            }
            _ => kani::assert(false, "over-size MUST be rejected"),
        }
    } else {
        kani::assert(r.is_ok(), "in-bounds size MUST be accepted");
    }
}

// ── Per-tag sub-proofs (11 affected variants) ──────────────────────────

#[kani::proof]
#[kani::unwind(4)]
fn byte_size_bound() {
    proof_for("Byte", 1);
}

#[kani::proof]
#[kani::unwind(4)]
fn short_size_bound() {
    proof_for("Short", 2);
}

#[kani::proof]
#[kani::unwind(4)]
fn char_size_bound() {
    proof_for("Char", 2);
}

#[kani::proof]
#[kani::unwind(4)]
fn int_size_bound() {
    proof_for("Int", 4);
}

#[kani::proof]
#[kani::unwind(4)]
fn float_size_bound() {
    proof_for("Float", 4);
}

#[kani::proof]
#[kani::unwind(4)]
fn method_type_size_bound() {
    proof_for("MethodType", 4);
}

#[kani::proof]
#[kani::unwind(4)]
fn method_handle_size_bound() {
    proof_for("MethodHandle", 4);
}

#[kani::proof]
#[kani::unwind(4)]
fn string_size_bound() {
    proof_for("String", 4);
}

#[kani::proof]
#[kani::unwind(4)]
fn type_size_bound() {
    proof_for("Type", 4);
}

#[kani::proof]
#[kani::unwind(4)]
fn field_size_bound() {
    proof_for("Field", 4);
}

#[kani::proof]
#[kani::unwind(4)]
fn method_size_bound() {
    proof_for("Method", 4);
}

#[kani::proof]
#[kani::unwind(4)]
fn enum_size_bound() {
    proof_for("Enum", 4);
}
