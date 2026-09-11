// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proof — F11n 4-bit signed-literal sign-extension at
//! `droidsaw_dex::decode::sign_extend_4bit_to_i64`.
//!
//! Proves: for every `nibble: u16` in the 4-bit domain `0..=15`, the
//! production sign-extension result matches a subtraction-form
//! arithmetic oracle that computes `if v >= 8 { (v as i64) - 16 }
//! else { v as i64 }` — same observable, computationally distinct
//! path from production's `nibble as i8 | (sign-bit ? !0xF_u8 as i8
//! : 0)` bit-twiddle.
//!
//! **What this proof verifies (production-code gauge):**
//! - Target: production `sign_extend_4bit_to_i64`. Called directly;
//!   if production has a bug, the proof fails.
//! - Oracle: arithmetic subtraction-form re-derivation, mathematically
//!   equivalent under the input-range assume `nibble ≤ 15` but using
//!   pure i64 subtraction instead of i8 bit-OR. Same gauge-avoidance
//!   shape as the existing mutf8 6-byte proof's subtraction-form bit
//!   extraction.
//!
//! **Dominator proven** that lint + types do not already enforce:
//! the i8-narrow + OR-extend composition correctly maps the upper
//! nibble half (`[8, 15]`) to the negative i64 range `[-8, -1]`. A
//! typo flipping the sign-bit test (`b & 0x4` instead of `b & 0x8`)
//! or the OR mask (`!0x7_u8` instead of `!0xF_u8`) would diverge from
//! the arithmetic oracle.
//!
//! **Range-claim sub-proof** asserts the result is in `[-8, 7]` over
//! the full input domain — closes the "extended is bounded" contract
//! the F11n call site relies on when storing into `Instruction::literal`.

#![allow(clippy::arithmetic_side_effects)] // proof body
#![allow(clippy::unwrap_used)]
#![allow(clippy::as_conversions)]

use crate::decode::sign_extend_4bit_to_i64;

// BOUNDS: unwind-depth = 2; reason = no loops, straight-line
// arithmetic + single conditional. Default unwind covers.

#[kani::proof]
#[kani::unwind(2)]
fn sign_extend_4bit_agrees_with_subtraction_oracle() {
    let nibble: u16 = kani::any();
    kani::assume(nibble <= 15);

    let production = sign_extend_4bit_to_i64(nibble);

    // Subtraction-form oracle: high bit (bit 3) maps the input into the
    // negative half by subtracting 16. Pure i64 arithmetic, no i8 cast,
    // no bit-OR — different primitive ops from production.
    let oracle: i64 = if nibble >= 8 {
        (nibble as i64) - 16
    } else {
        nibble as i64
    };

    kani::assert(
        production == oracle,
        "sign_extend_4bit_to_i64 agrees with subtraction-form oracle on 0..=15",
    );
}

#[kani::proof]
#[kani::unwind(2)]
fn sign_extend_4bit_output_in_signed_4bit_range() {
    let nibble: u16 = kani::any();
    kani::assume(nibble <= 15);

    let v = sign_extend_4bit_to_i64(nibble);
    kani::assert(
        v >= -8 && v <= 7,
        "F11n sign-extension result is in [-8, 7] (signed 4-bit range)",
    );
}
