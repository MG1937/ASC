// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proofs — debug-info register bound enforcement at
//! `droidsaw_dex::debug::narrow_register`.
//!
//! Proves the anti-smuggling invariants of the typed-Err gate that
//! replaces the silent `register as u16` truncation. Without the gate,
//! a uleb128 value whose bits 16-31 are set (e.g. `0x00100005`)
//! silently truncates to a colliding `u16` (5), overwriting a
//! legitimate local's name in the active-locals map. With it, the
//! gate returns `DexError::InvalidDebugRegister` for ANY value outside
//! the method-declared `[0, registers_size)` range.
//!
//! Concrete claims:
//!
//! 1. For every `uleb_value > u16::MAX`, `narrow_register` returns Err
//!    regardless of `registers_size`.
//! 2. For every `(uleb_value, registers_size)` pair with
//!    `uleb_value >= registers_size`, `narrow_register` returns Err.
//! 3. For every `(uleb_value, registers_size)` pair with
//!    `uleb_value < registers_size`, `narrow_register` returns Ok with
//!    the value preserved (no narrowing artefact).
//!
//! **What this proof verifies (production-code gauge):**
//! - Target: `droidsaw_dex::debug::narrow_register`. Called directly;
//!   if production has a bug, the proof fails.
//! - Oracle: pure structural assertion on the returned `Result`. No
//!   re-derivation of the bounding arithmetic inside the proof body —
//!   the production `try_from` + `r < registers_size` is the spec.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unwrap_used)]

use crate::debug::narrow_register;
use crate::error::DexError;

// ── Sub-proof 1: every uleb_value > u16::MAX is rejected ───────────────

#[kani::proof]
#[kani::unwind(4)]
fn above_u16_max_always_rejected() {
    let uleb_value: u32 = kani::any();
    kani::assume(uleb_value > u32::from(u16::MAX));
    let registers_size: u16 = kani::any();
    let r = narrow_register(uleb_value, registers_size);
    kani::assert(
        matches!(r, Err(DexError::InvalidDebugRegister { .. })),
        "value > u16::MAX must always be rejected",
    );
}

// ── Sub-proof 2: every uleb_value >= registers_size is rejected ────────

#[kani::proof]
#[kani::unwind(4)]
fn at_or_above_registers_size_rejected() {
    let uleb_value: u32 = kani::any();
    let registers_size: u16 = kani::any();
    kani::assume(uleb_value >= u32::from(registers_size));
    let r = narrow_register(uleb_value, registers_size);
    kani::assert(
        matches!(r, Err(DexError::InvalidDebugRegister { .. })),
        "value >= registers_size must always be rejected",
    );
}

// ── Sub-proof 3: in-range values are accepted with value preserved ─────

#[kani::proof]
#[kani::unwind(4)]
fn in_range_accepted_and_preserved() {
    let registers_size: u16 = kani::any();
    kani::assume(registers_size > 0);
    let uleb_value: u32 = kani::any();
    kani::assume(uleb_value < u32::from(registers_size));
    let r = narrow_register(uleb_value, registers_size);
    let Ok(narrowed) = r else {
        kani::assert(false, "in-range value must be accepted");
        return;
    };
    // No narrowing artefact: the returned u16 equals the input u32
    // exactly (well-defined because uleb_value < u16::MAX by the assume).
    kani::assert(
        u32::from(narrowed) == uleb_value,
        "narrowed value must equal the input exactly",
    );
}

// ── Sub-proof 4: smuggling-shape regression ─────────────────────────────

#[kani::proof]
#[kani::unwind(4)]
fn smuggling_shape_high_bits_set_rejected() {
    // The smuggling pattern: a uleb128 with bits 16-31 set whose low
    // 16 bits would collide with a legitimate register index. Must
    // always be rejected, regardless of the method's registers_size.
    let low: u16 = kani::any();
    let high: u16 = kani::any();
    kani::assume(high > 0); // require at least one high bit set
    let uleb_value = (u32::from(high) << 16) | u32::from(low);
    let registers_size: u16 = kani::any();
    let r = narrow_register(uleb_value, registers_size);
    kani::assert(
        matches!(r, Err(DexError::InvalidDebugRegister { .. })),
        "smuggling-shape input must always be rejected",
    );
}
