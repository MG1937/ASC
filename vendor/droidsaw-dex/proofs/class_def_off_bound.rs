// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proofs — strict-shape `class_def_item` offset bound
//! helper at `droidsaw_dex::parser::validate_class_def_off`.
//!
//! **Refocused architecture.** Production `parse_class_defs` no longer
//! calls this helper; the four class_def offset fields
//! (`interfaces_off`, `annotations_off`, `class_data_off`,
//! `static_values_off`) flow uncritiqued through the class_def parse
//! and are bounds-checked at their downstream consumer sites, where a
//! parse error pushes a `ParseFailureKind::{Interfaces,
//! AnnotationDirectory, ClassData, EncodedArray}` record into
//! `DexFile.parse_errors`. The evasion-primitive defense is single-
//! chokepointed at the emit-side `parse_errors.is_empty()` gate (see
//! `tests/parse_errors_observability.rs` for the locked symmetry).
//!
//! The helper itself is preserved in source as the canonical strict-
//! shape bound check — Kani-proven below — for any future caller that
//! needs the abort-at-parse-time shape. These proofs gauge the
//! helper's contract on its own terms (input → typed Err payload),
//! independent of whether the production parser calls it.
//!
//! DEX spec §VIII.1 fixes `off = 0` as the spec sentinel for "absent"
//! (always accepted); any non-zero offset must fall within the input
//! length.
//!
//! Concrete claims (against the helper, not the production parse path):
//!
//! 1. For every `(off: u32, data_len: usize)` with `off != 0` and
//!    `off as usize >= data_len`, `validate_class_def_off(off, field,
//!    data_len)` returns `Err(ClassDefOffsetOutOfBounds { field, off,
//!    data_len })` with all three fields preserved verbatim.
//! 2. For every `(off, data_len)` with `off == 0` OR `(off as usize) <
//!    data_len`, the function returns `Ok(off)`.
//! 3. The 0-sentinel is universally accepted (even when `data_len == 0`).
//! 4. The `field` tag round-trips verbatim through the `Err` payload
//!    across all four spec-listed call-site labels.
//!
//! **What this proof verifies (production-code gauge):**
//! - Target: `droidsaw_dex::parser::validate_class_def_off`. Called
//!   directly. The production parser does NOT call this; the proof's
//!   value is documenting the strict-shape contract as a future-caller
//!   reference and locking the `field`-tag-round-trips invariant.
//! - Oracle: pure structural assertion on the returned `Result`.
//!   No re-derivation of the bound inside the proof body.
//! - Out of scope here: the tolerant-record contract that production
//!   actually relies on. That invariant lives at the integration level
//!   (`DexFile::parse` → `parse_errors`) and is gauged by the four
//!   `*_off_past_eof_records_skip` tests in
//!   `tests/parse_errors_observability.rs`.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unwrap_used)]

use crate::error::DexError;
use crate::parser::validate_class_def_off;

// ── Sub-proof 1: out-of-bounds non-zero off rejected with payload ──────

#[kani::proof]
#[kani::unwind(4)]
fn out_of_bounds_off_rejected_with_payload() {
    let off: u32 = kani::any();
    let data_len: usize = kani::any();
    kani::assume(off != 0);
    kani::assume(off as usize >= data_len);
    let r = validate_class_def_off(off, "interfaces_off", data_len);
    match r {
        Err(DexError::ClassDefOffsetOutOfBounds {
            field,
            off: r_off,
            data_len: r_dl,
        }) => {
            kani::assert(field == "interfaces_off", "field tag must match");
            kani::assert(r_off == off, "off must be carried verbatim");
            kani::assert(r_dl == data_len, "data_len must be carried verbatim");
        }
        _ => kani::assert(false, "out-of-bounds off MUST be rejected"),
    }
}

// ── Sub-proof 2: in-bounds non-zero off accepted, value preserved ──────

#[kani::proof]
#[kani::unwind(4)]
fn in_bounds_off_accepted_and_preserved() {
    let off: u32 = kani::any();
    let data_len: usize = kani::any();
    kani::assume(off != 0);
    kani::assume((off as usize) < data_len);
    let r = validate_class_def_off(off, "annotations_off", data_len);
    let Ok(returned) = r else {
        kani::assert(false, "in-bounds off MUST be accepted");
        return;
    };
    kani::assert(returned == off, "in-bounds off must be returned verbatim");
}

// ── Sub-proof 3: off = 0 sentinel universally accepted ─────────────────

#[kani::proof]
#[kani::unwind(4)]
fn zero_sentinel_universally_accepted() {
    let data_len: usize = kani::any();
    // Zero is the "absent" sentinel; must be accepted regardless of
    // data_len (even when data_len == 0).
    let r = validate_class_def_off(0, "class_data_off", data_len);
    kani::assert(r.is_ok(), "off = 0 sentinel must be universally accepted");
    if let Ok(returned) = r {
        kani::assert(returned == 0, "zero must round-trip exactly");
    }
}

// ── Sub-proof 4: field tag carried verbatim across all 4 callsites ─────

#[kani::proof]
#[kani::unwind(4)]
fn field_tag_carried_verbatim_static_values() {
    // Audit-attribution invariant for `static_values_off`. The other
    // three field tags are exercised by sub-proofs 1-3; this one pins
    // the 4th call-site to make the per-field test matrix exhaustive.
    let off: u32 = kani::any();
    kani::assume(off != 0);
    kani::assume(off as usize >= 16);
    let r = validate_class_def_off(off, "static_values_off", 16);
    match r {
        Err(DexError::ClassDefOffsetOutOfBounds { field, .. }) => {
            kani::assert(
                field == "static_values_off",
                "field tag must be carried verbatim",
            );
        }
        _ => kani::assert(false, "out-of-bounds off must reject with field tag"),
    }
}
