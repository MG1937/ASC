// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proof — DEX header endian-tag canonical-value gauge at
//! `droidsaw_dex::header::validate_endian_tag`.
//!
//! Proves the gauge-enforcement invariant fencing off the
//! "byte-swapped header" audit-mute primitive. DEX spec fixes the
//! `endian_tag` field at exactly `0x12345678` (little-endian on every
//! supported target). Without this gate, the byte-swapped
//! `0x78563412` REVERSE_ENDIAN_CONSTANT — which ART itself rejects —
//! could pass parser-side checks and skew downstream geometry audits.
//! The gate rejects every non-canonical declared value with
//! `DexError::BadEndianTag { tag }` — a typed variant carrying the
//! raw u32.
//!
//! **Helper-targeted harness shape.** Targets `validate_endian_tag`
//! directly rather than driving the full `DexHeader::parse`. The
//! parse path runs the `SUPPORTED_VERSIONS.iter().any(|v|
//! v.as_slice() == version)` slice-compare loop BEFORE reaching the
//! endian arm, which CBMC can't unwind cheaply under a full
//! `kani::any::<u32>()` enumeration of the endian field. The helper
//! is a single-comparison `pub(crate) const fn` — the production
//! call site is `validate_endian_tag(endian_tag)?` inside
//! `DexHeader::parse`. Verifying the helper proves the gate; the
//! parse-side discipline that ensures the helper is called is locked
//! by the focused unit tests in `header.rs::tests::bad_endian_tag_*`.
//!
//! Concrete claims:
//!
//! 1. For every `declared: u32` with `declared != 0x12345678`,
//!    `validate_endian_tag(declared)` returns
//!    `Err(DexError::BadEndianTag { tag })` with `tag == declared`
//!    (raw value carried verbatim, no narrowing / loss).
//! 2. For `declared == 0x12345678`, `validate_endian_tag(declared)`
//!    returns `Ok(())`.
//! 3. The byte-swapped `0x78563412` (REVERSE_ENDIAN_CONSTANT that
//!    ART itself rejects) is rejected as `BadEndianTag { tag:
//!    0x78563412 }`. Pinned as its own proof so a future
//!    "we'll just byte-swap-on-the-fly" relaxation surfaces here
//!    loudly.
//!
//! Companion to `header_size_gauge.rs` — same gate-correctness
//! template, different field. The two together prove the two
//! static-field gates the DEX parser enforces are both load-bearing
//! and both correctly enumerate their canonical value across the
//! full u32 input space.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unwrap_used)]

use crate::error::DexError;
use crate::header::validate_endian_tag;

const ENDIAN_CONSTANT: u32 = 0x1234_5678;

// BOUNDS: unwind-depth = 2; reason = validate_endian_tag is a single
// equality comparison + Result construction. No loops. Default unwind
// of 2 covers.

// ── Sub-proof 1: every non-canonical declared endian is rejected ───────

#[kani::proof]
#[kani::unwind(2)]
fn non_canonical_endian_always_rejected_with_typed_tag() {
    let declared: u32 = kani::any();
    kani::assume(declared != ENDIAN_CONSTANT);
    match validate_endian_tag(declared) {
        Err(DexError::BadEndianTag { tag }) => {
            kani::assert(
                tag == declared,
                "BadEndianTag must carry the input endian_tag verbatim (no narrowing / loss)",
            );
        }
        _ => kani::assert(
            false,
            "non-canonical endian_tag must surface as BadEndianTag specifically",
        ),
    }
}

// ── Sub-proof 2: canonical 0x12345678 is accepted ──────────────────────

#[kani::proof]
#[kani::unwind(2)]
fn canonical_endian_accepted() {
    kani::assert(
        validate_endian_tag(ENDIAN_CONSTANT).is_ok(),
        "canonical 0x12345678 endian_tag must validate Ok",
    );
}

// ── Sub-proof 3: byte-swapped REVERSE_ENDIAN_CONSTANT is rejected ──────

/// Anchor regression: the byte-swapped form (`0x78563412`) that ART
/// itself rejects (`runtime/dex_file.cc::CheckMagicAndVersion`) must
/// fail with the typed variant carrying the raw value. Pinned as its
/// own proof so a future relaxation of the gate ("we'll just byte-swap-
/// on-the-fly") surfaces here loudly rather than as silent behavioral
/// drift.
#[kani::proof]
#[kani::unwind(2)]
fn reverse_endian_constant_rejected_with_raw_tag() {
    match validate_endian_tag(0x7856_3412) {
        Err(DexError::BadEndianTag { tag }) => {
            kani::assert(
                tag == 0x7856_3412,
                "REVERSE_ENDIAN_CONSTANT surfaces with raw tag = 0x78563412",
            );
        }
        _ => kani::assert(
            false,
            "REVERSE_ENDIAN_CONSTANT must surface as BadEndianTag(0x78563412)",
        ),
    }
}
