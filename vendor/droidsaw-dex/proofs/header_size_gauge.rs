// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proof — DEX header canonical-size gauge at
//! `droidsaw_dex::header::DexHeader::parse`.
//!
//! Proves the gauge-enforcement invariant introduced to fence off the
//! "header that doesn't gauge" audit-mute primitive. DEX spec §3.1
//! fixes `header_size` at exactly `0x70` (112 bytes). Without this
//! gate, the parser reads the field into the struct but never
//! validates it, letting observed-vs-declared geometry audits
//! silently miss a wrong-shape header. The gate rejects every
//! `declared != 0x70` with `DexError::InvalidHeaderSize`.
//!
//! Concrete claims:
//!
//! 1. For every `declared: u32` with `declared != 0x70`, parsing a
//!    well-formed 112-byte buffer with `header_size = declared` returns
//!    `Err(DexError::InvalidHeaderSize { declared })`.
//! 2. For `declared == 0x70`, the same buffer parses successfully and
//!    `hdr.header_size == 0x70`.
//!
//! **What this proof verifies (production-code gauge):**
//! - Target: `droidsaw_dex::header::DexHeader::parse`. Called directly;
//!   if production has a bug, the proof fails.
//! - Oracle: pure structural assertion on the returned `Result`. No
//!   re-derivation of the gauge inside the proof body — the production
//!   `if declared != CANONICAL_HEADER_SIZE { return Err(...) }` is the
//!   spec.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unwrap_used)]

use crate::error::DexError;
use crate::header::DexHeader;

const ENDIAN_CONSTANT: u32 = 0x1234_5678;

/// Build a 112-byte well-formed DEX header buffer with a caller-chosen
/// `header_size` field. All other fields are valid: magic = "dex\n035\0",
/// endian_tag = ENDIAN_CONSTANT, everything else zero (the parser does
/// not validate zero-valued offsets at this point).
fn header_with_declared_size(declared: u32) -> [u8; 112] {
    let mut buf = [0u8; 112];
    buf[..4].copy_from_slice(b"dex\n");
    buf[4..7].copy_from_slice(b"035");
    buf[7] = 0;
    // file_size at offset 32; pick the canonical 0x70 so this doesn't
    // interfere with other unrelated checks.
    buf[32..36].copy_from_slice(&0x70u32.to_le_bytes());
    // header_size at offset 36
    buf[36..40].copy_from_slice(&declared.to_le_bytes());
    // endian_tag at offset 40
    buf[40..44].copy_from_slice(&ENDIAN_CONSTANT.to_le_bytes());
    buf
}

// ── Sub-proof 1: every non-canonical declared value is rejected ────────

#[kani::proof]
#[kani::unwind(8)]
fn non_canonical_header_size_always_rejected() {
    let declared: u32 = kani::any();
    kani::assume(declared != 0x70);
    let buf = header_with_declared_size(declared);
    let r = DexHeader::parse(&buf);
    let Err(err) = r else {
        kani::assert(false, "non-canonical header_size must be rejected");
        return;
    };
    // The variant must be InvalidHeaderSize AND must carry the input
    // value verbatim (no narrowing / loss).
    match err {
        DexError::InvalidHeaderSize { declared: d } => {
            kani::assert(
                d == declared,
                "InvalidHeaderSize must carry the input header_size verbatim",
            );
        }
        _ => kani::assert(
            false,
            "non-canonical header_size must surface as InvalidHeaderSize specifically",
        ),
    }
}

// ── Sub-proof 2: canonical 0x70 is accepted ────────────────────────────

#[kani::proof]
#[kani::unwind(8)]
fn canonical_header_size_accepted() {
    let buf = header_with_declared_size(0x70);
    let r = DexHeader::parse(&buf);
    let Ok(hdr) = r else {
        kani::assert(false, "canonical 0x70 header_size must be accepted");
        return;
    };
    kani::assert(
        hdr.header_size == 0x70,
        "canonical header_size round-trips exactly into the struct field",
    );
}
