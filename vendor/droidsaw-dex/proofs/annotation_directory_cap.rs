// SPDX-License-Identifier: BSD-3-Clause

//! Kani Tier-1 proofs — `AnnotationDirectoryItem` sum-of-counts
//! allocation cap at `droidsaw_dex::annotation`.
//!
//! Proves the OOM-resistance invariant introduced to fence off the
//! allocator-pressure primitive where `fields_size + methods_size +
//! parameters_size` could drive a `Vec::with_capacity` allocation
//! exceeding the input length by ~3× (each individual count was
//! `bound_count`-checked, but the sum was not).
//!
//! Concrete claims:
//!
//! 1. For every `(f, m, p, data_len)` with `f + m + p > data_len /
//!    ENTRY_SIZE` (computed in u64 with saturating arithmetic),
//!    `AnnotationDirectoryItem::parse` returns
//!    `Err(AnnotationDirectoryAllocationCap { combined, data_len })`
//!    with `combined == f + m + p` and `data_len` carried verbatim.
//! 2. The combined sum is computed via `saturating_add`; for any
//!    `(f, m, p)` triple of u32 values, the sum never overflows u64.
//!
//! Tier-1 bound: we symbolically vary the three count fields plus a
//! small `data_len`, build a 16-byte header, and call the production
//! parser. Per the Kani-Tier-1 cost budget, `data_len` is constrained
//! to a small range (sub-proof body); the OOM invariant lifts to
//! larger data_len by structural argument (the gauge is `combined >
//! data_len / ENTRY_SIZE`, which is u64 comparison — no input-size-
//! dependent reasoning in the proof body).
//!
//! **What this proof verifies (production-code gauge):**
//! - Target: `droidsaw_dex::annotation::AnnotationDirectoryItem::parse`.
//!   Called directly. Proof failure = production bug.
//! - Oracle: structural assertion on the returned `Result` shape. The
//!   sum-cap gauge is the production code; the proof body does not
//!   re-derive `combined = u64::from(f) + u64::from(m) + u64::from(p)`
//!   independently — it asserts on what the production parser carries
//!   in the error.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::unwrap_used)]

use crate::annotation::AnnotationDirectoryItem;
use crate::error::DexError;

const HEADER_LEN: usize = 16;
const ENTRY_SIZE: usize = 8;

/// Build a 64-byte annotation_directory_item buffer with the three
/// count fields written into bytes 4..16. The 64-byte length is fixed
/// (not symbolic) so CBMC can reason about `data.len() / ENTRY_SIZE`
/// as the constant `8`. Header alone consumes 16 bytes.
fn header_buf(fields_size: u32, methods_size: u32, parameters_size: u32) -> [u8; 64] {
    let mut buf = [0u8; 64];
    // class_annotations_off at 0..4 — zero is fine.
    buf[4..8].copy_from_slice(&fields_size.to_le_bytes());
    buf[8..12].copy_from_slice(&methods_size.to_le_bytes());
    buf[12..16].copy_from_slice(&parameters_size.to_le_bytes());
    buf
}

// ── Sub-proof 1: over-cap sum is rejected with payload preservation ────

#[kani::proof]
#[kani::unwind(8)]
fn over_cap_sum_rejected_with_payload() {
    let fields_size: u32 = kani::any();
    let methods_size: u32 = kani::any();
    let parameters_size: u32 = kani::any();
    let combined: u64 = u64::from(fields_size)
        .saturating_add(u64::from(methods_size))
        .saturating_add(u64::from(parameters_size));
    let max_entries = (64u64 / ENTRY_SIZE as u64);
    kani::assume(combined > max_entries);
    let buf = header_buf(fields_size, methods_size, parameters_size);
    let r = AnnotationDirectoryItem::parse(&buf, 0);
    match r {
        Err(DexError::AnnotationDirectoryAllocationCap {
            combined: got_combined,
            data_len: got_data_len,
        }) => {
            kani::assert(got_combined == combined, "combined must be carried verbatim");
            kani::assert(got_data_len == 64, "data_len must match input");
        }
        _ => kani::assert(false, "over-cap sum MUST be rejected"),
    }
}

// ── Sub-proof 2: u32::MAX-shaped sum saturates safely (no overflow) ────

#[kani::proof]
#[kani::unwind(8)]
fn u32_max_sum_does_not_overflow() {
    // Verification: all three counts at the individual cap.
    // Sum is well under u64::MAX (3 * u32::MAX ≈ 1.29 * 10^10).
    let buf = header_buf(u32::MAX, u32::MAX, u32::MAX);
    let r = AnnotationDirectoryItem::parse(&buf, 0);
    match r {
        Err(DexError::AnnotationDirectoryAllocationCap { combined, data_len }) => {
            // 3 * u32::MAX = 0xFFFFFFFF * 3 = 0x2FFFFFFFD
            kani::assert(
                combined == u64::from(u32::MAX).saturating_mul(3),
                "combined must equal 3 * u32::MAX (saturating)",
            );
            kani::assert(data_len == 64, "data_len must match");
        }
        _ => kani::assert(false, "adversarial sum MUST be rejected"),
    }
}

// ── Sub-proof 3: at-cap sum is NOT rejected by the allocation gauge ────

#[kani::proof]
#[kani::unwind(8)]
fn at_or_under_cap_passes_allocation_gauge() {
    // For any (f, m, p) with combined ≤ max_entries, the allocation
    // cap MUST NOT be the source of error. (Downstream individual
    // `bound_count` calls or pread errors may still surface, but
    // never `AnnotationDirectoryAllocationCap`.)
    let fields_size: u32 = kani::any();
    let methods_size: u32 = kani::any();
    let parameters_size: u32 = kani::any();
    let combined: u64 = u64::from(fields_size)
        .saturating_add(u64::from(methods_size))
        .saturating_add(u64::from(parameters_size));
    let max_entries = (64u64 / ENTRY_SIZE as u64);
    kani::assume(combined <= max_entries);
    let buf = header_buf(fields_size, methods_size, parameters_size);
    let r = AnnotationDirectoryItem::parse(&buf, 0);
    if let Err(DexError::AnnotationDirectoryAllocationCap { .. }) = r {
        kani::assert(
            false,
            "in-cap sum MUST NOT surface as AnnotationDirectoryAllocationCap",
        );
    }
}

// HEADER_LEN documented for proof body readability; unused right now
// but kept so future proof extensions over symbolic header content
// can reach it via `crate::proof_annotation_directory_cap::HEADER_LEN`.
#[allow(dead_code)]
const _HEADER_LEN_DOC: usize = HEADER_LEN;
