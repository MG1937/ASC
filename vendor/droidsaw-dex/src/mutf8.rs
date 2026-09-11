//! LEB128 and MUTF-8 decoders for DEX parsing.
//!
//! Implementations live in [`droidsaw_common::encoding`]. These
//! wrappers map the generic [`droidsaw_common::encoding::EncodingError`]
//! to [`DexError`] so call sites in this crate remain unchanged.
//!
//! # What the MUTF-8 codec accepts
//!
//! [`decode_mutf8`] returns `Ok(String)` on byte sequences that
//! conform to DEX spec §3.3.1. Specifically:
//!
//! - 1-byte ASCII `0x01..=0x7F`.
//! - 2-byte `0xC0..=0xDF` lead. Includes the MUTF-8 specialty
//!   encoding `0xC0 0x80 → U+0000`.
//! - 3-byte `0xE0..=0xEF` lead, non-surrogate codepoint.
//! - 6-byte surrogate-pair sequence: high surrogate
//!   `0xED 0xA0..=0xAF 0x??` immediately followed by low surrogate
//!   `0xED 0xB0..=0xBF 0x??`, decoding to a supplementary codepoint
//!   in `U+10000..=U+10FFFF`.
//!
//! # What the MUTF-8 codec rejects (returns typed `DexError::InvalidMutf8 { offset }`)
//!
//! Honest-naming matrix — every shape below produces a typed `Err`,
//! not a panic, not a U+FFFD substitution, not a silent skip. The
//! `offset` field is the byte index *within the input slice* where
//! the failing sequence begins.
//!
//! | Class | Example bytes | Why rejected |
//! |-------|---------------|--------------|
//! | **Lone high surrogate** | `ED A0..AF xx` not followed by `ED B0..BF xx` | Java strings legitimately contain unpaired UTF-16 code units, but Rust `String` is well-formed UTF-8; no valid encoding exists. Empirically ~50% of corpus decode failures. |
//! | **Lone low surrogate** | `ED B0..BF xx` appearing first | The codec dispatches surrogate-pair handling only on a high-surrogate prefix; a low surrogate at codepoint-start is structurally invalid. ~50% of corpus failures. |
//! | **Swapped surrogate pair** | low surrogate followed by high surrogate | Pair order is fixed by CESU-8 (high before low). A swapped pair is rejected at the low-surrogate-first arm. |
//! | **Oversized supplementary** | high surrogate followed by a 3-byte sequence that decodes outside `0xDC00..=0xDFFF` | The surrogate-pair arm expects the low half in the low-surrogate range; a 3-byte continuation in the surrogate-lead `0xE0..=0xEF` range but outside that band is rejected. Defensive `char::from_u32` check in [`droidsaw_common::encoding::decode_one_codepoint`] also rejects any computed value not in `U+10000..=U+10FFFF`. |
//! | **Overlong 2-byte** | `0xC1 0x81` (encodes `'A'` overlong) | Bypass primitive: post-decode `String` accumulator normalizes to `'A'` while raw-byte signature scans see no `0x41`. Rejected per §3.3.1. The single permitted "overlong" is `0xC0 0x80 → U+0000`. |
//! | **Overlong 3-byte** | `0xE0 0x81 0x82` (encodes `0x42` overlong) | Same scan-bypass concern; values `< 0x800` must use the 1-byte or 2-byte form. |
//! | **Truncated continuation** | `0xC3` alone; `0xE4 0xB8` | `UnexpectedEof` shape — the lead byte promises more continuations than the input supplies. |
//! | **Bad continuation byte** | `0xC0 0x00`; any byte without `b & 0xC0 == 0x80` after a multi-byte lead | Continuation bytes must match `10xxxxxx`. |
//! | **Bare null mid-string** | `0x00` at any position | DEX-spec MUTF-8 string terminator; the codec silently truncates the output at the first bare null and returns `Ok` of the prefix. Callers using `decode_mutf8` directly should account for this. `parse_strings` pre-scans for the NUL before invoking the codec, so the codec sees only the pre-terminator slice. |
//! | **Non-codepoint** | computed `code` for which `char::from_u32(code)` is `None` | Belt-and-suspenders rejection after numeric decode. Cannot fire for surrogate-pair decode (output bounded to `U+10000..=U+10FFFF`); covers any future codec extension. |
//!
//! # What this layer does NOT protect against
//!
//! Per §XVI.6 (honest-naming names what the layer below does NOT
//! promise):
//!
//! - **Consumer-side UTF-8-lossy fallback.** [`crate::parser`]'s
//!   `parse_strings` currently falls back to
//!   [`String::from_utf8_lossy`] on `decode_mutf8` Err. That fallback
//!   re-interprets MUTF-8 bytes as plain UTF-8, producing different
//!   U+FFFD substitution shapes than a MUTF-8-aware lossy decode
//!   would. The closed `droidsaw-audit-mutf8-codec-bypass-fix`
//!   stream measured this at 9.80% of production DEXes (refined to
//!   ~11.32% of production DEXes in corpus measurements). The fallback is
//!   tracked by the `lossy_decode_marks` parallel-vector gauge and
//!   rendered safe at the consumer layer (`string_raw_bytes`
//!   side-table for detector paths), but a scanner that consumes
//!   only the decoded `Vec<String>` still sees the substituted form.
//!   This is a **detector-layer concern**, tracked separately.
//! - **MUTF-8 *encoder* correctness.** This module is decode-only;
//!   `droidsaw-dex/src/emit.rs` owns the encoder, with its own
//!   roundtrip fixtures.
//!
//! # Encoder-side roundtrip
//!
//! For supplementary codepoints, MUTF-8 emits the 6-byte CESU-8
//! surrogate-pair form, not the 4-byte UTF-8 form. This wrapper does
//! not encode; see `droidsaw-dex/src/emit.rs` and its
//! roundtrip-byte-stable fixtures for the encoder side.
#![allow(missing_docs, reason = "internal")]
#![allow(clippy::map_err_ignore, reason = "every `.map_err(|_| DexError::...)` here converts an opaque `common::encoding` error into a DexError variant whose context is captured in the variant fields (offset, etc.). The discarded source adds no actionable info beyond what the typed error already carries.")]

use crate::error::{DexError, Result};

pub fn read_uleb128(data: &[u8], offset: usize) -> Result<(u32, usize)> {
    droidsaw_common::encoding::read_uleb128(data, offset)
        .map_err(|_| DexError::InvalidUleb128 { offset })
}

pub fn read_sleb128(data: &[u8], offset: usize) -> Result<(i32, usize)> {
    droidsaw_common::encoding::read_sleb128(data, offset)
        .map_err(|_| DexError::InvalidUleb128 { offset })
}

pub fn decode_mutf8(bytes: &[u8]) -> Result<String> {
    droidsaw_common::encoding::decode_mutf8(bytes)
        .map_err(|e| match e {
            droidsaw_common::encoding::EncodingError::UnexpectedEof { offset }
            | droidsaw_common::encoding::EncodingError::InvalidSequence { offset } => {
                DexError::InvalidMutf8 { offset }
            }
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // WHY: test
mod tests {
    //! Adversarial coverage for the four surrogate-pair failure cases
    //! the codec must reject (DEX spec §3.3.1). Each test pins one
    //! shape from the honest-naming matrix in the module docstring;
    //! the case set is anchored by corpus measurements showing
    //! ~50/50 lone-high vs lone-low-or-swapped failure
    //! frequency on 110/972 failing production DEXes (11.32%
    //! per-DEX, 0.0113% per-string).
    //!
    //! These tests assert the typed-Err contract at the **dex
    //! wrapper** layer (`mutf8::decode_mutf8 → Result<String,
    //! DexError>`). Equivalent assertions at the common codec layer
    //! live in `droidsaw_common::encoding::tests`.
    use super::*;

    /// **Case 1: lone high surrogate** — high surrogate not followed
    /// by a low-surrogate 3-byte sequence. Empirically the dominant
    /// (49.24%) real-world failure shape per the corpus re-sweep.
    #[test]
    fn lone_high_surrogate_rejected_with_typed_err() {
        // ED A0 BD encodes high surrogate U+D83D.
        // EE 88 9F is U+E21F (private-use plane, NOT a low surrogate).
        // The codec should reject because the post-high-surrogate
        // continuation does not start with another `0xED` byte.
        let bytes = [0xED, 0xA0, 0xBD, 0xEE, 0x88, 0x9F];
        let err = decode_mutf8(&bytes).expect_err("lone high surrogate must reject");
        let DexError::InvalidMutf8 { offset } = err else {
            panic!("expected InvalidMutf8, got {err:?}");
        };
        assert_eq!(offset, 0, "offset points to the high-surrogate codepoint start");
    }

    /// **Case 2: lone low surrogate** — low-surrogate 3-byte
    /// sequence appearing where a fresh codepoint should start.
    #[test]
    fn lone_low_surrogate_rejected_with_typed_err() {
        // ED B8 80 encodes low surrogate U+DE00. With no preceding
        // high-surrogate prefix, the 3-byte arm enters the
        // "lone low surrogate" rejection branch.
        let bytes = [0xED, 0xB8, 0x80];
        let err = decode_mutf8(&bytes).expect_err("lone low surrogate must reject");
        assert!(matches!(err, DexError::InvalidMutf8 { offset: 0 }));
    }

    /// **Case 3: swapped surrogate pair** — low surrogate first,
    /// then high surrogate. Pair order is fixed by CESU-8.
    #[test]
    fn swapped_surrogate_pair_rejected_with_typed_err() {
        // ED B8 80 (low U+DE00) before ED A0 BD (high U+D83D).
        // The low-surrogate-first arm rejects on the first codepoint,
        // before the high half is inspected.
        let bytes = [0xED, 0xB8, 0x80, 0xED, 0xA0, 0xBD];
        let err = decode_mutf8(&bytes).expect_err("swapped pair must reject");
        assert!(matches!(err, DexError::InvalidMutf8 { offset: 0 }));
    }

    /// **Case 4: oversized supplementary** — high surrogate followed
    /// by a 3-byte sequence that decodes outside the low-surrogate
    /// range. The honest-naming matrix calls this the "oversized
    /// supplementary" shape because the arithmetic
    /// `0x10000 + ((high - 0xD800) << 10) + (other - 0xDC00)` would
    /// produce an oversized value if the codec naively trusted the
    /// second half.
    ///
    /// Distinct from Case 1 (lone-high + private-use): here the
    /// continuation IS in the surrogate-lead `0xE0..=0xEF` range,
    /// but its decoded value is not in `0xDC00..=0xDFFF`.
    #[test]
    fn oversized_supplementary_rejected_with_typed_err() {
        // ED A0 BD (high U+D83D) followed by EF BF BF (U+FFFF, the
        // largest BMP codepoint; 3-byte 0xEF lead, not a low surrogate).
        let bytes = [0xED, 0xA0, 0xBD, 0xEF, 0xBF, 0xBF];
        let err = decode_mutf8(&bytes).expect_err("oversized supplementary must reject");
        assert!(matches!(err, DexError::InvalidMutf8 { offset: 0 }));
    }

    /// Regression anchor: the well-formed surrogate pair (high
    /// followed by low) must still decode cleanly. Without this
    /// anchor the four rejection cases above could be satisfied by
    /// a codec that simply rejects ALL `0xED` 3-byte sequences.
    #[test]
    fn well_formed_surrogate_pair_decodes_cleanly() {
        // ED A0 BD ED B8 80 → U+1F600 '😀'.
        let bytes = [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        assert_eq!(decode_mutf8(&bytes).expect("well-formed pair decodes"), "😀");
    }

    /// Regression anchor: the MUTF-8 NUL specialty `0xC0 0x80 →
    /// U+0000` must still decode cleanly. Without this anchor the
    /// surrogate-case tests could be satisfied by a codec that
    /// rejects ANY non-ASCII bytes.
    #[test]
    fn encoded_nul_decodes_cleanly() {
        assert_eq!(decode_mutf8(&[0xC0, 0x80]).expect("encoded NUL decodes"), "\0");
    }

    /// §XVI.11 anti-pattern anchor: the typed-Err contract holds
    /// across truncation shapes an adversary might use to
    /// short-circuit the codec. None of these should panic; all
    /// should return `DexError::InvalidMutf8`.
    #[test]
    fn truncation_shapes_return_typed_err_not_panic() {
        // Bare 2-byte lead with no continuation.
        assert!(matches!(
            decode_mutf8(&[0xC3]),
            Err(DexError::InvalidMutf8 { .. })
        ));
        // 3-byte lead, only one continuation.
        assert!(matches!(
            decode_mutf8(&[0xE4, 0xB8]),
            Err(DexError::InvalidMutf8 { .. })
        ));
        // High surrogate prefix, only one byte of the expected
        // 6-byte surrogate-pair form.
        assert!(matches!(
            decode_mutf8(&[0xED, 0xA0, 0xBD, 0xED]),
            Err(DexError::InvalidMutf8 { .. })
        ));
        // High surrogate prefix + correct second-half lead, but bad
        // continuation byte (not 10xxxxxx).
        assert!(matches!(
            decode_mutf8(&[0xED, 0xA0, 0xBD, 0xED, 0x00, 0x00]),
            Err(DexError::InvalidMutf8 { .. })
        ));
    }
}
