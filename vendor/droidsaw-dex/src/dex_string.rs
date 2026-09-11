//! One entry of the DEX string pool — the bytes plus their decode result.
//!
//! The bytes are the truth; the decoded `String` (when one exists) is a
//! view. This module consolidates the string representation, enforcing by-type
//! what is required by the type system and runtime safety invariants.
//!
//! # Empirical anchor
//!
//! Corpus measurement on 415 APKs / 972 DEXes:
//!
//! - **11.32%** of production DEXes contain at least one
//!   [`DexString::MalformedMutf8`] entry.
//! - Per-string failure rate **0.0113%** (5,016 of 44,420,352).
//! - Shape distribution split **~50/50** between lone-high surrogates
//!   (49.24%) and lone-low / swapped-pair surrogates (50.76%).
//!
//! The dominant real-world source is Kotlin `@Metadata` packing
//! channels embedding binary data via unpaired UTF-16 code units;
//! secondary sources are obfuscators and runtime string manipulation
//! that splits surrogate pairs. The mismatch is structural — Java
//! `String` permits arbitrary 16-bit code units; Rust `String` requires
//! well-formed UTF-8; the impedance gap is unavoidable.
//!
//! # Accessors
//!
//! Three accessors cover the three legitimate consumption patterns:
//!
//! | Accessor | Returns | When to use |
//! |---|---|---|
//! | [`DexString::raw_bytes`] | `&[u8]` | byte-pattern scanners, content-addressable hashing — **the scan-safe path** |
//! | [`DexString::decoded`] | `Result<&str, &EncodingError>` | strict consumers that require a well-formed Rust `&str` |
//! | [`DexString::as_str_lossy`] | `Cow<'_, str>` | decompiler emit, IDE display, log formatting — anything that wants a `&str` and tolerates U+FFFD substitution on malformed input |
//!
//! Migrating a `dex.strings[i]: String` call site to `DexString`
//! means picking which of the three views the consumer actually needs.
//! The type system forces the choice rather than letting detectors
//! silently consume the U+FFFD-substituted form.

use std::ops::Index;

use droidsaw_common::encoding::EncodingError;

/// One DEX string-pool entry — bytes plus decode result plus the
/// two on-disk gauges the parser captures alongside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DexString {
    /// MUTF-8 decoded cleanly to a Rust `String`.
    Decoded {
        /// The on-disk MUTF-8 bytes (excluding ULEB128 prefix and
        /// the terminating `0x00`).
        raw_bytes: Vec<u8>,
        /// Decoded form. Roundtrip invariant:
        /// `encode_mutf8(s) == raw_bytes` for spec-compliant input.
        s: String,
        /// Declared UTF-16 code-unit count from the ULEB128 prefix
        /// at `string_data_off`. Captured for downstream cross-
        /// validation (see
        /// `diag::collect_string_length_findings`).
        declared_chars: u32,
        /// `false` iff the NUL-scan in the parser did NOT find a
        /// `0x00` terminator and silently extended-to-EOF. A
        /// missing terminator is itself a corruption signal even
        /// if parsing recovered.
        had_terminator: bool,
    },
    /// MUTF-8 decode failed (lone surrogate, swapped pair, oversized
    /// supplementary, overlong, truncated continuation, etc.). Only
    /// `raw_bytes` is authoritative — every other field is derived.
    /// `lossy_str` is the pre-computed `from_utf8_lossy(raw_bytes)`
    /// form that [`DexString::as_str_lossy`] returns; carrying it
    /// inline keeps the `&str`-returning accessors fast on hot display
    /// paths.
    ///
    /// **Invariant**: `lossy_str` MUST equal
    /// `String::from_utf8_lossy(&raw_bytes).into_owned()`. This is
    /// enforced by-construction through [`DexString::new_malformed_mutf8`];
    /// `#[non_exhaustive]` on this variant blocks external direct-struct-
    /// literal construction so the invariant cannot be violated from
    /// outside the crate. **Inside `droidsaw-dex`, do NOT construct
    /// `MalformedMutf8 { ... }` directly — use the constructor.**
    #[non_exhaustive]
    MalformedMutf8 {
        /// The on-disk MUTF-8 bytes.
        raw_bytes: Vec<u8>,
        /// `String::from_utf8_lossy(&raw_bytes).into_owned()`,
        /// pre-computed at parse time so display call sites get a
        /// stable `&str` without per-call allocation. Carries U+FFFD
        /// at every malformed-byte position. **Do not use this for
        /// byte-pattern scanning** — use `raw_bytes` instead.
        ///
        /// **Invariant**: equal to `from_utf8_lossy(raw_bytes)` (enforced
        /// by [`DexString::new_malformed_mutf8`]).
        lossy_str: String,
        /// The `EncodingError` returned by `decode_mutf8`. Offset is
        /// relative to the start of `raw_bytes`.
        decode_error: EncodingError,
        /// Declared UTF-16 code-unit count from the ULEB128 prefix.
        declared_chars: u32,
        /// Whether the NUL terminator was present.
        had_terminator: bool,
    },
}

impl DexString {
    /// Construct a [`DexString::Decoded`] variant from a `&str`,
    /// using the UTF-8 bytes of `s` as the on-disk MUTF-8 bytes.
    ///
    /// This is the test / hand-built-IR ergonomic constructor — it
    /// assumes `s` decodes cleanly through MUTF-8 (which is true for
    /// any ASCII / well-formed UTF-8 string that doesn't contain
    /// bare NULs or surrogate halves). The `declared_chars` field is
    /// computed from `s.encode_utf16().count()` and `had_terminator`
    /// defaults to `true`.
    ///
    /// Parser-produced `DexString` entries do NOT use this — the
    /// parser walks `raw_bytes` directly and chooses the variant
    /// based on `decode_mutf8`'s result.
    #[must_use]
    pub fn from_decoded_str(s: &str) -> Self {
        Self::Decoded {
            raw_bytes: s.as_bytes().to_vec(),
            s: s.to_string(),
            declared_chars: s.encode_utf16().count().try_into().unwrap_or(u32::MAX),
            had_terminator: true,
        }
    }

    /// Construct a [`DexString::MalformedMutf8`] variant from its
    /// authoritative inputs (`raw_bytes` + `decode_error` + the two
    /// on-disk gauges). Computes `lossy_str` internally so the
    /// `lossy_str ≡ from_utf8_lossy(raw_bytes)` invariant holds by-
    /// construction.
    ///
    /// This is the **only sanctioned** way to build a `MalformedMutf8`
    /// entry — the variant is `#[non_exhaustive]`, so external crates
    /// cannot use direct struct-literal syntax; in-crate callers must
    /// use this constructor to keep the invariant intact.
    #[must_use]
    pub fn new_malformed_mutf8(
        raw_bytes: Vec<u8>,
        decode_error: EncodingError,
        declared_chars: u32,
        had_terminator: bool,
    ) -> Self {
        let lossy_str = String::from_utf8_lossy(&raw_bytes).into_owned();
        Self::MalformedMutf8 {
            raw_bytes,
            lossy_str,
            decode_error,
            declared_chars,
            had_terminator,
        }
    }

    /// The on-disk MUTF-8 bytes for this string. Always available,
    /// regardless of decode outcome. **This is the scan-safe view** —
    /// byte-pattern detectors (YARA, trufflehog, AWS-key heuristics,
    /// signature scanners) must use this, not [`Self::as_str_lossy`].
    #[inline]
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        match self {
            Self::Decoded { raw_bytes, .. } | Self::MalformedMutf8 { raw_bytes, .. } => raw_bytes,
        }
    }

    /// Strict decoded view. Returns `Ok(&str)` only when the parser
    /// successfully decoded the MUTF-8 bytes to a well-formed Rust
    /// `String`; returns `Err(&EncodingError)` otherwise.
    ///
    /// Use this when the consumer **requires** a well-formed Rust
    /// string and is prepared to handle the decode-failure case
    /// explicitly. For decompiler emit / IDE display / log formatting,
    /// prefer [`Self::as_str_lossy`] instead.
    #[inline]
    pub fn decoded(&self) -> Result<&str, &EncodingError> {
        match self {
            Self::Decoded { s, .. } => Ok(s.as_str()),
            Self::MalformedMutf8 { decode_error, .. } => Err(decode_error),
        }
    }

    /// Lossy display view. Returns the well-formed decoded `&str` on
    /// [`DexString::Decoded`]; returns the pre-computed
    /// `from_utf8_lossy` form on [`DexString::MalformedMutf8`].
    ///
    /// This is the right accessor for decompiler emit, IDE display,
    /// log messages, and any other path that wants a `&str` to print
    /// and tolerates lossy substitution on malformed input. **Do not
    /// use this for byte-pattern scanning** — the U+FFFD substitution
    /// loses the original bytes; use [`DexString::raw_bytes`] for
    /// that.
    #[inline]
    #[must_use]
    pub fn as_str_lossy(&self) -> &str {
        match self {
            Self::Decoded { s, .. } | Self::MalformedMutf8 { lossy_str: s, .. } => s.as_str(),
        }
    }

    /// Declared UTF-16 code-unit count from the on-disk ULEB128
    /// prefix at `string_data_off`. The DEX spec
    /// (`string_data_item.utf16_size`) makes this the authoritative
    /// count; `diag::collect_string_length_findings` cross-validates
    /// it against the NUL-scan-derived count and emits a Finding on
    /// disagreement.
    #[inline]
    #[must_use]
    pub fn declared_chars(&self) -> u32 {
        match self {
            Self::Decoded { declared_chars, .. } | Self::MalformedMutf8 { declared_chars, .. } => {
                *declared_chars
            }
        }
    }

    /// `true` iff the on-disk NUL terminator was present. `false`
    /// signals corruption — the parser silently extended-to-EOF and
    /// downstream detection should flag the entry.
    #[inline]
    #[must_use]
    pub fn had_terminator(&self) -> bool {
        match self {
            Self::Decoded { had_terminator, .. } | Self::MalformedMutf8 { had_terminator, .. } => {
                *had_terminator
            }
        }
    }

    /// `true` iff this entry could not be decoded as well-formed
    /// MUTF-8 / UTF-8 and any display rendering would substitute
    /// U+FFFD. Equivalent to `matches!(self, MalformedMutf8 { .. })`
    /// and to the old `string_has_lossy_decode(idx) == Some(true)`
    /// accessor.
    #[inline]
    #[must_use]
    pub fn is_lossy(&self) -> bool {
        matches!(self, Self::MalformedMutf8 { .. })
    }
}

/// Lexicographic ordering by [`DexString::raw_bytes`] — the canonical
/// sort key the DEX spec (§7.5) uses for the on-disk `string_ids`
/// table. Two entries with identical raw bytes are equal here even
/// if one is `Decoded` and the other is `MalformedMutf8`, because
/// the bytes are the source of truth and the decode outcome is a
/// derived property.
impl Ord for DexString {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw_bytes().cmp(other.raw_bytes())
    }
}

impl PartialOrd for DexString {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Convenience: `dex_string[..]` syntax for the raw bytes. Lets
/// existing code that uses byte-slice ops (`.starts_with(b"...")`,
/// `.contains(&b'/')`, etc.) work without an explicit `.raw_bytes()`
/// call.
impl<I> Index<I> for DexString
where
    I: std::slice::SliceIndex<[u8]>,
{
    type Output = I::Output;
    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        #[allow(clippy::indexing_slicing, reason = "`Index::index` is itself a panicking trait by design — callers opt into the panic by writing `dex_string[i]`. The `.get(index)` path here would be `SliceIndex::index(self, ...)` which has the same panic behavior. Use `.get` for non-panicking bounds-checked access.")]
        &self.raw_bytes()[index]
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // WHY: test
mod tests {
    use super::*;

    fn decoded(s: &str) -> DexString {
        DexString::Decoded {
            raw_bytes: s.as_bytes().to_vec(),
            s: s.to_string(),
            declared_chars: s.encode_utf16().count() as u32,
            had_terminator: true,
        }
    }

    fn malformed(bytes: &[u8]) -> DexString {
        DexString::new_malformed_mutf8(
            bytes.to_vec(),
            EncodingError::InvalidSequence { offset: 0 },
            1,
            true,
        )
    }

    #[test]
    fn decoded_accessors() {
        let d = decoded("hello");
        assert_eq!(d.raw_bytes(), b"hello");
        assert_eq!(d.decoded().unwrap(), "hello");
        assert_eq!(d.as_str_lossy(), "hello");
        assert!(!d.is_lossy());
        assert!(d.had_terminator());
        assert_eq!(d.declared_chars(), 5);
    }

    #[test]
    fn malformed_accessors() {
        // ED A0 BD = lone high surrogate, the corpus-dominant shape.
        let m = malformed(&[0xED, 0xA0, 0xBD]);
        assert_eq!(m.raw_bytes(), &[0xED, 0xA0, 0xBD]);
        assert!(m.decoded().is_err());
        let lossy = m.as_str_lossy();
        // String::from_utf8_lossy substitutes U+FFFD for the bad
        // 3-byte sequence — exact byte length depends on stdlib, but
        // the important assertion is "this is not the raw bytes."
        assert_ne!(lossy.as_bytes(), &[0xED, 0xA0, 0xBD]);
        assert!(m.is_lossy());
    }

    #[test]
    fn index_yields_raw_bytes() {
        let d = decoded("abc");
        assert_eq!(&d[..], b"abc");
        assert_eq!(d[0], b'a');

        let m = malformed(&[0xED, 0xA0, 0xBD]);
        assert_eq!(&m[..], &[0xED, 0xA0, 0xBD]);
        assert_eq!(m[1], 0xA0);
    }

    /// Anchor: `is_lossy()` is the byte-equality-of-truth gauge.
    /// `string_has_lossy_decode(idx) == Some(true)` on the old API
    /// corresponds to `dex.strings[idx].is_lossy() == true` here.
    #[test]
    fn is_lossy_matches_variant() {
        assert!(!decoded("ok").is_lossy());
        assert!(malformed(&[0x80]).is_lossy());
    }
}
