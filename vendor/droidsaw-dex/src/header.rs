//! DEX file header and section table parsing.
#![allow(missing_docs, reason = "internal")]
use scroll::{Pread, LE};

use crate::error::{DexError, Result};

const HEADER_SIZE: usize = 112;
/// DEX spec §3.1: the canonical header is exactly 112 (`0x70`) bytes.
/// The on-disk `header_size` field must declare this value; any other
/// value indicates a malformed / adversarial header and is rejected
/// at parse time via `DexError::InvalidHeaderSize`. The gauge prevents
/// observed-vs-declared geometry audits from silently missing a
/// wrong-shape header.
const CANONICAL_HEADER_SIZE: u32 = 0x70;
const DEX_MAGIC: &[u8; 4] = b"dex\n";
const ENDIAN_CONSTANT: u32 = 0x12345678;
const SUPPORTED_VERSIONS: &[&[u8; 3]] = &[b"035", b"037", b"038", b"039", b"040", b"041"];

/// Endian-tag canonical-value gate. DEX spec fixes `endian_tag` at
/// exactly `0x12345678` (little-endian on every supported target).
/// Any other value — including the byte-swapped `0x78563412`
/// REVERSE_ENDIAN_CONSTANT that ART itself rejects
/// (`runtime/dex_file.cc::CheckMagicAndVersion`) — surfaces as
/// `Err(DexError::BadEndianTag { tag })` carrying the raw observed
/// u32 for triage.
///
/// Extracted from `DexHeader::parse`'s inline endian arm so the
/// Kani harness can verify the gate without symbolically modeling
/// the upstream `SUPPORTED_VERSIONS.iter().any()` slice-compare
/// loops (which blow CBMC's state space at any meaningful unwind
/// bound on a full `kani::any::<u32>()` enumeration). The helper
/// is a single-comparison `const fn`; the harness enumerates the
/// full u32 input space in a tight envelope.
///
/// Verified by `proofs/endian_tag_gauge.rs`.
pub(crate) const fn validate_endian_tag(tag: u32) -> Result<()> {
    if tag == ENDIAN_CONSTANT {
        Ok(())
    } else {
        Err(DexError::BadEndianTag { tag })
    }
}

/// Raw DEX file header (112 bytes at offset 0).
#[derive(Debug, Clone, PartialEq)]
pub struct DexHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

impl DexHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(DexError::Truncated {
                offset: 0,
                need: HEADER_SIZE,
                have: data.len(),
            });
        }

        // Validate magic
        let mut magic = [0u8; 8];
        let Some(magic_src) = data.get(..8) else {
            return Err(DexError::Truncated {
                offset: 0,
                need: HEADER_SIZE,
                have: data.len(),
            });
        };
        magic.copy_from_slice(magic_src);

        if &magic[..4] != DEX_MAGIC {
            let mut found = [0u8; 4];
            found.copy_from_slice(&magic[..4]);
            return Err(DexError::BadMagic { found });
        }

        // Validate version
        let version = &magic[4..7];
        if !SUPPORTED_VERSIONS.iter().any(|v| v.as_slice() == version) {
            return Err(DexError::UnsupportedVersion {
                version: String::from_utf8_lossy(version).into_owned(),
            });
        }

        // Null terminator
        if magic[7] != 0 {
            let mut found = [0u8; 4];
            found.copy_from_slice(&magic[..4]);
            return Err(DexError::BadMagic { found });
        }

        let pread = |off: usize| -> Result<u32> {
            data.pread_with::<u32>(off, LE)
                .map_err(|e| DexError::ScrollRead {
                    offset: off,
                    source: e,
                })
        };

        let checksum = pread(8)?;

        let mut signature = [0u8; 20];
        let Some(sig_src) = data.get(12..32) else {
            return Err(DexError::Truncated {
                offset: 12,
                need: 20,
                have: data.len().saturating_sub(12),
            });
        };
        signature.copy_from_slice(sig_src);

        let file_size = pread(32)?;
        let header_size = pread(36)?;
        if header_size != CANONICAL_HEADER_SIZE {
            return Err(DexError::InvalidHeaderSize {
                declared: header_size,
            });
        }
        let endian_tag = pread(40)?;
        validate_endian_tag(endian_tag)?;

        Ok(Self {
            magic,
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size: pread(44)?,
            link_off: pread(48)?,
            map_off: pread(52)?,
            string_ids_size: pread(56)?,
            string_ids_off: pread(60)?,
            type_ids_size: pread(64)?,
            type_ids_off: pread(68)?,
            proto_ids_size: pread(72)?,
            proto_ids_off: pread(76)?,
            field_ids_size: pread(80)?,
            field_ids_off: pread(84)?,
            method_ids_size: pread(88)?,
            method_ids_off: pread(92)?,
            class_defs_size: pread(96)?,
            class_defs_off: pread(100)?,
            data_size: pread(104)?,
            data_off: pread(108)?,
        })
    }

    /// DEX version string, e.g. "035", "039".
    #[allow(
        clippy::expect_used,
        reason = "PROOF: a `DexHeader` is only constructed via `parse()`, which asserts `magic[4..7]` matches one of `SUPPORTED_VERSIONS` (all 3-byte ASCII strings). The earlier `unwrap_or(\"???\")` defense-in-depth was dead — `from_utf8` on ASCII never fails. Removing it surfaces the actual invariant; if `SUPPORTED_VERSIONS` ever gains a non-UTF-8 entry the `expect` here aborts at runtime under `panic = abort`, making the invariant break loud rather than silently masking it as `\"???\"`."
    )]
    pub fn version(&self) -> &str {
        std::str::from_utf8(&self.magic[4..7])
            .expect("magic[4..7] is ASCII by SUPPORTED_VERSIONS gate in parse()")
    }

    /// Verify the Adler-32 checksum over bytes [12..file_size].
    pub fn verify_checksum(&self, data: &[u8]) -> Result<()> {
        // PROOF: `self.file_size: u32` → `usize` widening, lossless on
        // 64-bit targets (droidsaw's supported set). The `end > data.len()`
        // check below catches OOB before slicing.
        #[allow(clippy::as_conversions, reason = "PROOF: u32 → usize widening, lossless on 64-bit; bounded by `end > data.len()` check.")]
        let end = self.file_size as usize;
        if end > data.len() {
            return Err(DexError::Truncated {
                offset: 0,
                need: end,
                have: data.len(),
            });
        }
        if end < 12 {
            return Err(DexError::Truncated {
                offset: 0,
                need: 12,
                have: end,
            });
        }
        let Some(checksum_input) = data.get(12..end) else {
            return Err(DexError::Truncated {
                offset: 12,
                need: end.saturating_sub(12),
                have: data.len().saturating_sub(12),
            });
        };
        let computed = adler2::adler32_slice(checksum_input);
        if computed != self.checksum {
            return Err(DexError::ChecksumMismatch {
                expected: self.checksum,
                computed,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(version: &[u8; 3]) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_SIZE];
        // magic
        buf[..4].copy_from_slice(b"dex\n");
        buf[4..7].copy_from_slice(version);
        buf[7] = 0;
        // checksum at 8 — skip (not validated in parse)
        // signature at 12 — skip
        // file_size at 32
        buf[32..36].copy_from_slice(&112u32.to_le_bytes());
        // header_size at 36
        buf[36..40].copy_from_slice(&112u32.to_le_bytes());
        // endian_tag at 40
        buf[40..44].copy_from_slice(&ENDIAN_CONSTANT.to_le_bytes());
        buf
    }

    #[test]
    fn parse_valid_header() {
        let buf = make_header(b"035");
        let hdr = DexHeader::parse(&buf).unwrap();
        assert_eq!(hdr.version(), "035");
        assert_eq!(hdr.file_size, 112);
        assert_eq!(hdr.header_size, 112);
    }

    #[test]
    fn parse_all_versions() {
        for ver in SUPPORTED_VERSIONS {
            let buf = make_header(ver);
            let hdr = DexHeader::parse(&buf).unwrap();
            assert_eq!(hdr.version().as_bytes(), ver.as_slice());
        }
    }

    #[test]
    fn bad_magic() {
        let mut buf = make_header(b"035");
        buf[0] = b'X';
        assert!(matches!(
            DexHeader::parse(&buf),
            Err(DexError::BadMagic { .. })
        ));
    }

    #[test]
    fn unsupported_version() {
        let buf = make_header(b"099");
        assert!(matches!(
            DexHeader::parse(&buf),
            Err(DexError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn bad_endian_tag_canonical_swapped() {
        // Build a well-formed header with the byte-swapped
        // REVERSE_ENDIAN_CONSTANT — the canonical ART-rejected value.
        let mut buf = make_header(b"035");
        buf[40..44].copy_from_slice(&0x7856_3412_u32.to_le_bytes());
        match DexHeader::parse(&buf) {
            Err(DexError::BadEndianTag { tag }) => {
                assert_eq!(tag, 0x7856_3412, "BadEndianTag carries raw observed value");
            }
            other => panic!("expected BadEndianTag(0x78563412), got {other:?}"),
        }
    }

    #[test]
    fn bad_endian_tag_garbage() {
        let mut buf = make_header(b"035");
        buf[40..44].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        match DexHeader::parse(&buf) {
            Err(DexError::BadEndianTag { tag }) => {
                assert_eq!(tag, 0xDEAD_BEEF);
            }
            other => panic!("expected BadEndianTag(0xDEADBEEF), got {other:?}"),
        }
    }

    #[test]
    fn truncated_input() {
        let buf = vec![0u8; 50];
        assert!(matches!(
            DexHeader::parse(&buf),
            Err(DexError::Truncated { .. })
        ));
    }

    // ── InvalidHeaderSize gauge ───────────────────────────────────────

    #[test]
    fn parse_rejects_header_size_zero() {
        let mut buf = make_header(b"035");
        buf[36..40].copy_from_slice(&0u32.to_le_bytes());
        let err = DexHeader::parse(&buf).unwrap_err();
        assert!(
            matches!(err, DexError::InvalidHeaderSize { declared: 0 }),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_rejects_header_size_8() {
        // 8 is the prior "Truncated have: 8" placeholder-fixture value;
        // verify the gauge fires on it regardless of buffer length.
        let mut buf = make_header(b"035");
        buf[36..40].copy_from_slice(&8u32.to_le_bytes());
        let err = DexHeader::parse(&buf).unwrap_err();
        assert!(
            matches!(err, DexError::InvalidHeaderSize { declared: 8 }),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_rejects_header_size_113_off_by_one() {
        // Off-by-one above canonical — must still be rejected. The gauge
        // is equality, not range.
        let mut buf = make_header(b"035");
        buf[36..40].copy_from_slice(&113u32.to_le_bytes());
        let err = DexHeader::parse(&buf).unwrap_err();
        assert!(
            matches!(err, DexError::InvalidHeaderSize { declared: 113 }),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_rejects_header_size_u32_max() {
        let mut buf = make_header(b"035");
        buf[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = DexHeader::parse(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                DexError::InvalidHeaderSize {
                    declared: u32::MAX
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_accepts_canonical_header_size_0x70() {
        // make_header already writes 0x70 at offset 36; sanity-check
        // that the canonical value is accepted unmodified.
        let buf = make_header(b"035");
        let hdr = DexHeader::parse(&buf).unwrap();
        assert_eq!(hdr.header_size, CANONICAL_HEADER_SIZE);
    }

    // ── version() dead-defense retire ─────────────────────────────────

    #[test]
    fn version_round_trips_every_supported_version() {
        // The `unwrap_or("???")` defense at `version()` was dead because
        // parse() asserts magic[4..7] matches a SUPPORTED_VERSIONS entry
        // (all 3-byte ASCII). Verify the accessor produces a valid
        // &str for every supported version. (The earlier
        // `parse_all_versions` test exercises parse but doesn't check
        // round-trip for every supported version through the accessor.)
        for ver in SUPPORTED_VERSIONS {
            let buf = make_header(ver);
            let hdr = DexHeader::parse(&buf).unwrap();
            assert_eq!(hdr.version().as_bytes(), ver.as_slice());
        }
    }
}
