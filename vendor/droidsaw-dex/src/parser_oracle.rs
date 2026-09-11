// PARSER-ORACLE: Textbook recursive-descent on raw bytes.
// Sole purpose: differential cross-check on production DexFile::parse.
// MUST NOT call production DexFile::parse or any parser helper.
// If both share a decoder, both can be wrong in the same way.

// MAINTENANCE: This oracle covers the structural sections of the DEX format
// enumerated in the parser-differential-oracle maintenance doc:
//   header fields (magic, counts, offsets)
//   string_id_item array → string_data_item (ULEB128 length + MUTF-8 bytes)
//   type_id_item array → descriptor_idx per entry
//   class_def_item array → class_idx per entry
// Production parse sites:
//   droidsaw-dex/src/header.rs (DexHeader::parse)
//   droidsaw-dex/src/parser.rs:551 (parse_inner)
//   droidsaw-dex/src/parser.rs:976 (parse_strings)
//   droidsaw-dex/src/parser.rs:1051 (parse_string_raw_bytes)
//   droidsaw-dex/src/parser.rs:1084 (parse_types)
//   droidsaw-dex/src/parser.rs:1413 (parse_class_defs)
//
// ParseShape deliberately does NOT reuse DexHeader — shared types hide mismatches.

// Coverage table:
// - Header: magic[8], string_ids_size, string_ids_off, type_ids_size,
//           type_ids_off, class_defs_size, class_defs_off: COVERED
// - strings: raw MUTF-8 bytes per entry (pre-decode): COVERED
// - type_descriptors: descriptor_idx per type_id_item: COVERED
// - class_def_class_types: class_idx per class_def_item: COVERED
// - method_ids, field_ids, protos: NOT COVERED (out of scope)
// - code_items: NOT COVERED (instruction-level oracle is the CFG-builder concern)

#![cfg(any(test, kani, fuzzing))]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    missing_docs,
    reason = "PROOF: all arithmetic in this module is bounds-checked before use. \
              Multiplications use checked_mul; additions use checked_add; every \
              byte read is preceded by a bounds check that returns Err on failure. \
              as-casts from u32 to usize are safe on all supported platforms \
              (usize >= 32 bits). usize to u32 narrowing (id_off, ULEB128 result) \
              is bounded by DEX file_size: u32 from the header. missing_docs: \
              oracle module is test/fuzz-only."
)]

// ─── ParseShape — the oracle's comparison subject ─────────────────────────

/// Extracted DEX parse shape for differential comparison.
///
/// Production `DexFile` goes through `DexFile::to_shape()` before comparison;
/// the naive oracle returns this type directly. Both paths are independent —
/// `ParseShape` is the only comparison surface; no production types are reused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexParseShape {
    /// First 8 bytes of the file (magic + version + NUL).
    pub header_magic: [u8; 8],
    /// `string_ids_size` from the header.
    pub string_ids_size: u32,
    /// `string_ids_off` from the header.
    pub string_ids_off: u32,
    /// `type_ids_size` from the header.
    pub type_ids_size: u32,
    /// `type_ids_off` from the header.
    pub type_ids_off: u32,
    /// `class_defs_size` from the header.
    pub class_defs_size: u32,
    /// `class_defs_off` from the header.
    pub class_defs_off: u32,
    /// Raw MUTF-8 bytes for each string (pre-decode), in string-pool order.
    pub strings: Vec<Vec<u8>>,
    /// `descriptor_idx` per type_id_item entry, in order.
    pub type_descriptors: Vec<u32>,
    /// `class_idx` per class_def_item entry, in order.
    pub class_def_class_types: Vec<u32>,
}

/// Errors produced by the naive DEX parser oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOracleError {
    /// Input too short to contain the 112-byte DEX header.
    TruncatedHeader { have: usize },
    /// Magic bytes are not `dex\n`.
    BadMagic { found: [u8; 4] },
    /// Version bytes are not in the supported set.
    UnsupportedVersion { version: [u8; 3] },
    /// NUL terminator after version is missing.
    MissingNul,
    /// `file_size` field is smaller than the minimum meaningful size (12)
    /// or larger than the buffer, matching production `verify_checksum` gates.
    FileSizeInvalid { file_size: u32, buf_len: usize },
    /// Endian tag is not the expected little-endian constant.
    BadEndianTag { found: u32 },
    /// A `string_id_item` offset points outside the buffer.
    StringIdOffsetOob { index: usize, offset: u32 },
    /// ULEB128 overflow while reading a string's declared length.
    UlebOverflow { string_index: usize },
    /// A `type_id_item` offset points outside the buffer.
    TypeIdOffsetOob { index: usize },
    /// A `class_def_item` offset points outside the buffer.
    ClassDefOffsetOob { index: usize },
    /// Arithmetic overflow computing an offset or size.
    ArithmeticOverflow { context: &'static str },
    /// A count would imply a region larger than the input buffer.
    CountExceedsBounds {
        what: &'static str,
        count: u32,
        stride: usize,
        file_size: usize,
    },
}

impl core::fmt::Display for ParseOracleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── Internal helpers (no shared code with production) ────────────────────

/// Bounds-checked little-endian u32 reader. Returns `Err` on OOB.
/// No dependency on `scroll` or any production decoder.
fn read_le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let chunk = data.get(offset..end)?;
    Some(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

/// Minimum ULEB128 read. Returns `(value, bytes_consumed)` or `None` on OOB
/// or overflow (value exceeds u32::MAX). Reads at most 5 bytes (DEX spec:
/// `utf16_size` is a `uint` — at most 32 bits in ULEB128 encoding).
fn read_uleb128(data: &[u8], offset: usize) -> Option<(u32, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut consumed = 0usize;
    loop {
        if shift > 28 {
            // DEX ULEB128 values are `uint` (32-bit); more than 5 bytes
            // would overflow. Stop here to match the production contract.
            return None;
        }
        let byte = *data.get(offset.checked_add(consumed)?)?;
        consumed += 1;
        result |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    if result > u64::from(u32::MAX) {
        return None;
    }
    Some((result as u32, consumed))
}

/// Bound-count guard matching production `error::bound_count` semantics.
/// Verifies `count * stride <= file_size`. Returns `Err` on overflow or
/// bound violation.
fn bound_count(
    count: u32,
    stride: usize,
    file_size: usize,
    what: &'static str,
) -> Result<usize, ParseOracleError> {
    let total = (count as usize)
        .checked_mul(stride)
        .ok_or(ParseOracleError::ArithmeticOverflow { context: what })?;
    if total > file_size {
        return Err(ParseOracleError::CountExceedsBounds {
            what,
            count,
            stride,
            file_size,
        });
    }
    Ok(count as usize)
}

// ─── DEX header constants (independent of production header.rs) ───────────

const DEX_MAGIC_BYTES: [u8; 4] = *b"dex\n";
const DEX_HEADER_SIZE: usize = 112;
const DEX_ENDIAN_CONSTANT: u32 = 0x12345678;
const DEX_SUPPORTED_VERSIONS: [[u8; 3]; 6] =
    [*b"035", *b"037", *b"038", *b"039", *b"040", *b"041"];

// Offsets within the 112-byte DEX header (little-endian u32 fields).
// OFF_CHECKSUM and OFF_FILE_SIZE / OFF_HEADER_SIZE are not used by the oracle
// (structural parse only; checksum verification is production-only).
const OFF_ENDIAN_TAG: usize = 40;
const OFF_STRING_IDS_SIZE: usize = 56;
const OFF_STRING_IDS_OFF: usize = 60;
const OFF_TYPE_IDS_SIZE: usize = 64;
const OFF_TYPE_IDS_OFF: usize = 68;
const OFF_PROTO_IDS_SIZE: usize = 72;
const OFF_FIELD_IDS_SIZE: usize = 80;
const OFF_METHOD_IDS_SIZE: usize = 88;
const OFF_CLASS_DEFS_SIZE: usize = 96;
const OFF_CLASS_DEFS_OFF: usize = 100;

// Section strides (bytes per item).
const STRING_ID_STRIDE: usize = 4;   // string_data_off (u32)
const TYPE_ID_STRIDE: usize = 4;     // descriptor_idx (u32)
const PROTO_ID_STRIDE: usize = 12;   // shorty_idx + return_type_idx + parameters_off
const FIELD_ID_STRIDE: usize = 8;    // class_idx + type_idx + name_idx (packed)
const METHOD_ID_STRIDE: usize = 8;   // class_idx + proto_idx + name_idx (packed)
const CLASS_DEF_STRIDE: usize = 32;  // 8 × u32

// ─── Naive parser entry point ─────────────────────────────────────────────

/// Naive textbook recursive-descent DEX parser. Produces a `DexParseShape`
/// for differential comparison against `DexFile::parse`.
///
/// This function MUST NOT call `DexFile::parse`, `DexHeader::parse`,
/// `parse_inner`, `parse_strings`, or any production parser helper. It
/// implements its own field decoders from scratch using `read_le_u32` and
/// `read_uleb128` above.
pub fn naive_parse_dex(data: &[u8]) -> Result<DexParseShape, ParseOracleError> {
    // ── 1. Header (112 bytes) ──────────────────────────────────────────────
    if data.len() < DEX_HEADER_SIZE {
        return Err(ParseOracleError::TruncatedHeader { have: data.len() });
    }

    // Magic: bytes [0..4] must be b"dex\n".
    let magic_bytes: [u8; 4] = [data[0], data[1], data[2], data[3]];
    if magic_bytes != DEX_MAGIC_BYTES {
        return Err(ParseOracleError::BadMagic { found: magic_bytes });
    }

    // Version: bytes [4..7] must be in supported set.
    let version_bytes: [u8; 3] = [data[4], data[5], data[6]];
    if !DEX_SUPPORTED_VERSIONS.iter().any(|v| v == &version_bytes) {
        return Err(ParseOracleError::UnsupportedVersion { version: version_bytes });
    }

    // NUL terminator at byte 7.
    if data[7] != 0 {
        return Err(ParseOracleError::MissingNul);
    }

    // Reconstruct header_magic: bytes [0..8].
    let header_magic: [u8; 8] = [
        data[0], data[1], data[2], data[3],
        data[4], data[5], data[6], data[7],
    ];

    // file_size at offset 32 — validated the same way production's
    // `verify_checksum` does: (1) file_size must not exceed buf.len(),
    // (2) file_size must be >= 12 (at minimum covers magic + checksum).
    // Both gates produce `DexError::Truncated` in production; the oracle
    // mirrors them so it does not accept inputs production would reject.
    let file_size = read_le_u32(data, 32)
        .ok_or(ParseOracleError::TruncatedHeader { have: data.len() })?;
    if file_size as usize > data.len() || file_size < 12 {
        return Err(ParseOracleError::FileSizeInvalid {
            file_size,
            buf_len: data.len(),
        });
    }

    // Endian tag must be the LE constant.
    let endian_tag = read_le_u32(data, OFF_ENDIAN_TAG)
        .ok_or(ParseOracleError::TruncatedHeader { have: data.len() })?;
    if endian_tag != DEX_ENDIAN_CONSTANT {
        return Err(ParseOracleError::BadEndianTag { found: endian_tag });
    }

    // Read the section-pointer fields we need.
    let string_ids_size = read_le_u32(data, OFF_STRING_IDS_SIZE)
        .ok_or(ParseOracleError::TruncatedHeader { have: data.len() })?;
    let string_ids_off = read_le_u32(data, OFF_STRING_IDS_OFF)
        .ok_or(ParseOracleError::TruncatedHeader { have: data.len() })?;
    let type_ids_size = read_le_u32(data, OFF_TYPE_IDS_SIZE)
        .ok_or(ParseOracleError::TruncatedHeader { have: data.len() })?;
    let type_ids_off = read_le_u32(data, OFF_TYPE_IDS_OFF)
        .ok_or(ParseOracleError::TruncatedHeader { have: data.len() })?;
    let proto_ids_size = read_le_u32(data, OFF_PROTO_IDS_SIZE)
        .ok_or(ParseOracleError::TruncatedHeader { have: data.len() })?;
    let field_ids_size = read_le_u32(data, OFF_FIELD_IDS_SIZE)
        .ok_or(ParseOracleError::TruncatedHeader { have: data.len() })?;
    let method_ids_size = read_le_u32(data, OFF_METHOD_IDS_SIZE)
        .ok_or(ParseOracleError::TruncatedHeader { have: data.len() })?;
    let class_defs_size = read_le_u32(data, OFF_CLASS_DEFS_SIZE)
        .ok_or(ParseOracleError::TruncatedHeader { have: data.len() })?;
    let class_defs_off = read_le_u32(data, OFF_CLASS_DEFS_OFF)
        .ok_or(ParseOracleError::TruncatedHeader { have: data.len() })?;

    // Bound-count guards mirror production discipline — all section counts
    // validated before any allocations, even sections the oracle does not
    // decode (proto, field, method). This prevents oracle-more-permissive
    // divergence for inputs production rejects at its own bound_count gates.
    let string_count = bound_count(string_ids_size, STRING_ID_STRIDE, data.len(), "string_ids")?;
    let type_count = bound_count(type_ids_size, TYPE_ID_STRIDE, data.len(), "type_ids")?;
    bound_count(proto_ids_size, PROTO_ID_STRIDE, data.len(), "proto_ids")?;
    bound_count(field_ids_size, FIELD_ID_STRIDE, data.len(), "field_ids")?;
    bound_count(method_ids_size, METHOD_ID_STRIDE, data.len(), "method_ids")?;
    let class_count = bound_count(class_defs_size, CLASS_DEF_STRIDE, data.len(), "class_defs")?;

    // ── 2. String table ───────────────────────────────────────────────────
    // For each string_id_item at string_ids_off + i*4:
    //   read u32 string_data_off → points to {ULEB128 utf16_size; MUTF-8 bytes; \0}
    //   extract raw MUTF-8 bytes (pre-decode, NUL-terminated scan matching production)
    let string_base = string_ids_off as usize;
    let mut strings: Vec<Vec<u8>> = Vec::with_capacity(string_count);

    for i in 0..string_count {
        let id_off = string_base
            .checked_add(i.checked_mul(STRING_ID_STRIDE).ok_or(
                ParseOracleError::ArithmeticOverflow { context: "string_id_stride" },
            )?)
            .ok_or(ParseOracleError::ArithmeticOverflow { context: "string_id_off" })?;

        let string_data_off = read_le_u32(data, id_off)
            .ok_or(ParseOracleError::StringIdOffsetOob { index: i, offset: id_off as u32 })?;

        let sdo = string_data_off as usize;
        if sdo >= data.len() {
            return Err(ParseOracleError::StringIdOffsetOob {
                index: i,
                offset: string_data_off,
            });
        }

        // Read ULEB128 utf16_size (skip it — we only need the raw bytes).
        let (_utf16_size, uleb_len) = read_uleb128(data, sdo)
            .ok_or(ParseOracleError::UlebOverflow { string_index: i })?;

        let str_start = sdo
            .checked_add(uleb_len)
            .ok_or(ParseOracleError::ArithmeticOverflow { context: "str_start" })?;

        // NUL-scan: match production's `unwrap_or(data.len())` fallback exactly.
        let suffix = data.get(str_start..).unwrap_or(&[]);
        let str_end = match suffix.iter().position(|&b| b == 0) {
            Some(p) => str_start
                .checked_add(p)
                .ok_or(ParseOracleError::ArithmeticOverflow { context: "str_end" })?,
            None => data.len(),
        };

        let raw = data.get(str_start..str_end).unwrap_or(&[]);
        strings.push(raw.to_vec());
    }

    // ── 3. Type descriptor table ───────────────────────────────────────────
    // For each type_id_item at type_ids_off + i*4:
    //   read u32 descriptor_idx → index into string pool
    let type_base = type_ids_off as usize;
    let mut type_descriptors: Vec<u32> = Vec::with_capacity(type_count);

    for i in 0..type_count {
        let off = type_base
            .checked_add(i.checked_mul(TYPE_ID_STRIDE).ok_or(
                ParseOracleError::ArithmeticOverflow { context: "type_id_stride" },
            )?)
            .ok_or(ParseOracleError::ArithmeticOverflow { context: "type_id_off" })?;

        let descriptor_idx = read_le_u32(data, off)
            .ok_or(ParseOracleError::TypeIdOffsetOob { index: i })?;
        type_descriptors.push(descriptor_idx);
    }

    // ── 4. Class definition table ──────────────────────────────────────────
    // For each class_def_item at class_defs_off + i*32:
    //   read u32 class_idx at byte offset 0 within item
    let class_base = class_defs_off as usize;
    let mut class_def_class_types: Vec<u32> = Vec::with_capacity(class_count);

    for i in 0..class_count {
        let off = class_base
            .checked_add(i.checked_mul(CLASS_DEF_STRIDE).ok_or(
                ParseOracleError::ArithmeticOverflow { context: "class_def_stride" },
            )?)
            .ok_or(ParseOracleError::ArithmeticOverflow { context: "class_def_off" })?;

        let class_idx = read_le_u32(data, off)
            .ok_or(ParseOracleError::ClassDefOffsetOob { index: i })?;
        class_def_class_types.push(class_idx);
    }

    Ok(DexParseShape {
        header_magic,
        string_ids_size,
        string_ids_off,
        type_ids_size,
        type_ids_off,
        class_defs_size,
        class_defs_off,
        strings,
        type_descriptors,
        class_def_class_types,
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::DexFile;

    // ── Helper: run both parsers and assert shape isomorphism ───────────

    fn assert_shapes_equal(data: &[u8], label: &str) {
        let prod = DexFile::parse(data, None);
        let oracle = naive_parse_dex(data);

        match (&prod, &oracle) {
            (Ok(prod_file), Ok(oracle_shape)) => {
                let prod_shape = prod_file.to_shape();
                assert_eq!(
                    prod_shape, *oracle_shape,
                    "ParseShape diverged on {label}\nproduction: {prod_shape:#?}\noracle: {oracle_shape:#?}"
                );
            }
            (Err(_), Err(_)) => {
                // Both rejected — no shape to compare; agreement by rejection.
            }
            (Ok(prod_file), Err(oracle_err)) => {
                let prod_shape = prod_file.to_shape();
                panic!(
                    "production accepted {label} but oracle returned Err({oracle_err:?})\n\
                     prod_shape.string_ids_size={}, .type_ids_size={}, .class_defs_size={}",
                    prod_shape.string_ids_size,
                    prod_shape.type_ids_size,
                    prod_shape.class_defs_size,
                );
            }
            (Err(prod_err), Ok(oracle_shape)) => {
                // Oracle more permissive. The naive oracle is structural-only:
                // it does not verify the Adler-32 checksum, nor does it model
                // id-section non-overlap. Production rejects both, so a
                // `ChecksumMismatch` or `SectionOverlap` here is production
                // legitimately stricter than the oracle, not a divergence.
                let prod_err_str = format!("{prod_err:?}");
                if !prod_err_str.contains("ChecksumMismatch")
                    && !prod_err_str.contains("SectionOverlap")
                {
                    panic!(
                        "oracle accepted {label} but production Err({prod_err:?})\n\
                         oracle_shape.string_ids_size={}, .type_ids_size={}, .class_defs_size={}",
                        oracle_shape.string_ids_size,
                        oracle_shape.type_ids_size,
                        oracle_shape.class_defs_size,
                    );
                }
            }
        }
    }

    // ── Unit test 1: bad magic — both parsers reject ─────────────────────

    #[test]
    fn unit_bad_magic_both_reject() {
        let mut data = vec![0u8; 112];
        data[0..4].copy_from_slice(b"DEAD");
        let oracle = naive_parse_dex(&data);
        assert!(
            matches!(oracle, Err(ParseOracleError::BadMagic { .. })),
            "expected BadMagic, got {oracle:?}"
        );
        let prod = DexFile::parse(&data, None);
        assert!(prod.is_err(), "production must reject bad magic");
    }

    // ── Unit test 2: truncated header ────────────────────────────────────

    #[test]
    fn unit_truncated_header() {
        let data = b"dex\n035\0";
        let oracle = naive_parse_dex(data);
        assert!(
            matches!(oracle, Err(ParseOracleError::TruncatedHeader { .. })),
            "expected TruncatedHeader, got {oracle:?}"
        );
    }

    // ── Unit test 3: unsupported version ─────────────────────────────────

    #[test]
    fn unit_unsupported_version() {
        let mut data = vec![0u8; 112];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"999");
        data[7] = 0;
        let oracle = naive_parse_dex(&data);
        assert!(
            matches!(oracle, Err(ParseOracleError::UnsupportedVersion { .. })),
            "expected UnsupportedVersion, got {oracle:?}"
        );
    }

    // ── Unit test 3b: version "040" accepted by oracle ───────────────────
    //
    // DEX version 040 is a valid Android-14+ format version accepted by
    // production. The oracle must accept it so the parser_differential fuzz
    // target does not flag production-accepted 040 inputs as divergences.

    #[test]
    fn unit_version_040_oracle_accepts() {
        // Minimal well-formed 112-byte header with version "040".
        let mut data = vec![0u8; 112];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"040");
        data[7] = 0;
        // file_size at offset 32: must be >= 12 and == buf.len() (112).
        data[32..36].copy_from_slice(&112u32.to_le_bytes());
        // Endian tag at offset 40: little-endian constant 0x12345678.
        data[40..44].copy_from_slice(&0x12345678u32.to_le_bytes());
        // All section counts are zero; oracle should accept with empty tables.
        let result = naive_parse_dex(&data);
        assert!(
            result.is_ok(),
            "oracle must accept DEX version \"040\"; got {result:?}"
        );
        let shape = result.unwrap();
        assert_eq!(&shape.header_magic[4..7], b"040", "version bytes in shape");
        assert_eq!(shape.string_ids_size, 0);
        assert_eq!(shape.type_ids_size, 0);
        assert_eq!(shape.class_defs_size, 0);
    }

    // ── Unit test 3c: regression — crash seed with version "040" ─────────
    //
    // Regression seed from the parser_differential fuzz campaign. An oracle
    // that rejects version "040" as UnsupportedVersion diverges from
    // production, which accepts it, and triggers the ORACLE-REJECTED panic
    // in the fuzz harness.

    #[test]
    fn unit_regression_040_crash_seed() {
        let data = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fuzz/crashes/parser_differential/4356e5cf6538"
        ));
        // Production accepts this input (version "040" is valid).
        // Oracle must not return UnsupportedVersion.
        let oracle = naive_parse_dex(data);
        assert!(
            !matches!(oracle, Err(ParseOracleError::UnsupportedVersion { .. })),
            "oracle must not reject DEX version \"040\" as unsupported; got {oracle:?}"
        );
    }

    // ── Unit test 4: bad endian tag ───────────────────────────────────────

    #[test]
    fn unit_bad_endian_tag() {
        let mut data = vec![0u8; 112];
        data[0..4].copy_from_slice(b"dex\n");
        data[4..7].copy_from_slice(b"035");
        data[7] = 0;
        // file_size at offset 32 — must be >= 12 and <= buf.len() (112).
        data[32..36].copy_from_slice(&112u32.to_le_bytes());
        // Write bad endian tag at offset 40
        data[40..44].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let oracle = naive_parse_dex(&data);
        assert!(
            matches!(oracle, Err(ParseOracleError::BadEndianTag { .. })),
            "expected BadEndianTag, got {oracle:?}"
        );
    }

    // ── Unit test 5: real fixture — full shape equality ───────────────────

    #[test]
    fn unit_classes_dex_full_shape_equal() {
        let data = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/classes.dex"
        ));
        let prod = DexFile::parse(data, None).expect("production parse must succeed on classes.dex");
        let oracle = naive_parse_dex(data).expect("oracle parse must succeed on classes.dex");
        let prod_shape = prod.to_shape();

        assert_eq!(prod_shape.header_magic, oracle.header_magic, "header_magic");
        assert_eq!(prod_shape.string_ids_size, oracle.string_ids_size, "string_ids_size");
        assert_eq!(prod_shape.string_ids_off, oracle.string_ids_off, "string_ids_off");
        assert_eq!(prod_shape.type_ids_size, oracle.type_ids_size, "type_ids_size");
        assert_eq!(prod_shape.type_ids_off, oracle.type_ids_off, "type_ids_off");
        assert_eq!(prod_shape.class_defs_size, oracle.class_defs_size, "class_defs_size");
        assert_eq!(prod_shape.class_defs_off, oracle.class_defs_off, "class_defs_off");
        assert_eq!(prod_shape.strings.len(), oracle.strings.len(), "strings.len()");
        assert_eq!(prod_shape.strings, oracle.strings, "strings");
        assert_eq!(
            prod_shape.type_descriptors.len(),
            oracle.type_descriptors.len(),
            "type_descriptors.len()"
        );
        assert_eq!(prod_shape.type_descriptors, oracle.type_descriptors, "type_descriptors");
        assert_eq!(
            prod_shape.class_def_class_types.len(),
            oracle.class_def_class_types.len(),
            "class_def_class_types.len()"
        );
        assert_eq!(
            prod_shape.class_def_class_types,
            oracle.class_def_class_types,
            "class_def_class_types"
        );
    }

    // ── Unit test 6: named classes fixture ───────────────────────────────

    #[test]
    fn unit_classes_named_dex_full_shape_equal() {
        let data = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/classes_named.dex"
        ));
        assert_shapes_equal(data, "fixtures/classes_named.dex");
    }

    // ── Unit test 7: adversarial corpus sweep ────────────────────────────

    #[test]
    fn unit_corpus_adversarial_sweep() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let adversarial = std::path::Path::new(manifest).join("tests/fixtures/adversarial");
        if !adversarial.exists() {
            return;
        }
        let mut count = 0usize;
        for dir_entry in walkdir_dex(&adversarial) {
            let data = std::fs::read(&dir_entry).expect("read fixture");
            assert_shapes_equal(&data, &dir_entry.display().to_string());
            count += 1;
        }
        eprintln!("unit_corpus_adversarial_sweep: {count} samples checked");
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /// Walk a directory tree, yielding paths of files with `.dex` extension.
    fn walkdir_dex(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else { return };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "dex") {
                    out.push(path);
                }
            }
        }
        walk(root, &mut out);
        out.sort();
        out
    }
}
