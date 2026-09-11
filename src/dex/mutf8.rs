//! MUTF-8 encoding for query text.
//!
//! DEX strings are MUTF-8: NUL is stored as `0xC0 0x80` and supplementary
//! characters as a surrogate pair of three-byte sequences. A query has to be
//! encoded the same way before it can be matched against the string table.

pub(super) fn encode_mutf8(value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for unit in value.encode_utf16() {
        match unit {
            0 => out.extend_from_slice(&[0xc0, 0x80]),
            0x0001..=0x007f => out.push(unit as u8),
            0x0080..=0x07ff => {
                out.push((0xc0 | (unit >> 6)) as u8);
                out.push((0x80 | (unit & 0x3f)) as u8);
            }
            _ => {
                out.push((0xe0 | (unit >> 12)) as u8);
                out.push((0x80 | ((unit >> 6) & 0x3f)) as u8);
                out.push((0x80 | (unit & 0x3f)) as u8);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutf8_encodes_nul_and_supplementary_characters() {
        assert_eq!(encode_mutf8("a\0b"), b"a\xc0\x80b");
        assert_eq!(encode_mutf8("😀"), [0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]);
        assert_eq!(
            droidsaw_dex::mutf8::decode_mutf8(&encode_mutf8("A😀\0Z")).unwrap(),
            "A😀\0Z"
        );
    }
}
