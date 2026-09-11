//! Byte-level pre-filter over the query's target indices.
//!
//! Every reference instruction stores its target index as a little-endian operand
//! at `pc + 2`, so a method whose code does not contain those bytes cannot
//! reference it. One `memchr` pass over a method body is much cheaper than
//! decoding its instructions, and operand bytes are far more selective than the
//! opcode bytes: for a small target set almost every method is skipped.

use std::collections::BTreeSet;

/// Target indices together with a byte-level pre-filter over them.
///
/// Every reference instruction encodes its index as a little-endian operand at
/// `pc + 2`, so a method whose code does not contain the target's bytes cannot
/// reference it. Decoding a method's instructions costs far more than one
/// `memchr` pass over its code, and most methods reference nothing at all.
pub(super) struct Targets {
    indices: BTreeSet<u32>,
    /// `None` when the target set is too large for the filter to pay off.
    bytes: Option<TargetBytes>,
}

impl Targets {
    /// Above this many targets the filter scans the code once per target, which
    /// costs more than the instruction decode it would skip.
    const MAX_FILTER_TARGETS: usize = 4;

    /// Whether the filter would let `code` through; `true` when filtering is off.
    pub(super) fn might_reference(&self, code: &[u8]) -> bool {
        match &self.bytes {
            Some(bytes) => bytes.matches(code),
            None => true,
        }
    }

    /// Whether `index` is one of the query's targets.
    pub(super) fn contains(&self, index: u32) -> bool {
        self.indices.contains(&index)
    }

    pub(super) fn new(indices: impl IntoIterator<Item = u32>) -> Self {
        let indices: BTreeSet<u32> = indices.into_iter().collect();
        let bytes = (indices.len() <= Self::MAX_FILTER_TARGETS).then(|| TargetBytes::new(&indices));
        Self { indices, bytes }
    }
}

/// Encoded target indices, split by operand width.
struct TargetBytes {
    pairs: Vec<[u8; 2]>,
    quads: Vec<[u8; 4]>,
}

impl TargetBytes {
    fn new(indices: &BTreeSet<u32>) -> Self {
        let mut pairs = Vec::new();
        let mut quads = Vec::new();
        for &index in indices {
            if index <= u32::from(u16::MAX) {
                pairs.push((index as u16).to_le_bytes());
            } else {
                quads.push(index.to_le_bytes());
            }
        }
        Self { pairs, quads }
    }

    /// Whether `code` contains any target index as an operand.
    fn matches(&self, code: &[u8]) -> bool {
        self.pairs.iter().any(|pair| contains_pair(code, *pair))
            || self
                .quads
                .iter()
                .any(|quad| memchr::memmem::find(code, quad).is_some())
    }
}

/// Two-byte search: `memchr` on the first byte, then a check on both sides,
/// because the match may start one byte before the position found.
fn contains_pair(code: &[u8], [first, second]: [u8; 2]) -> bool {
    let mut from = 0;
    while let Some(found) = memchr::memchr(first, &code[from..]) {
        let at = from + found;
        if code.get(at + 1) == Some(&second) || (at > 0 && code[at - 1] == second) {
            return true;
        }
        from = at + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dex::tests::const_string_fixture;
    use crate::dex::{Dex, PARALLEL_SCAN_CLASSES};
    use crate::query::Query;

    #[test]
    fn pair_filter_finds_matches_at_both_edges() {
        assert!(contains_pair(b"\x1a\x05", [0x1a, 0x05]));
        assert!(contains_pair(b"\x00\x1a\x05\x00", [0x1a, 0x05]));
        assert!(contains_pair(b"\x05\x1a", [0x1a, 0x05]));
        assert!(!contains_pair(b"\x1a\x00\x05", [0x1a, 0x05]));
        assert!(!contains_pair(b"", [0x1a, 0x05]));
        assert!(!contains_pair(b"\x1a", [0x1a, 0x05]));
    }

    #[test]
    fn byte_filter_matches_the_unfiltered_scan() {
        let data = const_string_fixture(PARALLEL_SCAN_CLASSES);
        let dex = Dex::parse(&data).unwrap();
        let (kind, targets) = dex
            .resolve_targets(&Query::String("Authorization".to_owned()))
            .unwrap();
        let targets = Targets::new(targets);
        assert!(targets.bytes.is_some(), "one target must stay filterable");
        let filtered = dex.scan_all_classes(kind, &targets).unwrap();
        let unfiltered = Targets {
            indices: targets.indices.clone(),
            bytes: None,
        };
        assert_eq!(filtered, dex.scan_all_classes(kind, &unfiltered).unwrap());
        assert_eq!(filtered.len(), PARALLEL_SCAN_CLASSES);
    }
}
