//! Round-trip content-equivalence wrapper for `DexFile`. The PartialEq
//! impl is the single source of truth for "what counts as equivalent"
//! across `parse → emit → parse` roundtrips: pool content + subsection
//! cardinalities (ignoring layout-dependent fields like header offsets,
//! checksums, and BTreeMap keys keyed by on-disk offset).

use super::DexFile;

/// Content-equivalence wrapper for `DexFile`. Encodes the round-trip
/// contract `parse ∘ emit ∘ parse == parse` as a `PartialEq` impl
/// that compares semantic pool contents + subsection cardinalities,
/// ignoring layout-dependent fields (header offsets, checksums,
/// subsection BTreeMap keys which are keyed by on-disk offset and
/// legitimately differ across emit).
///
/// Previously this comparison was duplicated (manually, one field at
/// a time) across four test sites: `tests/roundtrip_proptest.rs`,
/// `tests/fixture_strip_emit.rs`, `tests/corpus_emit_smoke.rs`, and
/// `fuzz/fuzz_targets/fuzz_emit_roundtrip.rs`. Adding a subsection to
/// `DexFile` meant remembering to update four sites; drift risk.
///
/// Wrap a `&DexFile` and compare via this type; the `PartialEq` impl
/// is the single source of truth for "what counts as equivalent."
///
/// ## What is compared
///
/// - `strings` — pool contents, positional equality on the
///   `(declared_chars, raw_bytes)` pair `emit_string_pool` serializes;
///   `had_terminator` provenance is excluded (see the inline note in `eq`)
/// - `type_descriptors`, `fields`, `methods` — pool contents,
///   positional equality
/// - `class_defs.len()` — class count (individual `ClassDefItem`s
///   carry layout offsets that legitimately differ across emit;
///   content comparison at this level would require a layout-aware
///   field-by-field match)
/// - Subsection BTreeMap lengths — content equivalence modulo
///   offset-keyed map keys
///
/// ## What is NOT compared
///
/// - `header` — checksum + signature + section offsets, all
///   layout-dependent
/// - BTreeMap keys within each subsection map — original on-disk
///   offsets that emit rewrites
/// - Per-`ClassDefItem` offset fields (annotations_off etc)
/// - `DexString::had_terminator` — on-disk-malformation provenance the
///   validity-normalizing emitter does not reproduce (it always writes
///   the `0x00` terminator), so it is not a round-trip content property
///
/// For deeper content-level equivalence (walking inside each
/// subsection to compare values), extend with a separate
/// `DeepContentEquiv` wrapper. This level is the structural gate;
/// deep comparison is per-section and carries interpretive weight
/// (e.g., "are these two CodeItems semantically identical?" is a
/// richer question than structural eq allows).
#[derive(Debug)]
pub struct ContentEquiv<'a>(pub &'a DexFile);

impl<'a> PartialEq for ContentEquiv<'a> {
    fn eq(&self, other: &Self) -> bool {
        let a = self.0;
        let b = other.0;

        // String pool — compare exactly the (declared_chars, raw_bytes) pair
        // that `emit_string_pool` serializes per entry. `had_terminator` is
        // intentionally NOT compared: it is on-disk-malformation provenance
        // (the parser sets it `false` and extends-to-EOF when a string's data
        // runs to EOF without a `0x00` terminator), not string content. The
        // emitter canonicalizes it — `emit_string_pool` always writes the
        // terminator — so a truncated-trailing-string input faithfully round-
        // trips its bytes yet re-parses as `had_terminator: true`, which the
        // derived `DexString` `PartialEq` would otherwise report as a content
        // divergence. Comparing `raw_bytes` also covers the decoded view: `s`,
        // `lossy_str`, `decode_error`, and the variant are all deterministic
        // functions of `raw_bytes`, re-derived identically on re-parse.
        if a.strings.len() != b.strings.len()
            || a.strings.iter().zip(b.strings.iter()).any(|(sa, sb)| {
                sa.declared_chars() != sb.declared_chars() || sa.raw_bytes() != sb.raw_bytes()
            })
        {
            return false;
        }

        // Remaining pools — derived equality (no provenance-only fields).
        if a.type_descriptors != b.type_descriptors
            || a.fields != b.fields
            || a.methods != b.methods
        {
            return false;
        }

        // Protos: per-entry equality modulo parameters_off (which is
        // a layout offset; presence bit is invariant).
        if a.protos.len() != b.protos.len() {
            return false;
        }
        for (pa, pb) in a.protos.iter().zip(b.protos.iter()) {
            if pa.shorty_idx != pb.shorty_idx
                || pa.return_type_idx != pb.return_type_idx
                || (pa.parameters_off == 0) != (pb.parameters_off == 0)
            {
                return false;
            }
        }

        // Class defs: per-entry equality modulo offset fields
        // (interfaces_off / annotations_off / class_data_off /
        // static_values_off are layout-dependent; their presence
        // bits are invariant).
        if a.class_defs.len() != b.class_defs.len() {
            return false;
        }
        for (ca, cb) in a.class_defs.iter().zip(b.class_defs.iter()) {
            if ca.class_idx != cb.class_idx
                || ca.access_flags != cb.access_flags
                || ca.superclass_idx != cb.superclass_idx
                || ca.source_file_idx != cb.source_file_idx
                || (ca.interfaces_off == 0) != (cb.interfaces_off == 0)
                || (ca.annotations_off == 0) != (cb.annotations_off == 0)
                || (ca.class_data_off == 0) != (cb.class_data_off == 0)
                || (ca.static_values_off == 0) != (cb.static_values_off == 0)
            {
                return false;
            }
        }

        // Subsection BTreeMap lengths — content comparison modulo
        // offset-keyed map keys. Deeper per-value comparison is a
        // separate `DeepContentEquiv` concern.
        //
        // Equivalence covers two extensions:
        // - method_handles / call_site_ids — lambda metafactory
        //   reconstruction pool equivalence.
        // - debug_info_raw_bytes per-entry byte-identity — round-trip
        //   invariant is byte-exact on the section, not just
        //   count-equivalent. BTreeMap iteration is
        //   deterministic (sorted by key); keys legitimately differ
        //   across emit (offset remap) so values are compared
        //   positionally via zip.
        if a.type_lists.len() != b.type_lists.len()
            || a.class_datas.len() != b.class_datas.len()
            || a.code_items.len() != b.code_items.len()
            || a.annotations.len() != b.annotations.len()
            || a.annotation_items.len() != b.annotation_items.len()
            || a.annotation_sets.len() != b.annotation_sets.len()
            || a.annotation_set_ref_lists.len() != b.annotation_set_ref_lists.len()
            || a.encoded_arrays.len() != b.encoded_arrays.len()
            || a.method_handles != b.method_handles
            || a.call_site_ids.len() != b.call_site_ids.len()
            || a.debug_infos.len() != b.debug_infos.len()
            || a.debug_info_raw_bytes.len() != b.debug_info_raw_bytes.len()
        {
            return false;
        }

        // DELIBERATELY NOT compared: `parse_errors`. A strict
        // equality check here creates a false-positive:
        // `parse → emit → parse` does NOT preserve the
        // error-generating malformed bytes (emit serializes clean IR,
        // so the round-tripped DexFile has an empty parse_errors
        // while the original has populated ones). Including
        // parse_errors in ContentEquiv would cause every
        // malformed-subsection input to fail roundtrip by
        // construction, drowning fuzz / corpus-smoke signals in
        // predictable noise. `parse_errors` preservation is a
        // separate property (would belong on a future
        // `ParseErrorPreserving` trait if an emit path ever opts in
        // via `EmitConfig { permit_partial_ir }`); it is not
        // implied by "same content IR".

        // Byte-identity gate on the debug_info section. Every preserved
        // entry must round-trip byte-exact through emit; if any entry
        // diverges, either `scan_debug_info_bytes` or
        // `emit_debug_info_section` has a bug.
        for (va, vb) in a
            .debug_info_raw_bytes
            .values()
            .zip(b.debug_info_raw_bytes.values())
        {
            if va != vb {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test"
)]
mod tests {
    use super::*;
    use crate::DexString;

    const FIXTURE: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/classes.dex"));

    fn first_decoded_idx(dex: &DexFile) -> usize {
        dex.strings
            .iter()
            .position(|s| matches!(s, DexString::Decoded { .. }))
            .expect("fixture has at least one cleanly-decoded string")
    }

    /// `had_terminator` is round-trip *provenance*, not content: two `DexFile`s
    /// that differ ONLY in one string's `had_terminator` must be
    /// `ContentEquiv`-equal. This models the truncated-trailing-string round-
    /// trip — emit canonicalizes a missing terminator (parse sees
    /// `had_terminator: false`, emit writes the `0x00`, re-parse sees
    /// `had_terminator: true`). Red before the provenance-exclusion fix (the
    /// derived `DexString` `PartialEq` saw the flag); green after.
    #[test]
    fn content_equiv_ignores_had_terminator_flip() {
        let dex_a = DexFile::parse(FIXTURE, None).expect("fixture parses");
        let mut dex_b = DexFile::parse(FIXTURE, None).expect("fixture parses");
        let idx = first_decoded_idx(&dex_a);

        // Flip had_terminator only; declared_chars + raw_bytes untouched.
        match dex_b.strings.get_mut(idx).expect("same-length pool") {
            DexString::Decoded { had_terminator, .. }
            | DexString::MalformedMutf8 { had_terminator, .. } => {
                *had_terminator = !*had_terminator;
            }
        }

        // Precondition: the flip really does perturb the derived DexString eq...
        assert_ne!(
            dex_a.strings, dex_b.strings,
            "precondition: had_terminator flip must perturb derived DexString eq"
        );
        // ...yet ContentEquiv treats them as round-trip equivalent.
        assert_eq!(
            ContentEquiv(&dex_a),
            ContentEquiv(&dex_b),
            "had_terminator is provenance, not content — must not break round-trip equivalence"
        );
    }

    /// Negative control: the relaxation is surgical. Perturbing a real content
    /// field (`declared_chars`) on one string MUST still register as divergence.
    #[test]
    fn content_equiv_still_catches_declared_chars_divergence() {
        let dex_a = DexFile::parse(FIXTURE, None).expect("fixture parses");
        let mut dex_c = DexFile::parse(FIXTURE, None).expect("fixture parses");
        let idx = first_decoded_idx(&dex_a);

        match dex_c.strings.get_mut(idx).expect("same-length pool") {
            DexString::Decoded { declared_chars, .. }
            | DexString::MalformedMutf8 { declared_chars, .. } => {
                *declared_chars = declared_chars.wrapping_add(1);
            }
        }

        assert_ne!(
            ContentEquiv(&dex_a),
            ContentEquiv(&dex_c),
            "declared_chars is real content — divergence must still be caught"
        );
    }
}
