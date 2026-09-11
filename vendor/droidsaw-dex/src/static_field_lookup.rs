//! Look up a static-field String constant by `(class_descriptor, field_name)`.
//!
//! SBOM cataloger primitive: many DEX-only SDKs surface their version
//! number as `public static final String VERSION = "5.1.6";` in a known
//! class. The DEX layout encodes this as:
//!
//! 1. `class_def_item` references a `class_data_item` (via
//!    `class_data_off`) and an `encoded_array_item` of static-field
//!    initial values (via `static_values_off`).
//! 2. The `class_data_item.static_fields` list and the
//!    `encoded_array_item.values` list are **parallel-indexed** (DEX
//!    §5.7.1): `values[N]` is the initial value of `static_fields[N]`.
//! 3. The `encoded_array_item` may be SHORTER than `static_fields`;
//!    trailing fields default to zero/null and are omitted by the
//!    `dx`/`d8` compiler.
//!
//! This helper walks that path with explicit bounds checks at every
//! step and returns `Some(&str)` only when the static field exists, the
//! `encoded_array_item` carries an entry for it, and the value is an
//! `EncodedValue::String` whose `StringIdx` resolves into the string
//! pool.
//!
//! The helper is **stateless** and operates on `&DexFile`. Callers that
//! need a fast multi-lookup pattern over many `(descriptor, field_name)`
//! pairs should build their own `TypeToClassDefMap` (`crate::classes`)
//! once and call `lookup_static_string_in_class` directly with the
//! resolved class_def index.

use crate::annotation::EncodedValue;
use crate::parser::DexFile;

/// Resolve `class_descriptor` (e.g. `"Lcom/onesignal/OneSignal;"`) to a
/// class_def index, walk its `class_data.static_fields`, and return the
/// `String` initial value of the static field whose name matches
/// `field_name` (e.g. `"VERSION"`).
///
/// Returns `None` when any link in the chain is missing:
/// - No class_def with this descriptor in this DEX.
/// - Class has no `class_data` (abstract / interface / external).
/// - No static field with this name.
/// - `encoded_array_item` is shorter than the field's index (trailing
///   default).
/// - The encoded value is not `EncodedValue::String`.
/// - The `StringIdx` is out of range (malformed DEX).
///
/// O(C × F) where C is `dex.class_defs.len()` and F is the maximum
/// static-field count per class — adequate for a curated table of ~10
/// SDK lookups but call `TypeToClassDefMap` directly if scaling beyond
/// that.
pub fn lookup_static_string<'a>(
    dex: &'a DexFile,
    class_descriptor: &str,
    field_name: &str,
) -> Option<&'a str> {
    // First-wins-via-`.find()`: on duplicate-class_idx attacker DEX,
    // matches the `class_def_for_type` resolution semantics (first row
    // for a given class_idx wins) without an explicit shadow gate. A
    // shadowed row whose descriptor happens to match `class_descriptor`
    // is unreachable because the FIRST row sharing that descriptor's
    // class_idx is iterated first.
    let class_def = dex.class_defs.iter().find(|cd| {
        dex.get_type_descriptor(cd.class_idx)
            .ok()
            .is_some_and(|d| d == class_descriptor)
    })?;

    if class_def.class_data_off == 0 || class_def.static_values_off == 0 {
        return None;
    }

    let class_data = dex.class_datas.get(&class_def.class_data_off)?;
    let encoded_array = dex.encoded_arrays.get(&class_def.static_values_off)?;

    for (field_index, encoded_field) in class_data.static_fields.iter().enumerate() {
        #[allow(
            clippy::as_conversions,
            reason = "PROOF: widen u32→usize; FieldIdx.0 is bounded < dex.fields.len() by parser validation of field_ids pool; .get() returns None on OOB."
        )]
        let field_id = dex.fields.get(encoded_field.field_idx.0 as usize)?;
        let name = dex.get_string(field_id.name_idx).ok()?;
        if name != field_name {
            continue;
        }
        let value = encoded_array.get(field_index)?;
        if let EncodedValue::String(string_idx) = value {
            return dex.get_string(*string_idx).ok();
        }
        return None;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DexFile;

    fn fixture_bytes() -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sbom/dex_sdk_version/OneSignalVersion.dex");
        std::fs::read(&path).unwrap_or_else(|e| {
            panic!("read fixture {}: {e}", path.display());
        })
    }

    #[test]
    fn looks_up_static_string_constant_by_class_and_field() {
        let bytes = fixture_bytes();
        let dex = DexFile::parse(&bytes, None).expect("fixture parses");
        let v = lookup_static_string(&dex, "Lcom/onesignal/OneSignal;", "VERSION");
        assert_eq!(v, Some("5.1.6"));
    }

    #[test]
    fn returns_none_when_descriptor_missing() {
        let bytes = fixture_bytes();
        let dex = DexFile::parse(&bytes, None).expect("fixture parses");
        let v = lookup_static_string(&dex, "Lcom/nonexistent/Class;", "VERSION");
        assert_eq!(v, None);
    }

    #[test]
    fn returns_none_when_field_name_missing() {
        let bytes = fixture_bytes();
        let dex = DexFile::parse(&bytes, None).expect("fixture parses");
        let v = lookup_static_string(&dex, "Lcom/onesignal/OneSignal;", "NO_SUCH_FIELD");
        assert_eq!(v, None);
    }

    #[test]
    fn empty_dex_is_safe() {
        let dex = DexFile::empty_for_fuzz();
        let v = lookup_static_string(&dex, "Lcom/whatever/Foo;", "BAR");
        assert_eq!(v, None);
    }
}
