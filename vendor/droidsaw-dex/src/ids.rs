//! DEX id section types (string, type, proto, field, method).
#![allow(missing_docs, reason = "internal")]
/// Sentinel value for "no index" in DEX format.
pub const NO_INDEX: u32 = 0xFFFF_FFFF;

macro_rules! define_idx {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        pub struct $name(pub u32);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

define_idx!(StringIdx, "Index into the string pool.");
define_idx!(TypeIdx, "Index into the type pool.");
define_idx!(ProtoIdx, "Index into the proto pool.");
define_idx!(FieldIdx, "Index into the field pool.");
define_idx!(MethodIdx, "Index into the method pool.");
define_idx!(MethodHandleIdx, "Index into the method_handles section.");
define_idx!(CallSiteIdx, "Index into the call_site_ids section.");

/// 4 bytes on disk: offset to string_data_item (MUTF-8 encoded).
#[derive(Debug, Clone, PartialEq)]
pub struct StringIdItem {
    pub string_data_off: u32,
}

/// 4 bytes on disk: index into string_ids for type descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeIdItem {
    pub descriptor_idx: StringIdx,
}

/// 12 bytes on disk: shorty descriptor, return type, parameters offset.
#[derive(Debug, Clone, PartialEq)]
pub struct ProtoIdItem {
    pub shorty_idx: StringIdx,
    pub return_type_idx: TypeIdx,
    pub parameters_off: u32,
}

/// 8 bytes on disk: defining class, field type, field name.
/// Note: class_idx and type_idx are u16 on disk.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldIdItem {
    pub class_idx: TypeIdx,
    pub type_idx: TypeIdx,
    pub name_idx: StringIdx,
}

/// 8 bytes on disk: defining class, method prototype, method name.
/// Note: class_idx and proto_idx are u16 on disk.
#[derive(Debug, Clone, PartialEq)]
pub struct MethodIdItem {
    pub class_idx: TypeIdx,
    pub proto_idx: ProtoIdx,
    pub name_idx: StringIdx,
}

/// 32 bytes on disk: full class definition header.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassDefItem {
    pub class_idx: TypeIdx,
    pub access_flags: u32,
    pub superclass_idx: Option<TypeIdx>,
    pub interfaces_off: u32,
    pub source_file_idx: Option<StringIdx>,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

/// Convert a raw u32 to `Option<TypeIdx>`, treating NO_INDEX as None.
pub fn optional_type_idx(raw: u32) -> Option<TypeIdx> {
    if raw == NO_INDEX {
        None
    } else {
        Some(TypeIdx(raw))
    }
}

/// Convert a raw u32 to `Option<StringIdx>`, treating NO_INDEX as None.
pub fn optional_string_idx(raw: u32) -> Option<StringIdx> {
    if raw == NO_INDEX {
        None
    } else {
        Some(StringIdx(raw))
    }
}
