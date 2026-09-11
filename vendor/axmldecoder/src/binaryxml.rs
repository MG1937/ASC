use crate::stringpool::StringPool;
use deku::prelude::*;
use std::rc::Rc;

#[derive(Debug, DekuRead)]
pub(crate) struct BinaryXmlDocument {
    #[allow(dead_code)] // `header` is used by `deku`
    pub(crate) header: ChunkHeader,
    pub(crate) string_pool: StringPool,
    pub(crate) resource_map: ResourceMap,
    #[deku(bytes_read = "header.size -
            u32::try_from(header.header_size).unwrap() -
            string_pool.header.chunk_header.size -
            resource_map.header.size")]
    pub(crate) elements: Vec<XmlNode>,
}

#[derive(Debug, PartialEq, Clone, Copy, DekuRead, DekuWrite)]
#[deku(type = "u16")]
pub(crate) enum ResourceType {
    NullType = 0x000,
    StringPool = 0x0001,
    Table = 0x0002,
    Xml = 0x0003,
    XmlStartNameSpace = 0x0100,
    XmlEndNameSpace = 0x101,
    XmlStartElement = 0x0102,
    XmlEndElement = 0x0103,
    XmlCdata = 0x0104,
    XmlLastChunk = 0x017f,
    XmlResourceMap = 0x0180,
    TablePackage = 0x0200,
    TableType = 0x0201,
    TableTypeSpec = 0x0202,
    TableLibrary = 0x0203,
}

#[derive(Clone, Debug, DekuRead, DekuWrite)]
pub(crate) struct ChunkHeader {
    pub(crate) typ: ResourceType,
    pub(crate) header_size: u16,
    pub(crate) size: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
pub(crate) struct ResourceMap {
    pub(crate) header: ChunkHeader,
    #[deku(count = "(header.size - u32::from(header.header_size)) / 4")]
    pub(crate) resource_ids: Vec<u32>,
}

#[derive(Debug, DekuRead, DekuWrite)]
pub(crate) struct XmlNode {
    pub(crate) header: XmlNodeHeader,
    #[deku(ctx = "header.chunk_header.typ")]
    pub(crate) element: XmlNodeType,
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(ctx = "typ: ResourceType", id = "typ")]
pub(crate) enum XmlNodeType {
    #[deku(id = "ResourceType::XmlStartNameSpace")]
    XmlStartNameSpace(XmlStartNameSpace),
    #[deku(id = "ResourceType::XmlEndNameSpace")]
    XmlEndNameSpace(XmlEndNameSpace),
    #[deku(id = "ResourceType::XmlStartElement")]
    XmlStartElement(XmlStartElement),
    #[deku(id = "ResourceType::XmlEndElement")]
    XmlEndElement(XmlEndElement),
    #[deku(id = "ResourceType::XmlCdata")]
    XmlCdata(XmlCdata),
}

#[derive(Debug, DekuRead, DekuWrite)]
pub(crate) struct XmlNodeHeader {
    pub(crate) chunk_header: ChunkHeader,
    pub(crate) line_no: u32,
    pub(crate) comment: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
pub(crate) struct XmlStartNameSpace {
    pub(crate) prefix: u32,
    pub(crate) uri: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
pub(crate) struct XmlEndNameSpace {
    pub(crate) prefix: u32,
    pub(crate) uri: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
pub(crate) struct XmlAttrExt {
    pub(crate) ns: u32,
    pub(crate) name: u32,
    pub(crate) attribute_start: u16,
    pub(crate) attribute_size: u16,
    pub(crate) attribute_count: u16,
    pub(crate) id_index: u16,
    pub(crate) class_index: u16,
    pub(crate) style_index: u16,
}

#[derive(Debug, DekuRead, DekuWrite)]
pub(crate) struct ResourceValue {
    pub(crate) size: u16,
    pub(crate) res: u8,
    /// PATCHED (rasc): the raw type byte. AXML defines more types than
    /// `ResourceValueType` names (0x07/0x08, 0x13-0x1b, >= 0x20), and the
    /// reference renders those with its `<0x.., type 0x..>` fallback instead of
    /// refusing the document, so the byte is kept as-is and mapped when the value
    /// is rendered.
    pub(crate) raw_type: u8,
    pub(crate) data: u32,
}

impl ResourceValue {
    pub(crate) fn get_value(&self, string_pool: &StringPool) -> Rc<String> {
        Rc::new(format_value(self.raw_type, self.data, string_pool))
    }
}

/// PATCHED (rasc): formats a typed value the way `aapt` and the original Python
/// implementation do, instead of stringifying the raw data. The rules mirror
/// Androguard's `format_value`, including its `<0x.., type 0x..>` fallback.
fn format_value(raw_type: u8, data: u32, string_pool: &StringPool) -> String {
    // PATCHED (rasc): the exact powers of two (2^-8, 2^-15, 2^-23, 2^-31).
    // Androguard rounds them to seven digits, which shifts a large mantissa in
    // the sixth decimal (fraction mantissa 16384, radix 1: 50.000003% there,
    // 50.000000% here). The exact value is the correct one, so we keep it and
    // accept the divergence.
    const RADIX_MULTS: [f64; 4] = [
        0.00390625,
        3.0517578125e-05,
        1.1920928955078125e-07,
        4.6566128730773926e-10,
    ];
    const DIMENSION_UNITS: [&str; 6] = ["px", "dip", "sp", "pt", "in", "mm"];
    const FRACTION_UNITS: [&str; 2] = ["%", "%p"];

    let package = if data >> 24 == 1 { "android:" } else { "" };
    // AXML integers are signed, and the reference sign-extends from bit 31 whatever
    // width the value declares.
    let signed = i64::from(data & 0x7fff_ffff)
        - if data > 0x7fff_ffff { i64::from(0x8000_0000u32) } else { 0 };
    // Complex values pack a mantissa with a radix and a unit selector.
    let complex = f64::from(data & 0xffff_ff00) * RADIX_MULTS[((data >> 4) & 3) as usize];
    let unit = (data & 0x0f) as usize;

    match ResourceValueType::from_raw(raw_type) {
        Some(ResourceValueType::String) => string_pool
            .get(usize::try_from(data).unwrap())
            .map_or_else(String::new, |value| (*value).clone()),
        Some(ResourceValueType::Attribute) => format!("?{package}{data:08X}"),
        Some(ResourceValueType::Reference) => format!("@{package}{data:08X}"),
        Some(ResourceValueType::Float) => format!("{:.6}", f64::from(f32::from_bits(data))),
        Some(ResourceValueType::Dec) => format!("{signed}"),
        Some(ResourceValueType::Hex) => format!("0x{data:08X}"),
        Some(ResourceValueType::Boolean) => (if data == 0 { "false" } else { "true" }).to_string(),
        Some(ResourceValueType::Dimension) => format!(
            "{complex:.6}{}",
            DIMENSION_UNITS.get(unit).copied().unwrap_or("")
        ),
        Some(ResourceValueType::Fraction) => format!(
            "{:.6}{}",
            complex * 100.0,
            FRACTION_UNITS.get(unit).copied().unwrap_or("")
        ),
        Some(ResourceValueType::Color) => format!("#{data:08X}"),
        _ => format!("<0x{data:X}, type 0x{raw_type:02X}>"),
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum ResourceValueType {
    Null = 0x00,
    Reference = 0x01,
    Attribute = 0x02,
    String = 0x03,
    Float = 0x04,
    Dimension = 0x05,
    Fraction = 0x06,
    Dec = 0x10,
    Hex = 0x11,
    Boolean = 0x12,
    /// PATCHED (rasc): the four AOSP colour types (0x1C-0x1F), which all render
    /// as `#%08X`.
    Color = 0x1c,
}

impl ResourceValueType {
    /// The named type for `raw`, or `None` for the types AXML defines but
    /// Androguard does not name (its fallback renders those).
    fn from_raw(raw: u8) -> Option<Self> {
        Some(match raw {
            0x00 => Self::Null,
            0x01 => Self::Reference,
            0x02 => Self::Attribute,
            0x03 => Self::String,
            0x04 => Self::Float,
            0x05 => Self::Dimension,
            0x06 => Self::Fraction,
            0x10 => Self::Dec,
            0x11 => Self::Hex,
            0x12 => Self::Boolean,
            // PATCHED (rasc): 0x1C-0x1F really are the colour types (AOSP
            // `TYPE_FIRST_COLOR_INT .. TYPE_LAST_COLOR_INT`), so one variant
            // covers them. 0x13-0x1B stay unknown: they are reserved in AOSP,
            // and Androguard's habit of printing them as decimals (its integer
            // branch spans 0x10-0x1F) would claim to know what they are.
            0x1c..=0x1f => Self::Color,
            _ => return None,
        })
    }
}

#[derive(Debug, DekuRead, DekuWrite)]
pub(crate) struct XmlAttribute {
    pub(crate) ns: u32,
    pub(crate) name: u32,
    pub(crate) raw_value: u32,
    pub(crate) typed_value: ResourceValue,
}

#[derive(Debug, DekuRead, DekuWrite)]
pub(crate) struct XmlStartElement {
    pub(crate) attr_ext: XmlAttrExt,
    #[deku(count = "attr_ext.attribute_count")]
    pub(crate) attributes: Vec<XmlAttribute>,
}

#[derive(Debug, DekuRead, DekuWrite)]
pub(crate) struct XmlEndElement {
    pub(crate) ns: u32,
    pub(crate) name: u32,
}

#[derive(Debug, DekuRead, DekuWrite)]
pub(crate) struct XmlCdata {
    pub(crate) data: u32,
    pub(crate) typed_data: ResourceValue,
}
