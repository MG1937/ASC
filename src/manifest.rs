//! AndroidManifest.xml decoding: verbatim passthrough for a plain XML entry and
//! binary AXML decode plus indented printing for the compiled form.

use anyhow::{Context, Result, bail};
use axmldecoder::{Node, XmlDocument};
use std::fmt::Write;

pub fn decode(data: &[u8]) -> Result<String> {
    if let Ok(text) = std::str::from_utf8(data)
        && text.trim_start().starts_with('<')
    {
        return Ok(text.to_owned());
    }
    validate_chunks(data)?;
    let document = axmldecoder::parse(data).context("decode binary Android XML")?;
    render(&document)
}

/// Checks the chunk skeleton before handing the bytes to `axmldecoder`.
///
/// The decoder unwraps its reads and asserts on a few structural details, and the
/// release profile builds with `panic = "abort"`, so a truncated or crafted
/// manifest would abort the process instead of reporting an error. Everything
/// checked here is something the decoder would otherwise panic on: chunk sizes
/// that leave the buffer, a string pool whose declared size cannot hold its own
/// offsets, and a string pool with styles (the decoder asserts `style_count == 0`).
///
/// Residual risk: a document with a consistent skeleton but inconsistent contents
/// (a string offset pointing outside the pool, a string longer than 32767
/// characters) is still rejected by the decoder's own unwraps rather than here.
fn validate_chunks(data: &[u8]) -> Result<()> {
    const DOCUMENT: u16 = 0x0003;
    const STRING_POOL: u16 = 0x0001;
    const RESOURCE_MAP: u16 = 0x0180;
    const STRING_POOL_HEADER: usize = 28;

    let document = chunk_header(data, 0).context("read document chunk")?;
    if document.typ != DOCUMENT {
        bail!("binary XML does not start with a document chunk");
    }
    let end = document.size;

    // The decoder reads exactly these two chunks unconditionally before it starts
    // on the node list, so they are the ones worth checking up front; node chunks
    // are read by bounded counts and already fail as parse errors.
    let pool_start = usize::from(document.header_size);
    let pool = chunk_header(&data[..end], pool_start).context("read string pool chunk")?;
    if pool.typ != STRING_POOL {
        bail!("binary XML does not start with a string pool");
    }
    if pool.size < STRING_POOL_HEADER {
        bail!("string pool cannot hold its own header");
    }
    let fields = data
        .get(
            usize::from(document.header_size)
                ..usize::from(document.header_size) + STRING_POOL_HEADER,
        )
        .context("truncated string pool header")?;
    let string_count = u32::from_le_bytes(fields[8..12].try_into().unwrap()) as usize;
    let style_count = u32::from_le_bytes(fields[12..16].try_into().unwrap());
    let flags = u32::from_le_bytes(fields[16..20].try_into().unwrap());
    let strings_start = u32::from_le_bytes(fields[20..24].try_into().unwrap()) as usize;
    if string_count * 4 > pool.size - STRING_POOL_HEADER {
        bail!("string pool cannot hold its own offsets");
    }
    if style_count != 0 {
        bail!("string pool with styles is not supported");
    }
    if !(STRING_POOL_HEADER..=pool.size).contains(&strings_start) {
        bail!("string pool declares an impossible string start");
    }
    // The decoder calls `unimplemented!()` on the two-byte length form and indexes
    // strings without bounds checks, so walk the offsets here.
    let utf8 = flags & 0x0000_0100 != 0;
    let strings_base = pool_start + strings_start;
    for index in 0..string_count {
        let entry = data
            .get(
                pool_start + STRING_POOL_HEADER + index * 4
                    ..pool_start + STRING_POOL_HEADER + index * 4 + 4,
            )
            .context("truncated string pool offsets")?;
        let mut cursor = strings_base + u32::from_le_bytes(entry.try_into().unwrap()) as usize;
        // A UTF-8 entry stores the UTF-16 length and then the byte length, either of
        // which may use the extended form; a UTF-16 entry stores its length as one or
        // two units. Both were rejected here before rasc patched its decoder.
        let length = if utf8 {
            let _utf16_len = pool_length_8(data, &mut cursor)?;
            pool_length_8(data, &mut cursor)?
        } else {
            let units = pool_length_16(data, &mut cursor)?;
            units * 2
        };
        let end_of_string = cursor
            .checked_add(length)
            .context("string length overflow in the string pool")?;
        if end_of_string > pool_start + pool.size || end_of_string > data.len() {
            bail!("string runs past the string pool");
        }
    }

    let map_offset = usize::from(document.header_size) + pool.size;
    let map = chunk_header(&data[..end], map_offset).context("read resource map chunk")?;
    if map.typ != RESOURCE_MAP {
        bail!("binary XML has no resource map after its string pool");
    }
    // The decoder derives its entry count as `(size - header_size) / 4` in u32,
    // so a chunk declaring a size below its header size wraps to ~1e9 entries.
    // Nothing else validates this chunk.
    if map.header_size != 8 || map.size < 8 || (map.size - 8) % 4 != 0 {
        bail!(
            "binary XML resource map chunk is malformed: header_size={}, size={}",
            map.header_size,
            map.size
        );
    }
    let nodes = map_offset + map.size;
    if nodes >= end {
        bail!("binary XML has no node chunks");
    }
    Ok(())
}
/// One string length from a UTF-8 pool: one byte, or two when the high bit of the
/// first is set.
fn pool_length_8(data: &[u8], cursor: &mut usize) -> Result<usize> {
    let first = *data.get(*cursor).context("truncated string length")?;
    *cursor += 1;
    if first & 0x80 == 0 {
        return Ok(usize::from(first));
    }
    let second = *data.get(*cursor).context("truncated string length")?;
    *cursor += 1;
    Ok((usize::from(first & 0x7f) << 8) | usize::from(second))
}

/// One string length from a UTF-16 pool: one unit, or two when the high bit of the
/// first is set (the value is then in UTF-16 units, which the caller scales).
fn pool_length_16(data: &[u8], cursor: &mut usize) -> Result<usize> {
    let first = u16::from_le_bytes(
        data.get(*cursor..*cursor + 2)
            .context("truncated string length")?
            .try_into()
            .unwrap(),
    );
    *cursor += 2;
    if first & 0x8000 == 0 {
        return Ok(usize::from(first));
    }
    let second = u16::from_le_bytes(
        data.get(*cursor..*cursor + 2)
            .context("truncated string length")?
            .try_into()
            .unwrap(),
    );
    *cursor += 2;
    Ok(((usize::from(first & 0x7fff)) << 16) | usize::from(second))
}

/// One binary-XML chunk header: type, header size and total size.
struct ChunkHeader {
    typ: u16,
    header_size: u16,
    size: usize,
}

fn chunk_header(data: &[u8], offset: usize) -> Result<ChunkHeader> {
    let bytes = data
        .get(offset..offset + 8)
        .context("binary XML is shorter than a chunk header")?;
    let size = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    if size > data.len() - offset {
        bail!("binary XML chunk at {offset} runs past the end of the input");
    }
    Ok(ChunkHeader {
        typ: u16::from_le_bytes(bytes[..2].try_into().unwrap()),
        header_size: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
        size,
    })
}

fn render(document: &XmlDocument) -> Result<String> {
    let root = document
        .get_root()
        .as_ref()
        .context("AndroidManifest.xml has no root element")?;
    let mut output = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    render_node(root, 0, &mut output)?;
    Ok(output)
}

fn render_node(node: &Node, depth: usize, output: &mut String) -> Result<()> {
    match node {
        Node::Cdata(cdata) => {
            indent(depth, output);
            output.push_str("<![CDATA[");
            output.push_str(&cdata.get_data().replace("]]>", "]] ]]><![CDATA[>"));
            output.push_str("]]>");
        }
        Node::Element(element) => {
            let tag = element.get_tag();
            if tag.is_empty() {
                bail!("binary XML contains an empty element name");
            }
            indent(depth, output);
            write!(output, "<{tag}")?;
            for (name, value) in element.get_attributes() {
                write!(output, " {name}=\"")?;
                escape_xml(value, true, output);
                output.push('"');
            }
            if element.get_children().is_empty() {
                output.push_str(" />");
                return Ok(());
            }
            output.push('>');
            for child in element.get_children() {
                output.push('\n');
                render_node(child, depth + 1, output)?;
            }
            output.push('\n');
            indent(depth, output);
            write!(output, "</{tag}>")?;
        }
    }
    Ok(())
}

fn indent(depth: usize, output: &mut String) {
    for _ in 0..depth {
        output.push_str("    ");
    }
}

fn escape_xml(value: &str, attribute: bool, output: &mut String) {
    for ch in value.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' if attribute => output.push_str("&quot;"),
            '\'' if attribute => output.push_str("&apos;"),
            _ => output.push(ch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal binary AndroidManifest.xml: a root element with a
    /// namespaced attribute and a value that needs escaping, a nested element and
    /// a CDATA child whose text contains `]]>`.
    ///
    /// Layout follows the binary XML chunks `axmldecoder` reads: a chunk header is
    /// `type, headerSize, size`, a UTF-8 string pool stores `[utf16 len][utf8 len]
    /// bytes 0` per string, and every XML node extends the 8-byte chunk header with
    /// a line number and a comment index.
    fn binary_manifest() -> Vec<u8> {
        binary_manifest_with_cdata("a ]]> b")
    }

    fn binary_manifest_with_cdata(cdata: &str) -> Vec<u8> {
        const ANDROID_URI: &str = "http://schemas.android.com/apk/res/android";
        const PACKAGE: &str = "com.example&app\"x";
        let strings = vec![
            "manifest",
            ANDROID_URI,
            "package",
            PACKAGE,
            "versionCode",
            "42",
            "application",
            cdata,
            "icon",
            "protectionLevel",
            "textSize",
            "lineSpacingMultiplier",
            "colorAccent",
            "debuggable",
            "theme",
        ];
        let index = |needle: &str| strings.iter().position(|s| *s == needle).unwrap() as u32;

        fn start_chunk(out: &mut Vec<u8>, typ: u16, header_size: u16) -> usize {
            push_u16(out, typ);
            push_u16(out, header_size);
            push_u32(out, 0);
            out.len() - 4
        }

        fn finish_chunk(out: &mut [u8], size_pos: usize) {
            let size = (out.len() - (size_pos - 4)) as u32;
            out[size_pos..size_pos + 4].copy_from_slice(&size.to_le_bytes());
        }

        fn push_u16(out: &mut Vec<u8>, value: u16) {
            out.extend_from_slice(&value.to_le_bytes());
        }

        fn push_u32(out: &mut Vec<u8>, value: u32) {
            out.extend_from_slice(&value.to_le_bytes());
        }

        /// One typed value: `size, res0, type, data`.
        fn push_value(out: &mut Vec<u8>, value_type: u8, data: u32) {
            push_u16(out, 8);
            out.push(0);
            out.push(value_type);
            push_u32(out, data);
        }

        fn push_node_header(out: &mut Vec<u8>, typ: u16) -> usize {
            let size_pos = start_chunk(out, typ, 16);
            push_u32(out, 1); // line number
            push_u32(out, u32::MAX); // comment: none
            size_pos
        }

        fn push_element(out: &mut Vec<u8>, name: u32, attributes: &[(u32, u32, u8, u32)]) -> usize {
            let size_pos = push_node_header(out, 0x0102);
            push_u32(out, u32::MAX); // element namespace: none
            push_u32(out, name);
            push_u16(out, 20); // attribute_start
            push_u16(out, 20); // attribute_size
            push_u16(out, attributes.len() as u16);
            push_u16(out, 0); // id_index
            push_u16(out, 0); // class_index
            push_u16(out, 0); // style_index
            for (ns, name, value_type, data) in attributes {
                push_u32(out, *ns);
                push_u32(out, *name);
                push_u32(out, u32::MAX); // raw value: none
                push_value(out, *value_type, *data);
            }
            size_pos
        }

        // String pool.
        let mut pool = Vec::new();
        let size_pos = start_chunk(&mut pool, 0x0001, 28);
        push_u32(&mut pool, strings.len() as u32);
        push_u32(&mut pool, 0); // style count: the decoder requires zero
        push_u32(&mut pool, 0x0000_0100); // UTF-8 flag
        push_u32(&mut pool, 28 + 4 * strings.len() as u32); // strings start
        push_u32(&mut pool, 0); // style start
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for string in &strings {
            offsets.push(data.len() as u32);
            // AOSP writes a length as one byte, or as two when the high bit of the
            // first marks the extended form; both the UTF-16 and the byte length
            // use whichever form they need.
            for length in [string.chars().count(), string.len()] {
                if length >= 0x80 {
                    data.push(0x80 | (length >> 8) as u8);
                }
                data.push(length as u8);
            }
            data.extend_from_slice(string.as_bytes());
            data.push(0);
        }
        for offset in &offsets {
            push_u32(&mut pool, *offset);
        }
        pool.extend_from_slice(&data);
        while pool.len() % 4 != 0 {
            pool.push(0);
        }
        finish_chunk(&mut pool, size_pos);

        // Empty resource map: attribute names here are strings, not resource ids.
        let mut map = Vec::new();
        let size_pos = start_chunk(&mut map, 0x0180, 8);
        finish_chunk(&mut map, size_pos);

        // document nodes
        let mut nodes = Vec::new();
        let size_pos = push_element(
            &mut nodes,
            index("manifest"),
            &[
                (u32::MAX, index("package"), 0x03, index(PACKAGE)),
                (index(ANDROID_URI), index("versionCode"), 0x10, 42),
                (index(ANDROID_URI), index("icon"), 0x01, 0x7F0D_0001),
                (
                    index(ANDROID_URI),
                    index("protectionLevel"),
                    0x11,
                    0x4000_3FB4,
                ),
                (index(ANDROID_URI), index("textSize"), 0x05, (16 << 8) | 1),
                (
                    index(ANDROID_URI),
                    index("lineSpacingMultiplier"),
                    0x04,
                    0x4000_0000,
                ),
                (index(ANDROID_URI), index("colorAccent"), 0x1c, 0xFF11_2233),
                (index(ANDROID_URI), index("debuggable"), 0x12, 1),
                (index(ANDROID_URI), index("theme"), 0x01, 0x0103_0007),
            ],
        );
        finish_chunk(&mut nodes, size_pos);
        let size_pos = push_element(&mut nodes, index("application"), &[]);
        finish_chunk(&mut nodes, size_pos);
        let size_pos = push_node_header(&mut nodes, 0x0104);
        push_u32(&mut nodes, index(cdata));
        push_value(&mut nodes, 0x03, index(cdata));
        finish_chunk(&mut nodes, size_pos);
        for _ in 0..2 {
            let size_pos = push_node_header(&mut nodes, 0x0103);
            push_u32(&mut nodes, u32::MAX);
            push_u32(&mut nodes, u32::MAX);
            finish_chunk(&mut nodes, size_pos);
        }

        let mut out = Vec::new();
        let size_pos = start_chunk(&mut out, 0x0003, 8);
        out.extend_from_slice(&pool);
        out.extend_from_slice(&map);
        out.extend_from_slice(&nodes);
        finish_chunk(&mut out, size_pos);
        out
    }

    #[test]
    fn decodes_binary_axml_with_escaping_and_indentation() {
        let rendered = decode(&binary_manifest()).unwrap();
        assert_eq!(
            rendered,
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
                "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"",
                " package=\"com.example&amp;app&quot;x\" android:versionCode=\"42\"",
                " android:icon=\"@7F0D0001\" android:protectionLevel=\"0x40003FB4\"",
                " android:textSize=\"16.000000dip\" android:lineSpacingMultiplier=\"2.000000\"",
                " android:colorAccent=\"#FF112233\" android:debuggable=\"true\"",
                " android:theme=\"@android:01030007\">\n",
                "    <application>\n",
                "        <![CDATA[a ]] ]]><![CDATA[> b]]>\n",
                "    </application>\n",
                "</manifest>",
            )
        );
    }

    #[test]
    fn rejects_truncated_binary_axml_instead_of_aborting() {
        // The decoder unwraps its own reads, and the release profile aborts on
        // panic, so this has to be caught before it is handed over.
        let mut data = binary_manifest();
        data.truncate(data.len() / 2);
        let error = format!("{:#}", decode(&data).unwrap_err());
        assert!(
            error.contains("runs past the end of the input"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn renders_every_typed_value_like_android_tooling() {
        // The vendored decoder formats typed values; the forms mirror Androguard's
        // `format_value`, which is what the reference implementation prints.
        let rendered = decode(&binary_manifest()).unwrap();
        for expected in [
            "package=\"com.example&amp;app&quot;x\"",
            "android:versionCode=\"42\"",
            "android:icon=\"@7F0D0001\"",
            "android:protectionLevel=\"0x40003FB4\"",
            "android:textSize=\"16.000000dip\"",
            "android:lineSpacingMultiplier=\"2.000000\"",
            "android:colorAccent=\"#FF112233\"",
            "android:debuggable=\"true\"",
            "android:theme=\"@android:01030007\"",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected} in {rendered}"
            );
        }
        assert!(
            !rendered.contains("ResourceValueType::"),
            "placeholder leaked: {rendered}"
        );
    }

    #[test]
    fn rejects_a_document_whose_first_node_is_cdata() {
        // A CDATA node outside any element used to reach an unwrap inside the
        // vendored decoder; the patch turns it into a parse error.
        let mut data = binary_manifest();
        let pool = 8;
        let pool_size = u32::from_le_bytes(data[pool + 4..pool + 8].try_into().unwrap()) as usize;
        let map = pool + pool_size;
        let map_size = u32::from_le_bytes(data[map + 4..map + 8].try_into().unwrap()) as usize;
        let first_node = map + map_size;
        data[first_node..first_node + 2].copy_from_slice(&0x0104u16.to_le_bytes());
        data[first_node + 16..first_node + 20].copy_from_slice(&0u32.to_le_bytes());
        data[first_node + 20..first_node + 22].copy_from_slice(&8u16.to_le_bytes());
        data[first_node + 22] = 0;
        data[first_node + 23] = 0x03;
        data[first_node + 24..first_node + 28].copy_from_slice(&0u32.to_le_bytes());
        // Keep only this node: the decoder reads the whole node list before building
        // the tree, so a misaligned tail would hide the case under test.
        let end_of_document = first_node + 28;
        data[4..8].copy_from_slice(&(end_of_document as u32).to_le_bytes());
        data.truncate(end_of_document);
        let error = format!("{:#}", decode(&data).unwrap_err());
        assert!(
            error.contains("binary Android XML"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn decoded_manifest_carries_no_decoder_placeholders() {
        let rendered = decode(&binary_manifest()).unwrap();
        assert!(
            rendered.contains("android:icon=\"@7F0D0001\""),
            "unexpected manifest: {rendered}"
        );
        assert!(
            !rendered.contains("ResourceValueType::"),
            "placeholder leaked: {rendered}"
        );
    }

    #[test]
    fn decodes_strings_with_extended_lengths() {
        // A 200-byte string is written with the two-byte length form, which the
        // vendored decoder implements; upstream axmldecoder panicked on it.
        let long = "x".repeat(200);
        let rendered = decode(&binary_manifest_with_cdata(&long)).unwrap();
        assert!(
            rendered.contains(&long),
            "long string missing from: {rendered}"
        );
    }

    #[test]
    fn rejects_binary_axml_with_a_styled_string_pool() {
        // The decoder asserts style_count == 0; a crafted pool must be an error.
        let mut data = binary_manifest();
        let pool = 8; // the document chunk header comes first
        data[pool + 12..pool + 16].copy_from_slice(&1u32.to_le_bytes());
        let error = format!("{:#}", decode(&data).unwrap_err());
        assert!(
            error.contains("styles is not supported"),
            "unexpected error: {error}"
        );
    }

    /// First offset of `needle` in `haystack`.
    fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    #[test]
    fn renders_unknown_typed_values_like_the_reference() {
        // AXML defines types beyond the ones Androguard names (0x07 dynamic
        // reference, 0x08 dynamic attribute, 0x13-0x1b, >= 0x20). The reference
        // prints its `<0x.., type 0x..>` fallback rather than refusing the whole
        // document, so an unknown type byte must decode.
        let mut data = binary_manifest();
        // `android:icon` is a reference value: size 8, res0 0, type 0x01, data 0x7F0D0001.
        let icon = [0x08, 0x00, 0x00, 0x01, 0x01, 0x00, 0x0D, 0x7F];
        let at = find_bytes(&data, &icon).expect("icon attribute value");
        assert_eq!(
            find_bytes(&data[at + 1..], &icon),
            None,
            "value pattern is not unique"
        );
        data[at + 3] = 0x07;
        let rendered = decode(&data).unwrap();
        assert!(
            rendered.contains("android:icon=\"&lt;0x7F0D0001, type 0x07&gt;\""),
            "unexpected rendering: {rendered}"
        );
    }

    #[test]
    fn reserved_types_keep_the_unknown_value_fallback() {
        // 0x13-0x1B are reserved in AOSP. Androguard's integer branch spans
        // 0x10-0x1F, so it prints them as decimals; claiming to know a reserved
        // type is worse than showing the raw value, so they stay on the fallback.
        let mut data = binary_manifest();
        // `android:debuggable` is a boolean value: size 8, res0 0, type 0x12, data 1.
        let debuggable = [0x08, 0x00, 0x00, 0x12, 0x01, 0x00, 0x00, 0x00];
        let at = find_bytes(&data, &debuggable).expect("debuggable attribute value");
        assert_eq!(
            find_bytes(&data[at + 1..], &debuggable),
            None,
            "value pattern is not unique"
        );
        data[at + 3] = 0x13;
        let rendered = decode(&data).unwrap();
        assert!(
            rendered.contains("android:debuggable=\"&lt;0x1, type 0x13&gt;\""),
            "unexpected rendering: {rendered}"
        );
    }

    #[test]
    fn complex_values_use_exact_powers_of_two() {
        // Fraction with mantissa 16384 and radix 1 is exactly 0.5, so 50.000000%.
        // Androguard rounds its radix multiples to seven digits and prints
        // 50.000003%; the exact value is kept deliberately.
        let mut data = binary_manifest();
        // `android:textSize` is a dimension: size 8, res0 0, type 0x05, data 0x1001.
        let text_size = [0x08, 0x00, 0x00, 0x05, 0x01, 0x10, 0x00, 0x00];
        let at = find_bytes(&data, &text_size).expect("textSize attribute value");
        assert_eq!(
            find_bytes(&data[at + 1..], &text_size),
            None,
            "value pattern is not unique"
        );
        data[at + 3] = 0x06; // dimension -> fraction
        data[at + 4..at + 8].copy_from_slice(&0x0000_4010u32.to_le_bytes()); // mantissa 16384, radix 1, unit '%'
        let rendered = decode(&data).unwrap();
        assert!(
            rendered.contains("android:textSize=\"50.000000%\""),
            "unexpected rendering: {rendered}"
        );
    }

    #[test]
    fn rejects_a_resource_map_chunk_smaller_than_its_header() {
        // The decoder computes its entry count as `(size - header_size) / 4` in
        // u32, so a size below the header size wraps to ~1e9 entries. Nothing
        // else in the pipeline validates this chunk.
        let mut data = binary_manifest();
        let map = find_chunk(&data, 0x0180).expect("fixture has a resource map");
        data[map + 2..map + 4].copy_from_slice(&8u16.to_le_bytes());
        data[map + 4..map + 8].copy_from_slice(&4u32.to_le_bytes());
        let error = format!("{:#}", decode(&data).unwrap_err());
        assert!(
            error.contains("resource map chunk is malformed"),
            "unexpected error: {error}"
        );
    }

    /// Offset of the first chunk of `typ`, walking the fixture's chunk list.
    fn find_chunk(data: &[u8], typ: u16) -> Option<usize> {
        let mut offset = 8;
        while offset + 8 <= data.len() {
            let chunk_type = u16::from_le_bytes([data[offset], data[offset + 1]]);
            let size =
                u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;
            if chunk_type == typ {
                return Some(offset);
            }
            if size == 0 {
                return None;
            }
            offset += size;
        }
        None
    }

    #[test]
    fn rejects_input_that_is_not_a_document_chunk() {
        let error = format!("{:#}", decode(&[0u8; 32]).unwrap_err());
        assert!(
            error.contains("document chunk"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn accepts_plain_xml_manifests() {
        let input = b"<?xml version=\"1.0\"?><manifest package=\"example\"/>";
        assert_eq!(decode(input).unwrap().as_bytes(), input);
    }

    #[test]
    fn escapes_xml_attribute_values() {
        let mut output = String::new();
        escape_xml("a&<>'\"", true, &mut output);
        assert_eq!(output, "a&amp;&lt;&gt;&apos;&quot;");
    }
}
