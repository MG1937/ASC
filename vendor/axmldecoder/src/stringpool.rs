use deku::bitvec::{BitSlice, Msb0};
use deku::prelude::*;

use byteorder::ByteOrder;
use byteorder::LittleEndian;
use std::io::Read;
use std::rc::Rc;

use crate::binaryxml::ChunkHeader;
use crate::ParseError;

#[derive(Debug, DekuRead, DekuWrite)]
pub(crate) struct StringPoolHeader {
    pub(crate) chunk_header: ChunkHeader,
    pub(crate) string_count: u32,
    pub(crate) style_count: u32,
    pub(crate) flags: u32,
    pub(crate) string_start: u32,
    pub(crate) style_start: u32,
}

#[derive(Debug, DekuRead)]
pub(crate) struct StringPool {
    pub(crate) header: StringPoolHeader,
    #[deku(reader = "StringPool::read_strings(header, deku::rest)")]
    pub(crate) strings: Vec<Rc<String>>,
}

type DekuRest = BitSlice<u8, Msb0>;
impl StringPool {
    fn read_strings<'a>(
        header: &StringPoolHeader,
        mut rest: &'a DekuRest,
    ) -> Result<(&'a DekuRest, Vec<Rc<String>>), DekuError> {
        const STRINGPOOL_HEADER_SIZE: usize = std::mem::size_of::<StringPoolHeader>();

        // PATCHED (rasc): our caller validates this and rejects styled pools.
        assert_eq!(header.style_count, 0);

        let flag_is_utf8 = (header.flags & (1 << 8)) != 0;

        let s = usize::try_from(header.chunk_header.size).unwrap() - STRINGPOOL_HEADER_SIZE;

        let mut string_pool_data = vec![0; s];
        rest.read_exact(&mut string_pool_data).unwrap();

        // Parse string offsets
        let num_offsets = usize::try_from(header.string_count).unwrap();
        let offsets = parse_offsets(&string_pool_data, num_offsets);

        let string_data_start =
            usize::try_from(header.string_start).unwrap() - STRINGPOOL_HEADER_SIZE;
        let string_data = &string_pool_data[string_data_start..];

        let mut strings = Vec::with_capacity(usize::try_from(header.string_count).unwrap());

        let parse_fn = if flag_is_utf8 {
            parse_utf8_string
        } else {
            parse_utf16_string
        };

        for offset in offsets {
            strings.push(Rc::new(
                parse_fn(string_data, usize::try_from(offset).unwrap())
                    .map_err(|e| DekuError::Parse(e.to_string()))?,
            ));
        }

        Ok((rest, strings))
    }

    pub(crate) fn get(&self, i: usize) -> Option<Rc<String>> {
        if u32::try_from(i).unwrap() == u32::MAX {
            return None;
        }

        Some(self.strings.get(i)?.clone())
    }
}

fn parse_offsets(string_data: &[u8], count: usize) -> Vec<u32> {
    let mut offsets = Vec::with_capacity(count);

    for i in 0..count {
        let index = i * 4;
        let offset = LittleEndian::read_u32(&string_data[index..index + 4]);
        offsets.push(offset);
    }

    offsets
}

// PATCHED (rasc): the two-byte length forms below are implemented instead of
// panicking, because real manifests in the test corpus use them; see PATCHES.md.
fn parse_utf16_string(string_data: &[u8], offset: usize) -> Result<String, ParseError> {
    let mut cursor = offset;
    let len = decode_length_16(string_data, &mut cursor);

    let string_start = cursor;

    let mut s = Vec::with_capacity(len);
    for i in 0..len {
        let index = string_start + i * 2;
        let char = LittleEndian::read_u16(&string_data[index..index + 2]);
        s.push(char);
    }

    let s = String::from_utf16(&s).map_err(ParseError::Utf16StringParseError)?;
    Ok(s)
}

/// Reads one string length: a single UTF-16 unit, or three units when the high bit
/// of the first marks the extended form.
fn decode_length_16(string_data: &[u8], cursor: &mut usize) -> usize {
    let first = LittleEndian::read_u16(&string_data[*cursor..*cursor + 2]);
    *cursor += 2;
    if first & 0x8000 == 0 {
        return usize::from(first);
    }
    let second = LittleEndian::read_u16(&string_data[*cursor..*cursor + 2]);
    *cursor += 2;
    ((usize::from(first & 0x7fff)) << 16) | usize::from(second)
}

/// Reads one string length from a UTF-8 pool: one byte, or two when the high bit of
/// the first is set.
fn decode_length_8(string_data: &[u8], cursor: &mut usize) -> usize {
    let first = string_data[*cursor];
    *cursor += 1;
    if first & 0x80 == 0 {
        return usize::from(first);
    }
    let second = string_data[*cursor];
    *cursor += 1;
    (usize::from(first & 0x7f) << 8) | usize::from(second)
}

fn parse_utf8_string(string_data: &[u8], offset: usize) -> Result<String, ParseError> {
    // A UTF-8 pool entry stores the UTF-16 length first and the byte length second,
    // and either may use the two-byte form.
    let mut cursor = offset;
    let _utf16_len = decode_length_8(string_data, &mut cursor);
    let len = decode_length_8(string_data, &mut cursor);

    let string_start = cursor;

    let mut s = Vec::with_capacity(len);
    for i in 0..len {
        s.push(string_data[string_start + i]);
    }

    let s = String::from_utf8(s).map_err(ParseError::Utf8StringParseError)?;
    Ok(s)
}


