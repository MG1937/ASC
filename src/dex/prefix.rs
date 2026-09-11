//! String-only DEX prefix reader.
//!
//! A class index or a class lookup needs the header, the id tables that name
//! classes, the class_def rows and the string data - measured at 31.7% of the bytes
//! of a 343 MiB APK - and nothing after it. This module decodes exactly that much,
//! sharing the full reader's decoding rules, and answers `None` whenever the prefix
//! does not reach far enough so the caller falls back instead of trusting a guess.

use super::read_uleb;
use crate::bytes::read_u32;
use anyhow::Result;

const HEADER_SIZE: usize = 0x70;
const STRING_ID_ITEM: usize = 4;
const TYPE_ID_ITEM: usize = 4;
const CLASS_DEF_ITEM: usize = 32;

/// Class descriptors of `prefix`, or `None` when it is too short to hold them all.
pub(crate) fn class_names(prefix: &[u8]) -> Result<Option<Vec<String>>> {
    if prefix.len() < HEADER_SIZE || prefix.get(..4) != Some(b"dex\n") {
        return Ok(None);
    }
    let strings_size = read_u32(prefix, 0x38)? as usize;
    let strings_off = read_u32(prefix, 0x3c)? as usize;
    let types_size = read_u32(prefix, 0x40)? as usize;
    let types_off = read_u32(prefix, 0x44)? as usize;
    let classes_size = read_u32(prefix, 0x60)? as usize;
    let classes_off = read_u32(prefix, 0x64)? as usize;

    // Every table has to be present in full before a single descriptor is trusted.
    for end in [
        table_end(strings_off, strings_size, STRING_ID_ITEM),
        table_end(types_off, types_size, TYPE_ID_ITEM),
        table_end(classes_off, classes_size, CLASS_DEF_ITEM),
    ] {
        match end {
            Some(end) if end <= prefix.len() => {}
            _ => return Ok(None),
        }
    }

    let mut names = Vec::with_capacity(classes_size);
    for index in 0..classes_size {
        let class_idx = read_u32(prefix, classes_off + index * CLASS_DEF_ITEM)? as usize;
        if class_idx >= types_size {
            return Ok(None);
        }
        let string_idx = read_u32(prefix, types_off + class_idx * TYPE_ID_ITEM)? as usize;
        if string_idx >= strings_size {
            return Ok(None);
        }
        let data_off = read_u32(prefix, strings_off + string_idx * STRING_ID_ITEM)? as usize;
        let Some(bytes) = string_at(prefix, data_off) else {
            return Ok(None);
        };
        names.push(
            droidsaw_dex::mutf8::decode_mutf8(bytes)
                .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned()),
        );
    }
    Ok(Some(names))
}

fn table_end(offset: usize, count: usize, stride: usize) -> Option<usize> {
    offset.checked_add(count.checked_mul(stride)?)
}

/// The MUTF-8 bytes of the string_data item at `offset`, without its terminator.
fn string_at(data: &[u8], offset: usize) -> Option<&[u8]> {
    let mut cursor = offset;
    read_uleb(data, &mut cursor).ok()?;
    let tail = data.get(cursor..)?;
    let end = memchr::memchr(0, tail)?;
    Some(&tail[..end])
}

/// The byte offset just past the last string_data item, or `None` when the id tables
/// are not complete yet.
///
/// Reading this needs only the three tables - far less than the string data itself -
/// and it is what lets a caller decide whether inflating a prefix is cheaper than
/// inflating everything.
pub(crate) fn string_data_end(prefix: &[u8]) -> Option<usize> {
    if prefix.len() < HEADER_SIZE || prefix.get(..4) != Some(b"dex\n") {
        return None;
    }
    let strings_size = read_u32(prefix, 0x38).ok()? as usize;
    let strings_off = read_u32(prefix, 0x3c).ok()? as usize;
    let types_size = read_u32(prefix, 0x40).ok()? as usize;
    let types_off = read_u32(prefix, 0x44).ok()? as usize;
    let classes_size = read_u32(prefix, 0x60).ok()? as usize;
    let classes_off = read_u32(prefix, 0x64).ok()? as usize;
    let strings_end = table_end(strings_off, strings_size, STRING_ID_ITEM)?;
    let types_end = table_end(types_off, types_size, TYPE_ID_ITEM)?;
    let classes_end = table_end(classes_off, classes_size, CLASS_DEF_ITEM)?;
    if strings_end > prefix.len() || types_end > prefix.len() || classes_end > prefix.len() {
        return None;
    }
    let mut end = 0usize;
    for index in 0..strings_size {
        let off = read_u32(prefix, strings_off + index * STRING_ID_ITEM).ok()? as usize;
        end = end.max(off);
    }
    // Every class_def must be readable before the answer is trusted.
    for index in 0..classes_size {
        let class_idx = read_u32(prefix, classes_off + index * CLASS_DEF_ITEM).ok()? as usize;
        if class_idx >= types_size {
            return None;
        }
        if read_u32(prefix, types_off + class_idx * TYPE_ID_ITEM).is_err() {
            return None;
        }
    }
    Some(end)
}

/// Whether `prefix` shows that this DEX defines `descriptor`, or `None` when the
/// prefix cannot answer (too short, or a 041 container which the full reader owns).
pub(crate) fn defines_class(prefix: &[u8], descriptor: &[u8]) -> Result<Option<bool>> {
    if prefix.len() < HEADER_SIZE || prefix.get(..4) != Some(b"dex\n") {
        return Ok(None);
    }
    let strings_size = read_u32(prefix, 0x38)? as usize;
    let strings_off = read_u32(prefix, 0x3c)? as usize;
    let types_size = read_u32(prefix, 0x40)? as usize;
    let types_off = read_u32(prefix, 0x44)? as usize;
    let classes_size = read_u32(prefix, 0x60)? as usize;
    let classes_off = read_u32(prefix, 0x64)? as usize;
    for end in [
        table_end(strings_off, strings_size, STRING_ID_ITEM),
        table_end(types_off, types_size, TYPE_ID_ITEM),
        table_end(classes_off, classes_size, CLASS_DEF_ITEM),
    ]
    .into_iter()
    {
        match end {
            Some(end) if end <= prefix.len() => {}
            _ => return Ok(None),
        }
    }
    for index in 0..classes_size {
        let class_idx = read_u32(prefix, classes_off + index * CLASS_DEF_ITEM)? as usize;
        if class_idx >= types_size {
            return Ok(None);
        }
        let string_idx = read_u32(prefix, types_off + class_idx * TYPE_ID_ITEM)? as usize;
        if string_idx >= strings_size {
            return Ok(None);
        }
        let data_off = read_u32(prefix, strings_off + string_idx * STRING_ID_ITEM)? as usize;
        let Some(bytes) = string_at(prefix, data_off) else {
            return Ok(None);
        };
        if bytes == descriptor {
            return Ok(Some(true));
        }
    }
    Ok(Some(false))
}
