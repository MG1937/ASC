//! DEX 041 logical containers.
//!
//! A 041 entry can hold several logical DEX files: each carries a 0x78-byte header
//! whose section offsets are relative to the physical container start. The scanner
//! expects a checked view whose header sits at offset zero, so each logical header
//! is overlaid on a copy of the whole container and the complete address space is
//! kept.

use crate::bytes::read_u32;
use anyhow::{Context, Result, bail};
use std::borrow::Cow;

pub(crate) struct LogicalDex<'a> {
    pub(crate) name: String,
    pub(crate) data: Cow<'a, [u8]>,
}

pub(crate) fn logical_dexes<'a>(name: &str, data: &'a [u8]) -> Result<Vec<LogicalDex<'a>>> {
    const HEADER_SIZE_041: usize = 0x78;
    if data.len() < HEADER_SIZE_041 || data.get(..8) != Some(b"dex\n041\0") {
        return Ok(vec![LogicalDex {
            name: name.to_owned(),
            data: Cow::Borrowed(data),
        }]);
    }

    let container_size = read_u32(data, 0x70)? as usize;
    if container_size != data.len() {
        bail!(
            "DEX 041 container size mismatch: header={container_size}, actual={}",
            data.len()
        );
    }
    let mut logical = Vec::new();
    let mut header_offset = 0usize;
    while header_offset + HEADER_SIZE_041 <= data.len() {
        if data.get(header_offset..header_offset + 8) != Some(b"dex\n041\0") {
            break;
        }
        let file_size = read_u32(data, header_offset + 0x20)? as usize;
        let declared_header_offset = read_u32(data, header_offset + 0x74)? as usize;
        let declared_container_size = read_u32(data, header_offset + 0x70)? as usize;
        if declared_header_offset != header_offset || declared_container_size != container_size {
            bail!("inconsistent DEX 041 logical header at {header_offset}");
        }
        if file_size < HEADER_SIZE_041 || file_size > data.len() - header_offset {
            bail!("invalid DEX 041 logical file size at {header_offset}");
        }

        // DEX 041 section offsets are relative to the physical container. Keep
        // the complete container address space but overlay this logical header
        // at offset zero, matching the checked DEX view used by the scanner.
        let mut normalized = data.to_vec();
        normalized[..HEADER_SIZE_041]
            .copy_from_slice(&data[header_offset..header_offset + HEADER_SIZE_041]);
        logical.push(LogicalDex {
            name: format!("{name}!classes{}.dex", logical.len() + 1),
            data: Cow::Owned(normalized),
        });
        header_offset = header_offset
            .checked_add(file_size)
            .context("DEX 041 header offset overflow")?;
    }
    if logical.is_empty() || header_offset != data.len() {
        bail!("malformed DEX 041 logical container");
    }
    Ok(logical)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn dex041_container_exposes_all_logical_headers() {
        const SIZE: usize = 0x78;
        let mut data = vec![0; SIZE * 2];
        for offset in [0, SIZE] {
            data[offset..offset + 8].copy_from_slice(b"dex\n041\0");
            write_u32(&mut data, offset + 0x20, SIZE as u32);
            write_u32(&mut data, offset + 0x24, SIZE as u32);
            write_u32(&mut data, offset + 0x70, (SIZE * 2) as u32);
            write_u32(&mut data, offset + 0x74, offset as u32);
        }
        let logical = logical_dexes("classes.dex", &data).unwrap();
        assert_eq!(logical.len(), 2);
        assert_eq!(logical[0].name, "classes.dex!classes1.dex");
        assert_eq!(logical[1].name, "classes.dex!classes2.dex");
        assert_eq!(&logical[1].data[..8], b"dex\n041\0");
        assert_eq!(read_u32(&logical[1].data, 0x74).unwrap(), SIZE as u32);
    }
    #[test]
    fn dex041_rejects_inconsistent_offsets() {
        let mut data = vec![0; 0x78];
        data[..8].copy_from_slice(b"dex\n041\0");
        write_u32(&mut data, 0x20, 0x78);
        write_u32(&mut data, 0x70, 0x78);
        write_u32(&mut data, 0x74, 4);
        assert!(logical_dexes("classes.dex", &data).is_err());
    }
    #[test]
    fn ordinary_dex_uses_borrowed_fast_path() {
        let data = b"dex\n039\0rest";
        let logical = logical_dexes("classes.dex", data).unwrap();
        assert_eq!(logical.len(), 1);
        assert_eq!(logical[0].name, "classes.dex");
        assert!(matches!(logical[0].data, Cow::Borrowed(_)));
    }
}
