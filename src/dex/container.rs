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

const HEADER_SIZE_041: usize = 0x78;

pub(crate) struct LogicalDex<'a> {
    pub(crate) name: String,
    pub(crate) data: Cow<'a, [u8]>,
}

/// A copy of a DEX 041 view whose header looks like a standard 0x70 header.
///
/// `None` for anything that is not a 041 header, in which case the caller keeps
/// using its own bytes. DEX 041 adds two header fields after the standard ones and
/// its checksum covers the whole container, neither of which `droidsaw-dex`
/// accepts (`invalid DEX header_size: 120`), so the decompiler is handed a view
/// whose header size says 0x70 and whose Adler-32 matches the view again.
/// Section offsets stay container-relative, which is exactly what the buffer
/// produced by [`logical_dexes`] provides.
pub(crate) fn standard_header_view(data: &[u8]) -> Option<Vec<u8>> {
    const HEADER_SIZE_041: usize = 0x78;
    if data.len() < HEADER_SIZE_041 || data.get(..8) != Some(b"dex\n041\0") {
        return None;
    }
    let mut view = data.to_vec();
    view[0x24..0x28].copy_from_slice(&0x70u32.to_le_bytes());
    // The member's own `file_size` stops at its header/section block, while its
    // section offsets are container-relative and reach past that, so the view
    // has to declare the whole container as its file.
    let file_size = view.len() as u32;
    view[0x20..0x24].copy_from_slice(&file_size.to_le_bytes());
    let checksum = adler32(&view[12..]);
    view[0x08..0x0C].copy_from_slice(&checksum.to_le_bytes());
    Some(view)
}

/// DEX header checksum, the value `droidsaw-dex` validates before parsing.
fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for byte in bytes {
        a = (a + u32::from(*byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Iterator over the logical DEXes of one entry, produced one member at a time.
///
/// Every container member needs its own copy of the container with its header
/// overlaid at offset zero (DEX 041 section offsets are relative to the physical
/// container), so materializing all of them costs `members × entry size` of
/// resident memory: a 398 KiB entry with 3400 members measured **1.34 GiB** of
/// RSS before this became lazy. Members are therefore produced on demand, and a
/// caller that stops early (a `getclass` hit) never copies the rest.
pub(crate) struct LogicalDexes<'a> {
    name: &'a str,
    data: &'a [u8],
    /// Member header offsets; empty means "one plain DEX, borrowed".
    offsets: Vec<usize>,
    next: usize,
}

impl<'a> Iterator for LogicalDexes<'a> {
    type Item = LogicalDex<'a>;

    fn next(&mut self) -> Option<LogicalDex<'a>> {
        if self.offsets.is_empty() {
            if self.next > 0 {
                return None;
            }
            self.next = 1;
            return Some(LogicalDex {
                name: self.name.to_owned(),
                data: Cow::Borrowed(self.data),
            });
        }
        let index = self.next;
        let header_offset = *self.offsets.get(index)?;
        self.next += 1;
        // Keep the complete container address space but overlay this member's
        // header at offset zero, the checked view the scanner expects.
        let mut normalized = self.data.to_vec();
        normalized[..HEADER_SIZE_041]
            .copy_from_slice(&self.data[header_offset..header_offset + HEADER_SIZE_041]);
        Some(LogicalDex {
            name: format!("{}!classes{}.dex", self.name, index + 1),
            data: Cow::Owned(normalized),
        })
    }
}

/// The logical DEXes in `data`: validated up front, yielded lazily.
///
/// A single-member 041 container — and any ordinary DEX — keeps the entry's own
/// name and borrowed bytes, which is what the reference implementation does;
/// only a container with several members renames them `name!classesN.dex`.
pub(crate) fn logical_dexes<'a>(name: &'a str, data: &'a [u8]) -> Result<LogicalDexes<'a>> {
    let plain = LogicalDexes {
        name,
        data,
        offsets: Vec::new(),
        next: 0,
    };
    if data.len() < HEADER_SIZE_041 || data.get(..8) != Some(b"dex\n041\0") {
        return Ok(plain);
    }

    let container_size = read_u32(data, 0x70)? as usize;
    if container_size != data.len() {
        bail!(
            "DEX 041 container size mismatch: header={container_size}, actual={}",
            data.len()
        );
    }
    // Validate every member header first: metadata only, no copies, so a
    // malformed container is rejected before any member work happens.
    let mut offsets = Vec::new();
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
        offsets.push(header_offset);
        header_offset = header_offset
            .checked_add(file_size)
            .context("DEX 041 header offset overflow")?;
    }
    if offsets.is_empty() || header_offset != data.len() {
        bail!("malformed DEX 041 logical container");
    }
    if offsets.len() == 1 {
        // One member: the container is that DEX with an extra-long header, the
        // overlay would be a no-op, and the reference keeps the plain name.
        return Ok(plain);
    }
    Ok(LogicalDexes {
        name,
        data,
        offsets,
        next: 0,
    })
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
        let logical: Vec<_> = logical_dexes("classes.dex", &data).unwrap().collect();
        assert_eq!(logical.len(), 2);
        assert_eq!(logical[0].name, "classes.dex!classes1.dex");
        assert_eq!(logical[1].name, "classes.dex!classes2.dex");
        assert_eq!(&logical[1].data[..8], b"dex\n041\0");
        assert_eq!(read_u32(&logical[1].data, 0x74).unwrap(), SIZE as u32);
    }
    #[test]
    fn single_member_041_container_keeps_the_plain_name_and_bytes() {
        // One member means the container is that DEX with an extra-long header:
        // the overlay would be a no-op and the reference yields it under the
        // entry's own name, so nothing is copied.
        let container = crate::dex::tests::dex041_container(&[1]);
        let mut logical = logical_dexes("classes.dex", &container).unwrap();
        let member = logical.next().expect("one member");
        assert_eq!(member.name, "classes.dex");
        assert!(matches!(member.data, Cow::Borrowed(_)));
        assert!(logical.next().is_none());
    }

    #[test]
    fn logical_members_are_produced_lazily() {
        // A tiling container with 8000 members in a 600 KiB entry. Materializing
        // the members (each one copies the whole container, which is what the
        // first implementation did) would need ~4.8 GiB here; taking one member
        // costs a single copy instead.
        const MEMBERS: usize = 8000;
        let size = HEADER_SIZE_041 * MEMBERS;
        let mut data = vec![0; size];
        for index in 0..MEMBERS {
            let offset = index * HEADER_SIZE_041;
            data[offset..offset + 8].copy_from_slice(b"dex\n041\0");
            write_u32(&mut data, offset + 0x20, HEADER_SIZE_041 as u32);
            write_u32(&mut data, offset + 0x24, 0x70);
            write_u32(&mut data, offset + 0x70, size as u32);
            write_u32(&mut data, offset + 0x74, offset as u32);
        }
        let mut logical = logical_dexes("classes.dex", &data).unwrap();
        let first = logical.next().expect("first member");
        assert_eq!(first.name, "classes.dex!classes1.dex");
        assert_eq!(read_u32(&first.data, 0x74).unwrap(), 0);
        let second = logical.next().expect("second member");
        assert_eq!(second.name, "classes.dex!classes2.dex");
        assert_eq!(
            read_u32(&second.data, 0x74).unwrap(),
            HEADER_SIZE_041 as u32
        );
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
        let logical: Vec<_> = logical_dexes("classes.dex", data).unwrap().collect();
        assert_eq!(logical.len(), 1);
        assert_eq!(logical[0].name, "classes.dex");
        assert!(matches!(logical[0].data, Cow::Borrowed(_)));
    }
}
