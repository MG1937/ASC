//! ZIP container codec: end-of-central-directory discovery, central-directory
//! entries and per-entry inflation.
//!
//! Only what an APK reader needs: no ZIP64, no encryption, no data descriptors.
//! Sizes come from the central directory, so a smeared local header cannot make a
//! declared size disagree with the bytes that get inflated.

use crate::bytes::{read_u16, read_u32};
use anyhow::{Context, Result, bail};
use libdeflater::Decompressor;

#[derive(Clone, Debug)]
pub(crate) struct ZipEntry {
    pub(crate) name: String,
    pub(crate) uncompressed_size: usize,
    pub(crate) compressed_size: usize,
    pub(crate) local_header_offset: usize,
    pub(crate) compression: u16,
}

pub(crate) fn parse_zip_entries(
    data: &[u8],
    mut include: impl FnMut(&[u8]) -> bool,
) -> Result<Vec<ZipEntry>> {
    let search_start = data.len().saturating_sub(65_557);
    let eocd = data[search_start..]
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .map(|position| position + search_start)
        .context("EOCD not found")?;
    let cd_size = read_u32(data, eocd + 12)? as usize;
    let cd_offset = read_u32(data, eocd + 16)? as usize;
    let cd_end = cd_offset
        .checked_add(cd_size)
        .context("central directory overflow")?;
    if cd_end > data.len() {
        bail!("bad central directory range");
    }
    let mut entries = Vec::new();
    let mut offset = cd_offset;
    while offset + 46 <= cd_end {
        if data.get(offset..offset + 4) != Some(b"PK\x01\x02") {
            bail!("bad central directory signature at {offset}");
        }
        let name_len = read_u16(data, offset + 28)? as usize;
        let extra_len = read_u16(data, offset + 30)? as usize;
        let comment_len = read_u16(data, offset + 32)? as usize;
        let name_start = offset + 46;
        let name_end = name_start
            .checked_add(name_len)
            .context("ZIP name overflow")?;
        let name_bytes = data
            .get(name_start..name_end)
            .context("bad ZIP name range")?;
        if include(name_bytes) {
            entries.push(ZipEntry {
                name: String::from_utf8_lossy(name_bytes).into_owned(),
                uncompressed_size: read_u32(data, offset + 24)? as usize,
                compressed_size: read_u32(data, offset + 20)? as usize,
                local_header_offset: read_u32(data, offset + 42)? as usize,
                compression: read_u16(data, offset + 10)?,
            });
        }
        offset = name_end
            .checked_add(extra_len)
            .and_then(|v| v.checked_add(comment_len))
            .context("central directory entry overflow")?;
    }
    Ok(entries)
}

pub(crate) fn inflate_entry(data: &[u8], entry: &ZipEntry) -> Result<Vec<u8>> {
    let offset = entry.local_header_offset;
    if data.get(offset..offset + 4) != Some(b"PK\x03\x04") {
        bail!("bad local header for {}", entry.name);
    }
    let name_len = read_u16(data, offset + 26)? as usize;
    let extra_len = read_u16(data, offset + 28)? as usize;
    let start = offset + 30 + name_len + extra_len;
    let end = start
        .checked_add(entry.compressed_size)
        .context("compressed range overflow")?;
    let compressed = data.get(start..end).context("bad compressed range")?;
    match entry.compression {
        0 => {
            if compressed.len() != entry.uncompressed_size {
                bail!(
                    "size mismatch for {}: expected {}, got {}",
                    entry.name,
                    entry.uncompressed_size,
                    compressed.len()
                );
            }
            Ok(compressed.to_vec())
        }
        8 => {
            let mut output = vec![0; entry.uncompressed_size];
            let written = Decompressor::new()
                .deflate_decompress(compressed, &mut output)
                .with_context(|| format!("inflate {}", entry.name))?;
            if written != entry.uncompressed_size {
                bail!(
                    "size mismatch for {}: expected {}, got {written}",
                    entry.name,
                    entry.uncompressed_size
                );
            }
            Ok(output)
        }
        method => bail!("unsupported compression method {method} for {}", entry.name),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Raw deflate of `payload`, the way a ZIP writer stores a DEX entry.
    fn deflate(payload: &[u8]) -> Vec<u8> {
        let mut compressor = libdeflater::Compressor::new(libdeflater::CompressionLvl::default());
        let mut out = vec![0u8; compressor.deflate_compress_bound(payload.len())];
        let written = compressor.deflate_compress(payload, &mut out).unwrap();
        out.truncate(written);
        out
    }

    /// Builds a ZIP archive in memory. The third tuple field selects deflate
    /// (8) over stored (0); CRC fields are left zero because the parser never
    /// reads them.
    pub(crate) fn build_zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut local = Vec::new();
        let mut central = Vec::new();
        for (name, payload, deflated) in entries {
            let stored = if *deflated {
                deflate(payload)
            } else {
                payload.to_vec()
            };
            let offset = local.len() as u32;
            local.extend_from_slice(b"PK\x03\x04");
            local.extend_from_slice(&20u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&if *deflated { 8u16 } else { 0u16 }.to_le_bytes());
            local.extend_from_slice(&[0; 4]);
            local.extend_from_slice(&0u32.to_le_bytes());
            local.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            local.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            local.extend_from_slice(&(name.len() as u16).to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(name.as_bytes());
            local.extend_from_slice(&stored);

            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&if *deflated { 8u16 } else { 0u16 }.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let mut data = local;
        let central_offset = data.len() as u32;
        let central_size = central.len() as u32;
        data.extend_from_slice(&central);
        data.extend_from_slice(b"PK\x05\x06");
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        data.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        data.extend_from_slice(&central_size.to_le_bytes());
        data.extend_from_slice(&central_offset.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data
    }

    /// Offsets inside a central-directory entry, as read by the parser.
    const CENTRAL_COMPRESSED_SIZE: usize = 20;
    const CENTRAL_UNCOMPRESSED_SIZE: usize = 24;

    /// Corrupts `field` of the first central-directory entry.
    fn patch_central_entry(zip: &mut [u8], field: usize, value: u32) {
        let start = zip
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .expect("archive has a central directory");
        write_u32(zip, start + field, value);
    }

    /// Writes `data` to a uniquely named temporary file.
    pub(crate) fn temp_apk(tag: &str, data: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("rasc-{tag}-{}.apk", std::process::id()));
        std::fs::write(&path, data).unwrap();
        path
    }

    #[test]
    fn parser_filters_entries_by_name_and_inflates_both_methods() {
        let first = vec![7u8; 4096];
        let second = b"second payload".to_vec();
        let zip = build_zip(&[
            ("classes.dex", &first, true),
            ("classes2.dex", &second, false),
            ("AndroidManifest.xml", b"<manifest/>", false),
        ]);
        let entries = parse_zip_entries(&zip, |name| name.starts_with(b"classes")).unwrap();
        let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, ["classes.dex", "classes2.dex"]);
        assert_eq!(entries[0].uncompressed_size, first.len());
        assert_eq!(entries[0].compression, 8);
        assert_eq!(inflate_entry(&zip, &entries[0]).unwrap(), first);
        assert_eq!(entries[1].compression, 0);
        assert_eq!(inflate_entry(&zip, &entries[1]).unwrap(), second);
    }

    #[test]
    fn stored_entry_size_mismatch_is_rejected() {
        // A stored entry whose compressed size disagrees with its declared
        // uncompressed size used to pass unvalidated.
        let mut zip = build_zip(&[("classes.dex", b"payload", false)]);
        patch_central_entry(&mut zip, CENTRAL_COMPRESSED_SIZE, 3);
        let entry = &parse_zip_entries(&zip, |_| true).unwrap()[0];
        let error = inflate_entry(&zip, entry).unwrap_err().to_string();
        assert!(error.contains("size mismatch"), "unexpected error: {error}");
    }

    #[test]
    fn deflate_size_mismatch_is_rejected() {
        let payload = vec![1u8; 2048];
        let mut zip = build_zip(&[("classes.dex", &payload, true)]);
        patch_central_entry(&mut zip, CENTRAL_UNCOMPRESSED_SIZE, 2048 + 64);
        let entry = &parse_zip_entries(&zip, |_| true).unwrap()[0];
        let error = inflate_entry(&zip, entry).unwrap_err().to_string();
        assert!(error.contains("size mismatch"), "unexpected error: {error}");
    }

    #[test]
    fn deflate_into_an_undersized_buffer_is_rejected() {
        let payload = vec![2u8; 2048];
        let mut zip = build_zip(&[("classes.dex", &payload, true)]);
        patch_central_entry(&mut zip, CENTRAL_UNCOMPRESSED_SIZE, 1024);
        let entry = &parse_zip_entries(&zip, |_| true).unwrap()[0];
        assert!(inflate_entry(&zip, entry).is_err());
    }

    #[test]
    fn archive_without_end_of_central_directory_is_rejected() {
        let zip = build_zip(&[("classes.dex", b"payload", false)]);
        let truncated = &zip[..zip.len() - 30];
        let error = parse_zip_entries(truncated, |_| true)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("EOCD not found"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn bad_central_directory_signature_is_rejected() {
        let mut zip = build_zip(&[("classes.dex", b"payload", false)]);
        let start = zip
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .unwrap();
        zip[start + 3] = b'X';
        let error = parse_zip_entries(&zip, |_| true).unwrap_err().to_string();
        assert!(
            error.contains("central directory signature"),
            "unexpected error: {error}"
        );
    }
}
