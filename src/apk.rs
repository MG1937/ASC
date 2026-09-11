use crate::cli::Query;
use crate::dex;
use anyhow::{Context, Result, bail};
use libdeflater::Decompressor;
use memmap2::Mmap;
use rayon::prelude::*;
use std::borrow::Cow;
use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

type ClassSearchResult = Result<Option<(String, Vec<u8>)>>;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClassEntry {
    pub descriptor: String,
    pub dex_name: String,
}

impl ClassEntry {
    pub fn java_name(&self) -> &str {
        self.descriptor
            .strip_prefix('L')
            .and_then(|name| name.strip_suffix(';'))
            .unwrap_or(&self.descriptor)
    }

    pub fn package(&self) -> &str {
        self.java_name()
            .rsplit_once('/')
            .map_or("", |(package, _)| package)
    }

    pub fn simple_name(&self) -> &str {
        self.java_name()
            .rsplit_once('/')
            .map_or(self.java_name(), |(_, name)| name)
    }
}

#[derive(Clone, Debug)]
struct ZipEntry {
    name: String,
    uncompressed_size: usize,
    compressed_size: usize,
    local_header_offset: usize,
    compression: u16,
}

pub fn find_references(
    path: &Path,
    query: &Query,
    threads: usize,
    debug: bool,
) -> Result<Vec<String>> {
    if threads == 0 {
        bail!("worker count must be greater than zero");
    }
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }.context("map APK")?;
    let mut entries = parse_dex_entries(&mmap)?;
    entries.sort_by_key(|entry| entry.compressed_size);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()?;
    let results: Vec<Result<Vec<String>>> = pool.install(|| {
        entries
            .par_iter()
            .map(|entry| {
                let started = Instant::now();
                let data = inflate_entry(&mmap, entry)?;
                let inflate_elapsed = started.elapsed();
                let mut rows = Vec::new();
                for logical in logical_dexes(&entry.name, &data)? {
                    rows.extend(dex::find_references(&logical.name, &logical.data, query)?);
                }
                if debug {
                    eprintln!(
                        "[APK] '{}' inflate={:.2} us process={:.2} us",
                        entry.name,
                        inflate_elapsed.as_secs_f64() * 1_000_000.0,
                        (started.elapsed() - inflate_elapsed).as_secs_f64() * 1_000_000.0
                    );
                }
                Ok(rows)
            })
            .collect()
    });
    let mut rows = Vec::new();
    for result in results {
        rows.extend(result?);
    }
    rows.sort();
    Ok(rows)
}

pub fn list_classes(path: &Path, threads: usize) -> Result<Vec<ClassEntry>> {
    if threads == 0 {
        bail!("worker count must be greater than zero");
    }
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }.context("map APK")?;
    let entries = parse_dex_entries(&mmap)?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()?;
    let results: Vec<Result<Vec<ClassEntry>>> = pool.install(|| {
        entries
            .par_iter()
            .map(|entry| {
                let data = inflate_entry(&mmap, entry)?;
                let mut classes = Vec::new();
                for logical in logical_dexes(&entry.name, &data)? {
                    for descriptor in dex::class_names(&logical.data)? {
                        classes.push(ClassEntry {
                            descriptor,
                            dex_name: logical.name.clone(),
                        });
                    }
                }
                Ok(classes)
            })
            .collect()
    });
    let mut classes = Vec::new();
    for result in results {
        classes.extend(result?);
    }
    classes.sort();
    classes.dedup_by(|left, right| left.descriptor == right.descriptor);
    Ok(classes)
}

pub fn find_class(
    path: &Path,
    descriptor: &str,
    threads: usize,
    debug: bool,
) -> Result<Option<(String, Vec<u8>)>> {
    if threads == 0 {
        bail!("worker count must be greater than zero");
    }
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }.context("map APK")?;
    let mut entries = parse_dex_entries(&mmap)?;
    entries.sort_by_key(|entry| entry.compressed_size);
    let stop = AtomicBool::new(false);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()?;
    let results: Vec<ClassSearchResult> = pool.install(|| {
        entries
            .par_iter()
            .map(|entry| {
                if stop.load(Ordering::Relaxed) {
                    return Ok(None);
                }
                let started = Instant::now();
                let data = inflate_entry(&mmap, entry)?;
                for logical in logical_dexes(&entry.name, &data)? {
                    if dex::defines_class(&logical.data, descriptor.as_bytes())? {
                        stop.store(true, Ordering::Relaxed);
                        if debug {
                            eprintln!(
                                "[APK] '{}' hit=true total={:.2} us",
                                entry.name,
                                started.elapsed().as_secs_f64() * 1_000_000.0
                            );
                        }
                        return Ok(Some((logical.name, logical.data.into_owned())));
                    }
                }
                if debug {
                    eprintln!(
                        "[APK] '{}' hit=false total={:.2} us",
                        entry.name,
                        started.elapsed().as_secs_f64() * 1_000_000.0
                    );
                }
                Ok(None)
            })
            .collect()
    });
    for result in results {
        if let Some(hit) = result? {
            return Ok(Some(hit));
        }
    }
    Ok(None)
}

pub fn decompile_class(
    path: &Path,
    descriptor: &str,
    threads: usize,
    debug: bool,
) -> Result<Option<(String, String)>> {
    let Some((dex_name, data)) = find_class(path, descriptor, threads, debug)? else {
        return Ok(None);
    };
    let dex =
        droidsaw_dex::DexFile::parse(&data, None).context("parse target DEX for decompilation")?;
    let Some((_index, class_def)) = dex.find_class(descriptor) else {
        bail!("class disappeared from selected DEX");
    };
    let source = droidsaw_dex::classes::decompile_class(&dex, &data, class_def);
    Ok(Some((dex_name, source)))
}

pub fn read_entry(path: &Path, wanted: &str) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }.context("map APK")?;
    let entry = parse_zip_entries(&mmap, |name| name == wanted.as_bytes())?
        .into_iter()
        .next()
        .with_context(|| format!("{wanted} not found in APK"))?;
    inflate_entry(&mmap, &entry)
}

fn parse_dex_entries(data: &[u8]) -> Result<Vec<ZipEntry>> {
    parse_zip_entries(data, |name| {
        name.starts_with(b"classes") && name.ends_with(b".dex") && !name.contains(&b'/')
    })
}

fn parse_zip_entries(data: &[u8], mut include: impl FnMut(&[u8]) -> bool) -> Result<Vec<ZipEntry>> {
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

fn inflate_entry(data: &[u8], entry: &ZipEntry) -> Result<Vec<u8>> {
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
    let output = match entry.compression {
        0 => compressed.to_vec(),
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
            output
        }
        method => bail!("unsupported compression method {method} for {}", entry.name),
    };
    if output.len() != entry.uncompressed_size {
        bail!(
            "size mismatch for {}: expected {}, got {}",
            entry.name,
            entry.uncompressed_size,
            output.len()
        );
    }
    Ok(output)
}

struct LogicalDex<'a> {
    name: String,
    data: Cow<'a, [u8]>,
}

fn logical_dexes<'a>(name: &str, data: &'a [u8]) -> Result<Vec<LogicalDex<'a>>> {
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

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .context("truncated u16")?
        .try_into()?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .context("truncated u32")?
        .try_into()?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn class_entry_exposes_name_components() {
        let entry = ClassEntry {
            descriptor: "Lcom/example/Main$Nested;".to_owned(),
            dex_name: "classes.dex".to_owned(),
        };
        assert_eq!(entry.java_name(), "com/example/Main$Nested");
        assert_eq!(entry.package(), "com/example");
        assert_eq!(entry.simple_name(), "Main$Nested");
    }

    #[test]
    fn ordinary_dex_uses_borrowed_fast_path() {
        let data = b"dex\n039\0rest";
        let logical = logical_dexes("classes.dex", data).unwrap();
        assert_eq!(logical.len(), 1);
        assert_eq!(logical[0].name, "classes.dex");
        assert!(matches!(logical[0].data, Cow::Borrowed(_)));
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
}
