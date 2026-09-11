//! APK container layer: ZIP discovery, inflation, DEX 041 views and the
//! scheduler that runs one command's work over every entry.
//!
//! Everything that reads the archive goes through [`map_dex_entries`], which owns
//! the mmap, the worker pool, entry ordering and the `--debug` inflate timings.
//! Results are flattened in central-directory order, so output is deterministic
//! no matter which worker stole which entry. Nothing here shells out to Python, a
//! JVM or an external decompiler.

use crate::dex;
use crate::query::Query;
use crate::zip::{ZipEntry, inflate_entry};
use anyhow::{Context, Result, bail};
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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

struct InflatedDex<'a> {
    entry: &'a ZipEntry,
    data: Vec<u8>,
    started: Instant,
    inflate_elapsed: Duration,
}

/// How [`map_dex_entries`] orders the entries it hands to the worker pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EntryOrder {
    /// Central-directory order.
    Natural,
    /// Smallest entries first, so the cheapest ones answer first.
    SmallestFirst,
}

/// Opens `path`, inflates every `classes*.dex` entry in parallel and returns the
/// flattened results of `map`, in central-directory order.
///
/// `order` picks the sequence entries are handed out in. `stop` lets a caller
/// give up on entries that have not started yet: anything already in flight on a
/// worker still runs to completion, so it shortens the work that follows an early
/// hit rather than cancelling it.
fn map_dex_entries<T: Send>(
    path: &Path,
    threads: usize,
    order: EntryOrder,
    stop: Option<&AtomicBool>,
    map: impl for<'a> Fn(InflatedDex<'a>) -> Result<Vec<T>> + Sync,
) -> Result<Vec<T>> {
    if threads == 0 {
        bail!("worker count must be greater than zero");
    }
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }.context("map APK")?;
    let mut entries = parse_dex_entries(&mmap)?;
    match order {
        EntryOrder::Natural => {}
        EntryOrder::SmallestFirst => entries.sort_by_key(|entry| entry.compressed_size),
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()?;
    let results: Vec<Result<Vec<T>>> = pool.install(|| {
        entries
            .par_iter()
            .map(|entry| {
                if stop.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                    return Ok(Vec::new());
                }
                let started = Instant::now();
                let data = inflate_entry(&mmap, entry)?;
                map(InflatedDex {
                    entry,
                    data,
                    started,
                    inflate_elapsed: started.elapsed(),
                })
            })
            .collect()
    });
    let mut out = Vec::new();
    for result in results {
        out.extend(result?);
    }
    Ok(out)
}

/// Renders one hit the way `findrefs` prints it.
///
/// Rendering happens here rather than in the CLI because this is the parallel
/// phase: a wide query produces hundreds of thousands of lines, and formatting
/// them on the main thread costs more than the whole instruction scan.
fn render_reference(dex_name: &str, row: &dex::ReferenceRow) -> String {
    format!(
        "{} | {}->{} | matched=({})",
        dex_name,
        row.class_name,
        row.method_name,
        row.matched.join("; ")
    )
}

/// Rendered reference hits for `query`, aggregated in central-directory order.
///
/// The lines are unsorted: the caller sorts them, which is what keeps the printed
/// order independent of how the work was stolen.
pub fn find_references(
    path: &Path,
    query: &Query,
    threads: usize,
    debug: bool,
) -> Result<Vec<String>> {
    let rows = map_dex_entries(path, threads, EntryOrder::SmallestFirst, None, |inflated| {
        let mut rows = Vec::new();
        for logical in dex::container::logical_dexes(&inflated.entry.name, &inflated.data)? {
            for row in dex::find_references(&logical.data, query)? {
                rows.push(render_reference(&logical.name, &row));
            }
        }
        if debug {
            eprintln!(
                "[APK] '{}' inflate={:.2} us process={:.2} us",
                inflated.entry.name,
                inflated.inflate_elapsed.as_secs_f64() * 1_000_000.0,
                (inflated.started.elapsed() - inflated.inflate_elapsed).as_secs_f64() * 1_000_000.0
            );
        }
        Ok(rows)
    })?;
    Ok(rows)
}

pub fn list_classes(path: &Path, threads: usize) -> Result<Vec<ClassEntry>> {
    let mut classes = map_dex_entries(path, threads, EntryOrder::Natural, None, |inflated| {
        let mut classes = Vec::new();
        for logical in dex::container::logical_dexes(&inflated.entry.name, &inflated.data)? {
            for descriptor in dex::class_names(&logical.data)? {
                classes.push(ClassEntry {
                    descriptor,
                    dex_name: logical.name.clone(),
                });
            }
        }
        Ok(classes)
    })?;
    classes.sort();
    classes.dedup_by(|left, right| left.descriptor == right.descriptor);
    Ok(classes)
}

/// A located class: the DEX entry that defines it and that entry's bytes.
///
/// The bytes are a copy because the mapping they were borrowed from ends with the
/// lookup.
pub struct ClassHit {
    pub dex_name: String,
    pub data: Vec<u8>,
}

/// Locates `descriptor`, cheapest DEX entries first so an early answer needs as
/// little inflation as possible.
pub fn find_class(
    path: &Path,
    descriptor: &str,
    threads: usize,
    debug: bool,
) -> Result<Option<ClassHit>> {
    let stop = AtomicBool::new(false);
    let hits = map_dex_entries(
        path,
        threads,
        EntryOrder::SmallestFirst,
        Some(&stop),
        |inflated| {
            for logical in dex::container::logical_dexes(&inflated.entry.name, &inflated.data)? {
                if dex::defines_class(&logical.data, descriptor.as_bytes())? {
                    stop.store(true, Ordering::Relaxed);
                    if debug {
                        eprintln!(
                            "[APK] '{}' hit=true total={:.2} us",
                            inflated.entry.name,
                            inflated.started.elapsed().as_secs_f64() * 1_000_000.0
                        );
                    }
                    return Ok(vec![ClassHit {
                        dex_name: logical.name,
                        data: logical.data.into_owned(),
                    }]);
                }
            }
            if debug {
                eprintln!(
                    "[APK] '{}' hit=false total={:.2} us",
                    inflated.entry.name,
                    inflated.started.elapsed().as_secs_f64() * 1_000_000.0
                );
            }
            Ok(Vec::new())
        },
    )?;
    Ok(hits.into_iter().next())
}

/// Decompiles `descriptor` to Java-like source, returning the DEX entry it was
/// found in and the source. `None` when no DEX defines the class.
pub fn decompile_class(
    path: &Path,
    descriptor: &str,
    threads: usize,
    debug: bool,
) -> Result<Option<(String, String)>> {
    let Some(hit) = find_class(path, descriptor, threads, debug)? else {
        return Ok(None);
    };
    let dex = droidsaw_dex::DexFile::parse(&hit.data, None)
        .context("parse target DEX for decompilation")?;
    let Some((_index, class_def)) = dex.find_class(descriptor) else {
        bail!("{descriptor} is missing from the DEX that reported defining it");
    };
    let source = droidsaw_dex::classes::decompile_class(&dex, &hit.data, class_def);
    Ok(Some((hit.dex_name, source)))
}

pub fn read_entry(path: &Path, wanted: &str) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }.context("map APK")?;
    let entry = crate::zip::parse_zip_entries(&mmap, |name| name == wanted.as_bytes())?
        .into_iter()
        .next()
        .with_context(|| format!("{wanted} not found in APK"))?;
    inflate_entry(&mmap, &entry)
}

/// Root DEX entries, `classes*.dex` preferred.
///
/// The reference implementation falls back to any root `*.dex` when an APK names
/// its DEX files differently, and matching that keeps both tools reporting the
/// same entries for the same archive.
fn parse_dex_entries(data: &[u8]) -> Result<Vec<ZipEntry>> {
    let named = crate::zip::parse_zip_entries(data, |name| {
        name.starts_with(b"classes") && name.ends_with(b".dex") && !name.contains(&b'/')
    })?;
    if !named.is_empty() {
        return Ok(named);
    }
    crate::zip::parse_zip_entries(data, |name| {
        name.ends_with(b".dex") && !name.contains(&b'/')
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::zip::tests::{build_zip, temp_apk};

    #[test]
    fn dex_entries_fall_back_to_any_root_dex_name() {
        let dex = dex::tests::const_string_fixture(1);
        let zip = build_zip(&[("app.dex", &dex, true), ("assets/other.dex", &dex, false)]);
        let path = temp_apk("fallback", &zip);
        let rows =
            find_references(&path, &Query::String("Authorization".to_owned()), 2, false).unwrap();
        assert_eq!(rows, ["app.dex | LFixture0;->m0 | matched=(Authorization)"]);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn named_dex_entries_win_over_the_fallback() {
        let named = dex::tests::const_string_fixture(1);
        let other = dex::tests::const_string_fixture(2);
        let zip = build_zip(&[("app.dex", &other, true), ("classes.dex", &named, true)]);
        let path = temp_apk("prefer-named", &zip);
        let rows =
            find_references(&path, &Query::String("Authorization".to_owned()), 2, false).unwrap();
        assert_eq!(
            rows,
            ["classes.dex | LFixture0;->m0 | matched=(Authorization)"]
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn dex_entries_are_selected_by_name() {
        let zip = build_zip(&[
            ("classes.dex", b"first", false),
            ("classes2.dex", b"second", false),
            ("assets/classes3.dex", b"nested", false),
            ("AndroidManifest.xml", b"<manifest/>", false),
        ]);
        let names: Vec<String> = parse_dex_entries(&zip)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(
            names,
            ["classes.dex", "classes2.dex"],
            "root DEX entries only"
        );
    }

    #[test]
    fn find_references_searches_every_logical_dex_in_a_041_container() {
        let container = dex::tests::dex041_container(&[2, 1]);
        let zip = build_zip(&[("classes.dex", &container, true)]);
        let path = temp_apk("dex041", &zip);
        let rows =
            find_references(&path, &Query::String("Authorization".to_owned()), 2, false).unwrap();
        assert_eq!(
            rows,
            [
                "classes.dex!classes1.dex | LFixture0;->m0 | matched=(Authorization)",
                "classes.dex!classes1.dex | LFixture1;->m1 | matched=(Authorization)",
                "classes.dex!classes2.dex | LFixture0;->m0 | matched=(Authorization)",
            ]
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn find_references_runs_end_to_end_on_a_synthetic_apk() {
        let first = dex::tests::const_string_fixture(2);
        let second = dex::tests::const_string_fixture(1);
        let zip = build_zip(&[
            ("classes.dex", &first, true),
            ("classes2.dex", &second, false),
            ("AndroidManifest.xml", b"<manifest/>", false),
        ]);
        let path = temp_apk("synthetic", &zip);
        let query = Query::String("Authorization".to_owned());
        let rows = find_references(&path, &query, 2, false).unwrap();
        assert_eq!(
            rows,
            [
                "classes.dex | LFixture0;->m0 | matched=(Authorization)",
                "classes.dex | LFixture1;->m1 | matched=(Authorization)",
                "classes2.dex | LFixture0;->m0 | matched=(Authorization)",
            ]
        );
        assert_eq!(
            find_references(&path, &query, 2, false).unwrap(),
            rows,
            "deterministic"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn worker_count_must_be_positive() {
        let zip = build_zip(&[("classes.dex", b"payload", false)]);
        let path = temp_apk("workers", &zip);
        let query = Query::String("x".to_owned());
        assert!(find_references(&path, &query, 0, false).is_err());
        std::fs::remove_file(&path).unwrap();
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
}
