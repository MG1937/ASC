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
    // DEX 041 containers carry an extra-long header and a container-wide
    // checksum, which the decompiler rejects; hand it a normalized view.
    let normalized = dex::container::standard_header_view(&hit.data);
    let data = normalized.as_deref().unwrap_or(&hit.data);
    // Scoped parse (vendored patch, see vendor/droidsaw-dex/PATCHES.md): the full
    // parse spends most of its time on emit-supporting tables and on class bodies
    // other than this one, none of which decompilation reads. The scoped parse
    // returns the same source for the requested class, verified byte-for-byte
    // against an unpatched binary over a stratified class sample.
    let dex = droidsaw_dex::DexFile::parse_for_class(data, descriptor)
        .context("parse target DEX for decompilation")?;
    let Some((_index, class_def)) = dex.find_class(descriptor) else {
        bail!("{descriptor} is missing from the DEX that reported defining it");
    };
    let source = droidsaw_dex::classes::decompile_class(&dex, data, class_def);
    Ok(Some((hit.dex_name, source)))
}

pub fn read_entry(path: &Path, wanted: &str) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }.context("map APK")?;
    // CPython's `zipfile` resolves a name to the *last* central-directory record
    // carrying it, and the reference implementation reads the manifest through
    // it; matching that keeps a crafted archive with two AndroidManifest.xml
    // entries resolving the same way in both tools.
    let entry = crate::zip::parse_zip_entries(&mmap, |name| name == wanted.as_bytes())?
        .into_iter()
        .last()
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
        return Ok(dedup_names(named));
    }
    Ok(dedup_names(crate::zip::parse_zip_entries(data, |name| {
        name.ends_with(b".dex") && !name.contains(&b'/')
    })?))
}

/// Keeps the first entry for each name.
///
/// A ZIP may hold two entries with the same name (crafted or repacked archives
/// do). The reference implementation keeps the first `classes*.dex` it meets
/// while scanning the central directory, so a class defined only in a duplicate
/// entry stays invisible there; scanning both copies would instead report every
/// row twice and pick up classes the reference never sees.
fn dedup_names(entries: Vec<crate::zip::ZipEntry>) -> Vec<crate::zip::ZipEntry> {
    let mut seen = std::collections::HashSet::new();
    entries
        .into_iter()
        .filter(|entry| seen.insert(entry.name.clone()))
        .collect()
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
    fn duplicate_classes_dex_entries_use_the_first_copy() {
        let first = dex::tests::const_string_fixture(1);
        let second = dex::tests::const_string_fixture(2);
        let zip = build_zip(&[
            ("classes.dex", &first, true),
            ("classes.dex", &second, true),
        ]);
        let path = temp_apk("duplicate-classes", &zip);
        let rows =
            find_references(&path, &Query::String("Authorization".to_owned()), 2, false).unwrap();
        assert_eq!(
            rows,
            ["classes.dex | LFixture0;->m0 | matched=(Authorization)"]
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn duplicate_fallback_dex_entries_use_the_first_copy() {
        let first = dex::tests::const_string_fixture(1);
        let second = dex::tests::const_string_fixture(2);
        let zip = build_zip(&[("app.dex", &first, true), ("app.dex", &second, true)]);
        let path = temp_apk("duplicate-fallback", &zip);
        let rows =
            find_references(&path, &Query::String("Authorization".to_owned()), 2, false).unwrap();
        assert_eq!(rows, ["app.dex | LFixture0;->m0 | matched=(Authorization)"]);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn duplicate_manifest_entries_use_the_last_copy() {
        let zip = build_zip(&[
            ("AndroidManifest.xml", b"first".as_slice(), false),
            ("AndroidManifest.xml", b"second".as_slice(), false),
        ]);
        let path = temp_apk("duplicate-manifest", &zip);
        assert_eq!(read_entry(&path, "AndroidManifest.xml").unwrap(), b"second");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn scoped_parse_keeps_only_the_requested_class_bodies() {
        let dex = dex::tests::const_string_fixture(2);
        let full = droidsaw_dex::DexFile::parse(&dex, None).unwrap();
        let scoped = droidsaw_dex::DexFile::parse_for_class(&dex, "LFixture1;").unwrap();
        assert!(
            full.class_datas.len() > scoped.class_datas.len(),
            "scoped parse kept every class body ({} vs {})",
            full.class_datas.len(),
            scoped.class_datas.len()
        );
        assert!(scoped.find_class("LFixture1;").is_some());
        let (_, full_def) = full.find_class("LFixture1;").unwrap();
        let (_, scoped_def) = scoped.find_class("LFixture1;").unwrap();
        assert_eq!(
            droidsaw_dex::classes::decompile_class(&full, &dex, full_def),
            droidsaw_dex::classes::decompile_class(&scoped, &dex, scoped_def),
            "scoped parse changed the decompiled source"
        );
    }

    #[test]
    fn scoped_parse_falls_back_to_the_full_parse_for_an_unknown_descriptor() {
        // The vendor patch's guard compares against canonical descriptors; a
        // spelling that matches no class must not hand back a body-less DEX.
        let dex = dex::tests::const_string_fixture(2);
        let full = droidsaw_dex::DexFile::parse(&dex, None).unwrap();
        let fallback = droidsaw_dex::DexFile::parse_for_class(&dex, "LNo/Such;").unwrap();
        assert_eq!(fallback.code_items.len(), full.code_items.len());
        assert_eq!(fallback.class_datas.len(), full.class_datas.len());
    }

    #[test]
    fn decompiles_a_class_from_a_synthetic_apk() {
        let dex = dex::tests::const_string_fixture(1);
        let zip = build_zip(&[("classes.dex", &dex, true)]);
        let path = temp_apk("decompile", &zip);
        let (entry, source) = decompile_class(&path, "LFixture0;", 2, false)
            .unwrap()
            .expect("fixture class is found");
        assert_eq!(entry, "classes.dex");
        assert!(source.contains("Fixture0"), "unexpected source: {source}");
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
    fn decompiles_a_class_from_every_logical_dex_of_a_041_container() {
        // A DEX 041 container overlays each member's header at offset 0, so the
        // Adler-32 a member stores no longer covers the bytes the decompiler
        // sees. findrefs never validates it (our scanner does not); the
        // decompiler does, so this test guards the second member too.
        // Member one defines LFixture0;, member two LFixture0; and LFixture1;.
        let container = dex::tests::dex041_container(&[1, 2]);
        let zip = build_zip(&[("classes.dex", &container, true)]);
        let path = temp_apk("dex041-getclass", &zip);
        for (descriptor, expected_entry) in [
            ("LFixture0;", "classes.dex!classes1.dex"),
            ("LFixture1;", "classes.dex!classes2.dex"),
        ] {
            let hit = decompile_class(&path, descriptor, 2, false).unwrap();
            let (entry, source) = hit.unwrap_or_else(|| panic!("{descriptor} did not decompile"));
            assert!(entry.starts_with(expected_entry), "found in {entry}");
            assert!(source.contains("Fixture"), "unexpected source: {source}");
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn an_entry_that_is_not_a_dex_is_a_clean_error() {
        // A packer can leave junk in a classes*.dex entry, and a corrupted magic
        // looks the same. rasc reports that loudly instead of guessing: the
        // reference's findrefs errors on such archives too (its class lookup
        // skips them silently), and silently analysing "the rest" would hide the
        // fact that part of the archive was not analysed at all. What this test
        // pins is that the failure is a message with an exit code, not a panic and
        // not an empty result.
        let good = dex::tests::const_string_fixture(1);
        let zip = build_zip(&[
            ("classes.dex", b"JUNKJUNKJUNK".as_slice(), false),
            ("classes2.dex", &good, true),
        ]);
        let path = temp_apk("junk-dex", &zip);
        let error = find_references(&path, &Query::String("Authorization".to_owned()), 2, false)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("invalid DEX header"),
            "unexpected error: {error}"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn find_class_finds_a_class_whose_type_id_is_a_later_duplicate() {
        // A DEX may repeat a descriptor across several type ids. `list_classes`
        // resolves each class_def's own type id, so `find_class` has to do the
        // same: looking up "the" type id for the descriptor makes the two
        // commands contradict each other on such a file.
        let mut dex = dex::tests::const_string_fixture(2);
        let header_size = crate::bytes::read_u32(&dex, 0x24).unwrap() as usize;
        let strings = crate::bytes::read_u32(&dex, 0x38).unwrap() as usize;
        // type_ids[0] belongs to no class_def; pointing it at "LFixture0;"
        // (string index 1) makes the descriptor's first match a different id than
        // the one the class's class_def carries.
        crate::zip::tests::write_u32(&mut dex, header_size + strings * 4, 1);
        let zip = build_zip(&[("classes.dex", &dex, true)]);
        let path = temp_apk("duplicate-type-id", &zip);
        let listed = list_classes(&path, 2).unwrap();
        assert!(
            listed.iter().any(|entry| entry.descriptor == "LFixture0;"),
            "fixture stopped listing the class: {listed:?}"
        );
        let hit = find_class(&path, "LFixture0;", 2, false).unwrap();
        assert!(
            hit.is_some(),
            "listed by classes but missing from find_class"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn single_member_041_container_reports_the_plain_dex_name() {
        // The reference implementation only renames container members when there
        // is more than one, so a single-member container keeps the entry name in
        // every row (the dex column is part of a row's identity).
        let container = dex::tests::dex041_container(&[1]);
        let zip = build_zip(&[("classes.dex", &container, true)]);
        let path = temp_apk("dex041-single", &zip);
        let rows =
            find_references(&path, &Query::String("Authorization".to_owned()), 2, false).unwrap();
        assert_eq!(
            rows,
            ["classes.dex | LFixture0;->m0 | matched=(Authorization)"]
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
