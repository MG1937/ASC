//! Walk every class in every `classes*.dex` file under a path,
//! decompile each via `droidsaw_dex::classes::decompile_class`, and
//! report pass-rate counts in the shape the `droidsaw-bench` runner
//! expects.
//!
//! # Usage
//!
//! ```text
//! cargo run --release --example full_audit -- <path>
//! ```
//!
//! `<path>` is either a single `.dex` file or a directory containing
//! `classes*.dex` files. Output goes to stderr (which is what
//! `droidsaw-bench`'s `DroidsawDexSummary::parse` reads). stdout is
//! unused.
//!
//! # Format contract (DroidsawDexSummary::parse)
//!
//! - Per-DEX preamble line (one per file):
//!   `   <filename>: N/M syntax ok (P.P%), E errors, F panics`
//! - Cumulative TOTAL line (parser keys on `=== TOTAL:`):
//!   `=== TOTAL: N/M (P.P%), E errors, F panics ===`
//! - Top-20 error-pattern taxonomy block follows TOTAL — informational
//!   only; not consumed by the bench parser. Used by hand for triage
//!   when the pass rate drops.
//!
//! # What "syntax ok" means here
//!
//! A class counts as "ok" when (a) `decompile_class` returns without
//! panicking and (b) every emitted line passes a small list of Java-
//! invalid pattern checks. Today the only check is "no line assigns to
//! `this`" (illegal Java; was the load-bearing failure that motivated
//! restoring this binary). Add patterns here as new
//! emit-layer regressions surface.
//!
//! # Why an audit binary instead of in-process bench code
//!
//! The bench is a sibling crate with its own dependencies; it does not
//! link the algorithm crates (dex/hermes/apk) directly. The audit binary
//! is the seam: bench shells out to it, reads the per-DEX + TOTAL summary
//! lines from stderr, and records the resulting pass rate as a
//! `correctness_score` on each `ResultRow`. See
//! `droidsaw-bench/src/droidsaw_dex_runner.rs`.

use droidsaw_dex::{
    classes::decompile_class_with_census, parser::DexFile,
    r8_inversion::build_trampoline_census,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const TAXONOMY_TOP_N: usize = 20;
const TAXONOMY_KEY_LEN: usize = 60;

#[derive(Default)]
struct DexCounts {
    total: u64,
    syntax_ok: u64,
    errors: u64,
    panics: u64,
    /// per-pattern → (count, exemplar_class_descriptor, exemplar_line)
    taxonomy: BTreeMap<String, (u64, String, String)>,
}

impl DexCounts {
    fn record(&mut self, other: &DexCounts) {
        self.total += other.total;
        self.syntax_ok += other.syntax_ok;
        self.errors += other.errors;
        self.panics += other.panics;
        for (k, (n, ex_class, ex_line)) in &other.taxonomy {
            let entry = self
                .taxonomy
                .entry(k.clone())
                .or_insert_with(|| (0, ex_class.clone(), ex_line.clone()));
            entry.0 += n;
        }
    }

    fn pass_rate_pct(&self) -> f32 {
        if self.total == 0 {
            0.0
        } else {
            (self.syntax_ok as f32) * 100.0 / (self.total as f32)
        }
    }
}

#[derive(Default)]
struct ClassRange {
    /// Skip this many classes at the start of each DEX.
    skip: usize,
    /// Process at most this many classes per DEX (None = all).
    limit: Option<usize>,
}

fn main() -> ExitCode {
    let mut path: Option<PathBuf> = None;
    let mut range = ClassRange::default();

    let mut iter = std::env::args().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--skip" => {
                range.skip = iter.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--limit" => {
                range.limit = iter.next().and_then(|s| s.parse().ok());
            }
            "--help" | "-h" => {
                eprintln!(
                    "usage: full_audit <path-to-dex-or-dir> [--skip N] [--limit N]\n\
                     \n\
                     --skip N    skip the first N classes in each DEX (bisect)\n\
                     --limit N   process at most N classes per DEX (bisect / cap)"
                );
                return ExitCode::SUCCESS;
            }
            _ => {
                if path.is_none() {
                    path = Some(PathBuf::from(a));
                } else {
                    eprintln!("full_audit: unexpected argument: {a}");
                    return ExitCode::from(2);
                }
            }
        }
    }

    let Some(path) = path else {
        eprintln!("usage: full_audit <path-to-dex-or-dir> [--skip N] [--limit N]");
        return ExitCode::from(2);
    };
    if !path.exists() {
        eprintln!("full_audit: path does not exist: {}", path.display());
        return ExitCode::from(2);
    }

    let dex_paths = match collect_dex_paths(&path) {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => {
            eprintln!("full_audit: no classes*.dex files under {}", path.display());
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("full_audit: io error: {e}");
            return ExitCode::from(2);
        }
    };

    let mut total = DexCounts::default();
    for dex_path in &dex_paths {
        let counts = audit_dex(dex_path, &range);
        let name = dex_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("?.dex");
        eprintln!(
            "   {name}: {}/{} syntax ok ({:.1}%), {} errors, {} panics",
            counts.syntax_ok,
            counts.total,
            counts.pass_rate_pct(),
            counts.errors,
            counts.panics,
        );
        total.record(&counts);
    }

    eprintln!();
    eprintln!(
        "=== TOTAL: {}/{} ({:.1}%), {} errors, {} panics ===",
        total.syntax_ok,
        total.total,
        total.pass_rate_pct(),
        total.errors,
        total.panics,
    );

    if !total.taxonomy.is_empty() {
        eprintln!();
        eprintln!("=== ERROR TAXONOMY (top {TAXONOMY_TOP_N}) ===");
        let mut entries: Vec<(&String, &(u64, String, String))> = total.taxonomy.iter().collect();
        entries.sort_by_key(|b| std::cmp::Reverse(b.1 .0));
        for (key, (n, ex_class, ex_line)) in entries.iter().take(TAXONOMY_TOP_N) {
            eprintln!("[{n:4}] other: {key}");
            eprintln!("        example: {ex_class}");
            eprintln!("        line: {ex_line}");
        }
    }

    ExitCode::SUCCESS
}

/// Resolve `path` to one or more DEX files. If `path` is a regular
/// file, returns a single-element vec. If it's a directory, returns
/// every entry whose file name starts with `classes` and ends with
/// `.dex`, sorted lexicographically (`classes.dex`, `classes2.dex`,
/// `classes10.dex` — natural sort matters less than determinism).
fn collect_dex_paths(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut v: Vec<PathBuf> = fs::read_dir(path)?
        .filter_map(|r| r.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("classes") && n.ends_with(".dex"))
                .unwrap_or(false)
        })
        .collect();
    v.sort();
    Ok(v)
}

/// Audit a single DEX file: parse, walk every class def, decompile,
/// classify the result.
fn audit_dex(dex_path: &Path, range: &ClassRange) -> DexCounts {
    let mut counts = DexCounts::default();
    let data = match fs::read(dex_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("full_audit: read {} failed: {e}", dex_path.display());
            return counts;
        }
    };
    let dex = match DexFile::parse(&data, None) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("full_audit: parse {} failed: {e:?}", dex_path.display());
            return counts;
        }
    };

    let iter = dex
        .class_defs
        .iter()
        .enumerate()
        .skip(range.skip)
        .take(range.limit.unwrap_or(usize::MAX));

    // Amortize r8_inversion::build_trampoline_census across all classes.
    // Was per-class via decompile_class; the rebuild cost was a bottleneck
    // in full-corpus decompilation. Switch to decompile_class_with_census
    // so bench-side numbers are not quadratic-biased.
    let census = build_trampoline_census(&dex);

    let verbose = std::env::var("DROIDSAW_FULL_AUDIT_VERBOSE").is_ok();
    for (class_idx, class_def) in iter {
        counts.total += 1;
        if verbose {
            let descriptor = dex
                .get_type_descriptor(class_def.class_idx)
                .unwrap_or("L?;");
            eprintln!("   [class {class_idx}] {descriptor}");
        }
        // Single-class panics get bucketed as `panics` counts and
        // don't abort the sweep. Class-boundary state isolation is
        // structural: `decompile_class_with_census` takes no
        // class-scoped state — the census is per-DEX.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            decompile_class_with_census(&dex, &data, class_def, &census)
        }));
        let java = match result {
            Ok(s) => s,
            Err(_) => {
                counts.panics += 1;
                continue;
            }
        };

        if let Some((key, line)) = first_invalid_pattern(&java) {
            counts.errors += 1;
            let descriptor = dex
                .get_type_descriptor(class_def.class_idx)
                .unwrap_or("L?;");
            let class_name = simple_name(descriptor);
            let entry = counts
                .taxonomy
                .entry(key)
                .or_insert_with(|| (0, class_name.clone(), line.clone()));
            entry.0 += 1;
            // Keep the first exemplar; don't overwrite.
        } else {
            counts.syntax_ok += 1;
        }
    }
    counts
}

/// Look for the first line in `java` that matches a known-invalid Java
/// pattern. Returns `(taxonomy_key, exemplar_line)`.
///
/// Pattern set is intentionally narrow — every entry must be Java-
/// invalid in any context, never a false positive on legitimate
/// decompiled output. Add new patterns here as emit-layer regressions
/// surface.
fn first_invalid_pattern(java: &str) -> Option<(String, String)> {
    for raw in java.lines() {
        let line = raw.trim();
        // Pattern 1: assignment to `this`. Illegal in Java; was the
        // load-bearing failure that motivated re-introducing this
        // binary (the previous full_audit was stale and the emit
        // path had since been fixed; the bench was reporting fake
        // errors).
        if line.starts_with("this =") || line.starts_with("this=") {
            let key = truncate_key(line);
            return Some((key, line.to_string()));
        }
    }
    None
}

fn truncate_key(line: &str) -> String {
    if line.len() <= TAXONOMY_KEY_LEN {
        line.to_string()
    } else {
        line.chars().take(TAXONOMY_KEY_LEN).collect()
    }
}

/// `Lcom/foo/Bar$Baz;` → `Bar$Baz`
fn simple_name(descriptor: &str) -> String {
    let trimmed = descriptor
        .trim_start_matches('L')
        .trim_end_matches(';');
    trimmed
        .rsplit('/')
        .next()
        .unwrap_or(trimmed)
        .to_string()
}
