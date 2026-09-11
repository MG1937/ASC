//! CLI entry point: argument parsing, dispatch, output.
//!
//! stdout carries a command's payload and nothing else: every diagnostic,
//! including `--debug` timing, goes to stderr, so redirecting a result can never
//! capture debug lines. An `-o` file receives exactly the bytes stdout received.

mod apk;
mod bytes;
mod cli;
mod dex;
mod manifest;
mod query;
mod zip;

use anyhow::{Context, Result, bail};
use clap::Parser;
use cli::{Cli, Command};
use rayon::prelude::*;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

fn main() {
    restore_default_sigpipe();
    if let Err(error) = run() {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}

/// Restore the default `SIGPIPE` disposition so that piping into `head`, `grep`,
/// or a closed consumer terminates quietly, the way standard Unix filters do.
///
/// Rust ignores `SIGPIPE` at startup, which turns an early-closed pipe into a
/// `BrokenPipe` write error and then a panic; with `panic = "abort"` that aborts
/// the process and prints a panic message for a completely normal shell idiom.
#[cfg(unix)]
fn restore_default_sigpipe() {
    // SAFETY: setting the disposition of SIGPIPE to SIG_DFL is
    // async-signal-safe and only affects this process.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn restore_default_sigpipe() {}

/// Writes a command's payload to stdout and, when `output` is set, to that file
/// as well.
///
/// Diagnostics deliberately do not travel through here: they go to stderr, so a
/// redirected payload can never pick up `--debug` lines, and the file always
/// receives exactly the bytes stdout received.
fn emit(payload: &str, output: Option<&Path>) -> Result<()> {
    if let Some(path) = output {
        fs::write(path, payload).with_context(|| format!("write {}", path.display()))?;
    }
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    stdout.write_all(payload.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

/// This is the only place the CLI reports timing, so `--debug` reads the same
/// for every subcommand.
fn debug_timing(started: Instant) {
    eprintln!(
        "[DEBUG] Total Execution Time: {:.2} us",
        started.elapsed().as_secs_f64() * 1_000_000.0
    );
}

fn run() -> Result<()> {
    let started = Instant::now();
    let args = Cli::parse();
    match args.command {
        Command::Findrefs(args) => {
            let query = args.query()?;
            let scan_started = Instant::now();
            let mut lines = apk::find_references(&args.apk_path, &query, args.threads, args.debug)?;
            let scanned = scan_started.elapsed();
            lines.sort();
            let sorted = scan_started.elapsed();
            let mut payload = String::new();
            for line in lines {
                payload.push_str(&line);
                payload.push('\n');
            }
            if args.debug {
                eprintln!(
                    "[findrefs] rows={} scan={:.2} ms sort={:.2} ms assemble={:.2} ms payload={} MiB",
                    payload.lines().count(),
                    scanned.as_secs_f64() * 1e3,
                    (sorted - scanned).as_secs_f64() * 1e3,
                    (scan_started.elapsed() - sorted).as_secs_f64() * 1e3,
                    payload.len() / (1 << 20)
                );
            }
            emit(&payload, args.output_path())?;
            if args.debug {
                debug_timing(started);
            }
        }
        Command::Classes(args) => {
            let filter = args.filter.as_deref().map(str::to_lowercase);
            let started = Instant::now();
            let classes = apk::list_classes(&args.apk_path, args.threads, args.debug)?;
            let listed = started.elapsed();
            // Rendering is per-row independent, so the rows are rendered in parallel
            // chunks (kept in the order they will be printed) and concatenated once.
            // The filter, the row format and the resulting bytes are unchanged.
            const RENDER_CHUNK: usize = 8192;
            let pieces: Vec<String> = classes
                .par_chunks(RENDER_CHUNK)
                .map(|chunk| {
                    let mut payload = String::with_capacity(chunk.len() * 128);
                    for class in chunk {
                        let java_name = class.java_name().replace('/', ".");
                        if filter
                            .as_ref()
                            .is_some_and(|pattern| !java_name.to_lowercase().contains(pattern))
                        {
                            continue;
                        }
                        payload.push_str(&class.dex_name);
                        payload.push_str(" | ");
                        payload.push_str(&class.descriptor);
                        payload.push_str(" | ");
                        payload.push_str(&java_name);
                        payload.push_str(" | package=");
                        payload.push_str(class.package());
                        payload.push_str(" | class=");
                        payload.push_str(class.simple_name());
                        payload.push('\n');
                    }
                    payload
                })
                .collect();
            let mut payload = String::with_capacity(pieces.iter().map(String::len).sum());
            for piece in &pieces {
                payload.push_str(piece);
            }
            if args.debug {
                eprintln!(
                    "[classes] render={:.2} ms payload={} MiB (list {:.2} ms)",
                    started.elapsed().as_secs_f64() * 1e3 - listed.as_secs_f64() * 1e3,
                    payload.len() / (1 << 20),
                    listed.as_secs_f64() * 1e3
                );
            }
            emit(&payload, args.output.as_deref())?;
        }
        Command::Manifest(args) => {
            let data = apk::read_entry(&args.apk_path, "AndroidManifest.xml")?;
            let xml = manifest::decode(&data)?;
            emit(&xml, args.output.as_deref())?;
        }
        Command::Getclass(args) => {
            let class_name = query::format_class_name(&args.dalvik_class)?;
            let hit = apk::decompile_class(&args.apk_path, &class_name, args.threads, args.debug)?;
            let Some((dex_name, source)) = hit else {
                bail!("Class {class_name} not found in APK.");
            };
            if args.debug {
                eprintln!("[DEBUG] Hit DEX: {dex_name}");
                debug_timing(started);
                eprintln!("{}", "-".repeat(50));
            }
            let mut payload = source;
            payload.push('\n');
            emit(&payload, args.output.as_deref())?;
        }
    }
    Ok(())
}
