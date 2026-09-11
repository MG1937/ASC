mod apk;
mod cli;
mod dex;
mod manifest;

use anyhow::{Context, Result, bail};
use clap::Parser;
use cli::{Cli, Command};
use std::fs;
use std::io::{self, Write};
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

fn run() -> Result<()> {
    let started = Instant::now();
    let args = Cli::parse();
    match args.command {
        Command::Findrefs(args) => {
            let query = args.query()?;
            let rows = apk::find_references(&args.apk_path, &query, args.threads, args.debug)?;
            let mut stdout = io::BufWriter::new(io::stdout().lock());
            let mut rendered = String::new();
            for row in rows {
                rendered.push_str(&row);
                rendered.push('\n');
            }
            stdout.write_all(rendered.as_bytes())?;
            stdout.flush()?;
            if let Some(path) = args.output_path() {
                fs::write(path, rendered).with_context(|| format!("write {}", path.display()))?;
            }
            if args.debug {
                println!(
                    "[DEBUG] Total Execution Time: {:.2} us",
                    started.elapsed().as_secs_f64() * 1_000_000.0
                );
            }
        }
        Command::Classes(args) => {
            let filter = args.filter.as_deref().map(str::to_lowercase);
            let classes = apk::list_classes(&args.apk_path, args.threads)?;
            let mut rendered = String::new();
            for class in classes {
                let java_name = class.java_name().replace('/', ".");
                if filter
                    .as_ref()
                    .is_some_and(|pattern| !java_name.to_lowercase().contains(pattern))
                {
                    continue;
                }
                rendered.push_str(&class.dex_name);
                rendered.push_str(" | ");
                rendered.push_str(&class.descriptor);
                rendered.push_str(" | ");
                rendered.push_str(&java_name);
                rendered.push_str(" | package=");
                rendered.push_str(class.package());
                rendered.push_str(" | class=");
                rendered.push_str(class.simple_name());
                rendered.push('\n');
            }
            if let Some(path) = &args.output {
                fs::write(path, &rendered).with_context(|| format!("write {}", path.display()))?;
            }
            print!("{rendered}");
        }
        Command::Manifest(args) => {
            let data = apk::read_entry(&args.apk_path, "AndroidManifest.xml")?;
            let xml = manifest::decode(&data)?;
            if let Some(path) = &args.output {
                fs::write(path, &xml).with_context(|| format!("write {}", path.display()))?;
            }
            print!("{xml}");
        }
        Command::Getclass(args) => {
            let class_name = cli::format_class_name(&args.dalvik_class)?;
            let hit = apk::decompile_class(&args.apk_path, &class_name, args.threads, args.debug)?;
            let Some((dex_name, source)) = hit else {
                bail!("Class {class_name} not found in APK.");
            };
            if args.debug {
                println!("[DEBUG] Hit DEX: {dex_name}");
                println!(
                    "[DEBUG] Total Execution Time: {:.2} us",
                    started.elapsed().as_secs_f64() * 1_000_000.0
                );
                println!("{}", "-".repeat(50));
            }
            if let Some(path) = &args.output {
                let mut text = source.clone();
                if !text.ends_with('\n') {
                    text.push('\n');
                }
                fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
            }
            println!("{source}");
        }
    }
    Ok(())
}
