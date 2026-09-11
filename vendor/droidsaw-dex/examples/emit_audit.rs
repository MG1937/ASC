//! Corpus measurement for emit validation.
//!
//! Output: structured stats (per-DEX, then aggregate) on the distributions of:
//!   - opcode counts (top-N by frequency)
//!   - string count
//!   - method count per class (min/p50/p80/p95/max)
//!   - class hierarchy depth (superclass chain length, proxy for structural
//!     depth; exact depth requires resolution across DEX files — skipped here)
//!   - code_item length distribution (insns_size, min/p50/p80/p95/max)
//!   - switch-table sizes (packed + sparse, min/p50/p80/p95/max)
//!   - jumbo-string presence (strings with byte-length > 127 or that would
//!     require `ConstStringJumbo`)
//!   - call_site_ids / method_handles section presence
//!
//! Usage:
//!   cargo run --release --example emit_audit -- <dex-or-dir> [<dex-or-dir> ...]
//!
//! One output block per argument; aggregate block at the end.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use droidsaw_dex::decode;
use droidsaw_dex::opcodes::Opcode;
use droidsaw_dex::parser::DexFile;

#[derive(Default, Debug)]
struct DexStats {
    name: String,
    total_classes: u64,
    total_methods: u64,
    total_strings: u64,
    jumbo_strings: u64,
    methods_per_class: Vec<u64>,
    insns_per_method: Vec<u64>,
    switch_sizes_packed: Vec<u64>,
    switch_sizes_sparse: Vec<u64>,
    opcode_counts: BTreeMap<String, u64>,
    call_site_ids_present: bool,
    method_handles_present: bool,
    version: String,
}

fn main() -> ExitCode {
    let args: Vec<PathBuf> = std::env::args().skip(1).map(PathBuf::from).collect();
    if args.is_empty() {
        eprintln!("usage: emit_audit <dex-or-dir> [<dex-or-dir> ...]");
        return ExitCode::from(2);
    }

    let mut dex_paths: Vec<PathBuf> = Vec::new();
    for path in &args {
        if path.is_file() {
            dex_paths.push(path.clone());
        } else if path.is_dir() {
            if let Ok(rd) = std::fs::read_dir(path) {
                for ent in rd.flatten() {
                    let p = ent.path();
                    if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                        if name.starts_with("classes") && name.ends_with(".dex") {
                            dex_paths.push(p);
                        }
                    }
                }
            }
        }
    }
    dex_paths.sort();

    let mut agg = DexStats {
        name: format!("aggregate ({} DEX files)", dex_paths.len()),
        ..DexStats::default()
    };
    let mut per_dex: Vec<DexStats> = Vec::new();

    for dex_path in &dex_paths {
        let data = match std::fs::read(dex_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("skip {}: {e}", dex_path.display());
                continue;
            }
        };
        let dex = match DexFile::parse(&data, None) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("parse fail {}: {e:?}", dex_path.display());
                continue;
            }
        };
        let mut s = DexStats {
            name: dex_path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default(),
            version: dex.header.version().to_string(),
            total_strings: dex.strings.len() as u64,
            total_classes: dex.class_defs.len() as u64,
            ..DexStats::default()
        };

        for str_s in &dex.strings {
            // MUTF-8 byte length can exceed char count — approximate with bytes.
            if str_s.raw_bytes().len() > 127 {
                s.jumbo_strings += 1;
            }
        }

        // call_site_ids / method_handles: parser doesn't track them, infer from
        // header map_list if available. Approximation: these sections exist
        // only if any InvokeCustom / InvokePolymorphic opcode appears.
        // We'll set flags after the instruction walk.

        for class_def in dex.class_defs.iter() {
            if class_def.class_data_off == 0 {
                s.methods_per_class.push(0);
                continue;
            }
            let cd = match decode::parse_class_data(&data, class_def.class_data_off) {
                Ok(cd) => cd,
                Err(_) => {
                    s.methods_per_class.push(0);
                    continue;
                }
            };
            let total = (cd.direct_methods.len() + cd.virtual_methods.len()) as u64;
            s.methods_per_class.push(total);
            s.total_methods += total;

            for em in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
                if em.code_off == 0 {
                    continue;
                }
                let code = match decode::parse_code_item(&data, em.code_off) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                s.insns_per_method.push(code.instructions.len() as u64);

                for insn in &code.instructions {
                    let key = format!("{:?}", insn.op);
                    *s.opcode_counts.entry(key).or_insert(0) += 1;

                    if matches!(insn.op, Opcode::InvokeCustom | Opcode::InvokeCustomRange) {
                        s.call_site_ids_present = true;
                    }
                    if matches!(insn.op, Opcode::InvokePolymorphic | Opcode::InvokePolymorphicRange) {
                        s.method_handles_present = true;
                    }
                }

                for pd in code.payloads.values() {
                    match pd {
                        decode::PayloadData::PackedSwitch { targets, .. } => {
                            s.switch_sizes_packed.push(targets.len() as u64);
                        }
                        decode::PayloadData::SparseSwitch { keys, .. } => {
                            s.switch_sizes_sparse.push(keys.len() as u64);
                        }
                        _ => {}
                    }
                }
            }
        }

        print_stats(&s);
        merge(&mut agg, &s);
        per_dex.push(s);
    }

    println!();
    println!("========= AGGREGATE =========");
    print_stats(&agg);

    // Surfaces distinguished from Brief's expectations:
    if agg.call_site_ids_present {
        println!("\nNOTE: call_site_ids used in corpus — Directive 6 step 9 'skip if pre-v038' does NOT hold.");
    }
    if agg.method_handles_present {
        println!("NOTE: method_handles used in corpus — emit must handle method_handle_item.");
    }
    let jumbo_frac = if agg.total_strings > 0 {
        100.0 * (agg.jumbo_strings as f64) / (agg.total_strings as f64)
    } else { 0.0 };
    if jumbo_frac > 0.5 {
        println!("NOTE: jumbo-strings are {jumbo_frac:.2}% of corpus — not long-tail; early implement.");
    }
    ExitCode::SUCCESS
}

fn merge(dst: &mut DexStats, src: &DexStats) {
    dst.total_classes += src.total_classes;
    dst.total_methods += src.total_methods;
    dst.total_strings += src.total_strings;
    dst.jumbo_strings += src.jumbo_strings;
    dst.methods_per_class.extend(&src.methods_per_class);
    dst.insns_per_method.extend(&src.insns_per_method);
    dst.switch_sizes_packed.extend(&src.switch_sizes_packed);
    dst.switch_sizes_sparse.extend(&src.switch_sizes_sparse);
    for (k, v) in &src.opcode_counts {
        *dst.opcode_counts.entry(k.clone()).or_insert(0) += v;
    }
    dst.call_site_ids_present |= src.call_site_ids_present;
    dst.method_handles_present |= src.method_handles_present;
    if dst.version.is_empty() {
        dst.version = src.version.clone();
    }
}

fn pct(mut v: Vec<u64>, p: f64) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    let idx = ((v.len() as f64) * p).floor() as usize;
    v[idx.min(v.len() - 1)]
}

fn print_stats(s: &DexStats) {
    println!("\n--- {} (version={}) ---", s.name, s.version);
    println!("  strings     : {} (jumbo: {})", s.total_strings, s.jumbo_strings);
    println!("  classes     : {}", s.total_classes);
    println!("  methods     : {}", s.total_methods);
    let mpc = s.methods_per_class.clone();
    println!(
        "  methods/cls : min={} p50={} p80={} p95={} max={}",
        mpc.iter().min().copied().unwrap_or(0),
        pct(mpc.clone(), 0.50),
        pct(mpc.clone(), 0.80),
        pct(mpc.clone(), 0.95),
        mpc.iter().max().copied().unwrap_or(0),
    );
    let ipm = s.insns_per_method.clone();
    println!(
        "  insns/method: min={} p50={} p80={} p95={} max={}",
        ipm.iter().min().copied().unwrap_or(0),
        pct(ipm.clone(), 0.50),
        pct(ipm.clone(), 0.80),
        pct(ipm.clone(), 0.95),
        ipm.iter().max().copied().unwrap_or(0),
    );
    if !s.switch_sizes_packed.is_empty() {
        let sp = s.switch_sizes_packed.clone();
        println!(
            "  packed-sw   : n={} p50={} p80={} p95={} max={}",
            sp.len(),
            pct(sp.clone(), 0.50),
            pct(sp.clone(), 0.80),
            pct(sp.clone(), 0.95),
            sp.iter().max().copied().unwrap_or(0),
        );
    }
    if !s.switch_sizes_sparse.is_empty() {
        let sp = s.switch_sizes_sparse.clone();
        println!(
            "  sparse-sw   : n={} p50={} p80={} p95={} max={}",
            sp.len(),
            pct(sp.clone(), 0.50),
            pct(sp.clone(), 0.80),
            pct(sp.clone(), 0.95),
            sp.iter().max().copied().unwrap_or(0),
        );
    }
    if s.call_site_ids_present {
        println!("  call_site_ids     : YES (invoke-custom in corpus)");
    } else {
        println!("  call_site_ids     : no");
    }
    if s.method_handles_present {
        println!("  method_handles    : YES (invoke-polymorphic in corpus)");
    } else {
        println!("  method_handles    : no");
    }
    // Top 10 opcodes
    let mut op_list: Vec<(String, u64)> =
        s.opcode_counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
    op_list.sort_by_key(|b| std::cmp::Reverse(b.1));
    let total_ops: u64 = op_list.iter().map(|(_, v)| v).sum();
    println!("  top opcodes (of {} total):", total_ops);
    for (op, n) in op_list.iter().take(10) {
        let pct = 100.0 * (*n as f64) / (total_ops.max(1) as f64);
        println!("    {op:30} {n:>9} ({pct:>5.2}%)");
    }
}
