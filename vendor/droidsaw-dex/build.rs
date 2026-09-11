// build.rs — lockstep CI gates.
//
// 1) Opcode-lockstep gate: cross-check that the CF opcode names declared in the
//    production CF predicates (src/cfg.rs) match those declared in the naive
//    CFG oracle (src/cfg_oracle.rs). Mirrors droidsaw-hermes/build.rs (0791697).
// 2) Matrix-lockstep gate: cross-check that the InsnFormat names declared in
//    src/decode.rs::insn_format match the format-row inventory in
//    docs/opcode-invariant-matrix.md §1. Adding a new InsnFormat variant
//    without a matching matrix row (or vice versa) becomes a compile-time error.
//
// Design: extract name-string literals from sentinel-delimited sections in
// each file, sort + deduplicate, then assert equality.
// Sentinels:
//   // ORACLE-OPCODE-LOCKSTEP-BEGIN / END  (opcode-lockstep)
//   // MATRIX-LOCKSTEP-BEGIN / END         (matrix-lockstep; HTML-comment form in markdown)
// Any double-quoted string literal found between the sentinels in each file is
// treated as a tracked name. Both files must track the same set.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

fn extract_lockstep_names(path: &Path, begin_sentinel: &str, end_sentinel: &str) -> BTreeSet<String> {
    let content = fs::read_to_string(path).unwrap_or_else(|e| {
        panic!("lockstep: cannot read {}: {}", path.display(), e);
    });
    let mut inside = false;
    let mut names: BTreeSet<String> = BTreeSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains(begin_sentinel) {
            inside = true;
            continue;
        }
        if trimmed.contains(end_sentinel) {
            inside = false;
            continue;
        }
        if !inside {
            continue;
        }
        let mut rest = line;
        while let Some(open) = rest.find('"') {
            rest = &rest[open + 1..];
            if let Some(close) = rest.find('"') {
                let candidate = &rest[..close];
                if !candidate.is_empty() && !candidate.contains(' ') && !candidate.contains('\\') {
                    names.insert(candidate.to_string());
                }
                rest = &rest[close + 1..];
            } else {
                break;
            }
        }
    }
    names
}

fn opcode_lockstep_check() {
    let prod_path = Path::new("src/cfg.rs");
    let oracle_path = Path::new("src/cfg_oracle.rs");

    println!("cargo::rerun-if-changed=src/cfg.rs");
    println!("cargo::rerun-if-changed=src/cfg_oracle.rs");

    if !oracle_path.exists() {
        return;
    }

    let prod_names = extract_lockstep_names(
        prod_path,
        "ORACLE-OPCODE-LOCKSTEP-BEGIN",
        "ORACLE-OPCODE-LOCKSTEP-END",
    );
    let oracle_names = extract_lockstep_names(
        oracle_path,
        "ORACLE-OPCODE-LOCKSTEP-BEGIN",
        "ORACLE-OPCODE-LOCKSTEP-END",
    );

    if prod_names.is_empty() && oracle_names.is_empty() {
        println!(
            "cargo::warning=opcode-lockstep: ORACLE-OPCODE-LOCKSTEP-BEGIN/END sentinels not \
            found in cfg.rs or cfg_oracle.rs — gate is inactive. Add sentinels to activate."
        );
        return;
    }

    if prod_names != oracle_names {
        let only_prod: Vec<_> = prod_names.difference(&oracle_names).collect();
        let only_oracle: Vec<_> = oracle_names.difference(&prod_names).collect();
        panic!(
            "opcode-lockstep FAIL: CF opcode name sets diverge.\n\
            Only in production (cfg.rs): {only_prod:?}\n\
            Only in oracle (cfg_oracle.rs): {only_oracle:?}\n\
            Update the oracle's ORACLE-OPCODE-LOCKSTEP section to match production \
            (or vice versa) and ensure the actual predicate bodies follow."
        );
    }
}

fn matrix_lockstep_check() {
    let prod_path = Path::new("src/decode.rs");
    let doc_path = Path::new("docs/opcode-invariant-matrix.md");

    println!("cargo::rerun-if-changed=src/decode.rs");
    println!("cargo::rerun-if-changed=docs/opcode-invariant-matrix.md");

    if !doc_path.exists() {
        return;
    }

    let prod_names = extract_lockstep_names(prod_path, "MATRIX-LOCKSTEP-BEGIN", "MATRIX-LOCKSTEP-END");
    let doc_names = extract_lockstep_names(doc_path, "MATRIX-LOCKSTEP-BEGIN", "MATRIX-LOCKSTEP-END");

    if prod_names.is_empty() && doc_names.is_empty() {
        println!(
            "cargo::warning=matrix-lockstep: MATRIX-LOCKSTEP-BEGIN/END sentinels not \
            found in decode.rs or opcode-invariant-matrix.md — gate is inactive. \
            Add sentinels to activate."
        );
        return;
    }

    if prod_names != doc_names {
        let only_prod: Vec<_> = prod_names.difference(&doc_names).collect();
        let only_doc: Vec<_> = doc_names.difference(&prod_names).collect();
        panic!(
            "matrix-lockstep FAIL: InsnFormat name sets diverge.\n\
            Only in production (decode.rs::insn_format): {only_prod:?}\n\
            Only in matrix doc (opcode-invariant-matrix.md §1): {only_doc:?}\n\
            Update both sentinel-delimited inventories to match (and ensure the \
            actual `insn_format` match arms + matrix rows follow)."
        );
    }
}

fn main() {
    opcode_lockstep_check();
    matrix_lockstep_check();
}
