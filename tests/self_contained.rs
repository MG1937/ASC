//! The shipped binary must stay self-contained.
//!
//! The project objective forbids the Rust production code from invoking or embedding
//! Python, Androguard, JADX or a JVM. In practice that means production code never
//! spawns a process (the only way to reach Python or a JVM) and the dependency list
//! stays free of Python/JVM bindings. Both held by construction; these tests keep
//! them holding, because a future change could otherwise silently reintroduce a
//! runtime dependency that the release binary is not allowed to have.

use std::fs;
use std::path::{Path, PathBuf};

/// APIs that would let production code start another process.
const FORBIDDEN_APIS: [&str; 5] = [
    "process::Command",
    "Command::new",
    ".spawn(",
    ".exec(",
    "build.rs",
];

/// Crates that would pull a Python or JVM runtime into the binary.
const FORBIDDEN_DEPENDENCIES: [&str; 6] =
    ["pyo3", "cpython", "j4rs", "jni", "java-locator", "jni-sys"];

fn rust_sources(directory: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("read src directory") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

/// Everything up to the first `#[cfg(test)]` marker.
///
/// That is the same convention the benchmark harness uses to count production lines,
/// and it keeps these tests from matching their own strings inside test modules.
fn production_part(source: &str) -> &str {
    source.split("#[cfg(test)]").next().unwrap_or(source)
}

#[test]
fn production_code_never_starts_a_process() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    rust_sources(&root.join("src"), &mut sources);
    assert!(!sources.is_empty(), "no Rust sources found under src/");

    for path in sources {
        let source = fs::read_to_string(&path).expect("read source");
        for api in FORBIDDEN_APIS {
            assert!(
                !production_part(&source).contains(api),
                "{} uses {api}; the release binary must not spawn processes",
                path.display()
            );
        }
    }
}

#[test]
fn dependencies_carry_no_python_or_jvm_binding() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("read Cargo.toml");
    for dependency in FORBIDDEN_DEPENDENCIES {
        assert!(
            !manifest.contains(dependency),
            "Cargo.toml mentions {dependency}; the release binary must not embed a Python or JVM runtime"
        );
    }
    assert!(
        !manifest.contains("build ="),
        "Cargo.toml declares a build script; production code must stay Rust-only"
    );
}
