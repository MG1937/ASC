//! Public API surface: class and method summaries.
#![allow(missing_docs, reason = "internal")]

//! High-level read-only query API over a parsed `DexFile`.
//!
//! These methods are the public surface that downstream tools (notably
//! the `droidsaw-mcp` binary and the `dex_classes`/`dex_methods` CLI
//! subcommands — both now shipped from the `droidsaw-core` crate)
//! call instead of walking `dex.class_defs` / `dex.methods` directly.
//! Keep them stable: every change here is a breaking change for at
//! least one MCP tool.

use crate::decode::{parse_class_data, EncodedMethod};
use crate::error::Result;
use crate::ids::ClassDefItem;
use crate::DexFile;
use serde::{Deserialize, Serialize};

/// Tri-state verdict returned by every public DEX detector / recognizer
/// that consumes tolerant-parsed subsections (`annotation_directory`,
/// `annotation_set`, `annotation_item`, `class_data`, `code_item`,
/// `debug_info`). Distinguishes:
///
/// - `Yes` — the predicate holds on the parsed IR.
/// - `No` — the predicate provably does not hold.
/// - `Indeterminate` — at least one subsection reachable from the
///   detector's query failed to parse (tracked in `DexFile.parse_errors`).
///   The detector cannot answer honestly; the caller must treat this
///   as poison rather than collapsing to `No`.
///
/// This enum closes the silent-skip evasion primitive: an attacker plants
/// a malformed annotation/code_item, parser tolerantly records a `ParseFailure`,
/// detector reads `None` from the relevant map and answers "not present" —
/// laundering the malicious shape as benign. Detectors must not collapse
/// `Indeterminate` to `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectorVerdict {
    Yes,
    No,
    Indeterminate,
}

impl DetectorVerdict {
    /// Conservative bool conversion (`Indeterminate → false`). Use only
    /// at sites that explicitly want "treat absence-of-yes as not-yes"
    /// semantics AND have separately consulted `dex.parse_errors` or
    /// the `DEX_DETECTOR_INDETERMINATE` finding stream. New code should
    /// pattern-match the enum directly.
    #[inline]
    #[must_use]
    pub fn is_yes(self) -> bool {
        matches!(self, DetectorVerdict::Yes)
    }

    /// Strict-no: only `No`. `Indeterminate` returns `false` (it is NOT
    /// a no). Test assertions on benign fixtures should prefer this
    /// over `!is_yes()` to catch a regression where a benign fixture
    /// starts emitting parse_errors.
    #[inline]
    #[must_use]
    pub fn is_no(self) -> bool {
        matches!(self, DetectorVerdict::No)
    }

    #[inline]
    #[must_use]
    pub fn is_indeterminate(self) -> bool {
        matches!(self, DetectorVerdict::Indeterminate)
    }
}

impl From<bool> for DetectorVerdict {
    /// Adapter for legacy boolean predicates. New code should construct
    /// the variants directly to make `Indeterminate` reachable.
    fn from(b: bool) -> Self {
        if b {
            DetectorVerdict::Yes
        } else {
            DetectorVerdict::No
        }
    }
}

/// Lightweight summary of a class for listing UIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassSummary {
    /// Position in `dex.class_defs` — pass back to `list_methods`.
    pub class_idx: usize,
    /// Type descriptor: `Lcom/foo/Bar;`.
    pub descriptor: String,
    pub access_flags: u32,
    /// Superclass descriptor, or `None` for `java.lang.Object`.
    pub superclass: Option<String>,
    /// Source file name from the SourceFile attribute, if present.
    pub source_file: Option<String>,
}

/// Lightweight summary of a method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodSummary {
    /// Index into `dex.methods` (the global method-id pool).
    pub method_idx: u32,
    pub name: String,
    pub access_flags: u32,
    pub return_type: String,
    pub parameters: Vec<String>,
    /// `true` for `direct_methods` (private/static/`<init>`), `false` for `virtual_methods`.
    pub is_direct: bool,
    /// `true` when the method has a code item (i.e. not abstract/native).
    pub has_code: bool,
    /// File offset of the code item, or 0 if abstract/native. Pass to
    /// `emit_smali` to disassemble the body without re-walking class_data.
    pub code_off: u32,
}

impl DexFile {
    /// Enumerate every class defined in this DEX file.
    ///
    /// Order matches `dex.class_defs`. Returned `class_idx` is stable for
    /// the lifetime of this `DexFile`.
    pub fn list_classes(&self) -> Vec<ClassSummary> {
        self.class_defs
            .iter()
            .enumerate()
            .map(|(i, cd)| ClassSummary {
                class_idx: i,
                descriptor: self
                    .get_type_descriptor(cd.class_idx)
                    .unwrap_or("?")
                    .to_string(),
                access_flags: cd.access_flags,
                superclass: cd
                    .superclass_idx
                    .and_then(|t| self.get_type_descriptor(t).ok())
                    .map(|s| s.to_string()),
                source_file: cd
                    .source_file_idx
                    .and_then(|s| self.get_string(s).ok())
                    .map(|s| s.to_string()),
            })
            .collect()
    }

    /// Find a class by descriptor or name.
    ///
    /// Match priority:
    /// 1. Exact descriptor (`Lcom/foo/Bar;`)
    /// 2. Exact short name (`Bar` matches `Lcom/foo/Bar;`)
    /// 3. Substring match on the descriptor
    ///
    /// Returns the index into `dex.class_defs` and a borrow of the entry.
    /// Use the index for subsequent `list_methods` calls.
    pub fn find_class(&self, query: &str) -> Option<(usize, &ClassDefItem)> {
        // All three passes shadow-gate: a duplicate-class_idx row
        // (typically attacker-planted) would otherwise leak through as
        // a separate (i, cd) result, letting a downstream `list_methods`
        // / `decompile` caller operate on the shadowed row's class_data
        // while the index-based resolver picks the first row. The
        // disagreement is the polarity-flip evasion primitive.
        // Pass 1: exact descriptor
        for (i, cd) in self.class_defs.iter().enumerate() {
            if self.class_def_is_shadowed(i) {
                continue;
            }
            if let Ok(desc) = self.get_type_descriptor(cd.class_idx) {
                if desc == query {
                    return Some((i, cd));
                }
            }
        }
        // Pass 2: exact short name
        for (i, cd) in self.class_defs.iter().enumerate() {
            if self.class_def_is_shadowed(i) {
                continue;
            }
            if let Ok(desc) = self.get_type_descriptor(cd.class_idx) {
                if let Some(short) = short_name(desc) {
                    if short == query {
                        return Some((i, cd));
                    }
                }
            }
        }
        // Pass 3: substring on descriptor
        for (i, cd) in self.class_defs.iter().enumerate() {
            if self.class_def_is_shadowed(i) {
                continue;
            }
            if let Ok(desc) = self.get_type_descriptor(cd.class_idx) {
                if desc.contains(query) {
                    return Some((i, cd));
                }
            }
        }
        None
    }

    /// Enumerate methods declared on a class.
    ///
    /// `class_idx` is the index returned by `list_classes` / `find_class`.
    /// `data` is the original DEX byte slice — needed to parse class_data,
    /// which is stored out-of-line from the class_def header.
    ///
    /// Returns direct methods first, then virtual methods, both in the
    /// order they appear in class_data. Empty for classes with no
    /// `class_data_off` (interfaces with no static initializer, etc).
    #[allow(clippy::arithmetic_side_effects, reason = "`direct_methods.len() + virtual_methods.len()` — both Vec lengths bounded by class_data parse which enforces uleb128 count caps via bound_count.")]
    pub fn list_methods(&self, class_idx: usize, data: &[u8]) -> Result<Vec<MethodSummary>> {
        let cd = match self.class_defs.get(class_idx) {
            Some(cd) => cd,
            None => return Ok(Vec::new()),
        };
        if cd.class_data_off == 0 {
            return Ok(Vec::new());
        }
        let class_data = parse_class_data(data, cd.class_data_off)?;
        let mut out =
            Vec::with_capacity(class_data.direct_methods.len() + class_data.virtual_methods.len());
        for em in &class_data.direct_methods {
            out.push(self.method_summary(em, true));
        }
        for em in &class_data.virtual_methods {
            out.push(self.method_summary(em, false));
        }
        Ok(out)
    }

    // WHY: method_summary takes a pre-validated `EncodedMethod`; method_idx and
    // proto_idx are pool indices from a parsed DexFile, bounds-checked at parse
    // time. Indexing into `self.methods` and `self.protos` via these indices is
    // bounded by the struct invariant (parsed pools are co-populated).
    #[allow(
        clippy::indexing_slicing,
        reason = "EncodedMethod indices bounds-checked at DexFile::parse time; struct invariant"
    )]
    #[allow(
        clippy::as_conversions,
        reason = "PROOF: MethodIdx/ProtoIdx (u32 newtype) → usize widening, lossless on 64-bit. Indexing safety is the indexing_slicing PROOF above."
    )]
    fn method_summary(&self, em: &EncodedMethod, is_direct: bool) -> MethodSummary {
        let m = &self.methods[em.method_idx.0 as usize];
        let proto = &self.protos[m.proto_idx.0 as usize];
        let return_type = self
            .get_type_descriptor(proto.return_type_idx)
            .unwrap_or("?")
            .to_string();
        let parameters = self
            .type_lists
            .get(&proto.parameters_off)
            .map(|tl| {
                tl.iter()
                    .map(|t| self.get_type_descriptor(*t).unwrap_or("?").to_string())
                    .collect()
            })
            .unwrap_or_default();
        MethodSummary {
            method_idx: em.method_idx.0,
            name: self.get_string(m.name_idx).unwrap_or("?").to_string(),
            access_flags: em.access_flags,
            return_type,
            parameters,
            is_direct,
            has_code: em.code_off != 0,
            code_off: em.code_off,
        }
    }
}

/// Extract the simple class name from a descriptor: `Lcom/foo/Bar;` → `Bar`.
fn short_name(desc: &str) -> Option<&str> {
    let inner = desc.strip_prefix('L')?.strip_suffix(';')?;
    Some(inner.rsplit('/').next().unwrap_or(inner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_name_basic() {
        assert_eq!(short_name("Lcom/foo/Bar;"), Some("Bar"));
        assert_eq!(short_name("LBar;"), Some("Bar"));
        assert_eq!(short_name("I"), None);
        assert_eq!(short_name("[I"), None);
    }
}
