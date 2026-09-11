//! R8-renamed-class identity hints.
//!
//! R8 / Proguard rename user classes to opaque short identifiers like
//! `LX/552;`. The bytecode still preserves cues that survive rename
//! (string literals, stdlib inheritance, cross-class refs to non-
//! renamed namespaces). This module emits those cues as a class-level
//! comment block above the class declaration so an analyst can answer
//! "what is this really?" without re-doing the bytecode trace.
//!
//! Pipeline placement: invoked from `classes::decompile_class_impl` at
//! the class-header emit site, gated on
//! [`is_r8_short_renamed`]. Non-renamed classes are unaffected — the
//! gate is the only behavioral change for normal Java fixtures.

use std::collections::BTreeSet;

use crate::decode::{self, ClassData, PoolIndex};
use crate::ids::{ClassDefItem, FieldIdx, MethodIdx, StringIdx, TypeIdx};
use crate::parser::DexFile;

/// Maximum number of string literals to surface.
const MAX_STRINGS: usize = 5;

/// Maximum number of user-namespace type references to surface.
const MAX_USER_TYPES: usize = 5;

/// Maximum bytes per string literal in the hint block. Longer literals
/// are truncated with `…`. Prevents a multi-kilobyte log-template
/// string from blowing up the comment block.
const MAX_STRING_LEN: usize = 80;

/// Returns true if `descriptor` matches R8's canonical short-renamed
/// shape `LX/<alphanumeric>;` with the class segment between `/` and
/// `;` being 1..=6 ASCII alphanumeric chars.
///
/// Conservative gate. Broader R8 shapes (`La/b/c;` short-segment
/// patterns, single-letter Kotlin patterns) are deferred — only
/// `LX/<id>;` triggers the hints emit in this stream.
pub fn is_r8_short_renamed(descriptor: &str) -> bool {
    let Some(inner) = descriptor
        .strip_prefix("LX/")
        .and_then(|s| s.strip_suffix(';'))
    else {
        return false;
    };
    !inner.is_empty()
        && inner.len() <= 6
        && inner.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Broader R8-renamed-class gate. Accepts BOTH:
///
/// 1. The strict `LX/<≤6 alphanum>;` shape recognised by
///    [`is_r8_short_renamed`] (R8 synthetic-helper namespace).
/// 2. The bare top-level `L<≤3 alphanum>;` shape with NO `/` infix —
///    R8's default rename scheme for top-level classes (e.g. `La;`,
///    `Lb;`, `Lcc;`) observed in real R8 9.0 output on the Wave 1B
///    `enum_values_cache` fixture where R8 outlined `Color.values()`
///    into a `La;::a(int)` synthetic helper.
///
/// **NOT** a replacement for `is_r8_short_renamed`. Strict callers
/// (identity-hints emit, stdlib-cue filter) keep using the strict
/// variant — broadening their gates risks tagging legitimate
/// user-namespace short classes (single-letter class names ARE valid
/// Java). The R8 inversion pass's BlockOutlined recogniser uses this
/// broader variant because its three load-bearing gates
/// (renamed-namespace + repetition + single-BB body) collectively
/// rule out false positives even with the broader gate.
///
/// Length cap of 3 on the bare-shape arm chosen empirically — R8 9.0
/// uses single + double + occasional triple lowercase chars; longer
/// short renames would be unusual and shade into legitimate
/// user-named short classes (`Log`, `App`, `Db`).
#[must_use]
pub fn is_r8_renamed_class(descriptor: &str) -> bool {
    if is_r8_short_renamed(descriptor) {
        return true;
    }
    let Some(inner) = descriptor
        .strip_prefix('L')
        .and_then(|s| s.strip_suffix(';'))
    else {
        return false;
    };
    !inner.is_empty()
        && inner.len() <= 3
        && !inner.contains('/')
        && inner.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Structural cues collected from an R8-renamed class's bytecode.
#[derive(Debug, Default)]
pub struct IdentityHints {
    /// Top string literals appearing in the class's method bodies.
    pub strings: Vec<String>,
    /// Superclass in pretty dot-separated form, if not `java.lang.Object`.
    pub super_class: Option<String>,
    /// Interfaces in pretty dot-separated form.
    pub interfaces: Vec<String>,
    /// User-namespace type descriptors referenced by this class.
    /// Stdlib types (`java.*`, `android.*`, `kotlin.*`, `kotlinx.*`,
    /// `dalvik.*`) are filtered out — they carry no identity signal.
    pub user_namespace_types: Vec<String>,
}

impl IdentityHints {
    /// True when no cues were collected. Callers can skip emitting an
    /// empty comment block.
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
            && self.super_class.is_none()
            && self.interfaces.is_empty()
            && self.user_namespace_types.is_empty()
    }
}

/// Collect identity cues for `class_def`. Returns an empty
/// `IdentityHints` if the class has no parseable `class_data` or every
/// method fails to decode — the comment block is suppressed in that
/// case (no panics, no half-rendered output).
pub fn collect(dex: &DexFile, data: &[u8], class_def: &ClassDefItem) -> IdentityHints {
    let own_class = class_def.class_idx;

    let mut strings: Vec<(StringIdx, String)> = Vec::new();
    let mut types: BTreeSet<TypeIdx> = BTreeSet::new();

    if class_def.class_data_off != 0 {
        if let Ok(class_data) = decode::parse_class_data(data, class_def.class_data_off) {
            collect_from_class_data(dex, data, &class_data, &mut strings, &mut types);
        }
    }

    let super_class = class_def
        .superclass_idx
        .and_then(|idx| dex.get_type_descriptor(idx).ok())
        .filter(|desc| *desc != "Ljava/lang/Object;")
        .map(pretty_class);

    let mut interfaces: Vec<String> = Vec::new();
    if class_def.interfaces_off != 0 {
        if let Some(ifaces) = dex.type_lists.get(&class_def.interfaces_off) {
            for tidx in ifaces {
                if let Ok(desc) = dex.get_type_descriptor(*tidx) {
                    interfaces.push(pretty_class(desc));
                }
            }
        }
    }

    let mut user_types: Vec<String> = types
        .into_iter()
        .filter(|tidx| *tidx != own_class)
        .filter_map(|tidx| dex.get_type_descriptor(tidx).ok().map(str::to_owned))
        .filter(|desc| !is_stdlib_descriptor(desc))
        .filter(|desc| !is_r8_short_renamed(desc))
        .map(|desc| pretty_class(&desc))
        .collect();
    user_types.sort();
    user_types.dedup();
    user_types.truncate(MAX_USER_TYPES);

    // Dedupe strings by content (different StringIdx can resolve to the
    // same bytes after MUTF-8 decode), then rank by length descending —
    // longer strings carry more identity signal than 2-3 char fragments.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut ranked: Vec<String> = Vec::new();
    for (_, s) in &strings {
        if seen.insert(s.clone()) {
            ranked.push(truncate(s));
        }
    }
    ranked.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    ranked.truncate(MAX_STRINGS);

    IdentityHints {
        strings: ranked,
        super_class,
        interfaces,
        user_namespace_types: user_types,
    }
}

fn collect_from_class_data(
    dex: &DexFile,
    data: &[u8],
    class_data: &ClassData,
    strings: &mut Vec<(StringIdx, String)>,
    types: &mut BTreeSet<TypeIdx>,
) {
    for field in class_data
        .static_fields
        .iter()
        .chain(class_data.instance_fields.iter())
    {
        if let Some(field_item) = resolve_field(dex, field.field_idx) {
            types.insert(field_item.type_idx);
        }
    }

    for method in class_data
        .direct_methods
        .iter()
        .chain(class_data.virtual_methods.iter())
    {
        if method.code_off == 0 {
            continue;
        }
        let Ok(code) = decode::parse_code_item(data, method.code_off) else {
            continue;
        };
        for insn in &code.instructions {
            let Some(pool_idx) = &insn.pool_idx else { continue };
            match pool_idx {
                PoolIndex::String(sidx) => {
                    if let Ok(s) = dex.get_string(*sidx) {
                        strings.push((*sidx, s.to_owned()));
                    }
                }
                PoolIndex::Type(tidx) => {
                    types.insert(*tidx);
                }
                PoolIndex::Field(fidx) => {
                    if let Some(field_item) = resolve_field(dex, *fidx) {
                        types.insert(field_item.type_idx);
                        types.insert(field_item.class_idx);
                    }
                }
                PoolIndex::Method(midx) | PoolIndex::MethodAndProto(midx, _) => {
                    if let Some(method_item) = resolve_method(dex, *midx) {
                        types.insert(method_item.class_idx);
                    }
                }
                PoolIndex::CallSite(_) => {}
            }
        }
    }
}

fn resolve_field(dex: &DexFile, idx: FieldIdx) -> Option<&crate::ids::FieldIdItem> {
    dex.fields.get(usize::try_from(idx.0).ok()?)
}

fn resolve_method(dex: &DexFile, idx: MethodIdx) -> Option<&crate::ids::MethodIdItem> {
    dex.methods.get(usize::try_from(idx.0).ok()?)
}

/// Stdlib filter for cue selection. Returns true for descriptors that
/// the analyst is unlikely to read as a CUE — they're scaffolding the
/// class extends/uses incidentally, not identity signal.
///
/// AndroidX (`Landroidx/`) and Google libraries (`Lcom/google/`) are
/// deliberately INCLUDED as user-namespace cues — referencing
/// `androidx.media3.exoplayer.video.PlaceholderSurface` is high-signal
/// for the class's role.
fn is_stdlib_descriptor(desc: &str) -> bool {
    desc.starts_with("Ljava/")
        || desc.starts_with("Landroid/")
        || desc.starts_with("Lkotlin/")
        || desc.starts_with("Lkotlinx/")
        || desc.starts_with("Ldalvik/")
}

fn pretty_class(desc: &str) -> String {
    // Strip leading 'L' and trailing ';', replace '/' and '$' with '.'
    // (Java source uses '.' for both package separators and nested-class
    // separators).
    let trimmed = desc.strip_prefix('L').unwrap_or(desc);
    let trimmed = trimmed.strip_suffix(';').unwrap_or(trimmed);
    trimmed
        .chars()
        .map(|c| if matches!(c, '/' | '$') { '.' } else { c })
        .collect()
}

fn truncate(s: &str) -> String {
    if s.len() <= MAX_STRING_LEN {
        return s.to_owned();
    }
    // Preserve UTF-8 boundary at the truncation point. `get(..end)`
    // returns None on a non-boundary index, so step back until we land
    // on one — char_indices is the cheap way to find the last valid
    // boundary at-or-below MAX_STRING_LEN-1.
    let cap = MAX_STRING_LEN.saturating_sub(1);
    let end = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= cap)
        .last()
        .unwrap_or(0);
    let head = s.get(..end).unwrap_or("");
    let mut out = String::with_capacity(head.len().saturating_add(4));
    out.push_str(head);
    out.push('…');
    out
}

/// Format the identity-hints block as a C-style `/* ... */` comment
/// suitable for direct insertion above the class declaration.
///
/// Returns an empty string when `hints.is_empty()` so the caller can
/// unconditionally `out.push_str(&format_block(&hints))` without
/// guarding.
pub fn format_block(hints: &IdentityHints) -> String {
    if hints.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    out.push_str("/*\n");
    out.push_str(" * droidsaw identity hints — this class is R8-renamed; the bytecode\n");
    out.push_str(" * preserved these cues that may help identify its original role:\n");

    if !hints.strings.is_empty() {
        out.push_str(" *\n");
        out.push_str(" *   String literals (top by length):\n");
        for s in &hints.strings {
            out.push_str(" *     - ");
            out.push_str(&escape_for_block_comment(s));
            out.push('\n');
        }
    }

    if hints.super_class.is_some() || !hints.interfaces.is_empty() {
        out.push_str(" *\n");
        out.push_str(" *   Inheritance:\n");
        if let Some(sc) = &hints.super_class {
            out.push_str(" *     - extends ");
            out.push_str(sc);
            out.push('\n');
        }
        for iface in &hints.interfaces {
            out.push_str(" *     - implements ");
            out.push_str(iface);
            out.push('\n');
        }
    }

    if !hints.user_namespace_types.is_empty() {
        out.push_str(" *\n");
        out.push_str(" *   User-namespace types referenced:\n");
        for ty in &hints.user_namespace_types {
            out.push_str(" *     - ");
            out.push_str(ty);
            out.push('\n');
        }
    }

    out.push_str(" *\n");
    out.push_str(" * Confidence: structural identity preserved. Original name unrecoverable\n");
    out.push_str(" * without R8 mapping file or library fingerprint match.\n");
    out.push_str(" */\n");
    out
}

/// Quote a string as a Java-style literal AND neutralise any `*/`
/// sequence that would otherwise close the surrounding block comment.
fn escape_for_block_comment(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    // Defensive: collapse any literal `*/` inside the string content
    // (after the outer quoting) so the surrounding block comment can't
    // be closed by adversarial input.
    out.replace("*/", "*\\/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_r8_short_renamed_accepts_canonical_shapes() {
        assert!(is_r8_short_renamed("LX/552;"));
        assert!(is_r8_short_renamed("LX/00A;"));
        assert!(is_r8_short_renamed("LX/A;"));
        assert!(is_r8_short_renamed("LX/abcdef;"));
    }

    #[test]
    fn is_r8_renamed_class_accepts_strict_shape() {
        // Strict LX/<short>; shape passes through.
        assert!(is_r8_renamed_class("LX/552;"));
        assert!(is_r8_renamed_class("LX/abcdef;"));
    }

    #[test]
    fn is_r8_renamed_class_accepts_bare_short_shape() {
        // R8 9.0 default top-level renames (observed on enum_values_cache
        // fixture where Color.values() got outlined into La;::a(int)).
        assert!(is_r8_renamed_class("La;"));
        assert!(is_r8_renamed_class("Lb;"));
        assert!(is_r8_renamed_class("Lcc;"));
        assert!(is_r8_renamed_class("LA;"));
        assert!(is_r8_renamed_class("L9;"));
    }

    #[test]
    fn is_r8_renamed_class_rejects_user_namespace() {
        // Anything with `/` is a normal package-qualified class —
        // never the bare-rename shape.
        assert!(!is_r8_renamed_class("Lcom/foo/Bar;"));
        assert!(!is_r8_renamed_class("Ljava/lang/Object;"));
        assert!(!is_r8_renamed_class("Lab/cd;"));
    }

    #[test]
    fn is_r8_renamed_class_rejects_long_bare_classes() {
        // Length cap of 3 on bare-shape arm — `Log`, `App`, `Db` are
        // borderline; `Logging`/`Worker`/`Database` are clearly user code.
        assert!(!is_r8_renamed_class("LWorker;"));
        assert!(!is_r8_renamed_class("LDatabase;"));
        assert!(!is_r8_renamed_class("LLogging;"));
    }

    #[test]
    fn is_r8_renamed_class_rejects_empty_and_malformed() {
        assert!(!is_r8_renamed_class(""));
        assert!(!is_r8_renamed_class("L;"));
        assert!(!is_r8_renamed_class("La"));
        assert!(!is_r8_renamed_class("a;"));
        assert!(!is_r8_renamed_class("L_;"));
    }

    #[test]
    fn is_r8_short_renamed_rejects_non_matching() {
        assert!(!is_r8_short_renamed("Lcom/foo/Bar;"));
        assert!(!is_r8_short_renamed("LX/TooLongName;"));
        assert!(!is_r8_short_renamed("LX/with_underscore;"));
        assert!(!is_r8_short_renamed("LX/;"));
        assert!(!is_r8_short_renamed("LY/552;"));
        assert!(!is_r8_short_renamed("Ljava/lang/Object;"));
        assert!(!is_r8_short_renamed(""));
    }

    #[test]
    fn is_stdlib_descriptor_classifies_correctly() {
        assert!(is_stdlib_descriptor("Ljava/lang/Object;"));
        assert!(is_stdlib_descriptor("Landroid/os/HandlerThread;"));
        assert!(is_stdlib_descriptor("Lkotlin/Unit;"));
        assert!(is_stdlib_descriptor("Lkotlinx/coroutines/Job;"));
        assert!(is_stdlib_descriptor("Ldalvik/system/PathClassLoader;"));
        // AndroidX is INCLUDED as user-namespace (a signal cue).
        assert!(!is_stdlib_descriptor("Landroidx/media3/Foo;"));
        assert!(!is_stdlib_descriptor("Lcom/google/firebase/Foo;"));
        assert!(!is_stdlib_descriptor("Lmy/app/Bar;"));
    }

    #[test]
    fn pretty_class_strips_l_and_semi() {
        assert_eq!(pretty_class("Ljava/lang/Object;"), "java.lang.Object");
        assert_eq!(
            pretty_class("Landroidx/media3/exoplayer/video/PlaceholderSurface;"),
            "androidx.media3.exoplayer.video.PlaceholderSurface"
        );
        assert_eq!(pretty_class("LFoo$Bar;"), "Foo.Bar");
    }

    #[test]
    fn truncate_respects_utf8_boundaries() {
        let s = "a".repeat(MAX_STRING_LEN.saturating_add(20));
        let t = truncate(&s);
        assert!(t.ends_with('…'));
        assert!(t.len() <= MAX_STRING_LEN.saturating_add(3));

        // Multi-byte char at the truncation point must not split.
        let multi = format!("{}€€€", "a".repeat(MAX_STRING_LEN.saturating_sub(2)));
        let t2 = truncate(&multi);
        // Should not panic and must be valid UTF-8 (Rust guarantees, but
        // verify the truncation didn't produce an invalid slice).
        assert!(t2.chars().count() >= 1);
    }

    #[test]
    fn truncate_passes_through_short_strings() {
        assert_eq!(truncate("hello"), "hello");
        assert_eq!(truncate(""), "");
    }

    #[test]
    fn escape_for_block_comment_neutralises_close_marker() {
        let s = "contains */ end-of-comment";
        let e = escape_for_block_comment(s);
        assert!(!e.contains("*/"), "must not allow block-comment close: {e}");
        assert!(e.contains("*\\/"));
    }

    #[test]
    fn escape_for_block_comment_escapes_control_chars() {
        let s = "newline\nhere";
        let e = escape_for_block_comment(s);
        assert!(e.contains("\\n"));
        assert!(!e.contains('\n'));
    }

    #[test]
    fn format_block_empty_returns_empty_string() {
        let hints = IdentityHints::default();
        assert_eq!(format_block(&hints), "");
    }

    #[test]
    fn format_block_includes_all_sections_when_present() {
        let hints = IdentityHints {
            strings: vec!["ExoPlayer:PlaceholderSurface".to_owned()],
            super_class: Some("android.os.HandlerThread".to_owned()),
            interfaces: vec!["android.os.Handler.Callback".to_owned()],
            user_namespace_types: vec!["androidx.media3.foo.Bar".to_owned()],
        };
        let block = format_block(&hints);
        assert!(block.starts_with("/*\n"));
        assert!(block.ends_with(" */\n"));
        assert!(block.contains("droidsaw identity hints"));
        assert!(block.contains("\"ExoPlayer:PlaceholderSurface\""));
        assert!(block.contains("extends android.os.HandlerThread"));
        assert!(block.contains("implements android.os.Handler.Callback"));
        assert!(block.contains("androidx.media3.foo.Bar"));
        assert!(block.contains("Confidence: structural identity preserved"));
    }

    #[test]
    fn format_block_omits_empty_sections() {
        let hints = IdentityHints {
            strings: vec!["only-string".to_owned()],
            ..IdentityHints::default()
        };
        let block = format_block(&hints);
        assert!(block.contains("String literals"));
        assert!(!block.contains("Inheritance"));
        assert!(!block.contains("User-namespace types"));
    }
}
