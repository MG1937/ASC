//! Pure-IR obfuscation-feature extractor.
//!
//! Consumes an already-parsed [`DexFile`] and produces a bag of
//! signals the apk-side bucket classifier composes into vendor
//! attribution.
//!
//! This module deliberately exports raw signals + small typed flags,
//! **not** vendor labels. Vendor attribution is downstream policy,
//! not a fact this module can prove from the IR alone: filename and
//! class-prefix matches are evidence consistent with a vendor's
//! default-config build, never proof.
//!
//! ### What lives here
//!
//! - [`DexObfuscationFeatures`] — the feature bag.
//! - [`KnownVendor`] — closed enum naming commercial obfuscators
//!   the runtime-prefix matcher knows about. Used only inside
//!   [`DexObfuscationFeatures::runtime_prefix_hits`].
//! - [`DexHeaderAnomalies`] — packed-DEX structural fingerprints
//!   readable from the parsed [`crate::header::DexHeader`] alone. Two further
//!   anomalies (`file_size_mismatch`, `map_off_inversions`) require
//!   parser-API additions and are deferred per the
//!   halt-and-report escape valve (a) — see SCOPE-DEFERRED below.
//! - [`extract`] — the pure-IR feature extractor.
//!
//! ### What does NOT live here
//!
//! - Bucket classification / `compose_bucket` — apk-side detector.
//! - Native-lib filename fingerprints, manifest flags — apk-side.
//! - Byte-level fallback for adversarial DEX — apk-side; this
//!   module's input is an already-parsed `DexFile`, callers handle
//!   parse failure upstream.
//! - Semantic-layer signals (anti-tamper bytecode patterns) —
//!   not yet implemented.
//!
//! ### SCOPE-DEFERRED — `DexHeaderAnomalies` subset
//!
//! Two structural-anomaly signals from the original brief require
//! parser surface that `DexFile` doesn't currently expose:
//!
//! - **`file_size_mismatch`** — compare `header.file_size` to actual
//!   buffer size. Needs the raw byte length (not retained in
//!   `DexFile`). Resolution: caller passes `data.len()` to a future
//!   `extract_with_data_len` variant, OR `DexFile` grows a
//!   `parsed_byte_len: usize` field. Filed for future parser-API
//!   discussion.
//!
//! - **`map_off_inversions`** — count of out-of-order entries in
//!   the `map_list`. Needs `DexFile.map_list` which does not exist
//!   today (the parser consumes `map_off` for layout but doesn't
//!   retain the parsed list). Resolution: `DexFile` grows
//!   `pub map_list: Option<Vec<MapItem>>`. Filed for future
//!   parser-API discussion.
//!
//! These two leave `DexHeaderAnomalies` with a meaningful subset
//! today (`link_size_nonzero`, `unaligned_section_offsets`,
//! `map_off_zero`, `data_off_unaligned`) and a documented gap.
#![allow(missing_docs, reason = "internal")]
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::as_conversions,
    reason = "INTENT: this module computes statistical features (entropies, ratios, Kendall tau, bimodality coefficient). Every `usize as f32` is a count being normalized into a [0,1]-shaped feature; the 23-bit f32 mantissa truncation is acceptable for the downstream bucket-classifier (feature ratios are compared at 2-3 decimal precision). `as u32` on injected class-def indices is bounded by the strings/types pool (u32 by DEX spec). as_conversions joins this bulk allow because the taxonomy is fully described above."
)]

use crate::parser::DexFile;

/// Closed taxonomy of commercial obfuscators whose default-config
/// runtime class-name prefixes the matcher knows about. New vendors
/// are a non-breaking addition (variant added; existing matches keep
/// working). Vendor names appear here only — the bucket classifier
/// downstream demotes them to an `Option<KnownVendor>` hint, never
/// to enum discriminants on its own bucket type.
///
/// **Adversary-resistance caveat:** runtime-prefix matching is
/// trivially defeated by a vendor build flag that randomizes or
/// strips the runtime class names. These hits are evidence of a
/// default-config build, not proof of a vendor's involvement. See
/// the apk-side `compose_bucket` policy for how this evidence weight
/// is calibrated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KnownVendor {
    /// Guardsquare DexGuard. Default runtime classes use the
    /// `com.guardsquare` package prefix on uncustomised builds.
    DexGuard,
    /// Bangcle SecShell. Default runtime classes use the
    /// `com.secneo` package prefix on uncustomised builds.
    Bangcle,
    /// LIAPP application shielding (Lockin Comp.). Default runtime
    /// classes use the `com.lockincomp` package prefix on
    /// uncustomised builds.
    Liapp,
    /// Akamai ApiGuard3 mobile-runtime shielding. Default runtime
    /// classes use the `com.apiguard3` package prefix. Also detectable
    /// via JNI export prefix `Java_com_apiguard3_` and asset path
    /// `assets/com/apiguard3/` on uncustomised builds.
    AkamaiApiGuard3,
    /// Zimperium MAPS (Mobile Application Protection Suite). Default
    /// runtime classes use the `com.zimperium` package prefix and
    /// may contact the `gts.zimperium.com` attestation endpoint on
    /// uncustomised builds.
    ZimperiumMaps,
    /// Promon SHIELD application shielding. Detectable via ELF
    /// import set (`memfd_create`, `mmap`, `mprotect`) plus tiny
    /// export surface and a single-int JNI entry-point pattern on
    /// uncustomised builds. No stable class-name prefix; fingerprint
    /// is native-lib-side only.
    PromonShield,
    /// AppSealing (Inka Entworks) mobile shielding. Default runtime
    /// classes use the `com.iankw` package prefix on uncustomised builds.
    AppSealing,
    /// Chromium crazy_linker dynamic-link shim. Detectable via ELF
    /// `.dynstr` exports `crazy_library_open_in_memory`,
    /// `crazy_library_find_symbol`, and `crazy_context_*` symbols on
    /// uncustomised builds. Not an obfuscator per se, but a reliable
    /// signal that the APK embeds a Chromium-derived linker layer.
    ChromiumCrazyLinker,
}

/// Packed-DEX structural fingerprints readable from `DexHeader`
/// alone. Each flag is a single bit of evidence about whether the
/// header has been mangled in ways consistent with packer / shell
/// processing. None is dispositive on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DexHeaderAnomalies {
    /// `header.link_size != 0`. Standard d8/dx output sets
    /// `link_size = 0` (the `link_data` section is unused). Some
    /// packers populate it with their loader payload.
    pub link_size_nonzero: bool,
    /// Count of section offsets in the header that aren't 4-byte
    /// aligned. Standard outputs are aligned; misalignment usually
    /// means a packer rewrote the layout without normalising.
    pub unaligned_section_offsets: u32,
    /// `header.map_off == 0`. The map_list is required by the spec;
    /// some packers strip it because Android's runtime can load
    /// without it.
    pub map_off_zero: bool,
    /// `header.data_off` not 4-byte aligned. Subset of
    /// `unaligned_section_offsets` exposed for direct inspection
    /// since the data section is the most common rewrite target.
    pub data_off_unaligned: bool,
}

/// Bag of obfuscation signals derived from a parsed [`DexFile`].
///
/// Field semantics describe the *signal*, not what bucket the signal
/// implies. Bucket classification is downstream policy.
#[derive(Debug, Clone, PartialEq)]
pub struct DexObfuscationFeatures {
    /// Number of class definitions in the DEX.
    pub class_count: usize,
    /// Class names matching the R8/ProGuard short-name heuristic:
    /// last `/`-separated segment ≤ 2 chars, all lowercase ASCII,
    /// ≤ 2 path segments. Counts the *type-descriptor* form (e.g.
    /// `Lcom/x/a;` → last segment `a` matches).
    pub obfuscated_class_count: usize,
    /// Kendall tau of obfuscated-class names vs class-index order,
    /// computed over the subset of short names if at least 5 exist;
    /// `None` otherwise. R8 produces sequential alphabetical short
    /// names → tau ≈ 1.0; adversarial obfuscation tends to
    /// scramble → tau ≈ 0.0.
    pub name_order_tau: Option<f32>,
    /// `name_order_tau > 0.7` — a heuristic threshold for "this
    /// looks like R8/ProGuard, not adversarial obfuscation."
    pub likely_r8: bool,
    /// Class names containing any non-ASCII codepoint (excluding
    /// the leading `L` and trailing `;` of the type descriptor).
    /// Commercial obfuscators sometimes use Unicode confusables
    /// for visual evasion; standard d8/R8 output stays ASCII.
    pub non_ascii_class_name_count: usize,
    /// Default-config vendor runtime class-prefix matches, with hit
    /// counts per vendor. Empty on standard d8/R8 builds. See
    /// `KnownVendor`'s adversary-resistance caveat: a renamed
    /// runtime defeats this signal.
    pub runtime_prefix_hits: Vec<(KnownVendor, u32)>,
    /// Average class-name length (full type descriptor minus
    /// leading `L` + trailing `;`). Minified DEX skews short.
    pub avg_class_name_len: f32,
    /// Average length of strings filtered as likely method names by
    /// the same heuristic that `obfuscated_method_count` counts
    /// against. Minified DEX skews short.
    pub avg_method_name_len: f32,
    /// Number of strings filtered as likely method names.
    pub method_name_count: usize,
    /// Method names matching the R8/ProGuard short-name heuristic
    /// (≤ 2 chars, all lowercase ASCII).
    pub obfuscated_method_count: usize,
    /// Strings of length ≥ 64 bytes (raw MUTF-8 byte length, not
    /// codepoint count). Commercial obfuscators that pack strings
    /// into a single jumbo entry skew this count high.
    pub jumbo_string_count: usize,
    /// Fraction of strings with Shannon entropy > 4.5 bits/byte.
    /// Encrypted-string-pool builds skew this high; ASCII text
    /// stays well below 4.5.
    pub high_entropy_string_pct: f32,
    /// Bimodality coefficient of per-string entropy distribution.
    /// `> 0.555` is the textbook bimodality threshold (Sarle's b);
    /// suggests a mix of plaintext + ciphertext strings, the
    /// signature of partial encryption.
    pub string_pool_entropy_bimodality: f32,
    /// Header-level structural anomalies; see [`DexHeaderAnomalies`].
    pub dex_header_anomalies: DexHeaderAnomalies,
    /// Count of non-shadowed class definitions whose type descriptor
    /// begins with the app's declared-package prefix
    /// `"L" + main_package.replace('.', '/') + "/"` — formally
    /// `|{ c : !shadowed(c) ∧ descriptor(c).starts_with(P) }|`, the
    /// number of classes that retained the app namespace (Wermke
    /// main-package isolation). `Some` iff a non-empty main package was
    /// supplied; `None` otherwise (e.g. the byte-level fallback path).
    ///
    /// Invariant `0 <= main_package_class_count <= class_count`, both
    /// bounds realizable. This is a **structural retention count, not
    /// an obfuscation count**: under default-mode R8 an app's
    /// *obfuscated* classes flatten to the root package and leave this
    /// prefix, so a low retained count on a large app is itself the
    /// flattening tell. Per-app obfuscation is not soundly measurable
    /// by prefix (the evidence leaves the namespace); that signal is
    /// deferred.
    pub main_package_class_count: Option<usize>,
}

/// Extract obfuscation features from a parsed `DexFile`. Pure
/// IR consumer; never panics. Prefer [`extract`] unless you have a
/// declared main package to isolate.
///
/// `main_package` is the app's declared reverse-DNS package (the
/// manifest `package` attribute), used to partition class names into
/// the app's own package vs bundled-library packages — Wermke's
/// main-package isolation, which strips the inflation that
/// pre-obfuscated vendor SDKs add to the all-packages ratio. It is
/// plain data (a `&str`), not manifest parsing; DEX owns no manifest
/// knowledge. `None` ⇒ the main-package strata are `None`. The
/// all-packages strata (`class_count` / `obfuscated_class_count`) are
/// computed unconditionally either way.
///
/// `VENDOR_PREFIXES` covers only vendors that have a stable DEX
/// class-name prefix fingerprint. `PromonShield` and
/// `ChromiumCrazyLinker` are native-lib-only and therefore absent
/// from this table — their `KnownVendor` variants are handled on the
/// APK layer instead.
#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: `runtime_hits: [u32; 6]` and `VENDOR_PREFIXES: [_; 6]` are fixed-size sibling arrays. `idx` is in `0..6` from the match on `vendor` (all 6 class-prefix variants are listed explicitly); `i` from `enumerate()` over VENDOR_PREFIXES is in `0..6`. Both within bounds. PromonShield and ChromiumCrazyLinker intentionally absent (no class prefix)."
)]
pub fn extract_with_package(dex: &DexFile, main_package: Option<&str>) -> DexObfuscationFeatures {
    // Shadow-filter the class set: duplicate-class_idx rows would
    // inflate `class_count` (the obfuscation-ratio denominator) and
    // double-count their descriptor in `class_names`, deflating the
    // operator-visible obfuscation classification on adversarial input.
    // First-wins via `class_def_is_shadowed` matches the discipline
    // applied at iteration call sites in classes.rs / api.rs.
    let class_count = dex
        .class_defs
        .iter()
        .enumerate()
        .filter(|(i, _)| !dex.class_def_is_shadowed(*i))
        .count();
    let class_names: Vec<&str> = dex
        .class_defs
        .iter()
        .enumerate()
        .filter(|(i, _)| !dex.class_def_is_shadowed(*i))
        .filter_map(|(_, cd)| dex.type_descriptors.get(cd.class_idx.0 as usize).map(|s| s.as_str()))
        .collect();

    let mut obfuscated_class_count = 0usize;
    let mut total_class_len: usize = 0;
    let mut non_ascii_class_name_count = 0usize;
    let mut short_names_with_index: Vec<(usize, String)> = Vec::new();
    let mut runtime_hits: [u32; 6] = [0; 6];
    // Only vendors with stable DEX class-name prefixes. Index in this
    // array must match the arm in the `match vendor` block below.
    const VENDOR_PREFIXES: [(KnownVendor, &str); 6] = [
        (KnownVendor::DexGuard, "Lcom/guardsquare"),
        (KnownVendor::Bangcle, "Lcom/secneo"),
        (KnownVendor::Liapp, "Lcom/lockincomp"),
        (KnownVendor::AkamaiApiGuard3, "Lcom/apiguard3"),
        (KnownVendor::ZimperiumMaps, "Lcom/zimperium"),
        (KnownVendor::AppSealing, "Lcom/iankw"),
    ];

    // Main-package isolation (Wermke). The manifest `package` is
    // reverse-DNS (`com.x.y`); DEX descriptors are `Lcom/x/y/Foo;`, so
    // the main-package prefix is `L<pkg-with-slashes>/`. The trailing
    // `/` prevents `com.x.y` from matching a sibling `com.x.yextra`.
    // Caveat: a built APK's manifest `package` == the final
    // applicationId, which can differ from the code namespace when a
    // distinct gradle applicationId is set; main-package matching then
    // under-counts. The all-packages stratum is the unconditional
    // baseline regardless. Empty/whitespace package ⇒ no stratum.
    let main_pkg_prefix: Option<String> = main_package
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| format!("L{}/", p.replace('.', "/")));
    let mut main_package_class_count_acc: usize = 0;

    for (i, name) in class_names.iter().enumerate() {
        let clean = name.trim_start_matches('L').trim_end_matches(';');
        total_class_len = total_class_len.saturating_add(clean.len());
        if clean.bytes().any(|b| b >= 0x80) {
            non_ascii_class_name_count = non_ascii_class_name_count.saturating_add(1);
        }
        for (vendor, prefix) in &VENDOR_PREFIXES {
            if name.starts_with(prefix) {
                let idx = match vendor {
                    KnownVendor::DexGuard => 0,
                    KnownVendor::Bangcle => 1,
                    KnownVendor::Liapp => 2,
                    KnownVendor::AkamaiApiGuard3 => 3,
                    KnownVendor::ZimperiumMaps => 4,
                    KnownVendor::AppSealing => 5,
                    // PromonShield + ChromiumCrazyLinker: no class prefix;
                    // intentionally absent from VENDOR_PREFIXES — unreachable.
                    _ => continue,
                };
                runtime_hits[idx] = runtime_hits[idx].saturating_add(1);
            }
        }
        let segments: Vec<&str> = clean.split('/').collect();
        let last = segments.last().copied().unwrap_or("");
        let is_short_name = last.len() <= 2
            && !last.is_empty()
            && last.chars().all(|c| c.is_ascii_lowercase())
            && segments.len() <= 2;
        if is_short_name {
            obfuscated_class_count = obfuscated_class_count.saturating_add(1);
            short_names_with_index.push((i, clean.to_string()));
        }
        // Main-package stratum: structural count of classes that
        // retained the declared-package namespace. NOT an obfuscation
        // count — under default R8 the obfuscated app classes flatten
        // to root and leave this prefix (see field doc).
        if let Some(prefix) = main_pkg_prefix.as_deref() {
            if name.starts_with(prefix) {
                main_package_class_count_acc =
                    main_package_class_count_acc.saturating_add(1);
            }
        }
    }

    let runtime_prefix_hits: Vec<(KnownVendor, u32)> = VENDOR_PREFIXES
        .iter()
        .enumerate()
        .filter_map(|(i, (v, _))| if runtime_hits[i] > 0 { Some((*v, runtime_hits[i])) } else { None })
        .collect();

    // Kendall tau on the short-name subset.
    let (name_order_tau, likely_r8) = compute_kendall_tau(&short_names_with_index);

    // Method-name analysis: walk method_ids.name_idx to get method names,
    // then filter by the same R8 heuristic.
    let mut method_name_count = 0usize;
    let mut total_method_len: usize = 0;
    let mut obfuscated_method_count = 0usize;
    for m in &dex.methods {
        let Some(entry) = dex.strings.get(m.name_idx.0 as usize) else {
            continue;
        };
        // Method names are ASCII identifiers per DEX spec; the lossy
        // view is fine here (a `MalformedMutf8` method-name is itself
        // a corrupt-DEX signal, and the U+FFFD substitution makes the
        // identifier-shape filter below reject the entry).
        let name = entry.as_str_lossy();
        // Filter to likely identifier-shaped names (matches the apk-side
        // heuristic in `analyze_obfuscation`'s scan_strings_full path).
        if name.is_empty()
            || name.len() > 64
            || name.contains('/')
            || name.contains(';')
            || name.contains('.')
            || name.contains('(')
            || name.starts_with('<')
            || name.starts_with('[')
            || !name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        {
            continue;
        }
        method_name_count = method_name_count.saturating_add(1);
        total_method_len = total_method_len.saturating_add(name.len());
        if name.len() <= 2 && name.chars().all(|c| c.is_ascii_lowercase()) {
            obfuscated_method_count = obfuscated_method_count.saturating_add(1);
        }
    }

    let avg_class_name_len = if class_count > 0 {
        total_class_len as f32 / class_count as f32
    } else {
        0.0
    };
    let avg_method_name_len = if method_name_count > 0 {
        total_method_len as f32 / method_name_count as f32
    } else {
        0.0
    };

    // String-pool analysis: jumbo + entropy distribution from raw bytes.
    let mut jumbo_string_count = 0usize;
    let mut entropies: Vec<f32> = Vec::with_capacity(dex.strings.len());
    for entry in &dex.strings {
        let raw = entry.raw_bytes();
        if raw.len() >= 64 {
            jumbo_string_count = jumbo_string_count.saturating_add(1);
        }
        if !raw.is_empty() {
            entropies.push(shannon_entropy(raw));
        }
    }
    let high_entropy_string_pct = if entropies.is_empty() {
        0.0
    } else {
        let n_high = entropies.iter().filter(|&&e| e > 4.5).count() as f32;
        n_high / entropies.len() as f32
    };
    let string_pool_entropy_bimodality = bimodality_coefficient(&entropies);

    // Header anomalies from DexHeader fields only (deferred subset noted in module doc).
    let h = &dex.header;
    let mut unaligned = 0u32;
    for off in [
        h.string_ids_off,
        h.type_ids_off,
        h.proto_ids_off,
        h.field_ids_off,
        h.method_ids_off,
        h.class_defs_off,
        h.data_off,
    ] {
        if off & 3 != 0 {
            unaligned = unaligned.saturating_add(1);
        }
    }
    let dex_header_anomalies = DexHeaderAnomalies {
        link_size_nonzero: h.link_size != 0,
        unaligned_section_offsets: unaligned,
        map_off_zero: h.map_off == 0,
        data_off_unaligned: h.data_off & 3 != 0,
    };

    DexObfuscationFeatures {
        class_count,
        obfuscated_class_count,
        name_order_tau,
        likely_r8,
        non_ascii_class_name_count,
        runtime_prefix_hits,
        avg_class_name_len,
        avg_method_name_len,
        method_name_count,
        obfuscated_method_count,
        jumbo_string_count,
        high_entropy_string_pct,
        string_pool_entropy_bimodality,
        dex_header_anomalies,
        main_package_class_count: main_pkg_prefix.as_ref().map(|_| main_package_class_count_acc),
    }
}

/// Extract obfuscation features without main-package isolation —
/// equivalent to [`extract_with_package`] with `main_package = None`
/// (the main-package strata on the result are `None`).
pub fn extract(dex: &DexFile) -> DexObfuscationFeatures {
    extract_with_package(dex, None)
}

/// Compute Kendall tau on the short-name set; mirrors the existing
/// `apk-side` `analyze_obfuscation` calculation.
#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: `i in 0..n`, `j in (i+1)..n` with `n = short_names.len()` — both indices strictly < n."
)]
fn compute_kendall_tau(short_names: &[(usize, String)]) -> (Option<f32>, bool) {
    if short_names.len() < 5 {
        return (None, false);
    }
    let mut concordant: i64 = 0;
    let mut discordant: i64 = 0;
    let n = short_names.len();
    for i in 0..n {
        let j_start = i.saturating_add(1);
        for j in j_start..n {
            let idx_order = short_names[i].0.cmp(&short_names[j].0);
            let name_order = short_names[i].1.cmp(&short_names[j].1);
            if idx_order == name_order {
                concordant = concordant.saturating_add(1);
            } else {
                discordant = discordant.saturating_add(1);
            }
        }
    }
    let total = concordant.saturating_add(discordant);
    if total == 0 {
        (None, false)
    } else {
        let tau = (concordant.saturating_sub(discordant)) as f32 / total as f32;
        (Some(tau), tau > 0.7)
    }
}

/// Shannon entropy in bits/byte. Used for both `high_entropy_string_pct`
/// and `string_pool_entropy_bimodality`.
#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: `counts: [u32; 256]` — `b: u8` so `b as usize` is in `0..=255`, always within bounds."
)]
fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] = counts[b as usize].saturating_add(1);
    }
    let len = bytes.len() as f32;
    let mut h = 0f32;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f32 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Sarle's bimodality coefficient: `b = (g² + 1) / (k + 3(n-1)²/((n-2)(n-3)))`
/// where `g` is sample skewness and `k` is sample excess kurtosis.
/// `b > 0.555` is the textbook threshold for bimodality. Returns 0.0
/// for samples too small (n < 4) where the coefficient is undefined.
fn bimodality_coefficient(xs: &[f32]) -> f32 {
    let n = xs.len();
    if n < 4 {
        return 0.0;
    }
    let mean: f32 = xs.iter().sum::<f32>() / n as f32;
    let mut m2 = 0f32;
    let mut m3 = 0f32;
    let mut m4 = 0f32;
    for &x in xs {
        let d = x - mean;
        let d2 = d * d;
        m2 += d2;
        m3 += d2 * d;
        m4 += d2 * d2;
    }
    let nf = n as f32;
    m2 /= nf;
    m3 /= nf;
    m4 /= nf;
    if m2 <= 0.0 {
        return 0.0;
    }
    let g = m3 / m2.powf(1.5);
    let k = m4 / (m2 * m2) - 3.0;
    let denom = k + 3.0 * (nf - 1.0).powi(2) / ((nf - 2.0) * (nf - 3.0));
    if denom == 0.0 {
        return 0.0;
    }
    (g * g + 1.0) / denom
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::DexFile;
    use proptest::prelude::*;

    /// Parse the fixture DEX bundled with droidsaw-dex tests so we
    /// exercise `extract` against a real (if minimal) DEX without
    /// hand-fabricating a `DexFile`.
    fn fixture_dex() -> DexFile {
        let bytes = include_bytes!("../tests/fixtures/classes.dex");
        DexFile::parse(bytes, None).expect("fixture parses")
    }

    #[test]
    fn extract_returns_class_count_matching_class_defs_len() {
        let dex = fixture_dex();
        let f = extract(&dex);
        assert_eq!(f.class_count, dex.class_defs.len());
    }

    #[test]
    fn obfuscation_class_count_excludes_shadowed_rows() {
        // Panel finding (Lens 4 FIX): duplicate-class_idx rows on
        // attacker DEX inflate `class_count` (obfuscation-ratio
        // denominator), deflating the operator-visible obfuscation
        // classification. Shadow-filter must skip duplicates.
        let mut dex = fixture_dex();
        let row_count_before = dex.class_defs.len();
        // Plant a duplicate-class_idx row by cloning class_defs[0].
        // class_def_index already points to row 0 for this class_idx;
        // the new row at the end is therefore shadowed by row 0.
        let dup_row = dex.class_defs[0].clone();
        dex.class_defs.push(dup_row);
        let row_count_after = dex.class_defs.len();
        assert_eq!(row_count_after, row_count_before + 1, "test setup planted one duplicate row");

        let f = extract(&dex);
        // The shadowed row must NOT inflate class_count.
        assert_eq!(
            f.class_count, row_count_before,
            "class_count must filter shadowed duplicates; got {} expected {} (raw class_defs.len()={})",
            f.class_count, row_count_before, row_count_after
        );
    }

    #[test]
    fn extract_does_not_panic_on_fixture_dex() {
        let dex = fixture_dex();
        let _f = extract(&dex);
    }

    #[test]
    fn extracts_runtime_prefix_hit_for_synthetic_dexguard_class_prefix() {
        // Build a minimal DexFile-shape-equivalent assertion: this test
        // proves that *if* a class descriptor matches the DexGuard
        // runtime prefix, the matcher records it. It does NOT prove
        // that "this DEX is DexGuard" — vendor attribution is downstream.
        let mut dex = fixture_dex();
        // Inject a synthetic descriptor + class_def referring to it.
        // We mutate the parsed IR directly, not the bytes — that's the
        // pure-IR contract.
        let injected_idx = dex.type_descriptors.len();
        dex.type_descriptors.push("Lcom/guardsquare/runtime/RuntimeStub;".to_string());
        let mut new_class_def = dex.class_defs[0].clone();
        new_class_def.class_idx = crate::ids::TypeIdx(injected_idx as u32);
        dex.class_defs.push(new_class_def);

        let f = extract(&dex);
        assert!(
            f.runtime_prefix_hits
                .iter()
                .any(|(v, n)| matches!(v, KnownVendor::DexGuard) && *n >= 1),
            "expected DexGuard runtime-prefix hit, got {:?}",
            f.runtime_prefix_hits
        );
    }

    #[test]
    fn extracts_non_ascii_class_name_count_from_synthetic_descriptor() {
        let mut dex = fixture_dex();
        let injected_idx = dex.type_descriptors.len();
        dex.type_descriptors.push("Lcom/example/Ñame;".to_string());
        let mut new_class_def = dex.class_defs[0].clone();
        new_class_def.class_idx = crate::ids::TypeIdx(injected_idx as u32);
        dex.class_defs.push(new_class_def);

        let f = extract(&dex);
        assert!(
            f.non_ascii_class_name_count >= 1,
            "expected non-ASCII class name to be counted, got {}",
            f.non_ascii_class_name_count
        );
    }

    fn push_raw_dex_string(dex: &mut DexFile, payload: Vec<u8>) {
        // Most synthetic payloads (`0xC0 0x80` runs, 0..255 sweeps) are
        // not well-formed Rust UTF-8 — store as `MalformedMutf8` with
        // a pre-computed lossy_str so the entropy / jumbo scans see
        // the bytes verbatim via `raw_bytes()`. For ASCII payloads the
        // shape matches the on-corpus pattern that DEX'd-cleanly
        // strings take.
        let decoded = std::str::from_utf8(&payload).map(str::to_string);
        let entry = match decoded {
            Ok(s) => crate::DexString::Decoded {
                raw_bytes: payload,
                s,
                declared_chars: 0,
                had_terminator: true,
            },
            Err(_) => crate::DexString::new_malformed_mutf8(
                payload,
                droidsaw_common::encoding::EncodingError::InvalidSequence { offset: 0 },
                0,
                true,
            ),
        };
        dex.strings.push(entry);
    }

    #[test]
    fn extracts_jumbo_string_count_from_synthetic_long_string() {
        let mut dex = fixture_dex();
        // Push a 100-byte string. `extract` walks `dex.strings[i].raw_bytes()`
        // for jumbo detection.
        push_raw_dex_string(&mut dex, vec![b'x'; 100]);

        let f = extract(&dex);
        assert!(
            f.jumbo_string_count >= 1,
            "expected ≥1 jumbo string (≥64 bytes), got {}",
            f.jumbo_string_count
        );
    }

    #[test]
    fn extracts_high_entropy_string_pct_from_high_entropy_payload() {
        let mut dex = fixture_dex();
        // Push 10 high-entropy strings (byte sequences with entropy
        // well above 4.5 bits/byte).
        for k in 0..10u8 {
            let payload: Vec<u8> = (0u8..=255).map(|b| b.wrapping_add(k)).collect();
            push_raw_dex_string(&mut dex, payload);
        }

        let f = extract(&dex);
        assert!(
            f.high_entropy_string_pct > 0.0,
            "expected high_entropy_string_pct > 0 with 10 high-entropy strings, got {}",
            f.high_entropy_string_pct
        );
    }

    #[test]
    fn extracts_link_size_nonzero_anomaly_when_header_link_size_set() {
        let mut dex = fixture_dex();
        dex.header.link_size = 0x1000;
        let f = extract(&dex);
        assert!(f.dex_header_anomalies.link_size_nonzero);
    }

    #[test]
    fn extracts_map_off_zero_anomaly_when_header_map_off_zeroed() {
        let mut dex = fixture_dex();
        dex.header.map_off = 0;
        let f = extract(&dex);
        assert!(f.dex_header_anomalies.map_off_zero);
    }

    #[test]
    fn extracts_unaligned_section_offsets_when_header_offsets_misaligned() {
        let mut dex = fixture_dex();
        dex.header.string_ids_off = 113; // odd alignment
        dex.header.data_off = 115;
        let f = extract(&dex);
        assert!(f.dex_header_anomalies.unaligned_section_offsets >= 2);
        assert!(f.dex_header_anomalies.data_off_unaligned);
    }

    #[test]
    fn shannon_entropy_zero_for_constant_buffer() {
        assert_eq!(shannon_entropy(&[0xAA; 64]), 0.0);
    }

    #[test]
    fn shannon_entropy_high_for_uniform_random_buffer() {
        let payload: Vec<u8> = (0u8..=255).collect();
        let h = shannon_entropy(&payload);
        assert!(h > 7.9, "expected ≈8 bits/byte for uniform 256-byte payload, got {h}");
    }

    #[test]
    fn shannon_entropy_zero_for_empty_buffer() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn bimodality_coefficient_zero_for_too_small_sample() {
        assert_eq!(bimodality_coefficient(&[1.0, 2.0, 3.0]), 0.0);
    }

    #[test]
    fn bimodality_coefficient_high_for_synthetic_two_cluster_distribution() {
        // Two tight clusters: 10 around 1.0, 10 around 5.0. Should
        // exceed Sarle's b > 0.555 threshold.
        let mut xs = vec![1.0_f32; 10];
        xs.extend(std::iter::repeat_n(5.0_f32, 10));
        let b = bimodality_coefficient(&xs);
        assert!(b > 0.555, "expected b > 0.555 for bimodal sample, got {b}");
    }

    #[test]
    fn compute_kendall_tau_returns_none_for_under_5_short_names() {
        let names: Vec<(usize, String)> = (0..4).map(|i| (i, format!("n{i}"))).collect();
        let (tau, likely_r8) = compute_kendall_tau(&names);
        assert!(tau.is_none());
        assert!(!likely_r8);
    }

    #[test]
    fn compute_kendall_tau_likely_r8_true_for_alphabetical_index_order() {
        // R8 produces (idx, name) pairs in alphabetical order: tau = 1.0.
        let names: Vec<(usize, String)> = vec![
            (0, "a".to_string()),
            (1, "b".to_string()),
            (2, "c".to_string()),
            (3, "d".to_string()),
            (4, "e".to_string()),
        ];
        let (tau, likely_r8) = compute_kendall_tau(&names);
        assert_eq!(tau, Some(1.0));
        assert!(likely_r8);
    }

    // ── New vendor prefix-hit tests ────────────────────────────────────────

    /// Helper: inject a single synthetic class descriptor and return
    /// the extracted features. Reused by all new-vendor prefix tests.
    fn extract_with_injected_descriptor(descriptor: &str) -> DexObfuscationFeatures {
        let mut dex = fixture_dex();
        let injected_idx = dex.type_descriptors.len();
        dex.type_descriptors.push(descriptor.to_string());
        let mut new_class_def = dex.class_defs[0].clone();
        new_class_def.class_idx = crate::ids::TypeIdx(injected_idx as u32);
        dex.class_defs.push(new_class_def);
        extract(&dex)
    }

    #[test]
    fn extracts_runtime_prefix_hit_for_akamai_apiguard3_class_prefix() {
        let f = extract_with_injected_descriptor("Lcom/apiguard3/runtime/Shield;");
        assert!(
            f.runtime_prefix_hits
                .iter()
                .any(|(v, n)| matches!(v, KnownVendor::AkamaiApiGuard3) && *n >= 1),
            "expected AkamaiApiGuard3 hit, got {:?}",
            f.runtime_prefix_hits
        );
    }

    #[test]
    fn extracts_runtime_prefix_hit_for_zimperium_maps_class_prefix() {
        let f = extract_with_injected_descriptor("Lcom/zimperium/zdefend/ZDefend;");
        assert!(
            f.runtime_prefix_hits
                .iter()
                .any(|(v, n)| matches!(v, KnownVendor::ZimperiumMaps) && *n >= 1),
            "expected ZimperiumMaps hit, got {:?}",
            f.runtime_prefix_hits
        );
    }

    #[test]
    fn extracts_runtime_prefix_hit_for_appsealing_class_prefix() {
        let f = extract_with_injected_descriptor("Lcom/iankw/appsealing/ASApp;");
        assert!(
            f.runtime_prefix_hits
                .iter()
                .any(|(v, n)| matches!(v, KnownVendor::AppSealing) && *n >= 1),
            "expected AppSealing hit, got {:?}",
            f.runtime_prefix_hits
        );
    }

    // ── FP-gate tests: new prefixes must NOT match unrelated classes ───────

    #[test]
    fn fp_gate_akamai_apiguard3_does_not_match_generic_com_api_prefix() {
        // "com.api" is common; "com.apiguard3" is the specific prefix.
        // A class like "Lcom/api/client/Client;" must NOT fire AkamaiApiGuard3.
        let f = extract_with_injected_descriptor("Lcom/api/client/Client;");
        assert!(
            !f.runtime_prefix_hits
                .iter()
                .any(|(v, _)| matches!(v, KnownVendor::AkamaiApiGuard3)),
            "FP: com/api/client should not match AkamaiApiGuard3 (need com/apiguard3), got {:?}",
            f.runtime_prefix_hits
        );
    }

    #[test]
    fn fp_gate_zimperium_maps_does_not_match_generic_com_zimmer_prefix() {
        // "com.zimmer.*" (e.g. a hypothetical UI lib) must not fire ZimperiumMaps.
        let f = extract_with_injected_descriptor("Lcom/zimmer/ui/Widget;");
        assert!(
            !f.runtime_prefix_hits
                .iter()
                .any(|(v, _)| matches!(v, KnownVendor::ZimperiumMaps)),
            "FP: com/zimmer/ui should not match ZimperiumMaps (need com/zimperium), got {:?}",
            f.runtime_prefix_hits
        );
    }

    #[test]
    fn fp_gate_appsealing_does_not_match_generic_com_ian_prefix() {
        // "com.ian.*" must not fire AppSealing.
        let f = extract_with_injected_descriptor("Lcom/ian/auth/Manager;");
        assert!(
            !f.runtime_prefix_hits
                .iter()
                .any(|(v, _)| matches!(v, KnownVendor::AppSealing)),
            "FP: com/ian/auth should not match AppSealing (need com/iankw), got {:?}",
            f.runtime_prefix_hits
        );
    }

    #[test]
    fn fp_gate_appsealing_does_not_match_com_ink_prefix() {
        // Another near-miss: "com.inkwell.*" must not fire AppSealing.
        let f = extract_with_injected_descriptor("Lcom/inkwell/plugin/Core;");
        assert!(
            !f.runtime_prefix_hits
                .iter()
                .any(|(v, _)| matches!(v, KnownVendor::AppSealing)),
            "FP: com/inkwell/plugin should not match AppSealing, got {:?}",
            f.runtime_prefix_hits
        );
    }

    // ── main-package isolation (structural retention count) ───────────

    /// Build a `DexFile` whose `class_defs` are exactly the given
    /// descriptors (each a distinct, non-shadowed class), reusing the
    /// fixture for all other DEX structure. Lets the strata tests
    /// control the descriptor set precisely.
    fn dex_with_class_descriptors(descriptors: &[&str]) -> DexFile {
        let mut dex = fixture_dex();
        let template = dex.class_defs[0].clone();
        dex.class_defs.clear();
        for d in descriptors {
            let idx = dex.type_descriptors.len();
            dex.type_descriptors.push((*d).to_string());
            let mut cd = template.clone();
            cd.class_idx = crate::ids::TypeIdx(idx as u32);
            dex.class_defs.push(cd);
        }
        dex
    }

    #[test]
    fn main_package_count_is_none_without_a_package() {
        // Option contract: `None` ⇒ no stratum, and empty / whitespace
        // package is treated as "no package supplied".
        let dex = fixture_dex();
        assert_eq!(extract(&dex).main_package_class_count, None);
        assert_eq!(extract_with_package(&dex, None).main_package_class_count, None);
        assert_eq!(extract_with_package(&dex, Some("")).main_package_class_count, None);
        assert_eq!(extract_with_package(&dex, Some("   ")).main_package_class_count, None);
    }

    #[test]
    fn main_package_count_is_some_with_a_nonempty_package() {
        let dex = fixture_dex();
        assert!(extract_with_package(&dex, Some("com.example.app"))
            .main_package_class_count
            .is_some());
    }

    #[test]
    fn main_package_count_reaches_class_count_when_all_under_prefix() {
        // Upper bound realized: every class retained the namespace (incl.
        // a sub-package, which is still the app's own code).
        let dex = dex_with_class_descriptors(&[
            "Lcom/test/app/Alpha;",
            "Lcom/test/app/Beta;",
            "Lcom/test/app/sub/Gamma;",
        ]);
        let f = extract_with_package(&dex, Some("com.test.app"));
        assert_eq!(f.class_count, 3);
        assert_eq!(f.main_package_class_count, Some(3));
    }

    #[test]
    fn main_package_count_is_zero_when_none_under_prefix() {
        // Lower bound realized: the count is 0 when no class is under
        // the prefix (guards against a silently-constant implementation).
        let dex = dex_with_class_descriptors(&["Lother/lib/A;", "Lthird/party/B;"]);
        let f = extract_with_package(&dex, Some("com.test.app"));
        assert_eq!(f.class_count, 2);
        assert_eq!(f.main_package_class_count, Some(0));
    }

    #[test]
    fn main_package_prefix_does_not_match_sibling_package() {
        // Trailing-`/` guard: app "com.x.y" must not absorb "com.x.yextra".
        let dex = dex_with_class_descriptors(&["Lcom/x/y/Real;", "Lcom/x/yextra/Sibling;"]);
        let f = extract_with_package(&dex, Some("com.x.y"));
        assert_eq!(f.main_package_class_count, Some(1));
    }

    proptest! {
        /// Oracle + bound: the stratum count equals the number of class
        /// descriptors under the app prefix, and never exceeds
        /// `class_count`. Mixed generation exercises both bounds.
        #[test]
        fn main_package_count_equals_prefix_match_count(
            under in proptest::collection::vec(any::<bool>(), 0..16usize),
        ) {
            let descriptors: Vec<String> = under
                .iter()
                .enumerate()
                .map(|(i, &u)| {
                    if u {
                        format!("Lcom/test/app/C{i};")
                    } else {
                        format!("Lother/lib/C{i};")
                    }
                })
                .collect();
            let refs: Vec<&str> = descriptors.iter().map(String::as_str).collect();
            let dex = dex_with_class_descriptors(&refs);
            let f = extract_with_package(&dex, Some("com.test.app"));
            let expected = under.iter().filter(|&&u| u).count();
            prop_assert_eq!(f.main_package_class_count, Some(expected));
            prop_assert_eq!(f.class_count, descriptors.len());
            prop_assert!(f.main_package_class_count.unwrap_or(usize::MAX) <= f.class_count);
        }
    }
}
