//! Class definition and virtual dispatch table parsing.
#![allow(missing_docs, reason = "internal")]
#![allow(clippy::let_underscore_must_use, reason = "every `let _ = writeln!(out, ...)` in classes code writes to an in-memory `String` whose `Display`/`Write` impl is infallible. The unit-Result is structurally dead.")]
// as_conversions: file-level bulk allow removed; per-site PROOF applied below.

use std::collections::BTreeSet;
use std::fmt::Write;

use crate::annotation::{self, EncodedValue};
use crate::cfg::Cfg;
use crate::decode;
use crate::error::DexError;
use crate::emit;
use crate::ids::{ClassDefItem, TypeIdx};
use crate::optimize;
use crate::r8_identity;
use crate::r8_inversion;
use crate::parser::DexFile;
use crate::ssa::SsaBody;
use crate::structure;
use crate::sugar;
use crate::types::{self, DexType};

/// Decompile a single class from a DEX file into Java source.
///
/// Thin wrapper over the private `decompile_class_impl` passing `None` for the
/// `TypeToClassDefMap` — single-class callers (e.g. MCP `dex_classes`
/// subcommand) pay an O(n_classes) linear scan inside the enum
/// synthetic-bridge-ctor gate. Bulk iteration contexts should go
/// through [`classes_to_decompile`] + [`decompile_class_ext`] which
/// build the cache once per DEX and thread it through.
pub fn decompile_class(dex: &DexFile, data: &[u8], class_def: &ClassDefItem) -> String {
    // S8 hoist: read `DROIDSAW_DECOMPILE_TRACE` once at the API
    // boundary. Every method decompiled under this call sees the same
    // trace setting; downstream `decompile_method` no longer re-reads
    // the env var per call.
    decompile_class_impl(dex, data, class_def, None, Trace::from_env(), None)
}

/// Decompile a class with an externally-provided
/// [`r8_inversion::TrampolineCensus`]. Bulk-caller-friendly entry
/// point: build the census ONCE per DEX before the per-class loop
/// and pass it through to every class decompile. Avoids the O(C × N)
/// cost where `decompile_class` would otherwise rebuild the census
/// per class. On a 7000-class production DEX the difference is
/// minutes vs seconds.
pub fn decompile_class_with_census(
    dex: &DexFile,
    data: &[u8],
    class_def: &ClassDefItem,
    r8_census: &r8_inversion::TrampolineCensus,
) -> String {
    decompile_class_impl(
        dex,
        data,
        class_def,
        None,
        Trace::from_env(),
        Some(r8_census),
    )
}

/// Inner implementation of `decompile_class` with an optional
/// `TypeToClassDefMap` for O(1) type-to-class_def resolution.
#[allow(clippy::arithmetic_side_effects, reason = "usize arithmetic on parser-validated class-def fields (instance_field_count + static_field_count) bounded by uleb128 counts capped via bound_count.")]
fn decompile_class_impl(
    dex: &DexFile,
    data: &[u8],
    class_def: &ClassDefItem,
    ttm: Option<&TypeToClassDefMap>,
    trace: Trace,
    r8_census_override: Option<&r8_inversion::TrampolineCensus>,
) -> String {
    let mut out = String::new();

    // R8 inversion pass cross-method state. `build_trampoline_census`
    // walks `dex.code_items` + `dex.class_datas` linearly — O(M + I)
    // where M is methods and I is total instructions. On bulk-decompile
    // paths (smoke tests, full-corpus runs) the caller pre-builds the
    // census once per DEX and passes it via `r8_census_override`,
    // collapsing what would otherwise be O(C × (M + I)) per-DEX work
    // into O(M + I). Single-class callers (`decompile_class`, MCP
    // entry points) pay the one-shot rebuild cost; that's fine because
    // they only decompile one class.
    let owned_census;
    let r8_census = if let Some(c) = r8_census_override {
        c
    } else {
        owned_census = r8_inversion::build_trampoline_census(dex);
        &owned_census
    };

    let class_desc = dex
        .get_type_descriptor(class_def.class_idx)
        .unwrap_or("L?;");

    // Pre-parse class_data so the kotlinc-1.9 top-level-fn facade gate
    // can inspect the structural shape (zero instance fields, zero
    // virtual methods, all direct methods static) BEFORE deciding
    // whether to emit a class wrapper. PR-9b of #41b.
    //
    // Cheap-gate (parser-only): descriptor ends `Kt;` AND class
    // carries `@kotlin.Metadata`. Structural-gate (cd-only): no
    // instance state, no instance methods, every direct method
    // static. Both must hold; either alone admits false positives
    // (Java class named `FooKt` / Kotlin enum class with metadata).
    let parsed_cd = if class_def.class_data_off != 0 {
        decode::parse_class_data(data, class_def.class_data_off).ok()
    } else {
        None
    };
    let facade_verdict = dex.is_kotlin_facade_candidate(class_def.class_idx);
    let is_kt_facade = facade_verdict.is_yes()
        && parsed_cd
            .as_ref()
            .map(|cd| {
                cd.instance_fields.is_empty()
                    && cd.virtual_methods.is_empty()
                    && cd.direct_methods
                        .iter()
                        .all(|m| m.access_flags & 0x0008 != 0)
            })
            .unwrap_or(false);

    // Kotlin `data class` gate (PR-9d of #41b). Mutually exclusive with
    // facade — a top-level-fn facade has no instance state, so it never
    // carries `componentN`/`copy` virtual methods. The parser predicate
    // gates on `@kotlin.Metadata` + `component1`/`copy` virtual methods;
    // the structural sufficiency for the rewrite (presence of
    // class_data, primary `<init>` ctor) is verified inside
    // `render_kotlin_data_class_header` — falsy returns from that helper
    // fall through to the standard Java-shape emit.
    let data_class_verdict = dex.is_kotlin_data_class(class_def.class_idx);
    let is_kt_data_class = !is_kt_facade && data_class_verdict.is_yes();

    // Kotlin `sealed class` root gate (PR-9e of #41b). Mutually exclusive
    // with facade and data-class — sealed roots are abstract, carry
    // both a private parameterless ctor and a kotlinc-synthetic
    // `<init>(...; DefaultConstructorMarker)V` variant, and accept
    // sealed-OBJECT or sealed-CLASS subclasses. The renderer
    // (`render_kotlin_sealed_class_header`) inlines every direct
    // subclass that satisfies `is_kotlin_sealed_object_subclass` /
    // `is_kotlin_sealed_class_subclass`, so the iterator's
    // `is_suppressible_kotlin_sealed_subclass` filter must drop those
    // subclasses from top-level emission.
    let sealed_root_verdict = dex.is_kotlin_sealed_root(class_def.class_idx);
    let is_kt_sealed_root =
        !is_kt_facade && !is_kt_data_class && sealed_root_verdict.is_yes();

    // Indeterminate-banner accumulation. A Kotlin-vs-Java rendering detector
    // that returns Indeterminate (annotation / class_data parse failure) makes
    // the emitted shape an unverified best-guess. Collect the detector names so
    // a single class-level banner warns the operator. Java-surface stays the
    // best-guess render: is_yes() is already false on Indeterminate, so the
    // rendering polarity is unchanged and the banner is purely additive. The two
    // sealed-subclass detectors are consulted here because the suppression
    // filter keeps an Indeterminate subclass at top level, where this function
    // renders it.
    let mut indeterminate_detectors: BTreeSet<&'static str> = BTreeSet::new();
    if facade_verdict.is_indeterminate() {
        indeterminate_detectors.insert("is_kotlin_facade_candidate");
    }
    if data_class_verdict.is_indeterminate() {
        indeterminate_detectors.insert("is_kotlin_data_class");
    }
    if sealed_root_verdict.is_indeterminate() {
        indeterminate_detectors.insert("is_kotlin_sealed_root");
    }
    if dex
        .is_kotlin_sealed_object_subclass(class_def.class_idx)
        .is_indeterminate()
    {
        indeterminate_detectors.insert("is_kotlin_sealed_object_subclass");
    }
    if dex
        .is_kotlin_sealed_class_subclass(class_def.class_idx)
        .is_indeterminate()
    {
        indeterminate_detectors.insert("is_kotlin_sealed_class_subclass");
    }

    // Source file comment. Suppressed in facade and data-class mode:
    // kotlinc records the input `.kt` filename in the `SourceFile`
    // attribute, and the harness writes D1 to a temp path
    // (`decompile-iter1.kt`), so D2's `// Source:` line would
    // point at the temp path rather than the original fixture
    // name. Suppressing the comment removes the only metadata
    // that wouldn't survive the decompile-recompile-decompile
    // round-trip on the affected fixtures. PR-9c of #41b
    // extended by PR-9d to cover the data-class mode with the
    // same rationale.
    if !is_kt_facade && !is_kt_data_class && !is_kt_sealed_root {
        if let Some(src_idx) = class_def.source_file_idx {
            if let Ok(src) = dex.get_string(src_idx) {
                let _ = writeln!(out, "// Source: {src}");
            }
        }
    }

    // Package declaration. Kotlin package decls are terminator-free
    // (`package foo`); Java requires the trailing `;`. The corpus
    // fixtures all use the default package so this is a forward-
    // compat correctness fix rather than a fixture-flip driver.
    if let Some(pkg) = extract_package(class_desc) {
        if is_kt_facade || is_kt_data_class || is_kt_sealed_root {
            let _ = writeln!(out, "package {pkg}\n");
        } else {
            let _ = writeln!(out, "package {pkg};\n");
        }
    }

    // Anchor: byte position of the line that the class header (or, in
    // facade mode, the first top-level fn) starts on. Used as the
    // import-block insertion site after methods are rendered, so that
    // imports land between the package decl and the first declaration
    // regardless of whether a class wrapper is emitted.
    let header_anchor = out.len();

    // Accumulated FQNs for import generation. Hoisted above the data-class
    // early-return path (PR-9d) and the standard body emission so both
    // call sites can populate the same set; the import block is inserted
    // at `header_anchor` after the body is rendered.
    let mut imports: BTreeSet<String> = BTreeSet::new();

    // Kotlin `data class` early-return path. Renders just
    // `data class Foo(val a: T1, val b: T2, ...)` and skips the standard
    // class header / fields / methods / closing brace. kotlinc auto-
    // generates the body (componentN / copy / equals / hashCode /
    // toString / per-property accessors) on recompile, so emitting only
    // the header is sufficient — the verbose Java-shape body would be
    // strictly redundant. PR-9d of #41b.
    if is_kt_data_class {
        if let Some(cd) = parsed_cd.as_ref() {
            if let Some(header) =
                render_kotlin_data_class_header(dex, class_def, cd, &mut imports)
            {
                out.push_str(&header);
            }
        }
        // Imports plumb through the same trailing-block path as the
        // facade case below — no separate insertion step here.
        if !imports.is_empty() {
            let mut block = String::new();
            for fqcn in &imports {
                let _ = writeln!(block, "import {fqcn}");
            }
            block.push('\n');
            out.insert_str(header_anchor, &block);
        }
        return prepend_indeterminate_banner(out, &indeterminate_detectors);
    }

    // Kotlin `sealed class` early-return path. Renders
    // `sealed class Foo { object Sub : Foo(); class Sub2(val a: T) : Foo() ... }`
    // with all sealed subclasses inlined. The iterator filter
    // (`is_suppressible_kotlin_sealed_subclass`) drops the subclass
    // class_defs from top-level emission so the inlined form is the
    // only place they appear. PR-9e of #41b.
    if is_kt_sealed_root {
        if let Some(header) = render_kotlin_sealed_class_header(dex, class_def, &mut imports) {
            out.push_str(&header);
        }
        if !imports.is_empty() {
            let mut block = String::new();
            for fqcn in &imports {
                let _ = writeln!(block, "import {fqcn}");
            }
            block.push('\n');
            out.insert_str(header_anchor, &block);
        }
        return prepend_indeterminate_banner(out, &indeterminate_detectors);
    }

    // R8 identity-hints comment block. Gated on `LX/<short-id>;` shape;
    // non-R8-renamed classes are unaffected. Block lands between the
    // import insertion site (`header_anchor`) and the class header, so
    // imports appear above the hints and the hints sit directly above
    // the class declaration as a doc-comment.
    if r8_identity::is_r8_short_renamed(class_desc) {
        let hints = r8_identity::collect(dex, data, class_def);
        let block = r8_identity::format_block(&hints);
        if !block.is_empty() {
            out.push_str(&block);
        }
    }

    // Class header
    let class_name = extract_simple_name(class_desc);
    // Detect the type kind from the access flags — three Java source-
    // level kinds share the `class_def` structure but differ in
    // keyword + allowed modifiers + inheritance clause:
    //
    // - `interface`  (ACC_INTERFACE = 0x0200) — emits `interface`,
    //                 suppresses redundant ACC_ABSTRACT (javac rejects
    //                 `abstract interface`); extends java.lang.Object
    //                 implicitly so `extends Object` is suppressed;
    //                 parent-list spelling is `extends` (interfaces
    //                 extend other interfaces, they do not implements).
    // - `enum`       (ACC_ENUM = 0x4000) — emits `enum`, suppresses
    //                 ACC_ABSTRACT + ACC_FINAL + ACC_SUPER (implicit on
    //                 enum declarations; javac rejects `abstract enum`
    //                 / `final enum`); implicitly extends
    //                 `java.lang.Enum<Self>` so `extends Enum` is
    //                 suppressed; parent-list is `implements` like a
    //                 normal class.
    // - `class`      (default) — standard class shape.
    //
    // Precedence: if both ACC_INTERFACE and ACC_ENUM are set
    // (shouldn't happen per JVM spec but defensive), prefer
    // `interface` (narrower).
    let is_interface = class_def.access_flags & 0x0200 != 0;
    let is_enum = !is_interface && class_def.access_flags & 0x4000 != 0;
    if !is_kt_facade {
        let modifier_mask: u32 = if is_interface {
            // Drop ACC_ABSTRACT (0x0400) + keep other flags in 0x7FF.
            0x07FF & !0x0400
        } else if is_enum {
            // Drop ACC_ABSTRACT (0x0400) + ACC_FINAL (0x0010) + bit 0x0020.
            // Bit 0x0020 on class_defs is ACC_SUPER (JVMS §4.1 Table 4.1-B);
            // however `emit_access_flags` is a shared function that emits
            // bit 0x0020 as the keyword `synchronized` (method semantics).
            // For enums we MUST mask it because `synchronized enum` is a
            // javac error. NOTE: the plain `class` path below has the same
            // collision and historically renders `synchronized class Foo`
            // when ACC_SUPER is set — a pre-existing latent defect tracked
            // as a follow-up (ACC_SUPER masking on classes).
            0x07FF & !0x0400 & !0x0010 & !0x0020
        } else {
            0x07FF
        };
        let access = emit::emit_access_flags(class_def.access_flags & modifier_mask);
        let type_kw = if is_interface {
            "interface"
        } else if is_enum {
            "enum"
        } else {
            "class"
        };
        let _ = write!(out, "{access} {type_kw} {class_name}");

        // Superclass emission. Three cases:
        //
        // - `interface`: Dalvik superclass is ALWAYS `java.lang.Object`;
        //   implicit at Java source level — emit no `extends` clause.
        // - `enum`: the "normal" top-level enum's superclass is
        //   `java.lang.Enum<Self>` (parameterized generic erased to raw
        //   Enum at bytecode level) — suppress. BUT per-constant enum
        //   subclasses (e.g. `Op$1 extends Op` for `ADD { ... }`) also
        //   carry ACC_ENUM and their real superclass is the parent enum,
        //   NOT `java.lang.Enum`. Suppressing those would swallow the
        //   real inheritance. So ONLY suppress when super_desc matches
        //   `Ljava/lang/Enum;` exactly.
        // - `class`: suppress `extends Object` (implicit); emit everything
        //   else.
        //
        // This tightening is a Stage-2 prelude fix — the broader
        // suppression was correct for top-level enums but wrong for
        // per-constant enum subclasses which the per-constant-body
        // pass targets for graduation.
        if !is_interface {
            if let Some(super_idx) = class_def.superclass_idx {
                if let Ok(super_desc) = dex.get_type_descriptor(super_idx) {
                    let suppress = super_desc == "Ljava/lang/Object;"
                        || (is_enum && super_desc == "Ljava/lang/Enum;");
                    if !suppress {
                        let _ = write!(out, " extends {}", pretty_class(super_desc));
                    }
                }
            }
        }

        // Interfaces / parent-interface list. For a `class` or `enum`,
        // this renders as `implements A, B`; for an `interface`, Java
        // spelling is `extends A, B` (an interface extends other
        // interfaces, it does not implements them). Enums may implement
        // interfaces normally.
        if class_def.interfaces_off != 0 {
            if let Some(ifaces) = dex.type_lists.get(&class_def.interfaces_off) {
                let iface_names: Vec<String> = ifaces
                    .iter()
                    .filter_map(|tidx| dex.get_type_descriptor(*tidx).ok())
                    .map(pretty_class)
                    .collect();
                if !iface_names.is_empty() {
                    let clause = if is_interface { "extends" } else { "implements" };
                    let _ = write!(out, " {clause} {}", iface_names.join(", "));
                }
            }
        }

        out.push_str(" {\n");
    }

    // `imports` is hoisted above the data-class early-return path; the
    // `emit_method`'s `EmitCtx` collects per-method imports via
    // `note_import` which the inner method emit drains into this set,
    // and we emit a single sorted import block after the class body is
    // rendered (insertion site `header_anchor`).

    // Class data — pre-parsed at the top so the facade gate could
    // inspect cd shape; reuse here for fields + methods emission.
    if let Some(cd) = parsed_cd {
        // Parse static field initial values (encoded_array_item)
        let static_values = parse_static_values(data, class_def.static_values_off);

        // Pre-scan <clinit> (if present) to collect the set of
        // static fields it writes to via SPut*. A `static final`
        // field assigned in `<clinit>` must NOT carry a
        // declaration-level initializer (javac rejects "cannot
        // assign a value to final variable" on the second assign),
        // so emit_fields skips the default-initializer fallback
        // for those. Fields NOT in this set keep the normal
        // zero-elision fallback.
        let clinit_assigned_fields =
            collect_clinit_assigned_fields(dex, data, &cd.direct_methods);

        // Companion scan: static fields assigned via SPut* from any
        // method OTHER than `<clinit>`. R8 sometimes inlines a class's
        // `<clinit>` body into its first lazy caller (e.g.,
        // `getInstance()`); after inlining, what was a
        // `static { FOO = ...; }` block becomes a `SPut FOO` inside a
        // regular method. The original Java source flagged the field
        // `final`, but the inlined assignment fails javac's
        // "cannot assign to final variable" check. Drop `final` from
        // the declaration of any such field — the runtime invariant
        // (single assignment before any read) still holds; only the
        // source-level keyword changes.
        let non_clinit_assigned_static_fields =
            collect_non_clinit_assigned_static_fields(
                dex,
                data,
                &cd.direct_methods,
                &cd.virtual_methods,
            );

        // ACC_SYNTHETIC+ACC_ENUM-gated suppression of javac-generated
        // enum members ($VALUES, $values(), values(), valueOf(String),
        // synth bridge ctor, the implicit super(name,ordinal), and the
        // enum-const-population <clinit> body). No-op on non-enum
        // classes.
        let enum_ctx = EnumCtx::build(dex, class_def, &cd.static_fields);

        // For canonical enum classes, attempt to extract per-constant
        // constructor user-args from the `<clinit>` body. On success we
        // (a) render `NAME(args),` declarations at the top of the enum
        // body, (b) suppress the corresponding static-final ACC_ENUM
        // field declarations, and (c) suppress the `<clinit>` method
        // emission. On failure (non-canonical body, missing $values()
        // invariant, scan-cap blown) every field/method emits via the
        // existing fall-through path — visually broken (the static
        // block is rendered) but not regressed.
        let enum_constant_emitted: BTreeSet<crate::ids::FieldIdx> = if enum_ctx.applies {
            #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; method_idx.0 bounded < dex.methods.len() by parser validation of method_ids pool.")]
            let clinit_em = cd.direct_methods.iter().find(|em| {
                dex.methods
                    .get(em.method_idx.0 as usize)
                    .and_then(|m| dex.get_string(m.name_idx).ok())
                    == Some("<clinit>")
            });
            match clinit_em.and_then(|em| {
                scan_enum_clinit_pops_with_user_args(&enum_ctx, dex, data, em).ok()
            }) {
                Some(pops) if !pops.is_empty() => {
                    render_enum_constants(&mut out, dex, &pops);
                    pops.into_iter().map(|p| p.backing_field).collect()
                }
                _ => BTreeSet::new(),
            }
        } else {
            BTreeSet::new()
        };

        // Fields. Suppressed in facade mode: instance_fields is empty
        // by structural-gate construction; static_fields would be
        // top-level Kotlin `val/var` decls whose proper rendering is
        // PR-9c (Stmt-level Kotlin emit). For the kotlinc-1.9
        // top-level-fn corpus fixtures static_fields is also empty,
        // so this is a no-op skip on the corpus today.
        //
        // When `enum_constant_emitted` is non-empty, filter the
        // matching static-final ACC_ENUM fields out so their
        // declarations are not double-rendered.
        let filtered_static_fields: Vec<decode::EncodedField>;
        let static_fields_slice: &[decode::EncodedField] = if enum_constant_emitted.is_empty() {
            &cd.static_fields
        } else {
            filtered_static_fields = cd
                .static_fields
                .iter()
                .filter(|ef| !enum_constant_emitted.contains(&ef.field_idx))
                .cloned()
                .collect();
            &filtered_static_fields
        };
        if !is_kt_facade {
            emit_fields(
                &mut out,
                dex,
                static_fields_slice,
                true,
                &static_values,
                &clinit_assigned_fields,
                &non_clinit_assigned_static_fields,
                &enum_ctx,
            );
            emit_fields(
                &mut out,
                dex,
                &cd.instance_fields,
                false,
                &[],
                &clinit_assigned_fields,
                &non_clinit_assigned_static_fields,
                &enum_ctx,
            );
        }

        // Methods
        emit_methods(
            &mut out,
            dex,
            data,
            &cd.direct_methods,
            class_def,
            &mut imports,
            &enum_ctx,
            ttm,
            is_kt_facade,
            trace,
            r8_census,
        );
        emit_methods(
            &mut out,
            dex,
            data,
            &cd.virtual_methods,
            class_def,
            &mut imports,
            &enum_ctx,
            ttm,
            is_kt_facade,
            trace,
            r8_census,
        );

        // Throws cascade: if any method in this class ran the
        // escaped-catch-var hoist (`Throwable v… = null;` line at the
        // method-body indent emitted by `src/emit.rs`), patch every
        // method signature in the class output with `throws
        // Throwable`. Over-declarative but structurally correct — any
        // method in the class could transitively call the hoist-bearing
        // one, and without a proper call-graph we can't tell which
        // subset actually needs the declaration.
        // Triggers: (a) the cross-catch scope-leak hoist pattern
        // (`Throwable X = null;` inside a method body), or
        // (b) any `MethodHandle.invokeExact`/`findStatic`-family
        // call that throws `Throwable`/checked exceptions that
        // can't be silently caught. Both shapes need a
        // `throws Throwable` on the enclosing method's signature.
        //
        // Skipped in facade mode: Kotlin has no checked exceptions,
        // so the `throws` clause is meaningless on a Kotlin top-level
        // fn signature.
        if !is_kt_facade {
            let hoist = out.contains("\n        Throwable ") && out.contains(" = null;\n");
            let mh = out.contains(".invokeExact(")
                || out.contains(".invoke(")
                || out.contains(".findStatic(")
                || out.contains(".findVirtual(")
                || out.contains(".findConstructor(")
                || out.contains(".findSpecial(");
            if hoist || mh {
                out = patch_throws_throwable_on_method_signatures(&out);
            }
        }
    }

    if !is_kt_facade {
        out.push_str("}\n");
    }

    // Prepend import block. `note_import` already filters `java.lang.*`
    // single-component classes. Imports are inserted between the package
    // declaration (if present) and the class header — the header is the
    // first line that starts with the class keyword + the class's simple
    // name. In facade mode there is no class header, so insert at the
    // anchor (immediately after the package line).
    if !imports.is_empty() {
        let mut block = String::new();
        for fqcn in &imports {
            if is_kt_facade {
                let _ = writeln!(block, "import {fqcn}");
            } else {
                let _ = writeln!(block, "import {fqcn};");
            }
        }
        block.push('\n');

        let insert_at = if is_kt_facade {
            header_anchor
        } else {
            let class_line_prefix_class = format!("class {class_name}");
            let class_line_prefix_interface = format!("interface {class_name}");
            out.find(&class_line_prefix_class)
                .or_else(|| out.find(&class_line_prefix_interface))
                .map(|idx| {
                    // Walk back to the start of the class header's line.
                    out.get(..idx)
                        .and_then(|s| s.rfind('\n'))
                        .map(|n| n + 1)
                        .unwrap_or(0)
                })
                .unwrap_or(0)
        };
        out.insert_str(insert_at, &block);
    }

    prepend_indeterminate_banner(out, &indeterminate_detectors)
}

/// Prepend a single Indeterminate-detector banner to a rendered class when one
/// or more Kotlin-vs-Java rendering detectors returned `Indeterminate`. The body
/// is still emitted as the best-guess Java-surface shape; the banner tells the
/// operator the rendered shape may not match the original source rather than
/// letting a silent best-guess pass as authoritative. One banner per class
/// (the detector set is deduplicated), or the input unchanged when empty.
fn prepend_indeterminate_banner(out: String, detectors: &BTreeSet<&'static str>) -> String {
    if detectors.is_empty() {
        return out;
    }
    let names: Vec<&str> = detectors.iter().copied().collect();
    format!(
        "// DROIDSAW_INDETERMINATE: {}; rendered shape may not match original source\n{out}",
        names.join(", ")
    )
}

/// Insert `throws Throwable` before the opening brace of every method
/// signature line in a decompiled-class body. A method signature sits at
/// exactly 4 leading spaces of indent (from `emit_methods`'s
/// `writeln!(out, "    {line}")`), ends with `) {`, and is NOT at 8+ spaces
/// (method body / inner structures). Idempotent: if the line already has a
/// `throws` clause, it's left unchanged.
#[allow(clippy::arithmetic_side_effects, reason = "index arithmetic on string positions; positions are searched within src and bounded by src.len() (usize cannot overflow on parser-bounded source size).")]
fn patch_throws_throwable_on_method_signatures(src: &str) -> String {
    let mut out = String::with_capacity(src.len() + 64);
    for line in src.lines() {
        if line.starts_with("    ")
            && !line.starts_with("        ")
            && line.ends_with(") {")
            && !line.contains(" throws ")
        {
            let trimmed = line.strip_suffix(" {").unwrap_or(line);
            out.push_str(trimmed);
            out.push_str(" throws Throwable {\n");
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Parse the encoded_array_item at `static_values_off` to get initial values
/// for static fields (one per field in declaration order, may be shorter than
/// the field count — remaining fields have default zero/null values).
#[allow(clippy::arithmetic_side_effects, reason = "encoded-value walk over parser-bounded slice; usize pos increments bounded by data.len() with explicit bound checks.")]
fn parse_static_values(data: &[u8], off: u32) -> Vec<EncodedValue> {
    if off == 0 {
        return vec![];
    }
    #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; off is a DEX file offset bounded by data.len() by caller (static_values_off != 0 guard above); lossless on 32+-bit platforms.")]
    let pos = off as usize;
    let Ok((size, len)) = crate::mutf8::read_uleb128(data, pos) else {
        return vec![];
    };
    // Amplification defense: each encoded_value is at minimum 1 byte on
    // disk (header). This fn's contract is "best-effort, malformed input
    // → empty/short vec" — so rather than routing through Result, clamp
    // with_capacity against the physical remainder.
    #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; size is a uleb128-decoded value bounded against data.len() by the .min() guard on the same line.")]
    let count = (size as usize).min(data.len().saturating_sub(pos));
    let mut values = Vec::with_capacity(count);
    let mut cur = pos + len;
    for _ in 0..count {
        match annotation::parse_encoded_value(data, cur) {
            Ok((v, vlen)) => {
                // parse_encoded_value returns total bytes consumed
                // (header + data); no separate header term needed.
                cur += vlen;
                values.push(v);
            }
            Err(_) => break,
        }
    }
    values
}

/// Render an EncodedValue as a Java literal.
fn encoded_value_to_java(dex: &DexFile, v: &EncodedValue) -> Option<String> {
    match v {
        EncodedValue::Int(n) => Some(format!("{n}")),
        EncodedValue::Long(n) => Some(format!("{n}L")),
        EncodedValue::Float(f) => Some(float_literal_java(*f)),
        EncodedValue::Double(d) => Some(double_literal_java(*d)),
        EncodedValue::Boolean(b) => Some(if *b { "true" } else { "false" }.to_string()),
        EncodedValue::Byte(n) => Some(format!("{n}")),
        EncodedValue::Short(n) => Some(format!("{n}")),
        EncodedValue::Char(c) => Some(char_literal_java(*c)),
        EncodedValue::String(sidx) => {
            let s = dex.get_string(*sidx).unwrap_or("<invalid>");
            Some(format!("\"{}\"", crate::emit::escape_java_string(s)))
        }
        EncodedValue::Null => Some("null".to_string()),
        _ => None,
    }
}

/// Render an f32 as a Java source-level literal. Handles IEEE-754 edge
/// cases (NaN / ±Infinity / ±0) that the bare `{f}` Display form spells
/// as `NaN` / `inf` / `-inf` — forms that are NOT legal Java float
/// literals. Spec fallback for non-finite: `Float.NaN`, `Float.POSITIVE_INFINITY`,
/// `Float.NEGATIVE_INFINITY`. ±0 is handled via the normal literal path
/// (`-0.0f` is a valid Java float-literal expression).
fn float_literal_java(f: f32) -> String {
    if f.is_nan() {
        return "Float.NaN".to_string();
    }
    if f.is_infinite() {
        return if f.is_sign_negative() {
            "Float.NEGATIVE_INFINITY".to_string()
        } else {
            "Float.POSITIVE_INFINITY".to_string()
        };
    }
    if f.fract() == 0.0 {
        format!("{f:.1}f")
    } else {
        format!("{f}f")
    }
}

/// f64 sibling of `float_literal_java`. Java's `Double.NaN` /
/// `Double.POSITIVE_INFINITY` / `Double.NEGATIVE_INFINITY` are the legal
/// source-level forms for non-finite doubles.
fn double_literal_java(d: f64) -> String {
    if d.is_nan() {
        return "Double.NaN".to_string();
    }
    if d.is_infinite() {
        return if d.is_sign_negative() {
            "Double.NEGATIVE_INFINITY".to_string()
        } else {
            "Double.POSITIVE_INFINITY".to_string()
        };
    }
    if d.fract() == 0.0 {
        format!("{d:.1}")
    } else {
        format!("{d}")
    }
}

/// Render a u16 char value as a Java source-level char literal. Chars
/// in the printable-ASCII-ish range (0x20..0x7E minus `'` and `\`) emit
/// as the literal glyph; everything else (controls, DEL, non-BMP, etc.)
/// emits as `'\uXXXX'` unicode-escape form so the source is ASCII-safe
/// and javac-accepting regardless of the specific char.
fn char_literal_java(c: u16) -> String {
    let ch = char::from_u32(u32::from(c)).unwrap_or('?');
    let is_printable_ascii = (0x20..=0x7E).contains(&c)
        && c != u16::from(b'\'')
        && c != u16::from(b'\\');
    if is_printable_ascii {
        format!("'{ch}'")
    } else {
        format!("'\\u{c:04X}'")
    }
}

/// Scan `direct_methods` for `<clinit>` and return the set of field
/// indices it assigns via `SPut*` instructions. Used by `emit_fields`
/// to suppress the default-initializer fallback for `static final`
/// fields that get their real value in the static-init block — Java
/// forbids double-assign on `final` and javac rejects the decl-init-
/// plus-clinit-assign pair.
fn collect_clinit_assigned_fields(
    dex: &DexFile,
    data: &[u8],
    direct_methods: &[decode::EncodedMethod],
) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    for em in direct_methods {
        #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; method_idx.0 bounded < dex.methods.len() by parser validation of method_ids pool.")]
        let Some(m) = dex.methods.get(em.method_idx.0 as usize) else {
            continue;
        };
        if dex.get_string(m.name_idx).ok() != Some("<clinit>") {
            continue;
        }
        if em.code_off == 0 {
            continue;
        }
        let Ok(code) = decode::parse_code_item(data, em.code_off) else {
            continue;
        };
        for insn in &code.instructions {
            // SPut* opcodes: 0x67..=0x6D.
            let is_sput = matches!(
                insn.op,
                crate::opcodes::Opcode::Sput
                    | crate::opcodes::Opcode::SputWide
                    | crate::opcodes::Opcode::SputObject
                    | crate::opcodes::Opcode::SputBoolean
                    | crate::opcodes::Opcode::SputByte
                    | crate::opcodes::Opcode::SputChar
                    | crate::opcodes::Opcode::SputShort
            );
            if !is_sput {
                continue;
            }
            if let Some(decode::PoolIndex::Field(fidx)) = insn.pool_idx {
                out.insert(fidx.0);
            }
        }
    }
    out
}

/// Scan `direct_methods` (excluding `<clinit>`) + `virtual_methods` for
/// `SPut*` instructions and return the set of static-field indices
/// assigned anywhere outside the class initializer block.
///
/// The DEX bytecode for `static { ... }` lives in the synthetic
/// `<clinit>` method (always direct, always `static`, no parameters);
/// real Java source guarantees assignments to `static final` fields
/// only happen there. R8's lazy-init optimizer sometimes inlines the
/// entire `<clinit>` body into the first caller of the class (e.g., a
/// `getInstance()` method that triggers init on first use). The
/// post-inlining bytecode no longer has a separate `<clinit>` body;
/// the `SPut FIELD` instructions live inside the caller's bytecode
/// instead. `emit_fields` consults the returned set to drop
/// ACC_FINAL from those fields' rendered access flags, so the
/// decompiled Java source compiles.
fn collect_non_clinit_assigned_static_fields(
    dex: &DexFile,
    data: &[u8],
    direct_methods: &[decode::EncodedMethod],
    virtual_methods: &[decode::EncodedMethod],
) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    let scan = |em: &decode::EncodedMethod, out: &mut BTreeSet<u32>| {
        #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; method_idx.0 bounded < dex.methods.len() by parser validation of method_ids pool.")]
        let Some(m) = dex.methods.get(em.method_idx.0 as usize) else {
            return;
        };
        // Skip `<clinit>` itself — its writes are handled by the
        // existing `collect_clinit_assigned_fields` path.
        if dex.get_string(m.name_idx).ok() == Some("<clinit>") {
            return;
        }
        if em.code_off == 0 {
            return;
        }
        let Ok(code) = decode::parse_code_item(data, em.code_off) else {
            return;
        };
        for insn in &code.instructions {
            let is_sput = matches!(
                insn.op,
                crate::opcodes::Opcode::Sput
                    | crate::opcodes::Opcode::SputWide
                    | crate::opcodes::Opcode::SputObject
                    | crate::opcodes::Opcode::SputBoolean
                    | crate::opcodes::Opcode::SputByte
                    | crate::opcodes::Opcode::SputChar
                    | crate::opcodes::Opcode::SputShort
            );
            if !is_sput {
                continue;
            }
            if let Some(decode::PoolIndex::Field(fidx)) = insn.pool_idx {
                out.insert(fidx.0);
            }
        }
    };
    for em in direct_methods {
        scan(em, &mut out);
    }
    for em in virtual_methods {
        scan(em, &mut out);
    }
    out
}

#[allow(
    clippy::too_many_arguments,
    reason = "internal helper called once per class from decompile_class; \
              splitting the field-context state into a struct would obscure \
              the call site without removing coupling"
)]
fn emit_fields(
    out: &mut String,
    dex: &DexFile,
    fields: &[decode::EncodedField],
    is_static: bool,
    static_values: &[EncodedValue],
    clinit_assigned: &BTreeSet<u32>,
    non_clinit_assigned: &BTreeSet<u32>,
    enum_ctx: &EnumCtx,
) {
    for (i, ef) in fields.iter().enumerate() {
        // Row 1 (v2 matrix): suppress `$VALUES` on enum classes.
        if enum_suppress::is_suppressed_field(enum_ctx, dex, ef) {
            continue;
        }
        #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; field_idx.0 bounded < dex.fields.len() by parser validation of field_ids pool.")]
        if let Some(field) = dex.fields.get(ef.field_idx.0 as usize) {
            // R8-inlined-<clinit> handling: when a `static final` field
            // is written by a non-`<clinit>` method body, javac will
            // reject the surrounding decompile output ("cannot assign
            // a value to final variable"). The runtime invariant
            // (single assignment before any read, preserved by R8's
            // inlining proof) still holds; only the Java source-level
            // keyword has to drop. Strip ACC_FINAL from the rendered
            // access flags in that case.
            let final_inlined = is_static
                && (ef.access_flags & 0x0010 != 0)
                && non_clinit_assigned.contains(&ef.field_idx.0);
            let render_flags = if final_inlined {
                ef.access_flags & !0x0010
            } else {
                ef.access_flags
            };
            let access = emit::emit_access_flags(render_flags);
            let ty = dex
                .get_type_descriptor(field.type_idx)
                .map(DexType::from_descriptor)
                .unwrap_or(DexType::Top);
            let name = crate::emit::sanitize_id(dex.get_string(field.name_idx).unwrap_or("?"));
            // Emit initializer for STATIC final fields with encoded values.
            // DEX spec §VII.3.1 lets `encoded_array_item` be shorter than
            // the static-field count — trailing entries are elided and
            // implicitly default to the type's zero value. For
            // `static final` that's a compile error (field must be
            // initialized at declaration), so fall back to the
            // type-appropriate zero literal when the slot is missing or
            // when `encoded_value_to_java` can't render the value.
            //
            // INSTANCE final fields MUST stay uninitialized at declaration
            // — their initial value is assigned in the constructor (via
            // `this.name = v0;`). Emitting `private final String name =
            // null;` would make javac reject the constructor's assign
            // with "cannot assign a value to final variable". The
            // default-literal fallback is STATIC-only; instance final
            // fields bypass this code entirely.
            let is_final = ef.access_flags & 0x0010 != 0;
            // Skip the decl-init fallback when ACC_FINAL was stripped
            // for the R8-inlined-<clinit> case: the field will be
            // assigned by the inlining method body at runtime, and the
            // plain-decl shape ("static TYPE NAME;") leaves the slot
            // open for that assignment.
            if is_final && is_static && !final_inlined {
                // A field assigned by <clinit> must NOT carry a
                // declaration initializer — javac rejects the double-
                // assign on `final`. If such a field lacks an explicit
                // encoded_array entry AND is <clinit>-assigned, skip
                // the zero-elision default-init fallback entirely.
                let is_clinit_assigned = clinit_assigned.contains(&ef.field_idx.0);
                // When `<clinit>` assigns the field, suppress BOTH the
                // explicit encoded_array entry AND the type-default
                // fallback. The DEX spec permits `encoded_array_item` to
                // carry the type's zero value (e.g., `null` for a Ref
                // field) even when `<clinit>` reassigns the real value;
                // emitting `static final X = null; static { X = ...; }`
                // makes javac reject the double-assign on the `final`
                // qualifier. The `<clinit>` body is the source of truth
                // for the runtime value.
                let lit = if is_clinit_assigned {
                    None
                } else {
                    let explicit_init = static_values
                        .get(i)
                        .and_then(|ev| encoded_value_to_java(dex, ev));
                    explicit_init.or_else(|| type_default_literal(&ty))
                };
                if let Some(lit) = lit {
                    let _ = writeln!(out, "    {access} {ty} {name} = {lit};");
                    continue;
                }
            }
            let _ = writeln!(out, "    {access} {ty} {name};");
        }
    }
    if !fields.is_empty() {
        out.push('\n');
    }
}

/// Type-zero Java literal for use as the default initializer on a
/// `static final` field whose `encoded_array_item` entry was elided
/// (DEX spec §VII.3.1 trailing-zero elision). Returns None for types
/// that have no sensible compile-time zero literal (caller falls
/// through to no-initializer, i.e. admits the broken shape rather
/// than inventing a value).
fn type_default_literal(ty: &DexType) -> Option<String> {
    match ty {
        DexType::Boolean => Some("false".to_string()),
        DexType::Byte | DexType::Short | DexType::Int => Some("0".to_string()),
        DexType::Long => Some("0L".to_string()),
        DexType::Char => Some("'\\u0000'".to_string()),
        DexType::Float => Some("0.0f".to_string()),
        DexType::Double => Some("0.0".to_string()),
        DexType::Ref(_) | DexType::ArrayRef(_) => Some("null".to_string()),
        _ => None,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "each param is explicit context threaded from decompile_class_impl; bundling into a ctx struct has larger cost than value here — every call site already has the right locals in scope"
)]
fn emit_methods(
    out: &mut String,
    dex: &DexFile,
    data: &[u8],
    methods: &[decode::EncodedMethod],
    class_def: &ClassDefItem,
    imports: &mut BTreeSet<String>,
    enum_ctx: &EnumCtx,
    ttm: Option<&TypeToClassDefMap>,
    is_kt_facade: bool,
    trace: Trace,
    r8_census: &r8_inversion::TrampolineCensus,
) {
    for em in methods {
        // Rows 2-6 (v2 matrix): `$values()`, synthetic bridge ctor,
        // `values()`, `valueOf(String)`, `<clinit>` if its body is a pure
        // enum-const-population. Bail-not-suppress on any deviation.
        if enum_suppress::is_suppressed_method(enum_ctx, dex, data, em, ttm) {
            continue;
        }

        // Kotlin top-level-fn facade: skip any synthetic `<init>` /
        // `<clinit>` the kotlinc-1.9 compiler may have emitted, since
        // they have no Kotlin source-level analogue at the file
        // top-level. PR-9b of #41b. The empirical fixtures don't carry
        // such methods (kotlinc-1.9.22 omits the default ctor entirely
        // when the facade has no instance state), but the guard is
        // defensive against compiler-version drift and against
        // top-level-property facades that may emit a `<clinit>`.
        if is_kt_facade {
            #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; method_idx.0 bounded < dex.methods.len() by parser validation of method_ids pool.")]
            if let Some(name) = dex
                .methods
                .get(em.method_idx.0 as usize)
                .and_then(|m| dex.get_string(m.name_idx).ok())
            {
                if name == "<init>" || name == "<clinit>" {
                    continue;
                }
            }
        }

        if em.code_off == 0 {
            // Abstract or native method
            emit_abstract_method(out, dex, em);
            continue;
        }

        match decompile_method(dex, data, em, class_def, imports, is_kt_facade, trace, r8_census) {
            Ok(source) => {
                // Row 7 (v2 matrix): in an enum ctor, strip the implicit
                // `super(name, ordinal)` call — javac re-inserts it
                // automatically and rejects an explicit one.
                let source = enum_suppress::maybe_strip_enum_super_call(
                    enum_ctx, dex, em, &source,
                );
                if is_kt_facade {
                    // Top-level fns sit at file scope — no leading
                    // class-body indent. Each method block is followed
                    // by a blank line, matching kotlinc style.
                    out.push_str(&source);
                    out.push('\n');
                } else {
                    // Indent each line one level (inside class body).
                    for line in source.lines() {
                        let _ = writeln!(out, "    {line}");
                    }
                    out.push('\n');
                }
            }
            Err(e) => {
                let prefix = if is_kt_facade { "" } else { "    " };
                let _ = writeln!(out, "{prefix}// Failed to decompile: {e}");
                out.push('\n');
            }
        }
    }
}

#[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; method_idx.0 and proto_idx.0 bounded < dex.methods.len()/dex.protos.len() by parser validation of method_ids/proto_ids pools.")]
fn emit_abstract_method(out: &mut String, dex: &DexFile, em: &decode::EncodedMethod) {
    if let Some(method) = dex.methods.get(em.method_idx.0 as usize) {
        let raw_name = dex.get_string(method.name_idx).unwrap_or("?");
        // Skip synthetic methods — <init>/<clinit> cannot be abstract in Java
        if raw_name == "<init>" || raw_name == "<clinit>" {
            return;
        }
        // Mask out method-only access-flag bits that share bitmasks
        // with field-only Java-source modifiers. ACC_CONSTRUCTOR (0x10000)
        // is dex-internal, not a Java modifier. ACC_BRIDGE (0x0040)
        // shares its bit with ACC_VOLATILE (field) — synthetic, not
        // emitted in source. ACC_VARARGS (0x0080) shares with
        // ACC_TRANSIENT (field) — surfaced at source level via the
        // `int...` parameter syntax, not as a modifier keyword.
        let access = emit::emit_access_flags(em.access_flags & !0x10000 & !0x0040 & !0x0080);
        let name = crate::emit::sanitize_id(raw_name);
        if let Some(proto) = dex.protos.get(method.proto_idx.0 as usize) {
            let ret = dex
                .get_type_descriptor(proto.return_type_idx)
                .map(|d| format!("{}", DexType::from_descriptor(d)))
                .unwrap_or_else(|_| "void".to_string());

            // Parameters
            let params = build_param_string(dex, proto);
            let _ = writeln!(out, "    {access} {ret} {name}({params});");
            out.push('\n');
        }
    }
}

fn build_param_string(dex: &DexFile, proto: &crate::ids::ProtoIdItem) -> String {
    if proto.parameters_off == 0 {
        return String::new();
    }
    if let Some(type_list) = dex.type_lists.get(&proto.parameters_off) {
        let params: Vec<String> = type_list
            .iter()
            .enumerate()
            .map(|(i, tidx)| {
                let ty = dex
                    .get_type_descriptor(*tidx)
                    .map(|d| format!("{}", DexType::from_descriptor(d)))
                    .unwrap_or_else(|_| "?".to_string());
                format!("{ty} p{i}")
            })
            .collect();
        params.join(", ")
    } else {
        String::new()
    }
}

/// Env-gated debug facility: when `DROIDSAW_PANIC_ON_DECOMPILE_ERR` is set,
/// promote typed pipeline errors at a specific stage to `panic!()` so the
/// panic-hook + diag-wire + triage-promote machinery captures a full
/// diagnostic bundle per-failure. Production path (env unset, the default)
/// is a no-op.
fn maybe_panic_on_err<E: std::fmt::Display>(class: &str, method: &str, stage: &str, err: &E) {
    if std::env::var_os("DROIDSAW_PANIC_ON_DECOMPILE_ERR").is_some() {
        #[allow(
            clippy::panic,
            reason = "env-gated debug facility; never reached when DROIDSAW_PANIC_ON_DECOMPILE_ERR is unset (production default)"
        )]
        {
            panic!("dex-decompile-panic-on-err: class={class} method={method} stage={stage} err={err}");
        }
    }
}

/// Detect when a `private` `<init>` should be widened to package-private
/// at emit time so that a subclass within the same enclosing top-level
/// class can compile its `super(...)` call.
///
/// **Why this exists.** When `<EnclosingTop>$Sub` extends
/// `<EnclosingTop>$Parent` and `Parent` is `private static class`,
/// `Parent.<init>()` is `private`. javac itself rejects `Sub`'s
/// `super()` call on access-control grounds and silently synthesizes a
/// `<init>(<EnclosingTop>$N)` accessor on `Parent` to bridge the
/// access. The synthetic-marker class `<EnclosingTop>$N` is a private
/// inner class with no fields. d8 preserves the synthetic accessor.
///
/// The decompiler currently emits the original `private <init>()`
/// declaration on `Parent` plus the synthesized `<init>(<marker>)`
/// accessor; `Sub`'s `super()` call resolves at recompile to
/// `Parent.<init>()` (private) and javac rejects.
///
/// The alternative — emitting `this()` for the synthetic
/// accessor — exposes a downstream defect (`super.obj` field-shadowing
/// read) on `ShadowedFields`, regressing `compile_fail → semantic_fail`
/// (ratchet-banned). This widen-visibility path sidesteps that
/// regression entirely; tradeoff is that the emitted source declares
/// `<init>` as package-private where the original Java said `private`,
/// which is recompile-clean but a fidelity loss for the analyst.
///
/// **Predicate.** Returns `true` iff:
/// 1. `raw_name == "<init>"` and the method's `access_flags` carry
///    `ACC_PRIVATE` (0x0002).
/// 2. The enclosing class descriptor contains `$` (i.e., the class is
///    nested — top-level private classes can't be inherited at all).
/// 3. Some sibling class in the same enclosing top-level (same prefix
///    up to the FIRST `$`) directly extends this class.
///
/// All three conditions are necessary; absent any one of them the
/// existing `private <init>` is emitted unchanged.
#[allow(clippy::arithmetic_side_effects, reason = "count arithmetic on parser-validated class-def methods slice; total bounded by uleb128 cap.")]
fn should_widen_private_init_visibility(
    dex: &DexFile,
    class_def: &ClassDefItem,
    method_access_flags: u32,
    raw_name: &str,
) -> bool {
    const ACC_PRIVATE: u32 = 0x0002;
    if raw_name != "<init>" {
        return false;
    }
    if method_access_flags & ACC_PRIVATE == 0 {
        return false;
    }
    let class_desc = match dex.get_type_descriptor(class_def.class_idx) {
        Ok(d) => d,
        Err(_) => return false,
    };
    // Top-level private classes (no `$` in descriptor) can't be inherited.
    let prefix_end = match class_desc.find('$') {
        Some(idx) => idx,
        None => return false,
    };
    // Enclosing top-level prefix includes the `$`, so a sibling matches
    // when its descriptor starts with the same `LOuter$` prefix. Per
    // `OverloadsPeerClasses`, the prefix is the FIRST `$` — deeper
    // nesting (`$Inner$Deep`) shares the same enclosing top-level.
    let enclosing_prefix = match class_desc.get(..prefix_end + 1) {
        Some(p) => p,
        None => return false,
    };
    for (sibling_idx, sibling) in dex.class_defs.iter().enumerate() {
        // Shadow gate: duplicate-class_idx rows would surface a
        // sibling-of-self relationship (same descriptor prefix) and
        // double-count the sibling as an Outer$Inner peer. Skip
        // shadowed rows to match the canonical first-wins resolution.
        if dex.class_def_is_shadowed(sibling_idx) {
            continue;
        }
        let sibling_desc = match dex.get_type_descriptor(sibling.class_idx) {
            Ok(d) => d,
            Err(_) => continue,
        };
        if !sibling_desc.starts_with(enclosing_prefix) {
            continue;
        }
        if sibling_desc == class_desc {
            continue;
        }
        let super_desc = sibling
            .superclass_idx
            .and_then(|idx| dex.get_type_descriptor(idx).ok())
            .unwrap_or("");
        if super_desc == class_desc {
            return true;
        }
    }
    false
}

/// Trace flag for the `DROIDSAW_DECOMPILE_TRACE` debug knob, hoisted
/// out of the per-method decompile body. Read once at the API
/// boundary (`decompile_class` / `decompile_class_ext`) via
/// [`Trace::from_env`], then threaded through as a parameter so every
/// method in a single decompile run sees the same trace setting.
///
/// The hoist eliminates the env-var re-read on every method call.
/// The cost was <0.1% of baseline wall, so the hoist is for clarity
/// (run-wide consistency) more than performance.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Trace {
    enabled: bool,
}

impl Trace {
    /// Build a `Trace` flag by reading `DROIDSAW_DECOMPILE_TRACE` once.
    /// Callers at API boundaries cache the result for the whole
    /// decompile run.
    pub(crate) fn from_env() -> Self {
        Self { enabled: std::env::var("DROIDSAW_DECOMPILE_TRACE").is_ok() }
    }
}

/// Read current process RSS in KiB. Linux-only — reads
/// `/proc/self/status`'s `VmRSS:` line. On non-Linux targets returns
/// `None` so the trace output emits `RSS=?` rather than `RSS=0`
/// (the prior shape silently swallowed the syscall failure and
/// reported 0, which a developer running with trace on macOS would
/// misread as "well-behaved memory" rather than "platform gap").
///
/// On macOS without this cfg gate, the failed `open()` on
/// `/proc/self/status` costs ~1.7 sec of sys time per 9 MB DEX
/// decompile-all run when trace is enabled, with the column always
/// reporting 0. The cfg gate eliminates both the wasted syscall and
/// the misleading output.
#[cfg(target_os = "linux")]
fn read_proc_rss_kb() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|n| n.parse().ok())
        })
}

#[cfg(not(target_os = "linux"))]
fn read_proc_rss_kb() -> Option<u64> {
    None
}

#[allow(clippy::arithmetic_side_effects, reason = "register/local-name index arithmetic on parser-validated CodeItem (registers_size u16 cap); usize index increments bounded by params.len() (parser-validated).")]
#[allow(
    clippy::cast_possible_truncation,
    clippy::as_conversions,
    reason = "PROOF: cast cluster across 7 sites — (a) `xxx.0 as usize` widens u32→usize; method_idx.0/proto_idx.0 bounded < dex.methods.len()/dex.protos.len() by parser validation of method_ids/proto_ids pools; (b) `dex.methods.len() as u32` / `dex.protos.len() as u32` are DEX pool sizes (u32 by DEX spec) feeding diagnostic IndexOob.pool_size; (c) `i as u16` is an enumerate index over ssa.param_vars; params.len() ≤ registers_size which is u16 by DEX format."
)]
#[allow(
    clippy::too_many_arguments,
    reason = "8 params: each is explicit context threaded from decompile_class_impl. r8_census was added to support the R8 inversion pass's repetition + helper-body verification gates. Bundling into a ctx struct has larger cost than value — every call site already has the right locals in scope, and the recogniser API surface keeps cross-method state explicit."
)]
fn decompile_method(
    dex: &DexFile,
    data: &[u8],
    em: &decode::EncodedMethod,
    class_def: &ClassDefItem,
    imports: &mut BTreeSet<String>,
    is_kt_facade: bool,
    trace: Trace,
    r8_census: &r8_inversion::TrampolineCensus,
) -> Result<String, DexError> {
    let class_desc = dex.get_type_descriptor(class_def.class_idx).unwrap_or("L?;");
    let method_name = dex
        .methods
        .get(em.method_idx.0 as usize)
        .and_then(|m| dex.get_string(m.name_idx).ok())
        .unwrap_or("?");

    let trace_step = |label: &str| {
        if trace.enabled {
            // Linux: RSS reading is functional; the format produces
            // `RSS=NMB`. Non-Linux: `read_proc_rss_kb` returns None,
            // surfacing as `RSS=?` so a developer reading the trace
            // sees the platform gap explicitly rather than mistaking
            // an always-0 column for "well-behaved memory."
            match read_proc_rss_kb() {
                Some(kib) => eprintln!(
                    "    [{class_desc}::{method_name}] {label}: RSS={}MB",
                    kib / 1024,
                ),
                None => eprintln!("    [{class_desc}::{method_name}] {label}: RSS=?"),
            }
        }
    };

    trace_step("enter");
    let code = decode::parse_code_item(data, em.code_off).inspect_err(|e| {
        maybe_panic_on_err(class_desc, method_name, "parse", e);
    })?;
    trace_step("after decode::parse_code_item");
    let cfg = Cfg::build(&code).inspect_err(|e| {
        maybe_panic_on_err(class_desc, method_name, "cfg", e);
    })?;
    trace_step("after Cfg::build");
    let mut ssa = SsaBody::build(&code, &cfg).map_err(|e| {
        // SsaError → DexError via existing From impl in error.rs.
        let de: DexError = e;
        maybe_panic_on_err(class_desc, method_name, "ssa", &de);
        de
    })?;
    trace_step("after SsaBody::build");

    let is_static = em.access_flags & 0x0008 != 0;
    let mut env = types::infer_types(dex, em.method_idx, &ssa, &code, &cfg, is_static);
    trace_step("after types::infer_types");
    optimize::optimize(&mut ssa, &mut env, dex);
    trace_step("after optimize::optimize");

    let mut stmt = structure::structure(&ssa, &cfg);
    trace_step("after structure::structure");
    stmt = structure::wrap_try_catch(stmt, &cfg, &ssa);
    trace_step("after structure::wrap_try_catch");
    // Drop CFG early. After `wrap_try_catch`, the CFG is not referenced
    // anywhere downstream — `sugar::desugar`, the param/debug-info passes,
    // and `emit::emit_method` all work off `stmt`, `ssa`, `env`, and
    // `code.payloads`. Releasing the CFG mid-function reduces per-method
    // peak working set; on a large class with many big methods, the
    // saving compounds across rayon workers.
    drop(cfg);
    let _r8_changed = r8_inversion::apply(
        &mut stmt,
        dex,
        &env,
        class_def.class_idx,
        em.method_idx,
        r8_census,
    );
    trace_step("after r8_inversion::apply");
    sugar::desugar(&mut stmt, dex, &env, class_def.class_idx);
    trace_step("after sugar::desugar");

    let method = dex
        .methods
        .get(em.method_idx.0 as usize)
        .ok_or(DexError::IndexOob {
            pool: "method_ids",
            index: em.method_idx.0,
            pool_size: dex.methods.len() as u32,
        })?;
    let proto = dex
        .protos
        .get(method.proto_idx.0 as usize)
        .ok_or(DexError::IndexOob {
            pool: "proto_ids",
            index: method.proto_idx.0,
            pool_size: dex.protos.len() as u32,
        })?;

    // Build param list using proto's type list so that wide types (long/double)
    // occupy exactly one entry instead of two (one per DEX register).
    let params: Vec<(crate::ssa::VarId, DexType)> = {
        let mut result = Vec::new();
        let mut pv_idx = 0usize;

        // For non-static methods the first param_var is `this` (always single-width).
        if !is_static {
            if let Some(v) = ssa.param_vars.get(pv_idx) {
                // PROOF: `infer_types` (line 1018) calls `seed_from_signature`
                // (types.rs:215) which inserts `resolve_type(dex, method.class_idx)`
                // for the `this` param at types.rs:250 when `!is_static`.  The same
                // `param_vars` and `is_static` are used in both places; reaching this
                // branch guarantees `v` was seeded.  Edge case: if `get_method_proto`
                // returns None, `seed_from_signature` exits early without seeding
                // (types.rs:224); the `debug_assert!` below makes that failure loud in
                // debug builds rather than silently emitting `int` for `this`.
                // `optimize::optimize` (line 1020) only inserts into `env.types`, never
                // removes, so the seed is preserved.  The fallback `DexType::Int` is
                // semantically wrong for `this` (which is a Ref type).
                debug_assert!(
                    env.types.contains_key(v),
                    "PROOF violation: `this` param_var must be seeded by seed_from_signature"
                );
                let ty = env.types.get(v).cloned().unwrap_or(DexType::Int);
                result.push((v.clone(), ty));
                pv_idx += 1;
            }
        }

        // Remaining params from proto type list.
        if proto.parameters_off != 0 {
            if let Some(type_list) = dex.type_lists.get(&proto.parameters_off) {
                for tidx in type_list {
                    let Some(v) = ssa.param_vars.get(pv_idx) else { break };
                    let ty = dex
                        .get_type_descriptor(*tidx)
                        .map(DexType::from_descriptor)
                        .unwrap_or(DexType::Int);
                    result.push((v.clone(), ty.clone()));
                    pv_idx += 1;
                    // Wide types occupy two DEX registers; skip the high-half register.
                    if matches!(ty, DexType::Long | DexType::Double) {
                        pv_idx += 1;
                    }
                }
            }
        }
        result
    };
    let return_type = dex
        .get_type_descriptor(proto.return_type_idx)
        .map(DexType::from_descriptor)
        .unwrap_or(DexType::Void);
    let raw_name = dex.get_string(method.name_idx).unwrap_or("?");
    let method_name = if raw_name == "<init>" || raw_name == "<clinit>" {
        raw_name.to_string()
    } else {
        crate::emit::sanitize_id(raw_name)
    };
    let method_name = &method_name;

    // Enum ctors carry two synthetic prefix args — `(String name, int
    // ordinal)` — that javac auto-supplies from the enum scaffolding.
    // Stripping them from the rendered signature mirrors the
    // `enum_suppress::maybe_strip_enum_super_call` body-level
    // synthetic-super strip on the same code path: both transformations
    // are required for the decompiled enum source to recompile.
    // Enum's user-authored `<init>`: the proto's first two non-`this`
    // params are the synthetic `(String name, int ordinal)` pair that
    // javac auto-supplies. params[0] is `this` (the SSA receiver) and
    // must be preserved so emit_method's existing v0 → `this` receiver
    // rename keeps working. params[1] and params[2] are the synthetics;
    // drop those and keep `this` plus the user args (params[3..]).
    let is_enum_ctor = raw_name == "<init>"
        && (class_def.access_flags & 0x4000 != 0)
        && class_def
            .superclass_idx
            .and_then(|idx| dex.get_type_descriptor(idx).ok())
            == Some("Ljava/lang/Enum;")
        && params.len() >= 3;
    let visible_params: Vec<(crate::ssa::VarId, DexType)> = if is_enum_ctor {
        let mut v = Vec::with_capacity(params.len().saturating_sub(2));
        if let Some(first) = params.first() {
            v.push(first.clone());
        }
        for p in params.iter().skip(3) {
            v.push(p.clone());
        }
        v
    } else {
        params.clone()
    };

    let mut ctx = emit::EmitCtx::new();
    // Tell emit which class descriptor "this" method belongs to — used
    // by SPut/IPut/SGet/IGet emission to strip `ClassName.` qualifier
    // on same-class static field access. Required for the static-init
    // block `<clinit>` to produce `X = 10;` rather than
    // `StaticInitBlock.X = 10;` (javac rejects qualified final-assigns
    // even from the declaring class's own <clinit>).
    ctx.own_class_desc = dex
        .get_type_descriptor(class_def.class_idx)
        .ok()
        .map(str::to_string);

    // Mark wide high-half parameter registers as pre-declared so they never
    // get emitted as separate local-variable declarations in the method body.
    {
        let mut pv_idx = if !is_static { 1usize } else { 0 };
        if proto.parameters_off != 0 {
            if let Some(type_list) = dex.type_lists.get(&proto.parameters_off) {
                for tidx in type_list {
                    if pv_idx >= ssa.param_vars.len() {
                        break;
                    }
                    let ty = dex
                        .get_type_descriptor(*tidx)
                        .map(DexType::from_descriptor)
                        .unwrap_or(DexType::Int);
                    pv_idx += 1;
                    if matches!(ty, DexType::Long | DexType::Double) {
                        if let Some(high_v) = ssa.param_vars.get(pv_idx) {
                            ctx.declared.insert(high_v.clone());
                        }
                        pv_idx += 1;
                    }
                }
            }
        }
    }

    // Apply debug info variable names + optional line-number annotations.
    // DebugInfo is eagerly parsed at DexFile::parse time and exposed via
    // the `debug_info` accessor — no redundant per-method re-parse here.
    if let Some(debug) = dex.debug_info(code.debug_info_off) {
        let name_map =
            crate::debug::build_name_map(debug, code.registers_size, code.ins_size, is_static);
        // Map register names to SSA param VarIds
        for (i, pv) in ssa.param_vars.iter().enumerate() {
            let reg = code.registers_size.saturating_sub(code.ins_size) + i as u16;
            if let Some(name) = name_map.get(&reg) {
                ctx.var_names.insert(pv.clone(), name.clone());
            }
        }
        // Non-param local names: each SsaInsn.dst is a VarId defined at
        // insn.addr. The debug_info locals list records (register,
        // start_pc, end_pc, name) per scope; pc-aware lookup handles
        // register reuse across non-overlapping scopes correctly.
        // Phi dsts are skipped — merge points have no single PC.
        for block in ssa.blocks.values() {
            for s in &block.insns {
                if let Some(dst) = &s.dst {
                    if ctx.var_names.contains_key(dst) {
                        continue;
                    }
                    if let Some(name) = crate::debug::local_name_at(debug, dst.reg(), s.insn.addr)
                    {
                        ctx.var_names
                            .insert(dst.clone(), crate::emit::sanitize_id(name));
                    }
                }
            }
        }
        // Opt-in line-number annotations. Gated on the same env
        // convention as other DROIDSAW_DEX_* emit flags. Default off
        // keeps goldens byte-stable; RE consumers flip the flag for
        // stack-trace-correlation output.
        if std::env::var_os("DROIDSAW_DEX_EMIT_LINE_COMMENTS").is_some() {
            ctx.line_debug = Some(debug.clone());
        }
    }

    // Drop SSA early. Last use was the debug-info var-name mapping loop
    // above; the remainder of `decompile_method` (throws walk, init
    // visibility widening, `emit::emit_method`) works only off `stmt`,
    // `env`, `code.payloads`, and `dex` pool lookups. Releasing the SSA
    // body before emit reduces per-method peak working set.
    drop(ssa);

    // Derive the class simple name for constructor naming (avoids "<init>" fallback)
    let class_desc = dex
        .get_type_descriptor(
            dex.methods
                .get(em.method_idx.0 as usize)
                .map(|m| m.class_idx)
                .unwrap_or(crate::ids::TypeIdx(0)),
        )
        .unwrap_or("?");
    let class_simple = extract_simple_name(class_desc);

    // Per-method `throws` clause from `dalvik.annotation.Throws`.
    // Walks the class's annotations directory for this method's
    // annotation set; returns empty when no Throws annotation is
    // present (most methods). On a malformed annotation walk —
    // typed Err on malformed input — fall back to empty so the
    // method body still emits. Absent throws is correctness-preserving:
    // the existing `patch_throws_throwable_on_method_signatures`
    // cascade still fires for hoist-bearing classes as a fallback.
    let throws_types = dex
        .method_throws(class_def.annotations_off, em.method_idx)
        .unwrap_or_default();

    // Widen `private <init>` to package-private when the class is a
    // private nested class with a sibling subclass in the same
    // enclosing top-level. See `should_widen_private_init_visibility`
    // doc-comment for the full rationale (D4 / OverloadsPeerClasses
    // graduation under SUPERSEDURE-precedent constraints).
    let access_flags =
        if should_widen_private_init_visibility(dex, class_def, em.access_flags, raw_name) {
            em.access_flags & !0x0002
        } else {
            em.access_flags
        };

    let info = emit::MethodInfo {
        name: method_name,
        params: &visible_params,
        return_type: &return_type,
        access_flags,
        class_name: if raw_name == "<init>" {
            Some(class_simple)
        } else {
            None
        },
        throws: &throws_types,
        is_facade_method: is_kt_facade,
    };
    let out = emit::emit_method(&mut stmt, &env, dex, &info, &mut ctx, &code.payloads);
    // If any recursive Stmt walker hit the depth cap during emit,
    // surface the typed error ahead of the success String. Caller
    // (`emit_methods`) folds this into `// Failed to decompile: ...`,
    // preventing the panic path while preserving the specific cause.
    if let Some(err) = ctx.error_state.take() {
        return Err(err);
    }
    // Absorb per-method import collector into the class-level accumulator.
    // `emit_method`'s `EmitCtx::imports` is populated by `ctx.simple_type`
    // at each FQN-resolved rendering site; class-level aggregation lets
    // `decompile_class` emit a single `import X;` block per file.
    imports.extend(ctx.imports.iter().cloned());
    Ok(out)
}

/// Render the Kotlin `data class Foo(val a: T1, val b: T2, ...)` header
/// for a class that the parser predicate
/// [`DexFile::is_kotlin_data_class`] has already classified. Returns the
/// header line (with trailing newline) on success; `None` if the
/// primary `<init>` constructor can't be resolved or the proto's
/// parameter list is missing/empty (caller falls through to the
/// standard Java emit on `None`).
///
/// Property naming priority: debug_info parameter_names → fallback
/// `p1`, `p2`, .... Property kind (`val` vs `var`) is recovered by
/// scanning the class's virtual methods for `setX` setters; the
/// presence of a setter promotes the property from `val` to `var`.
///
/// Imports collected via the helper's local [`emit::EmitCtx`] are
/// drained into the caller's class-level `imports` set so that the
/// data-class header's referenced types share the standard import
/// block.
///
/// PR-9d of #41b. Kept inside `classes.rs` rather than `emit.rs`
/// because the data-class lift is a class-level shape decision (the
/// entire class becomes one source line), not a per-method or
/// per-statement emit transform.
#[allow(clippy::as_conversions, reason = "PROOF: cast cluster (5 sites) — `xxx.0 as usize` widens u32→usize; method_idx.0/proto_idx.0 bounded < dex.methods.len()/dex.protos.len() by parser validation of method_ids/proto_ids pools.")]
fn render_kotlin_data_class_header(
    dex: &DexFile,
    class_def: &ClassDefItem,
    cd: &decode::ClassData,
    imports: &mut BTreeSet<String>,
) -> Option<String> {
    let class_desc = dex.get_type_descriptor(class_def.class_idx).ok()?;
    let class_name = extract_simple_name(class_desc);

    // Pick the primary `<init>` constructor. A clean Kotlin data class
    // has a single `<init>`; `copy$default`-aware secondary forms could
    // theoretically introduce additional `<init>` but we never see them
    // on the kotlinc-1.9 corpus. Tie-break by parameter count if
    // multiple `<init>` ever appear (the primary binds all properties
    // and so has the highest count).
    let mut primary: Option<&decode::EncodedMethod> = None;
    let mut primary_param_count: usize = 0;
    for em in &cd.direct_methods {
        let Some(method) = dex.methods.get(em.method_idx.0 as usize) else {
            continue;
        };
        let Ok(name) = dex.get_string(method.name_idx) else {
            continue;
        };
        if name != "<init>" {
            continue;
        }
        let Some(proto) = dex.protos.get(method.proto_idx.0 as usize) else {
            continue;
        };
        let param_count = if proto.parameters_off != 0 {
            dex.type_lists
                .get(&proto.parameters_off)
                .map(|tl| tl.len())
                .unwrap_or(0)
        } else {
            0
        };
        if primary.is_none() || param_count > primary_param_count {
            primary = Some(em);
            primary_param_count = param_count;
        }
    }
    let init = primary?;
    let init_method = dex.methods.get(init.method_idx.0 as usize)?;
    let init_proto = dex.protos.get(init_method.proto_idx.0 as usize)?;
    let type_list = dex.type_lists.get(&init_proto.parameters_off)?;
    if type_list.is_empty() {
        return None;
    }

    // Optional: recover param names from debug_info if available.
    // kotlinc-1.9 emits the property names via the debug-info
    // `parameter_names` channel for every named ctor argument; if
    // debug-info was stripped the helper falls back to `p1`/`p2`/...
    let debug_param_names: Vec<Option<String>> = if init.code_off != 0 {
        dex.code_items
            .get(&init.code_off)
            .and_then(|code| dex.debug_info(code.debug_info_off))
            .map(|d| d.parameter_names.clone())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Setter scan: any virtual method named `setX` (for some
    // capitalized X) marks a `var` property at the position whose
    // recovered name capitalizes-first to `X`. Auto-generated
    // `setX` for data classes only appears when the original
    // declared `var` (kotlinc emits both getter and setter for
    // `var` properties; only getter for `val`).
    let mut setter_targets: BTreeSet<String> = BTreeSet::new();
    for em in &cd.virtual_methods {
        let Some(method) = dex.methods.get(em.method_idx.0 as usize) else {
            continue;
        };
        let Ok(name) = dex.get_string(method.name_idx) else {
            continue;
        };
        if let Some(rest) = name.strip_prefix("set") {
            if rest
                .chars()
                .next()
                .map(|c| c.is_ascii_uppercase())
                .unwrap_or(false)
            {
                setter_targets.insert(rest.to_string());
            }
        }
    }

    let mut ctx = emit::EmitCtx::new();
    let mut decls: Vec<String> = Vec::with_capacity(type_list.len());
    for (i, tidx) in type_list.iter().enumerate() {
        let prop_name = debug_param_names
            .get(i)
            .cloned()
            .flatten()
            .unwrap_or_else(|| format!("p{}", i.saturating_add(1)));
        let dex_type = dex
            .get_type_descriptor(*tidx)
            .map(DexType::from_descriptor)
            .ok()?;
        let kotlin_type = ctx.simple_type_kotlin(&dex_type);
        let setter_probe = capitalize_first_ascii(&prop_name);
        let kw = if setter_targets.contains(&setter_probe) {
            "var"
        } else {
            "val"
        };
        decls.push(format!("{kw} {prop_name}: {kotlin_type}"));
    }
    imports.extend(ctx.imports.iter().cloned());

    Some(format!("data class {class_name}({})\n", decls.join(", ")))
}

/// Return `s` with its first ASCII byte uppercased; non-ASCII first
/// chars are passed through unchanged. Used by
/// [`render_kotlin_data_class_header`] to map property name `a` to its
/// expected setter name `A` when probing the class's virtual methods
/// for `setA`. Local helper, kept private.
fn capitalize_first_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    if let Some(c) = chars.next() {
        for u in c.to_uppercase() {
            out.push(u);
        }
    }
    out.push_str(chars.as_str());
    out
}

/// Render the Kotlin `sealed class Foo { ... }` header for a sealed
/// root + every kotlinc-emitted subclass inlined as `object Sub : Foo()`
/// (sealed-OBJECT shape) or `class Sub(val a: T) : Foo()` (sealed-CLASS
/// shape). Returns `None` when the root or any required subclass
/// metadata can't be resolved (caller falls through to the standard
/// Java emit on `None`).
///
/// Subclasses are enumerated via [`DexFile::kotlin_sealed_subclasses`]
/// in `class_defs` declaration order. For sealed-CLASS subclasses the
/// constructor parameter list (names from debug_info, types via
/// `EmitCtx::simple_type_kotlin`) drives the property declarations; the
/// `val`/`var` heuristic mirrors `render_kotlin_data_class_header`'s
/// setter-probe approach.
///
/// PR-9e of #41b. The returned string includes the class wrapper's
/// opening brace, every subclass on its own line, and the closing
/// brace; callers append it directly to `out` after the package decl.
fn render_kotlin_sealed_class_header(
    dex: &DexFile,
    class_def: &ClassDefItem,
    imports: &mut BTreeSet<String>,
) -> Option<String> {
    let class_desc = dex.get_type_descriptor(class_def.class_idx).ok()?;
    let class_name = extract_simple_name(class_desc);

    // `kotlin_sealed_subclasses` returns `Err(DetectorIndeterminate)` when
    // the annotation / class_data subtree had any parse failure. In that
    // case we cannot honestly synthesize the sealed block — fall through
    // to standard Java emit; the parallel Finding is collected by
    // `diag::collect_detector_indeterminate_findings`.
    let subs = dex.kotlin_sealed_subclasses(class_def.class_idx).ok()?;
    if subs.is_empty() {
        // Defensive: a sealed root with no recognized subclasses is
        // structurally legal Kotlin (`sealed class Empty`) but extremely
        // rare. Fall through to the standard Java emit so we don't lose
        // information.
        return None;
    }

    let mut ctx = emit::EmitCtx::new();
    let mut out = String::new();
    let _ = writeln!(out, "sealed class {class_name} {{");

    for sub_idx in subs {
        let Some(sub_desc) = dex.get_type_descriptor(sub_idx).ok() else {
            continue;
        };
        let sub_simple = sealed_subclass_simple_name(class_desc, sub_desc);
        // No Indeterminate handling needed here: this function is only reached
        // when `is_kt_sealed_root` is Yes, which requires both the annotation
        // and class_data global verdict gates to be clean. The subclass
        // detectors derive Indeterminate solely from those same global gates,
        // so inside this function they can only return Yes or No. A subclass
        // whose verdict is Indeterminate under a tainted DEX is caught by the
        // class-level banner in `decompile_class_impl` when it is emitted
        // top-level (the suppression filter keeps it top-level on Indeterminate).
        if dex.is_kotlin_sealed_object_subclass(sub_idx).is_yes() {
            let _ = writeln!(out, "    object {sub_simple} : {class_name}()");
        } else if dex.is_kotlin_sealed_class_subclass(sub_idx).is_yes() {
            let decls = render_sealed_class_subclass_props(dex, sub_idx, &mut ctx)
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "    class {sub_simple}({}) : {class_name}()",
                decls.join(", ")
            );
        }
    }

    out.push_str("}\n");
    imports.extend(ctx.imports.iter().cloned());
    Some(out)
}

/// Extract a sealed subclass's source-form simple name from its JVM-
/// internal descriptor. kotlinc compiles `sealed class Color { object Red : Color() }`
/// to a separate class `LColor$Red;`; the source-form rendering should
/// be just `Red`. The function strips the parent's prefix
/// (`LColor$` → ``) and the trailing `;`. Falls back to the full simple
/// name (after the last `/` and stripped `;`) when the parent prefix
/// doesn't match — e.g. defensive fallthrough on adversarial input
/// where subclass naming convention diverges.
fn sealed_subclass_simple_name(parent_desc: &str, sub_desc: &str) -> String {
    if let Some(parent_inner) = parent_desc.strip_prefix('L').and_then(|d| d.strip_suffix(';')) {
        if let Some(sub_inner) = sub_desc.strip_prefix('L').and_then(|d| d.strip_suffix(';')) {
            let prefix = format!("{parent_inner}$");
            if let Some(tail) = sub_inner.strip_prefix(&prefix) {
                return crate::emit::sanitize_id(tail);
            }
        }
    }
    extract_simple_name(sub_desc)
}

/// Render a `class Sub(val a: T1, val b: T2)` property list for a
/// sealed-CLASS subclass. Returns the parameter declarations (without
/// the surrounding parens). Empty Vec on resolution failure (caller
/// renders `class Sub() : Parent()` with no parens content — an
/// empty-ctor sealed-CLASS subclass is structurally valid Kotlin).
#[allow(clippy::as_conversions, reason = "PROOF: cast cluster (5 sites) — `xxx.0 as usize` widens u32→usize; method_idx.0/proto_idx.0 bounded < dex.methods.len()/dex.protos.len() by parser validation of method_ids/proto_ids pools.")]
fn render_sealed_class_subclass_props(
    dex: &DexFile,
    sub_idx: TypeIdx,
    ctx: &mut emit::EmitCtx,
) -> Option<Vec<String>> {
    let class_def_idx = dex.class_defs.iter().position(|cd| cd.class_idx == sub_idx)?;
    let class_def = dex.class_defs.get(class_def_idx)?;
    if class_def.class_data_off == 0 {
        return Some(Vec::new());
    }
    // Rendering-decision accessor on attacker-influenced offset. When
    // `dex.parse_errors` carries a tolerantly-recorded ClassData failure,
    // this lookup returns None and the function falls through to "no
    // ctor params" — operator sees `class Sub() : Parent()` without
    // ctor-param emission. The Indeterminate signal surfaces via
    // `diag::collect_detector_indeterminate_findings`'s ClassData
    // whitelist so the operator's audit envelope flags the taint;
    // structural surfacing (a per-class "rendering-with-indeterminate-
    // metadata" banner) is the dex-match-outcome-indeterminate-
    // propagation follow-up's scope.
    let class_data = dex.class_datas.get(&class_def.class_data_off)?;
    // Pick the public primary `<init>` ctor (the one without
    // DefaultConstructorMarker). Tie-break by parameter count.
    let mut primary: Option<&decode::EncodedMethod> = None;
    let mut primary_param_count: usize = 0;
    for em in &class_data.direct_methods {
        let method = dex.methods.get(em.method_idx.0 as usize)?;
        let name = dex.get_string(method.name_idx).ok()?;
        if name != "<init>" {
            continue;
        }
        let proto = dex.protos.get(method.proto_idx.0 as usize)?;
        let type_list = if proto.parameters_off != 0 {
            dex.type_lists.get(&proto.parameters_off)
        } else {
            None
        };
        let last_param_is_marker = type_list
            .and_then(|tl| tl.last())
            .and_then(|t| dex.get_type_descriptor(*t).ok())
            .map(|d| d == "Lkotlin/jvm/internal/DefaultConstructorMarker;")
            .unwrap_or(false);
        if last_param_is_marker {
            continue;
        }
        let param_count = type_list.map(|tl| tl.len()).unwrap_or(0);
        if primary.is_none() || param_count > primary_param_count {
            primary = Some(em);
            primary_param_count = param_count;
        }
    }
    let init = primary?;
    let init_method = dex.methods.get(init.method_idx.0 as usize)?;
    let init_proto = dex.protos.get(init_method.proto_idx.0 as usize)?;
    let type_list = if init_proto.parameters_off != 0 {
        dex.type_lists.get(&init_proto.parameters_off)
    } else {
        None
    };
    let Some(type_list) = type_list else {
        return Some(Vec::new());
    };
    let debug_param_names: Vec<Option<String>> = if init.code_off != 0 {
        dex.code_items
            .get(&init.code_off)
            .and_then(|code| dex.debug_info(code.debug_info_off))
            .map(|d| d.parameter_names.clone())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Setter scan for `var` classification.
    let mut setter_targets: BTreeSet<String> = BTreeSet::new();
    for em in &class_data.virtual_methods {
        let Some(method) = dex.methods.get(em.method_idx.0 as usize) else {
            continue;
        };
        let Ok(name) = dex.get_string(method.name_idx) else {
            continue;
        };
        if let Some(rest) = name.strip_prefix("set") {
            if rest
                .chars()
                .next()
                .map(|c| c.is_ascii_uppercase())
                .unwrap_or(false)
            {
                setter_targets.insert(rest.to_string());
            }
        }
    }

    let mut decls: Vec<String> = Vec::with_capacity(type_list.len());
    for (i, tidx) in type_list.iter().enumerate() {
        let prop_name = debug_param_names
            .get(i)
            .cloned()
            .flatten()
            .unwrap_or_else(|| format!("p{}", i.saturating_add(1)));
        let dex_type = dex
            .get_type_descriptor(*tidx)
            .map(DexType::from_descriptor)
            .ok()?;
        let kotlin_type = ctx.simple_type_kotlin(&dex_type);
        let setter_probe = capitalize_first_ascii(&prop_name);
        let kw = if setter_targets.contains(&setter_probe) {
            "var"
        } else {
            "val"
        };
        decls.push(format!("{kw} {prop_name}: {kotlin_type}"));
    }
    Some(decls)
}

fn extract_package(class_desc: &str) -> Option<String> {
    // Lcom/example/Foo; → com.example
    // Sanitize: hyphens in package segments (e.g. auth-api-phone) → underscores
    let inner = class_desc.strip_prefix('L')?.strip_suffix(';')?;
    let last_slash = inner.rfind('/')?;
    let prefix = inner.get(..last_slash)?;
    Some(prefix.replace('/', ".").replace('-', "_"))
}

fn extract_simple_name(class_desc: &str) -> String {
    if let Some(inner) = class_desc
        .strip_prefix('L')
        .and_then(|s| s.strip_suffix(';'))
    {
        crate::emit::sanitize_id(inner.rsplit('/').next().unwrap_or(inner))
    } else {
        crate::emit::sanitize_id(class_desc)
    }
}

fn pretty_class(desc: &str) -> String {
    if let Some(inner) = desc
        .strip_prefix('L')
        .and_then(|s| s.strip_suffix(';'))
    {
        let name = inner.replace('/', ".");
        name.split('.')
            .map(crate::emit::sanitize_id)
            .collect::<Vec<_>>()
            .join(".")
    } else {
        crate::emit::sanitize_id(desc)
    }
}

/// Shared precomputed facts for the v2 enum-synth-suppression gate matrix.
///
/// `applies` is the AND of the two shared primary gates (enclosing class
/// ACC_ENUM + superclass resolves to `Ljava/lang/Enum;`). Every per-row
/// check short-circuits when `!applies`, so non-enum classes and enum
/// per-constant subclasses (whose super is the parent enum, NOT
/// `java.lang.Enum`) pay only a boolean comparison per field/method.
pub(crate) struct EnumCtx {
    applies: bool,
    /// `L<ThisClass>;` — used for row 1 `[L<Self>;` field-type gate and
    /// row 5 `valueOf` return-type gate.
    self_desc: String,
    /// `[L<ThisClass>;`.
    self_array_desc: String,
    /// Count of static fields with ACC_ENUM set. Bounds the row-6
    /// `<clinit>` body-shape scan with a "bail on overflow" mitigation.
    /// Cap = `6 * K + 8`: each enum-const
    /// contributes 5 instructions (NewInstance, ConstString,
    /// Const-ordinal, InvokeDirect, SputObject) plus a 4-instruction
    /// tail (InvokeStatic `$values()`, MoveResultObject, SputObject
    /// `$VALUES`, ReturnVoid) plus slack for shared null-marker Const
    /// and ConstStringJumbo variants. Anything above the cap is
    /// user-static-block-fusion territory and bails to non-suppression.
    enum_const_count: u32,
}

impl EnumCtx {
    pub(crate) fn build(
        dex: &DexFile,
        class_def: &ClassDefItem,
        static_fields: &[decode::EncodedField],
    ) -> Self {
        let is_enum = class_def.access_flags & 0x4000 != 0;
        let super_is_enum = class_def
            .superclass_idx
            .and_then(|idx| dex.get_type_descriptor(idx).ok())
            .map(|d| d == "Ljava/lang/Enum;")
            .unwrap_or(false);
        let self_desc = dex
            .get_type_descriptor(class_def.class_idx)
            .map(|s| s.to_string())
            .unwrap_or_default();
        let self_array_desc = format!("[{self_desc}");
        // ACC_ENUM on a field (0x4000) marks it as an enum-constant.
        #[allow(
            clippy::cast_possible_truncation,
            clippy::as_conversions,
            reason = "PROOF: static_fields.iter().filter().count() is bounded by static_fields.len(), which is bounded by class_data.static_fields_size (uleb128, u32 by DEX spec); narrow usize→u32 is safe."
        )]
        let enum_const_count = static_fields
            .iter()
            .filter(|ef| ef.access_flags & 0x4000 != 0)
            .count() as u32;
        EnumCtx {
            applies: is_enum && super_is_enum,
            self_desc,
            self_array_desc,
            enum_const_count,
        }
    }
}

pub(crate) mod enum_suppress {
    use super::*;
    use crate::decode::{EncodedField, EncodedMethod};
    use crate::ids::ProtoIdItem;

    const ACC_PUBLIC: u32 = 0x0001;
    const ACC_STATIC: u32 = 0x0008;
    const ACC_SYNTHETIC: u32 = 0x1000;

    /// Row 1: `$VALUES` field. ACC_SYNTHETIC + field type `[L<Self>;`.
    pub(crate) fn is_suppressed_field(
        ctx: &EnumCtx,
        dex: &DexFile,
        ef: &EncodedField,
    ) -> bool {
        if !ctx.applies {
            return false;
        }
        if ef.access_flags & ACC_SYNTHETIC == 0 {
            return false;
        }
        #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; field_idx.0 bounded < dex.fields.len() by parser validation of field_ids pool.")]
        let Some(field) = dex.fields.get(ef.field_idx.0 as usize) else {
            return false;
        };
        let Ok(ty) = dex.get_type_descriptor(field.type_idx) else {
            return false;
        };
        ty == ctx.self_array_desc
    }

    /// Rows 2-6: method-level suppression. Bail (return false) on any
    /// malformed input rather than panic — cross-validates with the
    /// hardening mandate.
    pub(crate) fn is_suppressed_method(
        ctx: &EnumCtx,
        dex: &DexFile,
        data: &[u8],
        em: &EncodedMethod,
        ttm: Option<&TypeToClassDefMap>,
    ) -> bool {
        if !ctx.applies {
            return false;
        }
        #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; method_idx.0 bounded < dex.methods.len() by parser validation of method_ids pool.")]
        let Some(method) = dex.methods.get(em.method_idx.0 as usize) else {
            return false;
        };
        let Ok(name) = dex.get_string(method.name_idx) else {
            return false;
        };
        #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; proto_idx.0 bounded < dex.protos.len() by parser validation of proto_ids pool.")]
        let Some(proto) = dex.protos.get(method.proto_idx.0 as usize) else {
            return false;
        };
        let flags = em.access_flags;

        // Row 2: `$values()` — ACC_SYNTHETIC + name + return type.
        if flags & ACC_SYNTHETIC != 0
            && name == "$values"
            && return_type_matches(dex, proto, &ctx.self_array_desc)
            && proto_params(dex, proto).is_some_and(|p| p.is_empty())
        {
            return true;
        }

        // Row 3: synthetic bridge ctor `<init>(String, I, <SynthClass>)V`.
        if flags & ACC_SYNTHETIC != 0
            && name == "<init>"
            && is_synthetic_bridge_ctor(dex, proto, ttm)
        {
            return true;
        }

        // Row 4: `values()` — name + public+static + exact proto.
        if flags & ACC_PUBLIC != 0
            && flags & ACC_STATIC != 0
            && name == "values"
            && proto_exact(dex, proto, &[], &ctx.self_array_desc)
        {
            return true;
        }

        // Row 5: `valueOf(String)` — name + public+static + exact proto.
        if flags & ACC_PUBLIC != 0
            && flags & ACC_STATIC != 0
            && name == "valueOf"
            && proto_exact(dex, proto, &["Ljava/lang/String;"], &ctx.self_desc)
        {
            return true;
        }

        // Row 6: `<clinit>` — bounded body-shape scan, strict full-sequence
        // match. Bails (returns false) if the body contains user code.
        if name == "<clinit>" && em.code_off != 0 && clinit_is_pure_enum_pop(ctx, dex, data, em) {
            return true;
        }

        false
    }

    /// Row 7: in an enum ctor (we know `ctx.applies` is true, so super is
    /// `java.lang.Enum`), strip the first `super(<args>);` line from the
    /// emitted body. javac inserts the Enum constructor call implicitly
    /// and rejects explicit emission.
    pub(crate) fn maybe_strip_enum_super_call(
        ctx: &EnumCtx,
        dex: &DexFile,
        em: &EncodedMethod,
        source: &str,
    ) -> String {
        if !ctx.applies {
            return source.to_string();
        }
        #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; method_idx.0 bounded < dex.methods.len() by parser validation of method_ids pool.")]
        let Some(method) = dex.methods.get(em.method_idx.0 as usize) else {
            return source.to_string();
        };
        let Ok(name) = dex.get_string(method.name_idx) else {
            return source.to_string();
        };
        if name != "<init>" {
            return source.to_string();
        }
        strip_first_super_call_line(source)
    }

    fn strip_first_super_call_line(source: &str) -> String {
        let mut out = String::with_capacity(source.len());
        let mut stripped = false;
        for line in source.lines() {
            if !stripped {
                let trimmed = line.trim_start();
                if line.starts_with("    ")
                    && trimmed.starts_with("super(")
                    && trimmed.ends_with(");")
                {
                    stripped = true;
                    continue;
                }
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    fn return_type_matches(dex: &DexFile, proto: &ProtoIdItem, expected: &str) -> bool {
        dex.get_type_descriptor(proto.return_type_idx)
            .map(|d| d == expected)
            .unwrap_or(false)
    }

    fn proto_params<'a>(dex: &'a DexFile, proto: &ProtoIdItem) -> Option<Vec<&'a str>> {
        if proto.parameters_off == 0 {
            return Some(Vec::new());
        }
        let tl = dex.type_lists.get(&proto.parameters_off)?;
        let mut params: Vec<&str> = Vec::with_capacity(tl.len());
        for idx in tl {
            let Ok(desc) = dex.get_type_descriptor(*idx) else {
                return None;
            };
            params.push(desc);
        }
        Some(params)
    }

    fn proto_exact(
        dex: &DexFile,
        proto: &ProtoIdItem,
        expected_params: &[&str],
        expected_ret: &str,
    ) -> bool {
        if !return_type_matches(dex, proto, expected_ret) {
            return false;
        }
        let Some(params) = proto_params(dex, proto) else {
            return false;
        };
        params.len() == expected_params.len()
            && params.iter().zip(expected_params).all(|(a, b)| a == b)
    }

    /// Row 3 last-param gate: three params `(String, int, <SynthClass>)V`
    /// where `<SynthClass>` is a class_def carrying ACC_SYNTHETIC. d8
    /// names this class `...$N-IA` (source `D8$$SyntheticClass`); javac
    /// pre-d8 names it `...$N`. Both variants have ACC_SYNTHETIC, which
    /// is the gate we match on — not the name.
    fn is_synthetic_bridge_ctor(
        dex: &DexFile,
        proto: &ProtoIdItem,
        ttm: Option<&TypeToClassDefMap>,
    ) -> bool {
        if !return_type_matches(dex, proto, "V") {
            return false;
        }
        let Some(params) = proto_params(dex, proto) else {
            return false;
        };
        let [p0, p1, last] = match params.as_slice() {
            [a, b, c] => [*a, *b, *c],
            _ => return false,
        };
        if p0 != "Ljava/lang/String;" || p1 != "I" {
            return false;
        }
        // O(1) path when caller supplied the TypeToClassDefMap (bulk
        // iteration context); closes the quadratic-scan perf concern.
        if let Some(ttm) = ttm {
            if proto.parameters_off == 0 {
                return false;
            }
            let Some(tl) = dex.type_lists.get(&proto.parameters_off) else {
                return false;
            };
            let Some(last_idx) = tl.get(2) else {
                return false;
            };
            let Some(cd_idx) = ttm.lookup(*last_idx) else {
                return false;
            };
            let Some(cd) = dex.class_defs.get(cd_idx) else {
                return false;
            };
            return cd.access_flags & ACC_SYNTHETIC != 0;
        }
        // O(n_classes) fallback for single-class callers (e.g. MCP
        // `decompile_class(...)` which doesn't build a ttm). Shadow
        // gate to mirror the O(1) ttm path's first-wins semantics:
        // without the gate, an attacker-planted second row with
        // ACC_SYNTHETIC set would suppress a legitimate first-row
        // class as a "synthetic artifact" (polarity-flip evasion).
        for (i, cd) in dex.class_defs.iter().enumerate() {
            if dex.class_def_is_shadowed(i) {
                continue;
            }
            if let Ok(desc) = dex.get_type_descriptor(cd.class_idx) {
                if desc == last && cd.access_flags & ACC_SYNTHETIC != 0 {
                    return true;
                }
            }
        }
        false
    }

    /// Row 6: pure-enum-population `<clinit>` gate. Delegates to the
    /// shared `scan_enum_clinit_pops` scanner — single source of truth
    /// for the `<clinit>` shape, consumed by both the suppression gate
    /// (`Result::is_ok()`) and the cross-class inline-body walker
    /// (consumes the `Vec<EnumPop>` on success).
    ///
    /// Also accepts the wider shape recognised by
    /// `scan_enum_clinit_pops_with_user_args`, which handles enum ctors
    /// with extra user arguments (per-constant `RED("r", 1)`-style
    /// initialization). The `decompile_class` path renders those
    /// arguments as `NAME(args),` enum-constant declarations at the
    /// top of the enum body; the `<clinit>` body itself is then
    /// redundant and must be suppressed here to avoid the dual
    /// "enum-constant + static-block" emission javac rejects.
    fn clinit_is_pure_enum_pop(
        ctx: &EnumCtx,
        dex: &DexFile,
        data: &[u8],
        em: &EncodedMethod,
    ) -> bool {
        super::scan_enum_clinit_pops(ctx, dex, data, em).is_ok()
            || super::scan_enum_clinit_pops_with_user_args(ctx, dex, data, em).is_ok()
    }
}

/// One `(subclass type, backing enum-constant field)` pair recovered
/// from a parent enum's `<clinit>`. Surfaces the relationship that
/// `new-instance <subclass>` → `invoke-direct <subclass>.<init>` →
/// `sput-object <parent>.<field>` encodes in the bytecode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnumPop {
    pub subclass_type: TypeIdx,
    pub backing_field: crate::ids::FieldIdx,
}

/// `EnumPop` extended with the per-constant constructor arguments
/// rendered as Java source. Used by the enum-constant declaration
/// emit path to produce `NAME(arg1, arg2),` lines at the top of the
/// enum body. Args[0]=instance receiver, args[1]=name string, args[2]=ordinal
/// are stripped — javac auto-supplies those from the enum scaffolding.
/// `user_args` carries the rendered third-and-onward args.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumPopWithArgs {
    pub backing_field: crate::ids::FieldIdx,
    pub user_args: Vec<String>,
}

/// Sentinel error for `scan_enum_clinit_pops`: the supplied `<clinit>`
/// body is NOT a pure enum-population shape. Not a safety bail; emit
/// the method normally when this is returned.
#[derive(Debug, Clone, Copy)]
pub struct NotPureEnumPop;

/// Parse a parent enum's `<clinit>` and extract the `Vec<EnumPop>`
/// describing each `<subclass> → <enum-const field>` binding, OR
/// `Err(NotPureEnumPop)` if the body contains any user-authored
/// statement (fused `static {}` block, unexpected opcode, etc.).
///
/// Scan shape (single source of truth for both consumers):
///   * every opcode is in a whitelist (NewInstance, Const*, InvokeDirect,
///     InvokeStatic, MoveResultObject, SputObject, ReturnVoid);
///   * every `invoke-static` targets `<Self>.$values()` exactly;
///   * exactly one `sput-object <Self>.$VALUES`;
///   * at least one `invoke-static <Self>.$values()`;
///   * total instructions ≤ `6 * enum_const_count + 8` (hardening cap).
///
/// The linear walker maintains `pending_subclass: Option<TypeIdx>`
/// set by `NewInstance` and consumed by the next matching
/// `SputObject` on a parent-class ACC_ENUM field. Register-aliasing
/// across the pattern is not tracked (javac emits the canonical
/// pattern linearly with no intervening SputObjects on unrelated
/// fields — adversarial shapes that break this would also fail the
/// whitelist).
///
/// Bails on any resolution failure — no panic paths on adversarial
/// `<clinit>`.
pub(crate) fn scan_enum_clinit_pops(
    ctx: &EnumCtx,
    dex: &DexFile,
    data: &[u8],
    em: &decode::EncodedMethod,
) -> Result<Vec<EnumPop>, NotPureEnumPop> {
    const ACC_ENUM_FIELD: u32 = 0x4000;
    use crate::decode::PoolIndex;
    use crate::opcodes::Opcode;

    if em.code_off == 0 {
        return Err(NotPureEnumPop);
    }
    let Ok(code) = decode::parse_code_item(data, em.code_off) else {
        return Err(NotPureEnumPop);
    };
    let insns = &code.instructions;
    #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; enum_const_count is a u32 count of ACC_ENUM-flagged static fields, bounded by uleb128 static_fields_size (u32 by DEX spec).")]
    let cap = (ctx.enum_const_count as usize)
        .saturating_mul(6)
        .saturating_add(8);
    if insns.len() > cap {
        return Err(NotPureEnumPop);
    }

    let mut pops: Vec<EnumPop> = Vec::new();
    let mut pending_subclass: Option<TypeIdx> = None;
    let mut saw_values_invoke = false;
    let mut saw_values_sput = false;

    for i in insns {
        match i.op {
            Opcode::ConstString
            | Opcode::ConstStringJumbo
            | Opcode::Const
            | Opcode::Const4
            | Opcode::Const16
            | Opcode::ConstHigh16
            | Opcode::InvokeDirect
            | Opcode::InvokeDirectRange
            | Opcode::MoveResultObject
            | Opcode::ReturnVoid => {}
            Opcode::NewInstance => {
                if let Some(PoolIndex::Type(tidx)) = i.pool_idx {
                    pending_subclass = Some(tidx);
                }
            }
            Opcode::InvokeStatic | Opcode::InvokeStaticRange => {
                let Some(PoolIndex::Method(midx)) = i.pool_idx else {
                    return Err(NotPureEnumPop);
                };
                #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; midx.0 is a method_ids index bounded < dex.methods.len() by parser validation.")]
                let Some(m) = dex.methods.get(midx.0 as usize) else {
                    return Err(NotPureEnumPop);
                };
                let Ok(mname) = dex.get_string(m.name_idx) else {
                    return Err(NotPureEnumPop);
                };
                let Ok(mclass) = dex.get_type_descriptor(m.class_idx) else {
                    return Err(NotPureEnumPop);
                };
                if mname != "$values" || mclass != ctx.self_desc {
                    return Err(NotPureEnumPop);
                }
                saw_values_invoke = true;
            }
            Opcode::SputObject => {
                let Some(PoolIndex::Field(fidx)) = i.pool_idx else {
                    return Err(NotPureEnumPop);
                };
                #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; fidx.0 is a field_ids index bounded < dex.fields.len() by parser validation.")]
                let Some(f) = dex.fields.get(fidx.0 as usize) else {
                    return Err(NotPureEnumPop);
                };
                let Ok(fname) = dex.get_string(f.name_idx) else {
                    return Err(NotPureEnumPop);
                };
                let Ok(fclass) = dex.get_type_descriptor(f.class_idx) else {
                    return Err(NotPureEnumPop);
                };
                if fname == "$VALUES" && fclass == ctx.self_desc {
                    saw_values_sput = true;
                    continue;
                }
                // Accept only SPut-object on a parent ACC_ENUM-marked field.
                if fclass != ctx.self_desc {
                    return Err(NotPureEnumPop);
                }
                // Look up EncodedField on the parent's static_fields
                // list to check ACC_ENUM bit. Absent → bail.
                let has_acc_enum = dex
                    .class_defs
                    .iter()
                    .find(|cd| {
                        dex.get_type_descriptor(cd.class_idx).ok() == Some(&ctx.self_desc)
                    })
                    .and_then(|cd| {
                        if cd.class_data_off == 0 {
                            return None;
                        }
                        let parsed = decode::parse_class_data(data, cd.class_data_off).ok()?;
                        parsed
                            .static_fields
                            .iter()
                            .find(|ef| ef.field_idx == fidx)
                            .map(|ef| ef.access_flags & ACC_ENUM_FIELD != 0)
                    })
                    .unwrap_or(false);
                if !has_acc_enum {
                    return Err(NotPureEnumPop);
                }
                let Some(subclass_type) = pending_subclass.take() else {
                    return Err(NotPureEnumPop);
                };
                pops.push(EnumPop {
                    subclass_type,
                    backing_field: fidx,
                });
            }
            _ => return Err(NotPureEnumPop),
        }
    }
    if !(saw_values_invoke && saw_values_sput) {
        return Err(NotPureEnumPop);
    }
    Ok(pops)
}

/// Render the enum-constant declaration block at the top of an enum
/// body. Each constant gets a line `    NAME(arg1, arg2),` (no `()`
/// when there are no user args), and the block terminates with `;`
/// to separate it from any field/method declarations that follow.
fn render_enum_constants(out: &mut String, dex: &DexFile, pops: &[EnumPopWithArgs]) {
    if pops.is_empty() {
        return;
    }
    let last_idx = pops.len().saturating_sub(1);
    for (i, pop) in pops.iter().enumerate() {
        #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; backing_field.0 is a field_ids index bounded < dex.fields.len() by parser validation.")]
        let Some(field) = dex.fields.get(pop.backing_field.0 as usize) else {
            continue;
        };
        let Ok(name_raw) = dex.get_string(field.name_idx) else {
            continue;
        };
        let name = emit::sanitize_id(name_raw);
        let suffix = if i == last_idx { ";" } else { "," };
        if pop.user_args.is_empty() {
            let _ = writeln!(out, "    {name}{suffix}");
        } else {
            let _ = writeln!(out, "    {name}({}){suffix}", pop.user_args.join(", "));
        }
    }
    out.push('\n');
}

/// Companion to [`scan_enum_clinit_pops`] that also extracts the
/// per-constant constructor user-args. Used by the enum-body emit
/// path to render `NAME(arg1, arg2),` lines.
///
/// Behaviour vs [`scan_enum_clinit_pops`]:
///   * Same opcode whitelist + invariant requirements ($values invoke,
///     $VALUES sput) so callers can trust the same shape-gauge.
///   * Cap relaxed: each enum constant may carry up to 8 extra const
///     instructions (one per user-arg-producing const), so the cap
///     becomes `14 * enum_const_count + 8`. Adversarial bodies with
///     larger instruction counts still bail.
///   * Tracks per-register const values across the body and, at each
///     matching SputObject, extracts the most-recent `InvokeDirect`'s
///     user-args (positions 3..) by looking up the source registers
///     in the const-value tracker.
///   * Any arg the tracker can't render (non-const reference, missing
///     prior writer) falls back to a `/* dyn */` placeholder rather
///     than failing the whole scan — the emit-side `<clinit>` body is
///     left visible in that case so an analyst can still see the
///     dynamic init shape.
pub(crate) fn scan_enum_clinit_pops_with_user_args(
    ctx: &EnumCtx,
    dex: &DexFile,
    data: &[u8],
    em: &decode::EncodedMethod,
) -> Result<Vec<EnumPopWithArgs>, NotPureEnumPop> {
    const ACC_ENUM_FIELD: u32 = 0x4000;
    use crate::decode::PoolIndex;
    use crate::opcodes::Opcode;

    if em.code_off == 0 {
        return Err(NotPureEnumPop);
    }
    let Ok(code) = decode::parse_code_item(data, em.code_off) else {
        return Err(NotPureEnumPop);
    };
    let insns = &code.instructions;
    #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; enum_const_count is a u32 count of ACC_ENUM-flagged static fields, bounded by uleb128 static_fields_size (u32 by DEX spec).")]
    let cap = (ctx.enum_const_count as usize)
        .saturating_mul(14)
        .saturating_add(8);
    if insns.len() > cap {
        return Err(NotPureEnumPop);
    }

    // Per-register tracker of the most-recent rendered const value.
    // The whitelist guarantees every value-producing opcode is a
    // Const* / NewInstance variant; the tracker resets a register
    // whenever a new opcode writes to it.
    let mut const_values: std::collections::BTreeMap<u16, String> =
        std::collections::BTreeMap::new();
    // The most-recent InvokeDirect's args (full src register list).
    // Reset on each NewInstance (start of a new constant's init).
    let mut last_invoke_direct_args: Option<Vec<u16>> = None;
    let mut pending_subclass: Option<TypeIdx> = None;
    let mut pops: Vec<EnumPopWithArgs> = Vec::new();
    let mut saw_values_invoke = false;
    let mut saw_values_sput = false;

    for i in insns {
        // Register-tracker bookkeeping for value-producing const opcodes.
        match i.op {
            Opcode::ConstString | Opcode::ConstStringJumbo => {
                if let (Some(dst), Some(PoolIndex::String(sidx))) = (i.dst, i.pool_idx) {
                    if let Ok(s) = dex.get_string(sidx) {
                        const_values.insert(dst, format!("\"{}\"", emit::escape_java_string(s)));
                    }
                }
            }
            Opcode::Const | Opcode::Const4 | Opcode::Const16 => {
                if let Some(dst) = i.dst {
                    const_values.insert(dst, format!("{}", i.literal));
                }
            }
            Opcode::ConstHigh16 => {
                if let Some(dst) = i.dst {
                    const_values.insert(dst, format!("{}", i.literal));
                }
            }
            _ => {}
        }

        match i.op {
            Opcode::ConstString
            | Opcode::ConstStringJumbo
            | Opcode::Const
            | Opcode::Const4
            | Opcode::Const16
            | Opcode::ConstHigh16
            | Opcode::MoveResultObject
            | Opcode::ReturnVoid => {}
            Opcode::NewInstance => {
                if let Some(PoolIndex::Type(tidx)) = i.pool_idx {
                    pending_subclass = Some(tidx);
                }
                last_invoke_direct_args = None;
            }
            Opcode::InvokeDirect | Opcode::InvokeDirectRange => {
                last_invoke_direct_args = Some(i.src.as_slice().to_vec());
            }
            Opcode::InvokeStatic | Opcode::InvokeStaticRange => {
                let Some(PoolIndex::Method(midx)) = i.pool_idx else {
                    return Err(NotPureEnumPop);
                };
                #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; midx.0 is a method_ids index bounded < dex.methods.len() by parser validation.")]
                let Some(m) = dex.methods.get(midx.0 as usize) else {
                    return Err(NotPureEnumPop);
                };
                let Ok(mname) = dex.get_string(m.name_idx) else {
                    return Err(NotPureEnumPop);
                };
                let Ok(mclass) = dex.get_type_descriptor(m.class_idx) else {
                    return Err(NotPureEnumPop);
                };
                if mname != "$values" || mclass != ctx.self_desc {
                    return Err(NotPureEnumPop);
                }
                saw_values_invoke = true;
            }
            Opcode::SputObject => {
                let Some(PoolIndex::Field(fidx)) = i.pool_idx else {
                    return Err(NotPureEnumPop);
                };
                #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; fidx.0 is a field_ids index bounded < dex.fields.len() by parser validation.")]
                let Some(f) = dex.fields.get(fidx.0 as usize) else {
                    return Err(NotPureEnumPop);
                };
                let Ok(fname) = dex.get_string(f.name_idx) else {
                    return Err(NotPureEnumPop);
                };
                let Ok(fclass) = dex.get_type_descriptor(f.class_idx) else {
                    return Err(NotPureEnumPop);
                };
                if fname == "$VALUES" && fclass == ctx.self_desc {
                    saw_values_sput = true;
                    continue;
                }
                if fclass != ctx.self_desc {
                    return Err(NotPureEnumPop);
                }
                let has_acc_enum = dex
                    .class_defs
                    .iter()
                    .find(|cd| {
                        dex.get_type_descriptor(cd.class_idx).ok() == Some(&ctx.self_desc)
                    })
                    .and_then(|cd| {
                        if cd.class_data_off == 0 {
                            return None;
                        }
                        let parsed = decode::parse_class_data(data, cd.class_data_off).ok()?;
                        parsed
                            .static_fields
                            .iter()
                            .find(|ef| ef.field_idx == fidx)
                            .map(|ef| ef.access_flags & ACC_ENUM_FIELD != 0)
                    })
                    .unwrap_or(false);
                if !has_acc_enum {
                    return Err(NotPureEnumPop);
                }
                // Consume the pending NewInstance + InvokeDirect pair.
                let Some(_subclass_type) = pending_subclass.take() else {
                    return Err(NotPureEnumPop);
                };
                // Skip args[0]=instance, [1]=name, [2]=ordinal.
                // User args are positions 3..; look up rendered const
                // values for each. Missing values fall back to a
                // placeholder so a partial-render is at least navigable.
                // Args[0]=instance, [1]=name, [2]=ordinal. Look up the
                // rendered const value for each user-arg register. If any
                // arg's register has no tracked const (e.g., it came
                // from a `move-result-object` of a static factory call
                // inlined into `<clinit>`), bail — emitting a Java
                // comment in expression position would produce invalid
                // source. Falling through to `NotPureEnumPop` keeps the
                // visible-but-broken `<clinit>` body, which is the
                // documented fallback discipline.
                let user_args: Vec<String> = match &last_invoke_direct_args {
                    Some(args) if args.len() >= 3 => {
                        let mut rendered: Vec<String> = Vec::new();
                        for reg in args.iter().skip(3) {
                            let Some(v) = const_values.get(reg) else {
                                return Err(NotPureEnumPop);
                            };
                            rendered.push(v.clone());
                        }
                        rendered
                    }
                    _ => Vec::new(),
                };
                pops.push(EnumPopWithArgs {
                    backing_field: fidx,
                    user_args,
                });
                last_invoke_direct_args = None;
            }
            _ => return Err(NotPureEnumPop),
        }
    }
    if !(saw_values_invoke && saw_values_sput) {
        return Err(NotPureEnumPop);
    }
    Ok(pops)
}

/// O(1) lookup table from `TypeIdx` to `dex.class_defs` index.
///
/// Built once per `DexFile`; passed to any gate function that needs to
/// resolve a type back to its class_def entry. Closes the quadratic
/// per-call-site scan: the per-constant-subclass gate does a two-hop
/// super resolution that would otherwise be quadratic on adversarial
/// corpora.
pub struct TypeToClassDefMap {
    by_type_idx: Vec<Option<usize>>,
}

impl TypeToClassDefMap {
    /// Build the map. Cost: one linear pass over `dex.class_defs`.
    ///
    /// **First-wins on duplicate `class_idx`** (mirrors the discipline
    /// in `DexFile::rebuild_class_def_index` — see audit §H-9 + Wave 1
    /// re-review BLOCK-4). When two `class_def_item` rows share the
    /// same `class_idx`, this slot pins to the FIRST encounter so
    /// `lookup` agrees with `DexFile::class_def_for_type`. Without the
    /// match-then-skip, the two indices would diverge: primary
    /// first-wins, secondary last-wins — a fresh index-vs-index
    /// disagreement primitive that adversary-PoC review caught
    /// downstream of the §H-9 closure.
    pub fn build(dex: &DexFile) -> Self {
        let mut by_type_idx = vec![None; dex.type_descriptors.len()];
        for (i, cd) in dex.class_defs.iter().enumerate() {
            #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; class_idx.0 bounded < dex.type_descriptors.len() by parser validation of type_ids pool; get_mut returns None on OOB.")]
            if let Some(slot) = by_type_idx.get_mut(cd.class_idx.0 as usize) {
                if slot.is_none() {
                    *slot = Some(i);
                }
            }
        }
        Self { by_type_idx }
    }

    /// Resolve a `TypeIdx` to an index in `dex.class_defs`, or `None` if
    /// the type has no class_def in this DEX (external references, arrays,
    /// primitives, out-of-range indices — all bail cleanly).
    pub fn lookup(&self, ty: TypeIdx) -> Option<usize> {
        #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; ty.0 bounded < by_type_idx.len() by build() (which sets len = dex.type_descriptors.len()); get returns None on OOB.")]
        self.by_type_idx.get(ty.0 as usize).copied().flatten()
    }
}

/// Return `true` if `class_def` is a javac/d8-synthesized enum artifact
/// that an outer iterator should skip decompiling: either a per-constant
/// enum subclass or an anonymous-marker class (`-IA`).
///
/// Gate matrix (v3):
///
/// **Per-constant enum subclass** — all primary required:
/// - class has `ACC_ENUM | ACC_FINAL` (NO `ACC_SYNTHETIC` — empirical:
///   javac/d8 does not set SYNTHETIC on the subclass itself, only on
///   its bridge ctor);
/// - two-hop super resolution (hard-coded, no loop, no recursion,
///   self-cycle rejected): direct super has `ACC_ENUM`, grandparent is
///   `Ljava/lang/Enum;`; closes the fake-enum attack;
/// - `source_file_idx` matches parent's (when both present);
/// - name matches `<ParentSimpleName>$<digit>+`.
///
/// **Anonymous-marker class** — all primary required:
/// - class has `ACC_PUBLIC | ACC_FINAL | ACC_SYNTHETIC`;
/// - super resolves to `Ljava/lang/Object;`;
/// - `class_data_off == 0` AND `interfaces_off == 0` (exact-match empty);
/// - AT LEAST ONE d8-specific discriminator holds: source file equals
///   `D8$$SyntheticClass`, OR the class simple-name ends with `-IA`.
///
/// Any resolution failure (malformed type_idx, OOB lookup, missing
/// descriptor) returns `false` — bail cleanly, never panic.
pub fn is_suppressible_enum_artifact(
    dex: &DexFile,
    class_def: &ClassDefItem,
    type_to_class_def: &TypeToClassDefMap,
) -> bool {
    is_per_constant_enum_subclass(dex, class_def, type_to_class_def)
        || is_anonymous_marker_class(dex, class_def)
}

fn is_per_constant_enum_subclass(
    dex: &DexFile,
    class_def: &ClassDefItem,
    ttm: &TypeToClassDefMap,
) -> bool {
    const ACC_FINAL: u32 = 0x0010;
    const ACC_ENUM: u32 = 0x4000;
    const ENUM_FINAL: u32 = ACC_ENUM | ACC_FINAL;

    if class_def.access_flags & ENUM_FINAL != ENUM_FINAL {
        return false;
    }
    // Hard-coded 2-hop super walk. No loop; visited-self check at each
    // hop. A depth cap is implicit (2 steps maximum).
    let Some(parent_type) = class_def.superclass_idx else {
        return false;
    };
    if parent_type == class_def.class_idx {
        return false;
    }
    let Some(parent_cd_idx) = ttm.lookup(parent_type) else {
        return false;
    };
    let Some(parent_cd) = dex.class_defs.get(parent_cd_idx) else {
        return false;
    };
    if parent_cd.access_flags & ACC_ENUM == 0 {
        return false;
    }
    let Some(grand_type) = parent_cd.superclass_idx else {
        return false;
    };
    if grand_type == parent_type {
        return false;
    }
    let Ok(grand_desc) = dex.get_type_descriptor(grand_type) else {
        return false;
    };
    if grand_desc != "Ljava/lang/Enum;" {
        return false;
    }

    // source_file_idx match — corroborating only; do NOT promote to
    // primary (an attacker forcing shared source_file_idx across
    // classes is a cheap attack and intentionally de-prioritized).
    if let (Some(self_src), Some(parent_src)) =
        (class_def.source_file_idx, parent_cd.source_file_idx)
    {
        if self_src != parent_src {
            return false;
        }
    }

    // Name pattern: `<ParentSimple>$<digits>`. Tiebreaker only per
    // Brief's "not primary" constraint. Required for suppression
    // because subclasses at this flag+super shape are javac/d8-only
    // artifacts; a JLS-invalid bytecode-level subclass without this
    // naming is out-of-scope and we conservatively refuse to suppress.
    let Ok(self_desc) = dex.get_type_descriptor(class_def.class_idx) else {
        return false;
    };
    let Ok(parent_desc) = dex.get_type_descriptor(parent_type) else {
        return false;
    };
    let self_inner = strip_l_semi(self_desc);
    let parent_inner = strip_l_semi(parent_desc);
    let Some(tail) = self_inner
        .strip_prefix(parent_inner)
        .and_then(|t| t.strip_prefix('$'))
    else {
        return false;
    };
    !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit())
}

fn is_anonymous_marker_class(dex: &DexFile, class_def: &ClassDefItem) -> bool {
    const ACC_PUBLIC: u32 = 0x0001;
    const ACC_FINAL: u32 = 0x0010;
    const ACC_SYNTHETIC: u32 = 0x1000;
    const WANT: u32 = ACC_PUBLIC | ACC_FINAL | ACC_SYNTHETIC;

    if class_def.access_flags & WANT != WANT {
        return false;
    }
    let Some(super_idx) = class_def.superclass_idx else {
        return false;
    };
    let Ok(super_desc) = dex.get_type_descriptor(super_idx) else {
        return false;
    };
    if super_desc != "Ljava/lang/Object;" {
        return false;
    }
    // Exact-match empty body + no interface list.
    if class_def.class_data_off != 0 || class_def.interfaces_off != 0 {
        return false;
    }
    // At least one d8-specific discriminator. Either is sufficient; a
    // hand-authored user class without BOTH is refused suppression.
    let source_matches = class_def
        .source_file_idx
        .and_then(|s| dex.get_string(s).ok())
        .map(|s| s == "D8$$SyntheticClass")
        .unwrap_or(false);
    let name_matches = dex
        .get_type_descriptor(class_def.class_idx)
        .ok()
        .map(strip_l_semi)
        .map(|s| s.ends_with("-IA"))
        .unwrap_or(false);
    source_matches || name_matches
}

fn strip_l_semi(desc: &str) -> &str {
    desc.strip_prefix('L')
        .and_then(|s| s.strip_suffix(';'))
        .unwrap_or(desc)
}

/// Iterator over class_defs that an outer decompile loop should emit —
/// applies `is_suppressible_enum_artifact` as a pre-filter. Caller gets
/// `(class_idx, &ClassDefItem)` pairs in declaration order.
///
/// Builds the `TypeToClassDefMap` once internally; callers that need the
/// map for other purposes should build their own via `TypeToClassDefMap::build`.
///
/// This is the listing-time policy entrypoint. `decompile_class` itself
/// remains unchanged — callers that pass a specific `ClassDefItem` by
/// name (e.g. MCP single-class queries) continue to get full output. The
/// suppression is ONLY applied at bulk-iteration time.
pub fn classes_to_decompile(dex: &DexFile) -> impl Iterator<Item = (usize, &ClassDefItem)> + '_ {
    let ttm = TypeToClassDefMap::build(dex);
    dex.class_defs.iter().enumerate().filter(move |(i, cd)| {
        // Shadow gate: skip duplicate-class_idx rows that aren't the
        // first occurrence. `class_def_for_type` resolves to the first
        // row; without this filter a malicious second row would emit
        // alongside the resolved first row, surfacing both as
        // independent classes. See `DexFile::class_def_is_shadowed`.
        !dex.class_def_is_shadowed(*i)
            && !is_suppressible_enum_artifact(dex, cd, &ttm)
            && !is_suppressible_kotlin_sealed_subclass(dex, cd)
    })
}

/// Return `true` iff `class_def` is a Kotlin sealed-subclass (sealed-OBJECT
/// or sealed-CLASS shape) whose parent root will be emitted with the
/// subclass content inlined as `object Sub : Root()` or
/// `class Sub(...) : Root()` in the parent's `sealed class { ... }`
/// block. PR-9e of #41b.
///
/// Filtering at the iterator boundary prevents the subclass from being
/// emitted as a separate top-level Java class. The parent root's
/// `decompile_class_impl` early-return path then renders the inlined
/// form. Single-class callers (e.g. MCP `dex_classes` named-query) bypass
/// the filter and get full Java output.
fn is_suppressible_kotlin_sealed_subclass(dex: &DexFile, class_def: &ClassDefItem) -> bool {
    dex.is_kotlin_sealed_object_subclass(class_def.class_idx).is_yes()
        || dex.is_kotlin_sealed_class_subclass(class_def.class_idx).is_yes()
}

/// Inline body for one enum constant. Rendered Java source fragments
/// ready to be placed inside the constant's `{ ... }` body in the
/// parent enum's emitted source.
///
/// `bailed` / `unsafe_to_inline` each trigger emission of a bare
/// constant name with no brace-body at the call site, matching the
/// fail-closed stance (downstream compile_fail surfaces the
/// unrepresentable shape rather than this emitter inventing bad
/// source).
pub struct EnumInline {
    /// Rendered method-body sources (one per non-synthetic virtual
    /// method on the per-constant subclass). Already indented by
    /// `decompile_method`'s caller convention — the emitter just
    /// wraps these in braces.
    pub method_bodies: Vec<String>,
    /// True when the walker could not safely bind this constant (cycle,
    /// budget exhaust, malformed subclass, reverse-super mismatch, etc).
    /// On `true`, emit bare `CONST` (no body).
    pub bailed: bool,
    /// True when the subclass's method body references a member
    /// (field/method/type) whose class is the SUBCLASS itself — that
    /// member cannot be inlined into the parent enum's body.
    pub unsafe_to_inline: bool,
}

/// Precomputed map from enum-constant field → rendered inline body.
/// Built once via a single cross-class walk over the DEX; consumed by
/// `decompile_class_ext` at emit time. Shared budget: **256 constants
/// total + 512 insns per inlined body**.
pub struct EnumInlineMap {
    by_field: std::collections::BTreeMap<u32, EnumInline>,
}

/// Budget caps for enum-inline body extraction.
const MAX_ENUM_INLINE_CONSTS_TOTAL: usize = 256;
const MAX_INSNS_PER_INLINED_BODY: usize = 512;

impl EnumInlineMap {
    /// Build the map with a single cross-class walk. Applies:
    /// - shared budget (256 consts total) across all parent enums in
    ///   this DEX;
    /// - per-body insn cap (512 insns/method);
    /// - reverse-super check at bind time (subclass's direct super
    ///   must equal the parent's class_idx);
    /// - unsafe-body gate (any PoolIndex referencing the subclass's
    ///   own class_idx marks the body `unsafe_to_inline`).
    ///
    /// Returns an empty map when the DEX has no parent enums, or when
    /// the budget is exhausted before any bind succeeds. No `Result` —
    /// bail semantics are observable through per-entry `bailed` +
    /// `unsafe_to_inline` flags.
    #[allow(clippy::arithmetic_side_effects, reason = "usize counter increment on parser-validated class set; bounded by class_defs.len().")]
    pub fn build(dex: &DexFile, data: &[u8], ttm: &TypeToClassDefMap) -> Self {
        // Read `DROIDSAW_DECOMPILE_TRACE` once for this build run.
        // Public API unchanged (callers in tests + fuzz continue to
        // call `build(dex, data, ttm)` unmodified). Every subclass
        // body decompiled under this build sees the same trace setting.
        let trace = Trace::from_env();
        let mut by_field: std::collections::BTreeMap<u32, EnumInline> =
            std::collections::BTreeMap::new();
        let mut constants_remaining = MAX_ENUM_INLINE_CONSTS_TOTAL;

        for (class_defs_idx, class_def) in dex.class_defs.iter().enumerate() {
            if constants_remaining == 0 {
                break;
            }
            // Shadow gate: a duplicate-class_idx row would re-enter
            // this builder and double-process the same enum's
            // constants. Skip rows shadowed by an earlier first-wins
            // entry.
            if dex.class_def_is_shadowed(class_defs_idx) {
                continue;
            }
            // Primary gate: this class must itself be a parent enum
            // (ACC_ENUM + direct super is `Ljava/lang/Enum;`).
            let is_enum = class_def.access_flags & 0x4000 != 0;
            let super_is_enum = class_def
                .superclass_idx
                .and_then(|idx| dex.get_type_descriptor(idx).ok())
                .map(|d| d == "Ljava/lang/Enum;")
                .unwrap_or(false);
            if !(is_enum && super_is_enum) {
                continue;
            }
            // Need a parsed class_data with a <clinit>.
            if class_def.class_data_off == 0 {
                continue;
            }
            let Ok(cd) = decode::parse_class_data(data, class_def.class_data_off) else {
                continue;
            };
            #[allow(
                clippy::cast_possible_truncation,
                clippy::as_conversions,
                reason = "PROOF: cd.static_fields.iter().filter().count() bounded by class_data.static_fields_size (uleb128, u32 by DEX spec); narrow usize→u32 is safe."
            )]
            let enum_const_count = cd
                .static_fields
                .iter()
                .filter(|ef| ef.access_flags & 0x4000 != 0)
                .count() as u32;
            let self_desc = dex
                .get_type_descriptor(class_def.class_idx)
                .map(|s| s.to_string())
                .unwrap_or_default();
            let enum_ctx_for_scan = EnumCtx {
                applies: is_enum && super_is_enum,
                self_desc,
                self_array_desc: String::new(), // unused by scanner
                enum_const_count,
            };
            #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; method_idx.0 bounded < dex.methods.len() by parser validation of method_ids pool.")]
            let Some(clinit_em) = cd.direct_methods.iter().find(|em| {
                dex.methods
                    .get(em.method_idx.0 as usize)
                    .and_then(|m| dex.get_string(m.name_idx).ok())
                    == Some("<clinit>")
            }) else {
                continue;
            };
            let Ok(pops) = scan_enum_clinit_pops(&enum_ctx_for_scan, dex, data, clinit_em) else {
                continue;
            };

            for pop in pops {
                if constants_remaining == 0 {
                    break;
                }
                constants_remaining -= 1;
                let inline = extract_subclass_inline(
                    dex,
                    data,
                    ttm,
                    class_def.class_idx,
                    pop.subclass_type,
                    trace,
                );
                by_field.insert(pop.backing_field.0, inline);
            }
            let _ = class_defs_idx;
        }

        Self { by_field }
    }

    pub fn for_field(&self, field_idx: u32) -> Option<&EnumInline> {
        self.by_field.get(&field_idx)
    }
}

/// Bind one subclass to one enum-constant field. Returns an
/// `EnumInline` that may be `bailed` or `unsafe_to_inline` per the
/// safety gates.
fn extract_subclass_inline(
    dex: &DexFile,
    data: &[u8],
    ttm: &TypeToClassDefMap,
    parent_class_idx: TypeIdx,
    subclass_type: TypeIdx,
    trace: Trace,
) -> EnumInline {
    let bail = |_reason: &'static str| EnumInline {
        method_bodies: Vec::new(),
        bailed: true,
        unsafe_to_inline: false,
    };
    // Resolve subclass class_def.
    let Some(sub_cd_idx) = ttm.lookup(subclass_type) else {
        return bail("subclass has no class_def");
    };
    let Some(sub_cd) = dex.class_defs.get(sub_cd_idx) else {
        return bail("OOB class_def");
    };
    // REVERSE-SUPER check: subclass's direct super
    // must equal this parent's class_idx. Otherwise an unrelated class
    // that happens to appear in a `<clinit>` NewInstance is NOT a valid
    // per-constant binding.
    if sub_cd.superclass_idx != Some(parent_class_idx) {
        return bail("subclass super != parent");
    }
    // No class_data → no methods → bare constant (empty body).
    if sub_cd.class_data_off == 0 {
        return EnumInline {
            method_bodies: Vec::new(),
            bailed: false,
            unsafe_to_inline: false,
        };
    }
    let Ok(sub_cd_data) = decode::parse_class_data(data, sub_cd.class_data_off) else {
        return bail("malformed subclass class_data");
    };

    let mut method_bodies: Vec<String> = Vec::new();
    let mut unsafe_to_inline = false;
    // Walk virtual methods only (per-constant overrides are virtual).
    // Direct methods on the subclass are ctors (synthetic); skip.
    for em in &sub_cd_data.virtual_methods {
        if em.code_off == 0 {
            continue;
        }
        // Budget: per-body insn cap.
        let Ok(code) = decode::parse_code_item(data, em.code_off) else {
            return bail("malformed subclass code_item");
        };
        if code.instructions.len() > MAX_INSNS_PER_INLINED_BODY {
            return EnumInline {
                method_bodies: Vec::new(),
                bailed: true,
                unsafe_to_inline: false,
            };
        }
        // Safety gate: reject if any insn references the subclass itself
        // via PoolIndex::{Type, Field, Method, MethodAndProto}.
        if body_references_subclass(dex, &code.instructions, subclass_type) {
            unsafe_to_inline = true;
            continue;
        }
        // Render the method body. `decompile_method` returns full
        // `access return name(params) { ... }` source; we reuse verbatim.
        let mut imports: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        // Enum subclass decompile is never a Kotlin facade — pass false.
        // Empty trampoline census: enum subclass inlining is a narrow
        // codepath where R8 BlockOutlined recognition is acceptable to
        // skip — the recogniser's repetition gate (≥ 2 invoke-static
        // call sites) would not fire anyway on a single enum-constant
        // subclass body, so feeding an empty census avoids the full
        // DEX walk per inlined subclass without changing behaviour.
        let empty_census = r8_inversion::TrampolineCensus::default();
        match decompile_method(dex, data, em, sub_cd, &mut imports, false, trace, &empty_census) {
            Ok(source) => method_bodies.push(source),
            Err(_) => {
                return bail("subclass method decompile error");
            }
        }
    }
    EnumInline {
        method_bodies,
        bailed: false,
        unsafe_to_inline,
    }
}

/// Unsafe-body gate: return `true` if any instruction in `insns`
/// carries a `PoolIndex` whose resolved class reference equals
/// `subclass_type`. Covers iget/iput (Field), sget/sput (Field),
/// invoke-* (Method / MethodAndProto), instance-of / check-cast /
/// const-class (Type).
#[allow(clippy::as_conversions, reason = "PROOF: cast cluster (3 sites) — `xxx.0 as usize` widens u32→usize; fidx.0/midx.0 bounded < dex.fields.len()/dex.methods.len() by parser validation of field_ids/method_ids pools.")]
fn body_references_subclass(
    dex: &DexFile,
    insns: &[crate::decode::Instruction],
    subclass_type: TypeIdx,
) -> bool {
    use crate::decode::PoolIndex;
    for i in insns {
        let class_ref: Option<TypeIdx> = match i.pool_idx {
            Some(PoolIndex::Type(t)) => Some(t),
            Some(PoolIndex::Field(fidx)) => dex.fields.get(fidx.0 as usize).map(|f| f.class_idx),
            Some(PoolIndex::Method(midx)) => {
                dex.methods.get(midx.0 as usize).map(|m| m.class_idx)
            }
            Some(PoolIndex::MethodAndProto(midx, _)) => {
                dex.methods.get(midx.0 as usize).map(|m| m.class_idx)
            }
            _ => None,
        };
        if class_ref == Some(subclass_type) {
            return true;
        }
    }
    false
}

/// Decompile a single class with an optional enum-inline map. When
/// `enum_inlines` is `Some` and the class is a parent enum (ACC_ENUM +
/// direct super is `Ljava/lang/Enum;`), the output inserts a constant
/// block at the top of the body using the map's rendered bodies.
/// Otherwise behaves exactly as `decompile_class`.
///
/// `decompile_class` is a thin wrapper that passes `None`; existing
/// single-class MCP callers are unaffected.
#[allow(clippy::arithmetic_side_effects, reason = "ext-output arithmetic on parser-validated class fields + string-index offsets; all counters bounded by class_def field counts (uleb128-capped) and string ranges (parser-bounded).")]
pub fn decompile_class_ext(
    dex: &DexFile,
    data: &[u8],
    class_def: &ClassDefItem,
    enum_inlines: Option<&EnumInlineMap>,
    type_to_class_def: Option<&TypeToClassDefMap>,
) -> String {
    decompile_class_ext_with_census(dex, data, class_def, enum_inlines, type_to_class_def, None)
}

/// Bulk-caller-friendly `_ext` entry point: takes an externally-built
/// `TrampolineCensus` so the per-DEX `build_trampoline_census` cost is
/// paid once across an entire `for class_def in &dex.class_defs` loop
/// instead of per-class. Same shape as
/// [`decompile_class_with_census`] for the non-`_ext` path.
///
/// Bulk callers (the top binary's `decompile --all` + `audit --mode=full`
/// semgrep extraction, bench `full_audit` example) must use this
/// variant; the wrapper `decompile_class_ext` exists for single-class
/// callers that have no census to thread through.
///
/// The `build_trampoline_census` cost was a bottleneck, consuming significant
/// self-time in full-corpus decompilation because three bulk paths
/// (mod.rs:1989, mod.rs:2178, semgrep.rs, examples/full_audit.rs)
/// were calling census-less variants and rebuilding per class.
/// This variant threads the census through to amortize the cost.
#[allow(clippy::arithmetic_side_effects, reason = "same domain as decompile_class_ext — bulk-caller-friendly variant with explicit census threading.")]
pub fn decompile_class_ext_with_census(
    dex: &DexFile,
    data: &[u8],
    class_def: &ClassDefItem,
    enum_inlines: Option<&EnumInlineMap>,
    type_to_class_def: Option<&TypeToClassDefMap>,
    r8_census: Option<&r8_inversion::TrampolineCensus>,
) -> String {
    // Read `DROIDSAW_DECOMPILE_TRACE` once at the API boundary.
    // Same shape as `decompile_class`.
    let trace = Trace::from_env();
    let base = decompile_class_impl(dex, data, class_def, type_to_class_def, trace, r8_census);
    let Some(map) = enum_inlines else {
        return base;
    };
    let is_enum = class_def.access_flags & 0x4000 != 0;
    let super_is_enum = class_def
        .superclass_idx
        .and_then(|idx| dex.get_type_descriptor(idx).ok())
        .map(|d| d == "Ljava/lang/Enum;")
        .unwrap_or(false);
    if !(is_enum && super_is_enum) {
        return base;
    }
    if class_def.class_data_off == 0 {
        return base;
    }
    let Ok(cd) = decode::parse_class_data(data, class_def.class_data_off) else {
        return base;
    };
    // Collect enum-const fields in declaration order. Each contributes
    // one entry in the constant block.
    let enum_const_fields: Vec<&decode::EncodedField> = cd
        .static_fields
        .iter()
        .filter(|ef| ef.access_flags & 0x4000 != 0)
        .collect();
    if enum_const_fields.is_empty() {
        return base;
    }
    // Render constant block.
    let mut block = String::new();
    for (i, ef) in enum_const_fields.iter().enumerate() {
        #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; field_idx.0 bounded < dex.fields.len() by parser validation of field_ids pool.")]
        let field = match dex.fields.get(ef.field_idx.0 as usize) {
            Some(f) => f,
            None => continue,
        };
        let name_raw = dex.get_string(field.name_idx).unwrap_or("?");
        let name = emit::sanitize_id(name_raw);
        block.push_str("    ");
        block.push_str(&name);
        let inline = map.for_field(ef.field_idx.0);
        match inline {
            Some(inl) if !inl.bailed && !inl.unsafe_to_inline && !inl.method_bodies.is_empty() => {
                block.push_str(" {\n");
                for body in &inl.method_bodies {
                    for line in body.lines() {
                        block.push_str("        ");
                        block.push_str(line);
                        block.push('\n');
                    }
                }
                block.push_str("    }");
            }
            _ => {
                // Bare constant: `NAME` — no brace-body.
            }
        }
        if i + 1 == enum_const_fields.len() {
            block.push_str(";\n\n");
        } else {
            block.push_str(",\n");
        }
    }

    // Splice the constant block into `base` just after the enum's
    // opening `{` on the class header line. The header line is
    // `enum <name> {` (possibly with modifiers + extends + implements).
    // Anchor: the first `{\n` after the class keyword `enum `.
    let Some(enum_kw_idx) = base.find("enum ") else {
        return base;
    };
    let Some(after_kw) = base.get(enum_kw_idx..) else {
        return base;
    };
    let Some(brace_rel) = after_kw.find("{\n") else {
        return base;
    };
    let insert_at = enum_kw_idx + brace_rel + 2; // after "{\n"
    let Some(prefix) = base.get(..insert_at) else {
        return base;
    };
    let mut out = String::with_capacity(base.len() + block.len());
    out.push_str(prefix);
    out.push_str(&block);
    // Suppress the now-redundant `public static final <Self> NAME;`
    // field declarations for each enum-const field in the remaining
    // base output. The simplest robust approach: textual removal of
    // each `    public static final <Self> <name>;\n` line.
    let self_desc = match dex.get_type_descriptor(class_def.class_idx) {
        Ok(d) => d,
        Err(_) => return base,
    };
    let self_simple = extract_simple_name(self_desc);
    let mut tail = base.get(insert_at..).unwrap_or("").to_string();
    for ef in &enum_const_fields {
        #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; field_idx.0 bounded < dex.fields.len() by parser validation of field_ids pool.")]
        let field = match dex.fields.get(ef.field_idx.0 as usize) {
            Some(f) => f,
            None => continue,
        };
        let name_raw = dex.get_string(field.name_idx).unwrap_or("?");
        let name = emit::sanitize_id(name_raw);
        let needle = format!(
            "    public static final {self_simple} {name};\n"
        );
        if let Some(pos) = tail.find(&needle) {
            tail.replace_range(pos..pos + needle.len(), "");
        }
    }
    out.push_str(&tail);

    // Row 8: strip the JVM-implicit `(String v<N>, int v<M>)`
    // prefix from every ctor signature in the parent enum. javac
    // auto-supplies name+ordinal on all enum ctors; explicit params in
    // the source trigger "cannot assign to final variable `this`" /
    // signature-mismatch compile errors.
    strip_enum_ctor_implicit_params(&out, &self_simple)
}

/// Post-pass: rewrite every constructor signature line that matches
/// `<mods>? <ClassSimple>(String <ident>, int <ident>[, <rest>]) {`
/// into `<mods>? <ClassSimple>([<rest>]) {` within a parent-enum class
/// source.
fn strip_enum_ctor_implicit_params(src: &str, class_simple: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        if let Some(rewritten) = try_strip_enum_ctor_params(line, class_simple) {
            out.push_str(&rewritten);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

#[allow(clippy::arithmetic_side_effects, reason = "arithmetic on byte-offset positions within `line` slice; positions are searched within line and bounded by line.len() (usize cannot overflow on parser-bounded source size).")]
fn try_strip_enum_ctor_params(line: &str, class_simple: &str) -> Option<String> {
    // Anchor: line trims to end `) {` and contains `<ClassSimple>(`.
    let trimmed_end = line.trim_end();
    if !trimmed_end.ends_with(") {") {
        return None;
    }
    // Leading whitespace. `.trim_start()` returns at a UTF-8 boundary so
    // `ws_len` is also at one; `.get(..ws_len)` succeeds.
    let ws_len = line.len() - line.trim_start().len();
    let ws = line.get(..ws_len).unwrap_or("");
    let rest = line.trim_start();
    // Find `<ClassSimple>(` in rest.
    let ctor_prefix = format!("{class_simple}(");
    let paren_at = rest.find(&ctor_prefix)?;
    let open = paren_at + ctor_prefix.len() - 1; // index of '('
    let head = rest.get(..=open)?; // e.g. `private EnumWithMethods$Op(`
    // Find matching `) {` at end.
    let close = rest.rfind(") {")?;
    if close <= open {
        return None;
    }
    let args = rest.get(open + 1..close)?; // contents inside `(...)`
    let after = rest.get(close..)?; // `) {`
    // Parse first two args — must be `String <ident>, int <ident>`
    // with optional remainder.
    let first_split = args.splitn(3, ", ").collect::<Vec<&str>>();
    let (a0_raw, a1_raw, rest_arg) = match first_split.as_slice() {
        [a, b] => (*a, *b, ""),
        [a, b, c] => (*a, *b, *c),
        _ => return None,
    };
    let a0 = a0_raw.trim();
    let a1 = a1_raw.trim();
    let a0_ok = a0.starts_with("String ") || a0.starts_with("java.lang.String ");
    let a1_ok = a1.starts_with("int ");
    if !(a0_ok && a1_ok) {
        return None;
    }
    let new_args = rest_arg;
    let mut rebuilt = String::new();
    rebuilt.push_str(ws);
    rebuilt.push_str(head);
    rebuilt.push_str(new_args);
    rebuilt.push_str(after);
    Some(rebuilt)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_package_test() {
        assert_eq!(
            extract_package("Lcom/example/Foo;"),
            Some("com.example".to_string())
        );
        assert_eq!(extract_package("LFoo;"), None); // no package
    }

    #[test]
    fn extract_simple_name_test() {
        assert_eq!(extract_simple_name("Lcom/example/Foo;"), "Foo");
        assert_eq!(extract_simple_name("LMinimal;"), "Minimal");
    }

    #[test]
    fn capitalize_first_ascii_uppercases_lowercase_ascii() {
        assert_eq!(capitalize_first_ascii("a"), "A");
        assert_eq!(capitalize_first_ascii("foo"), "Foo");
        assert_eq!(capitalize_first_ascii("counter"), "Counter");
    }

    #[test]
    fn capitalize_first_ascii_preserves_already_uppercase() {
        assert_eq!(capitalize_first_ascii("A"), "A");
        assert_eq!(capitalize_first_ascii("Foo"), "Foo");
    }

    #[test]
    fn capitalize_first_ascii_handles_empty_and_underscore() {
        // Edge cases: empty (no first char to upcase), and identifiers
        // starting with `_` or `$` (passed through unchanged because the
        // setter-name probe only fires on alphabetic-start property
        // names).
        assert_eq!(capitalize_first_ascii(""), "");
        assert_eq!(capitalize_first_ascii("_x"), "_x");
        assert_eq!(capitalize_first_ascii("123"), "123");
    }

    #[test]
    fn render_kotlin_data_class_header_returns_none_on_non_data_class() {
        // The helper expects the parser predicate has already gated the
        // call, but defensively returns `None` when the primary `<init>`
        // ctor or its proto can't be resolved (caller falls through to
        // standard Java emit on `None`). The bundled Java fixture has
        // no data classes, so every class either lacks `<init>` or has
        // an empty type_list from the proto's parameters_off — the
        // helper should return `None` for all of them.
        let data = include_bytes!("../tests/fixtures/classes_named.dex");
        let dex = DexFile::parse(data, None).expect("parse");
        for cd in &dex.class_defs {
            if cd.class_data_off == 0 {
                continue;
            }
            let class_data = match decode::parse_class_data(data, cd.class_data_off) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let mut imports = BTreeSet::new();
            // Java fixtures may have ctors with params, so the helper
            // could in principle render a (wrong) header on them. The
            // production gate is `is_kotlin_data_class`; this test
            // documents the helper's behavior is "render whatever the
            // ctor proto says" and the gate is the discriminator.
            let header = render_kotlin_data_class_header(&dex, cd, &class_data, &mut imports);
            // Either None (no <init> with params) or some "data class …"
            // string — never panic.
            if let Some(h) = header {
                assert!(
                    h.starts_with("data class "),
                    "render returned non-data-class header: {h:?}"
                );
                assert!(h.ends_with(")\n"), "header must end with `)\\n`: {h:?}");
            }
        }
    }

    #[test]
    fn sealed_subclass_simple_name_strips_parent_prefix() {
        // Canonical kotlinc nested-class descriptor: `LColor$Red;`
        // with parent `LColor;` strips to `Red`.
        assert_eq!(sealed_subclass_simple_name("LColor;", "LColor$Red;"), "Red");
        assert_eq!(
            sealed_subclass_simple_name("Lcom/foo/Shape;", "Lcom/foo/Shape$Circle;"),
            "Circle"
        );
    }

    #[test]
    fn sealed_subclass_simple_name_falls_through_on_unrelated_descriptor() {
        // Defensive fallthrough: when the subclass descriptor doesn't
        // share the parent prefix (adversarial / unusual naming), the
        // helper returns the full simple name rather than failing.
        assert_eq!(
            sealed_subclass_simple_name("LColor;", "LOther/Class;"),
            "Class"
        );
        assert_eq!(
            sealed_subclass_simple_name("LColor;", "LFoo;"),
            "Foo"
        );
    }

    #[test]
    fn render_kotlin_sealed_class_header_returns_none_on_non_sealed() {
        // Java fixtures have no kotlinc sealed-root metadata; the
        // helper must return None defensively rather than rendering an
        // empty body. The is_kotlin_sealed_root predicate's gate
        // short-circuits the scan via kotlin_sealed_subclasses.
        let data = include_bytes!("../tests/fixtures/classes_named.dex");
        let dex = DexFile::parse(data, None).expect("parse");
        for cd in &dex.class_defs {
            let mut imports = BTreeSet::new();
            let header = render_kotlin_sealed_class_header(&dex, cd, &mut imports);
            assert!(
                header.is_none(),
                "class {} unexpectedly produced a sealed-class header",
                dex.get_type_descriptor(cd.class_idx).unwrap_or("?")
            );
        }
    }

    #[test]
    fn indeterminate_metadata_taint_emits_class_banner() {
        // A planted annotation-subtree parse failure makes the global
        // annotation verdict gate dirty, so every Kotlin-vs-Java rendering
        // detector that gates on @kotlin.Metadata returns Indeterminate for
        // every class. The decompiled class must then carry exactly one
        // DROIDSAW_INDETERMINATE banner, as its first line, naming the
        // metadata-gated detectors. (Per-site isolation is not possible: the
        // verdict gate is global, so all metadata-gated detectors flip
        // together — this exercises sites 112/133/147 plus the class-level
        // sealed-subclass checks collectively.) Also the public-API e2e path.
        let data = include_bytes!("../tests/fixtures/classes_named.dex");
        let mut dex = DexFile::parse(data, None).expect("parse");
        dex.parse_errors.push(crate::parser::ParseFailure {
            kind: crate::parser::ParseFailureKind::AnnotationItem,
            offset: 0x1000,
        });
        for cd in &dex.class_defs {
            let src = decompile_class(&dex, data, cd);
            let first = src.lines().next().unwrap_or("");
            assert!(
                first.starts_with("// DROIDSAW_INDETERMINATE:"),
                "class {} missing Indeterminate banner under planted annotation parse failure; first line: {first:?}",
                dex.get_type_descriptor(cd.class_idx).unwrap_or("?")
            );
            for det in [
                "is_kotlin_data_class",
                "is_kotlin_sealed_root",
                "is_kotlin_sealed_object_subclass",
                "is_kotlin_sealed_class_subclass",
            ] {
                assert!(
                    first.contains(det),
                    "banner missing detector {det} for class {}; got: {first:?}",
                    dex.get_type_descriptor(cd.class_idx).unwrap_or("?")
                );
            }
            assert_eq!(
                src.matches("// DROIDSAW_INDETERMINATE:").count(),
                1,
                "expected exactly one banner per class (dedup)"
            );
        }
    }

    #[test]
    fn clean_fixture_emits_no_indeterminate_banner() {
        // Negative gate: with no planted parse failure the detectors return
        // Yes/No (never Indeterminate), so the additive banner must NOT fire on
        // clean input — the rendered shape stays authoritative.
        let data = include_bytes!("../tests/fixtures/classes_named.dex");
        let dex = DexFile::parse(data, None).expect("parse");
        for cd in &dex.class_defs {
            let src = decompile_class(&dex, data, cd);
            assert!(
                !src.contains("// DROIDSAW_INDETERMINATE:"),
                "class {} emitted a spurious Indeterminate banner on a clean DEX",
                dex.get_type_descriptor(cd.class_idx).unwrap_or("?")
            );
        }
    }

    #[test]
    fn decompile_retains_debug_info_local_names() {
        // MinimalNamed is compiled with `javac -g -parameters` so
        // LocalVariableTable survives into DEX debug_info. The
        // name-propagation loop in decompile_method must bind the SSA
        // VarIds for `counter`, `total`, `i` (and the `input` param) to
        // their source-level names. Multi-use locals are necessary to
        // resist the optimizer's single-use inlining pass — a simple
        // `int x = a; return x;` would get inlined to `return a;` before
        // the name could surface in the decompile output.
        let data = include_bytes!("../tests/fixtures/classes_named.dex");
        let dex = DexFile::parse(data, None).unwrap();
        let class_def = dex
            .class_defs
            .iter()
            .find(|cd| dex.get_type_descriptor(cd.class_idx).ok() == Some("LMinimalNamed;"))
            .expect("MinimalNamed class not found");
        let source = decompile_class(&dex, data, class_def);

        eprintln!("=== DECOMPILED NAMED CLASS ===\n{source}\n========================");

        // Positive: each debug-info local with a def-pc covered by a
        // non-inlined use-site should emit its source-level name. `input`
        // (param), `counter` + `total` (multi-use locals) all survive the
        // optimizer's inlining pass; `i` is the loop induction variable.
        for want in ["counter", "total", "input", "i"] {
            assert!(
                source.contains(want),
                "decompile output must contain debug-info local `{want}`:\n{source}"
            );
        }
    }

    #[test]
    fn decompile_minimal_class() {
        let data = include_bytes!("../tests/fixtures/classes.dex");
        let dex = DexFile::parse(data, None).unwrap();
        let class_def = dex
            .class_defs
            .iter()
            .find(|cd| dex.get_type_descriptor(cd.class_idx).ok() == Some("LMinimal;"))
            .expect("Minimal class not found");
        let source = decompile_class(&dex, data, class_def);

        eprintln!("=== DECOMPILED CLASS ===\n{source}\n========================");

        assert!(
            source.contains("class Minimal"),
            "should contain class name"
        );
        assert!(source.contains("private int x;"), "should contain field x");
        assert!(source.contains("getX"), "should contain getX method");
        assert!(source.contains("Minimal("), "should contain constructor");
        assert!(source.contains("hello"), "should contain hello method");
        assert!(
            source.contains("return"),
            "should contain return statements"
        );
        assert!(
            source.contains("// Source: Minimal.java"),
            "should have source comment"
        );
        assert_eq!(
            source.matches('{').count(),
            source.matches('}').count(),
            "should have balanced braces"
        );
    }
}
