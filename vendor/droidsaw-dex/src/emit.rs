//! High-level decompiler output emission.
#![allow(missing_docs, reason = "internal")]
#![cfg_attr(not(test), allow(clippy::as_conversions, reason = "PROOF (bulk allow, 28 sites): emit.rs renders parser-validated DexFile elements as Java/source-form strings. Casts cluster uniformly: (a) `u32 pool-index newtype (.0) as usize` for `.get()` on pool arrays, lossless on 64-bit (`.get()` handles OOB by returning None); (b) `i64 as u32/u64` for bitcast-style float reassembly via `f32::from_bits`/`f64::from_bits` where the bit pattern is the entire payload; (c) `u32 as u32 → char::from_u32` for code-point decoding. No narrowing path is exercised on attacker-controlled bytes without a dominating bounds check. Per-site PROOF refinement deferred."))]
// Per-fn / per-callsite refinement of `clippy::arithmetic_side_effects`.
// Module-level allow removed; each fn or callsite carries its own
// `#[allow] // WHY:` with the dominator that bounds its arithmetic.
//
// Original module-wide WHY (now distributed per-fn): emit-side math
// operates on validated in-memory SSA / parsed values (VarIds,
// EmitCtx counters, formatted integer widths), not attacker-controlled
// file offsets.
#![allow(clippy::let_underscore_must_use, reason = "every `let _ = writeln!(out, ...)` in emit code writes to an in-memory `String`/`Vec<u8>` whose `Display`/`Write` impl is infallible. The unit-Result is structurally dead; per-site allow would add 64 attribute pairs without changing semantics.")]
#![cfg_attr(
    not(test),
    allow(
        clippy::indexing_slicing,
        clippy::string_slice,
        reason = "PROOF: emit consumes validated, structured IR — Method/Class/Stmt/Expr trees built post-parse, post-CFG, post-SSA, post-structuring, post-sugar. Every VarId, BlockIdx, MethodIdx, FieldIdx, TypeIdx, StringIdx is minted at parse time and validated against the corresponding pool length. Every string slice operates on UTF-8-validated identifiers (sanitized via emit::sanitize_id) or on emit-internal `String` buffers built up via push_str. Indices used in emit-internal arrays (e.g. lookup tables for opcode-name translation) are bounded by const array length. Per-fn refinement deferred to v1.x post-emit-API stabilization (~107 sites across 75 fns; per-fn would not be denser than module-level given uniform invariant)."
    )
)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write;

use crate::annotation::EncodedValue;

/// Adversarial-input cap on `Stmt`-tree recursion depth used by the
/// emit-layer walkers (`emit_stmt`, `count_uses_in_stmt`,
/// `enumerate_catch_bindings`, `collect_escaped_catch_vars`,
/// `merge_invoke_moveresult`, `stmt_has_dereferencing_use`). Chosen
/// to cover real-world nesting (measured p95 ≪ 50 in tier-1 fixtures
/// and a 3443-class real-world APK smoke) with ~10× headroom; attacker-crafted
/// inputs past 512 surface typed
/// [`crate::error::DexError::EmitRecursionDepthExceeded`] (via
/// [`EmitCtx::record_error`]) instead of a stack overflow. Matches
/// `droidsaw-common`'s `MAX_REGION_DEPTH = 512` on purpose — both
/// guards exist for the same class of attacker-controlled tree
/// nesting and share the same tier-1-fixture depth ceiling.
///
/// Brief had 2048 as orientation; empirical test-thread stack (2 MB
/// default) overflows around 1024 `emit_stmt_depth` frames given the
/// per-frame `String`/local-var footprint. 512 is the highest cap
/// that survives the full adversarial fixture on a 2 MB test thread;
/// larger caps would need a spawn-with-stack-size workaround.
///
/// The cap is calibrated against the WORST walker —
/// `emit_stmt_depth`, which heap-allocates `String` + holds a large
/// `match`-arm local set per frame (~8 KB). The other five walkers
/// (`count_uses_in_stmt_depth`, `enumerate_catch_bindings_depth`,
/// `stmt_has_dereferencing_use_depth`, `merge_invoke_moveresult_depth`,
/// and the non-recursive dispatcher `collect_escaped_catch_vars`)
/// have frames in the 200-400 B range and could tolerate a much
/// higher cap; a unified 512 across all walkers is simpler and keeps
/// the calibration conservative.
pub const MAX_STMT_DEPTH: usize = 512;

/// Returns true if an inlined expression string needs parentheses when placed
/// at an arbitrary use site (e.g. as an operand to a binary operator).
///
/// We wrap whenever the expression contains a top-level binary operator —
/// one not nested inside `(...)` or `[...]` — because at the call site we
/// don't know the surrounding operator's precedence. Wrapping is always
/// semantically safe; it only adds redundant parens in benign cases like
/// `return (a + b);`.
// WHY: byte-scanner over `s.as_bytes()`. Arithmetic shapes are `depth +/- 1`
// (paren-depth counter, bounded by `usize::MAX` after at most s.len()
// iterations; cannot overflow given str length bounded by isize::MAX),
// `i + 1` for next-byte index (preceded by `i + 1 < bytes.len()` checks),
#[allow(clippy::arithmetic_side_effects, reason = "byte-scanner over `s.as_bytes()`. Arithmetic shapes are `depth +/- 1` (paren-depth counter, bounded by `usize::MAX` after at most s.len() iterations; cannot overflow given str length bounded by isize::MAX), `i + 1` for next-byte index (preceded by `i + 1 < bytes.len()` checks), and `s.len() - 1` for last-byte check (preceded by `!s.is_empty()`).")]
fn inline_needs_parens(s: &str) -> bool {
    // String literal, constructor, logical-not — never need wrapping.
    if s.starts_with('"') || s.starts_with("new ") || s.starts_with('!') {
        return false;
    }
    // If the expression starts with '(' check whether the paren wraps the
    // entire expression.  `(a + b)` is fully grouped and needs no extra
    // parens, but `(a + b) & c` starts with '(' yet has a top-level `&`.
    if s.starts_with('(') {
        let mut depth: i32 = 0;
        for (i, ch) in s.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        // The opening '(' closes here.  If that's the end
                        // of the string, the whole expression is grouped.
                        if i == s.len() - 1 {
                            return false;
                        }
                        // Otherwise there's more after the closing ')' —
                        // fall through to the full scan below.
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    // Scan for a binary-operator token at depth 0.
    let mut depth: i32 = 0;
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b' ' if depth == 0 => {
                const OPS: &[&str] = &[
                    " + ", " - ", " * ", " / ", " % ",
                    " & ", " | ", " ^ ",
                    " << ", " >> ", " >>> ",
                    " == ", " != ", " <= ", " >= ", " < ", " > ",
                    " && ", " || ", " instanceof ",
                ];
                let rest = &s[i..];
                if OPS.iter().any(|op| rest.starts_with(op)) {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

/// USE position: returns the inlined expression if any, else the bare var name.
/// Inlined expressions that contain top-level binary operators are wrapped in
/// parentheses to preserve precedence at the call site.
/// Never call this on a definition LHS — those stay as `emit_var`.
// WHY: counter `inline_count += 1` over EmitCtx's inline-tracker map.
// Bounded by parser-validated VarId count (u32-bounded); cannot
// overflow usize within input limits.
#[allow(clippy::arithmetic_side_effects, reason = "counter `inline_count += 1` over EmitCtx's inline-tracker map. Bounded by parser-validated VarId count (u32-bounded); cannot overflow usize within input limits.")]
fn emit_use(v: &VarId, ctx: &EmitCtx) -> String {
    if let Some(expr) = ctx.inline_exprs.get(v) {
        return if inline_needs_parens(expr) {
            format!("({expr})")
        } else {
            expr.clone()
        };
    }
    emit_var(v)
}

use crate::decode::PoolIndex;
use crate::opcodes::Opcode;
use crate::parser::DexFile;
use crate::ssa::{SsaInsn, VarId};
use crate::structure::{
    ArmPattern, ConcatPart, Discriminant, MultiArm, SourceDialect, Stmt, UnrecognizedReason,
};
use crate::types::{DexType, TypeEnv};

// ── Emit context ────────────────────────────────────────────────────

/// Context for emission: carries `this` var, variable name overrides, imports.
pub struct EmitCtx {
    /// The VarId representing `this` (None for static methods).
    pub this_var: Option<VarId>,
    /// Variable name overrides (from debug info or `this`).
    pub var_names: BTreeMap<VarId, String>,
    /// Collected fully-qualified type names for import generation.
    pub imports: BTreeSet<String>,
    /// Track declared variables.
    pub declared: BTreeSet<VarId>,
    /// Single-use vars whose defining expression can be inlined.
    pub inline_exprs: BTreeMap<VarId, String>,
    /// Vars that have been inlined (skip their defining statement).
    pub inlined: BTreeSet<VarId>,
    /// MoveResult VarId → invoke expression (for replacing /* move-result */ placeholders).
    pub mro_map: BTreeMap<VarId, String>,
    /// fill-array-data payloads for the current method: payload_pc → (element_width, data).
    pub fill_array_payloads: BTreeMap<u32, (u16, Vec<u8>)>,
    /// The declared return type of the current method (for cast insertion on Stmt::Return).
    pub return_type: Option<crate::types::DexType>,
    /// Catch-bound VarIds promoted to method-scope locals because they're used
    /// outside the catch body (cross-catch SSA-scope leak — see TryResources
    /// fixture). Catch emission re-binds to a fresh tmp name and prologues the
    /// body with `{hoisted} = {tmp};`.
    pub hoisted_catch_vars: BTreeSet<VarId>,
    /// Class-level flag: any method in the current class has had at least one
    /// hoisted-catch-var escape. When set, every method signature in the class
    /// is patched with `throws Throwable` at class-emit completion so the
    /// lowered `throw v;` of a Throwable-typed hoisted local compiles without
    /// a runtime-fragile cast. Reset at class-emit entry.
    pub class_has_hoist: bool,
    /// Type descriptor of the currently-emitting class (e.g. `LFoo/Bar;`).
    /// Used by SPut/IPut/SGet/IGet emit to drop the `ClassName.` qualifier
    /// when accessing a static field of the SAME class — required because
    /// javac rejects qualified writes to `static final` fields even from
    /// inside the declaring class (`Foo.X = 10;` in `Foo`'s `<clinit>` fails
    /// with "cannot assign a value to final variable X"; unqualified
    /// `X = 10;` succeeds). None when not emitting a class method body.
    pub own_class_desc: Option<String>,
    /// When `Some(debug)`, `emit_stmt` emits `// line N` source-line
    /// comments before each SsaInsn-carrying statement (Expr,
    /// InlinedReturn, InlinedThrow, StringConcat). Gated at decompile
    /// entry on `DROIDSAW_DEX_EMIT_LINE_COMMENTS=1` so default goldens
    /// stay byte-stable. None = disabled.
    pub line_debug: Option<crate::debug::DebugInfo>,
    /// Most recent source line emitted as a `// line N` comment. Suppresses
    /// duplicate comments when several consecutive statements share a line.
    /// Reset per method by `decompile_method` (each method's PC space
    /// restarts at 0; carrying state across methods would emit spurious
    /// zero-diff cases on the first statement of each new method).
    pub last_emitted_line: Option<u32>,
    /// First-wins error slot set by recursive `Stmt`-tree walkers when
    /// they hit [`MAX_STMT_DEPTH`]. Checked at the `emit_method`
    /// boundary; surfaces as `Err(...)` rather than a stack-overflow
    /// panic. First-wins semantics prevent a second (deeper) overflow
    /// from clobbering the location-of-first-failure evidence.
    pub error_state: Option<crate::error::DexError>,
}

impl EmitCtx {
    pub fn new() -> Self {
        Self {
            this_var: None,
            var_names: BTreeMap::new(),
            imports: BTreeSet::new(),
            declared: BTreeSet::new(),
            inline_exprs: BTreeMap::new(),
            inlined: BTreeSet::new(),
            mro_map: BTreeMap::new(),
            fill_array_payloads: BTreeMap::new(),
            return_type: None,
            hoisted_catch_vars: BTreeSet::new(),
            class_has_hoist: false,
            own_class_desc: None,
            line_debug: None,
            last_emitted_line: None,
            error_state: None,
        }
    }

    /// Record a typed error from a recursive walker. First-wins: if
    /// `error_state` is already `Some`, leave it — the first failure
    /// carries the most specific location. Subsequent overflows on
    /// the same tree would just be deeper versions of the same cause.
    pub fn record_error(&mut self, err: crate::error::DexError) {
        if self.error_state.is_none() {
            self.error_state = Some(err);
        }
    }

    /// Write `// line N` before a statement's main body when
    /// `DROIDSAW_DEX_EMIT_LINE_COMMENTS` is on. Dedupes against
    /// `last_emitted_line` to avoid a cascade of identical comments on
    /// statements that share a source line. No-op when `line_debug` is
    /// `None` — the default (and golden-stable) path.
    fn emit_line_comment(&mut self, out: &mut String, level: usize, pc: u32) {
        let Some(debug) = &self.line_debug else { return };
        let Some(line) = crate::debug::line_at(debug, pc) else { return };
        if self.last_emitted_line == Some(line) {
            return;
        }
        indent(out, level);
        let _ = writeln!(out, "// line {line}");
        self.last_emitted_line = Some(line);
    }

    fn var_name(&self, v: &VarId) -> String {
        if let Some(name) = self.var_names.get(v) {
            return name.clone();
        }
        if self.this_var.as_ref() == Some(v) {
            return "this".to_string();
        }
        v.to_string()
    }

    /// Record a fully-qualified class name for import collection.
    /// Filters:
    /// - Default-package classes (no `.` in FQCN) can't be imported at all
    ///   — javac rejects `import Shape;` with "'.' expected".
    /// - Single-level `java.lang.X` is implicit; skip. Nested `java.lang.X.Y`
    ///   (e.g. `java.lang.reflect.Field` — no, that's `java.lang.reflect.*`
    ///   which is not under lang; the "nested" concern is `java.lang.Foo.Bar`
    ///   inner classes, rare).
    ///
    /// Each dot-separated segment of the stored FQCN is sanitized via
    /// `sanitize_id` so that R8/Proguard-renamed segments (which are
    /// valid DEX descriptor components but may fail the Java identifier
    /// grammar — e.g. leading digit `LX/552;` → `X.552`) become valid
    /// Java identifiers on the import line. Without this, `import X.552;`
    /// would be emitted verbatim and javac rejects with `'.' expected`.
    /// `pretty_class_name` already applies the same per-segment sanitize
    /// at type-reference sites; this aligns the import-collection path
    /// with that idiom.
    fn note_import(&mut self, fqcn: &str) {
        if !fqcn.contains('.') {
            return;
        }
        if fqcn.starts_with("java.lang.") && fqcn.matches('.').count() == 2 {
            return;
        }
        let sanitized = fqcn
            .split('.')
            .map(sanitize_id)
            .collect::<Vec<_>>()
            .join(".");
        self.imports.insert(sanitized);
    }

    /// Get the simple name of a type, recording the import.
    // WHY: `desc[1..desc.len() - 1]` strips the leading `L` and trailing
    // `;` from a JVM class descriptor. The `desc.starts_with('L')` +
    // `desc.ends_with(';')` guards above prove `desc.len() >= 2`, so
    // `desc.len() - 1` cannot underflow.
    #[allow(clippy::arithmetic_side_effects, reason = "`desc[1..desc.len() - 1]` strips the leading `L` and trailing `;` from a JVM class descriptor. The `desc.starts_with('L')` + `desc.ends_with(';')` guards above prove `desc.len() >= 2`, so `desc.len() - 1` cannot underflow.")]
    fn simple_type(&mut self, ty: &DexType) -> String {
        match ty {
            DexType::Ref(desc) if desc.starts_with('L') && desc.ends_with(';') => {
                let fqcn = desc[1..desc.len() - 1].replace('/', ".");
                let simple = sanitize_id(fqcn.rsplit('.').next().unwrap_or(&fqcn));
                self.note_import(&fqcn);
                simple
            }
            DexType::ArrayRef(elem) => {
                format!("{}[]", self.simple_type(elem))
            }
            _ => emit_type(ty),
        }
    }

    /// Kotlin source-form type rendering with import recording. Mirrors
    /// [`simple_type`](Self::simple_type) for the Java dialect; used by
    /// the Kotlin top-level-fn facade emit path (PR-9b of #41b).
    ///
    /// Differences from Java:
    /// - Primitives map to Kotlin names: `int → Int`, `void → Unit`,
    ///   `boolean → Boolean`, etc.
    /// - Reference types use the same simple-name + import pattern as
    ///   Java; `note_import` already filters `java.lang.*` (implicit
    ///   in both languages — Kotlin maps `kotlin.String` to JVM
    ///   `java.lang.String`).
    /// - Nested-class descriptors `Foo$Bar` render as `Foo.Bar`
    ///   (Kotlin source form; Java keeps `$` for the
    ///   `Outer$Inner.java` filename contract).
    /// - Reference arrays render as `Array<T>`; primitive arrays use
    ///   the dedicated unboxed types `IntArray`, `LongArray`, etc.
    ///
    /// Visibility note: `pub(crate)` because PR-9d's
    /// `classes.rs::render_kotlin_data_class_header` reuses the same
    /// type-rendering logic when emitting the data-class header
    /// (`data class Foo(val a: T1, val b: T2)`). Kept `pub(crate)` so
    /// the surface area of EmitCtx outside the dex crate remains
    /// minimal.
    // WHY: same shape as `simple_type` (Java sibling above):
    // `desc[1..desc.len() - 1]` strips `L`/`;`. Pattern guards prove
    // `desc.len() >= 2`; subtraction safe.
    #[allow(clippy::arithmetic_side_effects, reason = "same shape as `simple_type` (Java sibling above): `desc[1..desc.len() - 1]` strips `L`/`;`. Pattern guards prove `desc.len() >= 2`; subtraction safe.")]
    pub(crate) fn simple_type_kotlin(&mut self, ty: &DexType) -> String {
        match ty {
            DexType::Void => "Unit".to_string(),
            DexType::Boolean => "Boolean".to_string(),
            DexType::Byte => "Byte".to_string(),
            DexType::Short => "Short".to_string(),
            DexType::Char => "Char".to_string(),
            DexType::Int => "Int".to_string(),
            DexType::Long => "Long".to_string(),
            DexType::Float => "Float".to_string(),
            DexType::Double => "Double".to_string(),
            DexType::Ref(desc) if desc.starts_with('L') && desc.ends_with(';') => {
                // FQN with `$` → `.` rewrite per Kotlin nested-class
                // form (mirrors `pretty_class_name_kotlin`).
                let fqcn = desc[1..desc.len() - 1].replace(['/', '$'], ".");
                let simple = sanitize_id(fqcn.rsplit('.').next().unwrap_or(&fqcn));
                self.note_import(&fqcn);
                simple
            }
            DexType::Ref(_) => emit_type(ty),
            DexType::ArrayRef(elem) => match &**elem {
                DexType::Int => "IntArray".to_string(),
                DexType::Long => "LongArray".to_string(),
                DexType::Float => "FloatArray".to_string(),
                DexType::Double => "DoubleArray".to_string(),
                DexType::Boolean => "BooleanArray".to_string(),
                DexType::Byte => "ByteArray".to_string(),
                DexType::Short => "ShortArray".to_string(),
                DexType::Char => "CharArray".to_string(),
                _ => format!("Array<{}>", self.simple_type_kotlin(elem)),
            },
            // Internal type-system markers (never appear in JVM
            // method signatures — they exist only inside type
            // inference). Defensive fallthrough to the Java-shape
            // emit_type which emits a stable placeholder.
            DexType::Bottom | DexType::Null | DexType::Top => emit_type(ty),
        }
    }
}

impl Default for EmitCtx {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("    ");
    }
}

fn emit_var(v: &VarId) -> String {
    v.to_string()
}

fn use0(insn: &SsaInsn, ctx: &EmitCtx) -> String {
    insn.uses
        .first()
        .map(|v| emit_use(v, ctx))
        .unwrap_or_else(|| "?".to_string())
}

fn use1(insn: &SsaInsn, ctx: &EmitCtx) -> String {
    insn.uses
        .get(1)
        .map(|v| emit_use(v, ctx))
        .unwrap_or_else(|| "?".to_string())
}

fn use2(insn: &SsaInsn, ctx: &EmitCtx) -> String {
    insn.uses
        .get(2)
        .map(|v| emit_use(v, ctx))
        .unwrap_or_else(|| "?".to_string())
}

// WHY: `desc[11..desc.len() - 1]` strips the `Lkotlin/Function` (11-byte
// prefix) and `;` (1-byte suffix) from a Kotlin function-type descriptor.
// The pattern guards above prove descriptor length ≥ 12; subtraction safe.
#[allow(clippy::arithmetic_side_effects, reason = "`desc[11..desc.len() - 1]` strips the `Lkotlin/Function` (11-byte prefix) and `;` (1-byte suffix) from a Kotlin function-type descriptor. The pattern guards above prove descriptor length ≥ 12; subtraction safe.")]
fn emit_type(ty: &DexType) -> String {
    match ty {
        DexType::Ref(desc) if desc.starts_with("Ljava/lang/") && !desc[11..].contains('/') => {
            // Local shortcut for java.lang.* (auto-imported), e.g.
            // `Ljava/lang/String;` -> `String`. `$` rewritten to `.`
            // so `Ljava/lang/Thread$State;` renders as `Thread.State`
            // (source form) rather than `Thread$State` (bytecode form,
            // which javac rejects as a type reference).
            let inner = &desc[11..desc.len() - 1];
            inner
                .split('$')
                .map(sanitize_id)
                .collect::<Vec<_>>()
                .join(".")
        }
        DexType::Ref(desc) if desc.starts_with('L') && desc.ends_with(';') => {
            pretty_class_name(desc)
        }
        DexType::ArrayRef(elem) => format!("{}[]", emit_type(elem)),
        _ => format!("{ty}"),
    }
}

/// Return the Java default literal for a type (used to pre-declare loop-condition variables).
fn default_literal(ty: &DexType) -> &'static str {
    match ty {
        DexType::Long => "0L",
        DexType::Float => "0.0f",
        DexType::Double => "0.0",
        DexType::Boolean => "false",
        DexType::Ref(_) | DexType::ArrayRef(_) | DexType::Null => "null",
        _ => "0",
    }
}

/// Scan the first statement of a while-body for an assignment to `reg`.
/// Returns the emitted expression string for that assignment, or `None`.
///
/// This is used to pre-declare while-condition variables with the correct
/// initial value when the loop-header instruction (which becomes the first
/// body statement after structuring) defines the variable before the branch.
/// Examples:
///   - `const/4 v1, 1` → pre-declare `v1 = 1` (Collatz termination check)
///   - `invoke-virtual v3.length()` stored to v2 → pre-declare `v2 = v3.length()`
///     (for-i-over-string-length pattern)
fn find_init_in_body(body: &Stmt, reg: u16, env: &TypeEnv, dex: &DexFile, ctx: &EmitCtx) -> Option<String> {
    let first = match body {
        Stmt::Seq(stmts) => stmts.first()?,
        other => other,
    };
    if let Stmt::Expr(insn) = first {
        if insn.dst.as_ref().map(|v| v.reg()) == Some(reg) {
            // Any assignment that writes this register can be used as the
            // initial value.  Skip void-like instructions that produce no
            // usable value (moves with no dst shouldn't get here, but guard
            // anyway).  Also skip new-instance: the uninitialized object
            // should not be pre-declared here.
            use crate::opcodes::Opcode;
            if matches!(insn.insn.op, Opcode::NewInstance) {
                return None;
            }
            return Some(emit_expr(insn, env, dex, ctx));
        }
    }
    None
}

pub fn emit_access_flags(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & 0x0001 != 0 {
        parts.push("public");
    }
    if flags & 0x0002 != 0 {
        parts.push("private");
    }
    if flags & 0x0004 != 0 {
        parts.push("protected");
    }
    if flags & 0x0008 != 0 {
        parts.push("static");
    }
    if flags & 0x0010 != 0 {
        parts.push("final");
    }
    if flags & 0x0020 != 0 {
        parts.push("synchronized");
    }
    if flags & 0x0040 != 0 {
        parts.push("volatile");
    }
    if flags & 0x0080 != 0 {
        parts.push("transient");
    }
    if flags & 0x0100 != 0 {
        parts.push("native");
    }
    if flags & 0x0400 != 0 {
        parts.push("abstract");
    }
    if flags & 0x0800 != 0 {
        parts.push("strictfp");
    }
    parts.join(" ")
}

/// Coerce a rendered expression to match a type demanded by the use site.
///
/// Use sites that have a demanded type (return position, narrow-integer
/// stores, reference-typed slots) call this oracle so the rendering
/// boundary handles the val-vs-demand mismatch in one place. SSA typing
/// is sound enough at return-position that most calls degenerate to the
/// identity case; `render_as` is the structural backstop so a future
/// SSA-typing regression doesn't re-surface as an emit defect, and so
/// the same rule holds across `Stmt::Return` and `Stmt::InlinedReturn` (which
/// the const-inlining peephole produces).
///
/// Coercion rules:
/// - val_ty == demand_ty → identity.
/// - Int → Boolean: const-0/-1 fold to `false`/`true`; else `(val) != 0`.
/// - Int → Byte/Char/Short: cast.
/// - anything → reference: `"0"` / `Null` type → `"null"`; otherwise val.
/// - else: identity.
fn render_as(val: &str, val_ty: &DexType, demand_ty: &DexType) -> String {
    if val_ty == demand_ty {
        return val.to_string();
    }
    match (val_ty, demand_ty) {
        (DexType::Int, DexType::Boolean) => match val {
            "0" => "false".to_string(),
            "1" => "true".to_string(),
            _ => {
                if inline_needs_parens(val) {
                    format!("({val}) != 0")
                } else {
                    format!("{val} != 0")
                }
            }
        },
        (DexType::Int, DexType::Byte) => format!("(byte){val}"),
        (DexType::Int, DexType::Char) => format!("(char){val}"),
        (DexType::Int, DexType::Short) => format!("(short){val}"),
        (_, DexType::Ref(_) | DexType::ArrayRef(_))
            if val == "0" || matches!(val_ty, DexType::Null) =>
        {
            "null".to_string()
        }
        _ => val.to_string(),
    }
}

#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    reason = "INTENT: bit-reinterpretation. DEX literals are stored as i64 but for DexType::Float / Double / Char the i64 holds the bit pattern of a smaller IEEE-754 / u32 char value. Sign / width-narrowing of the bit pattern is the IDIOM — the bits are subsequently passed to f32::from_bits / f64::from_bits / char::from_u32, which require the unsigned narrowed integer."
)]
pub fn emit_literal(value: i64, ty: &DexType) -> String {
    match ty {
        DexType::Long => format!("{value}L"),
        DexType::Float => {
            let f = f32::from_bits(value as u32);
            // IEEE-754 edge cases: NaN / ±Infinity have no bare-literal
            // Java source form — `NaNf` / `inff` aren't legal. Use the
            // constant names from `java.lang.Float`.
            if f.is_nan() {
                "Float.NaN".to_string()
            } else if f.is_infinite() {
                if f.is_sign_negative() {
                    "Float.NEGATIVE_INFINITY".to_string()
                } else {
                    "Float.POSITIVE_INFINITY".to_string()
                }
            } else if f.fract() == 0.0 {
                format!("{f:.1}f")
            } else {
                format!("{f}f")
            }
        }
        DexType::Double => {
            let d = f64::from_bits(value as u64);
            if d.is_nan() {
                "Double.NaN".to_string()
            } else if d.is_infinite() {
                if d.is_sign_negative() {
                    "Double.NEGATIVE_INFINITY".to_string()
                } else {
                    "Double.POSITIVE_INFINITY".to_string()
                }
            } else if d.fract() == 0.0 {
                format!("{d:.1}")
            } else {
                format!("{d}")
            }
        }
        DexType::Boolean => {
            if value == 0 {
                "false".to_string()
            } else {
                "true".to_string()
            }
        }
        DexType::Char => {
            let c = char::from_u32(value as u32).unwrap_or('?');
            let escaped = match c {
                '\'' => "\\'".to_string(),
                '\\' => "\\\\".to_string(),
                '\n' => "\\n".to_string(),
                '\r' => "\\r".to_string(),
                '\t' => "\\t".to_string(),
                '\0' => "\\0".to_string(),
                c if c.is_control() => format!("\\u{:04x}", c as u32),
                c => c.to_string(),
            };
            format!("'{escaped}'")
        }
        _ => format!("{value}"),
    }
}

// ── Expression emitter ──────────────────────────────────────────────

// WHY: `dims += 1` for array-dimension counter; bounded by the number
// of leading `[` characters in a DexType descriptor, which is itself
// bounded by parser validation (DexType descriptors capped at u32 len).
#[allow(clippy::arithmetic_side_effects, reason = "`dims += 1` for array-dimension counter; bounded by the number of leading `[` characters in a DexType descriptor, which is itself bounded by parser validation (DexType descriptors capped at u32 len).")]
fn emit_expr(insn: &SsaInsn, env: &TypeEnv, dex: &DexFile, ctx: &EmitCtx) -> String {
    use Opcode::*;
    match insn.insn.op {
        // Constants
        Const4 | Const16 | Const | ConstHigh16 => {
            let ty = insn
                .dst
                .as_ref()
                .and_then(|d| env.types.get(d))
                .unwrap_or(&DexType::Int);
            // Check if 0 used as null reference
            if insn.insn.literal == 0 && ty.is_reference() {
                "null".to_string()
            } else {
                emit_literal(insn.insn.literal, ty)
            }
        }
        ConstWide16 | ConstWide32 | ConstWide | ConstWideHigh16 => {
            let ty = insn
                .dst
                .as_ref()
                .and_then(|d| env.types.get(d))
                .unwrap_or(&DexType::Long);
            emit_literal(insn.insn.literal, ty)
        }
        ConstString | ConstStringJumbo => {
            if let Some(PoolIndex::String(sidx)) = insn.insn.pool_idx {
                let s = dex.get_string(sidx).unwrap_or("<invalid>");
                format!("\"{}\"", escape_java_string(s))
            } else {
                "\"<invalid>\"".to_string()
            }
        }
        ConstClass => {
            if let Some(PoolIndex::Type(tidx)) = insn.insn.pool_idx {
                let ty = dex.get_type_descriptor(tidx).unwrap_or("?");
                format!("{}.class", pretty_class_name(ty))
            } else {
                "?.class".to_string()
            }
        }

        // New instance
        NewInstance => {
            if let Some(PoolIndex::Type(tidx)) = insn.insn.pool_idx {
                let ty = dex.get_type_descriptor(tidx).unwrap_or("?");
                format!("new {}()", pretty_class_name(ty))
            } else {
                "new ?()".to_string()
            }
        }
        NewArray => {
            if let Some(PoolIndex::Type(tidx)) = insn.insn.pool_idx {
                let ty = dex.get_type_descriptor(tidx).unwrap_or("?");
                let size = use0(insn, ctx);
                // Count array dimensions and get base type
                let mut dims: usize = 0;
                let mut base = ty;
                while let Some(rest) = base.strip_prefix('[') {
                    dims += 1;
                    base = rest;
                }
                let base_name = pretty_class_name(base);
                // Put size in first dimension: new int[size][] not new int[][size]
                let extra_dims = "[]".repeat(dims.saturating_sub(1));
                format!("new {base_name}[{size}]{extra_dims}")
            } else {
                "new ?[?]".to_string()
            }
        }

        // Field access
        Iget | IgetWide | IgetObject | IgetBoolean | IgetByte | IgetChar | IgetShort => {
            let obj = use0(insn, ctx);
            let field_name = resolve_field_name(dex, &insn.insn.pool_idx);
            format!("{obj}.{field_name}")
        }
        Sget | SgetWide | SgetObject | SgetBoolean | SgetByte | SgetChar | SgetShort => {
            if let Some(PoolIndex::Field(fidx)) = insn.insn.pool_idx {
                if let Some(field) = dex.fields.get(fidx.0 as usize) {
                    let class =
                        pretty_class_name(dex.get_type_descriptor(field.class_idx).unwrap_or("?"));
                    let name = sanitize_id(dex.get_string(field.name_idx).unwrap_or("?"));
                    format!("{class}.{name}")
                } else {
                    "?.?".to_string()
                }
            } else {
                "?.?".to_string()
            }
        }

        // Field store
        Iput | IputWide | IputObject | IputBoolean | IputByte | IputChar | IputShort => {
            let value = use0(insn, ctx);
            let obj = use1(insn, ctx);
            let field_name = resolve_field_name(dex, &insn.insn.pool_idx);
            format!("{obj}.{field_name} = {value}")
        }
        Sput | SputWide | SputObject | SputBoolean | SputByte | SputChar | SputShort => {
            let value = use0(insn, ctx);
            if let Some(PoolIndex::Field(fidx)) = insn.insn.pool_idx {
                if let Some(field) = dex.fields.get(fidx.0 as usize) {
                    let target_desc =
                        dex.get_type_descriptor(field.class_idx).unwrap_or("?");
                    let name = sanitize_id(dex.get_string(field.name_idx).unwrap_or("?"));
                    // Drop `ClassName.` qualifier when writing to a
                    // static field of the currently-emitting class —
                    // javac rejects qualified writes to static final
                    // fields even from inside the declaring class's
                    // <clinit>. Unqualified form resolves identically
                    // for non-final fields too; always safe.
                    if ctx.own_class_desc.as_deref() == Some(target_desc) {
                        format!("{name} = {value}")
                    } else {
                        let class = pretty_class_name(target_desc);
                        format!("{class}.{name} = {value}")
                    }
                } else {
                    format!("?.? = {value}")
                }
            } else {
                format!("?.? = {value}")
            }
        }

        // Array access
        Aget | AgetWide | AgetObject | AgetBoolean | AgetByte | AgetChar | AgetShort => {
            let arr = use0(insn, ctx);
            let idx = use1(insn, ctx);
            format!("{arr}[{idx}]")
        }
        Aput | AputWide | AputObject | AputBoolean | AputByte | AputChar | AputShort => {
            let value = use0(insn, ctx);
            let arr = use1(insn, ctx);
            let idx = use2(insn, ctx);
            format!("{arr}[{idx}] = {value}")
        }

        // Invokes
        InvokeVirtual | InvokeSuper | InvokeDirect | InvokeVirtualRange | InvokeSuperRange
        | InvokeDirectRange => emit_invoke(insn, dex, InvokeKind::from_opcode(insn.insn.op), ctx),
        InvokeStatic | InvokeStaticRange => emit_invoke(insn, dex, InvokeKind::Static, ctx),
        InvokeInterface | InvokeInterfaceRange => emit_invoke(insn, dex, InvokeKind::Interface, ctx),
        InvokeCustom | InvokeCustomRange => emit_invoke_custom(insn, dex, ctx),
        InvokePolymorphic | InvokePolymorphicRange => {
            emit_invoke_polymorphic(insn, dex, ctx)
        }

        // Moves (should be eliminated by copy prop, but emit as assignment)
        Move | MoveFrom16 | Move16 | MoveWide | MoveWideFrom16 | MoveWide16 | MoveObject
        | MoveObjectFrom16 | MoveObject16 => use0(insn, ctx),
        MoveResult | MoveResultWide | MoveResultObject => "/* move-result */".to_string(),
        MoveException => "/* caught exception */".to_string(),

        // Arithmetic (binary)
        AddInt | AddInt2Addr => emit_binop(insn, "+", ctx),
        SubInt | SubInt2Addr => emit_binop(insn, "-", ctx),
        MulInt | MulInt2Addr => emit_binop(insn, "*", ctx),
        DivInt | DivInt2Addr => emit_binop(insn, "/", ctx),
        RemInt | RemInt2Addr => emit_binop(insn, "%", ctx),
        AndInt | AndInt2Addr => emit_binop(insn, "&", ctx),
        OrInt | OrInt2Addr => emit_binop(insn, "|", ctx),
        XorInt | XorInt2Addr => emit_binop(insn, "^", ctx),
        ShlInt | ShlInt2Addr => emit_binop(insn, "<<", ctx),
        ShrInt | ShrInt2Addr => emit_binop(insn, ">>", ctx),
        UshrInt | UshrInt2Addr => emit_binop(insn, ">>>", ctx),

        AddLong | AddLong2Addr => emit_binop(insn, "+", ctx),
        SubLong | SubLong2Addr => emit_binop(insn, "-", ctx),
        MulLong | MulLong2Addr => emit_binop(insn, "*", ctx),
        DivLong | DivLong2Addr => emit_binop(insn, "/", ctx),
        RemLong | RemLong2Addr => emit_binop(insn, "%", ctx),
        AndLong | AndLong2Addr => emit_binop(insn, "&", ctx),
        OrLong | OrLong2Addr => emit_binop(insn, "|", ctx),
        XorLong | XorLong2Addr => emit_binop(insn, "^", ctx),
        ShlLong | ShlLong2Addr => emit_binop(insn, "<<", ctx),
        ShrLong | ShrLong2Addr => emit_binop(insn, ">>", ctx),
        UshrLong | UshrLong2Addr => emit_binop(insn, ">>>", ctx),

        AddFloat | AddFloat2Addr => emit_binop(insn, "+", ctx),
        SubFloat | SubFloat2Addr => emit_binop(insn, "-", ctx),
        MulFloat | MulFloat2Addr => emit_binop(insn, "*", ctx),
        DivFloat | DivFloat2Addr => emit_binop(insn, "/", ctx),
        RemFloat | RemFloat2Addr => emit_binop(insn, "%", ctx),

        AddDouble | AddDouble2Addr => emit_binop(insn, "+", ctx),
        SubDouble | SubDouble2Addr => emit_binop(insn, "-", ctx),
        MulDouble | MulDouble2Addr => emit_binop(insn, "*", ctx),
        DivDouble | DivDouble2Addr => emit_binop(insn, "/", ctx),
        RemDouble | RemDouble2Addr => emit_binop(insn, "%", ctx),

        // Lit ops
        AddIntLit16 | AddIntLit8 => emit_litop(insn, "+", ctx),
        RsubInt | RsubIntLit8 => {
            let a = use0(insn, ctx);
            format!("{} - {a}", insn.insn.literal)
        }
        MulIntLit16 | MulIntLit8 => emit_litop(insn, "*", ctx),
        DivIntLit16 | DivIntLit8 => emit_litop(insn, "/", ctx),
        RemIntLit16 | RemIntLit8 => emit_litop(insn, "%", ctx),
        AndIntLit16 | AndIntLit8 => emit_litop(insn, "&", ctx),
        OrIntLit16 | OrIntLit8 => emit_litop(insn, "|", ctx),
        XorIntLit16 | XorIntLit8 => emit_litop(insn, "^", ctx),
        ShlIntLit8 => emit_litop(insn, "<<", ctx),
        ShrIntLit8 => emit_litop(insn, ">>", ctx),
        UshrIntLit8 => emit_litop(insn, ">>>", ctx),

        // Unary
        NegInt | NegLong | NegFloat | NegDouble => {
            let a = use0(insn, ctx);
            format!("-{a}")
        }
        NotInt | NotLong => {
            let a = use0(insn, ctx);
            format!("~{a}")
        }

        // Type conversions
        IntToLong => emit_cast(insn, "long", ctx),
        IntToFloat => emit_cast(insn, "float", ctx),
        IntToDouble => emit_cast(insn, "double", ctx),
        LongToInt => emit_cast(insn, "int", ctx),
        LongToFloat => emit_cast(insn, "float", ctx),
        LongToDouble => emit_cast(insn, "double", ctx),
        FloatToInt => emit_cast(insn, "int", ctx),
        FloatToLong => emit_cast(insn, "long", ctx),
        FloatToDouble => emit_cast(insn, "double", ctx),
        DoubleToInt => emit_cast(insn, "int", ctx),
        DoubleToLong => emit_cast(insn, "long", ctx),
        DoubleToFloat => emit_cast(insn, "float", ctx),
        IntToByte => emit_cast(insn, "byte", ctx),
        IntToChar => emit_cast(insn, "char", ctx),
        IntToShort => emit_cast(insn, "short", ctx),

        // Comparisons — emit the typed comparator so the result is valid Java
        CmplFloat | CmpgFloat => {
            let a = use0(insn, ctx);
            let b = use1(insn, ctx);
            format!("Float.compare({a}, {b})")
        }
        CmplDouble | CmpgDouble => {
            let a = use0(insn, ctx);
            let b = use1(insn, ctx);
            format!("Double.compare({a}, {b})")
        }
        CmpLong => {
            let a = use0(insn, ctx);
            let b = use1(insn, ctx);
            format!("Long.compare({a}, {b})")
        }

        // Other
        ArrayLength => {
            let a = use0(insn, ctx);
            format!("{a}.length")
        }
        InstanceOf => {
            let a = use0(insn, ctx);
            if let Some(PoolIndex::Type(tidx)) = insn.insn.pool_idx {
                let ty = dex.get_type_descriptor(tidx).unwrap_or("?");
                format!("{a} instanceof {}", pretty_class_name(ty))
            } else {
                format!("{a} instanceof ?")
            }
        }
        CheckCast => {
            let a = use0(insn, ctx);
            if let Some(PoolIndex::Type(tidx)) = insn.insn.pool_idx {
                let ty = dex.get_type_descriptor(tidx).unwrap_or("?");
                format!("({}) {a}", pretty_class_name(ty))
            } else {
                format!("(?) {a}")
            }
        }
        MonitorEnter => {
            let a = use0(insn, ctx);
            format!("/* monitor-enter {a} */")
        }
        MonitorExit => {
            let a = use0(insn, ctx);
            format!("/* monitor-exit {a} */")
        }
        FilledNewArray | FilledNewArrayRange => {
            if let Some(PoolIndex::Type(tidx)) = insn.insn.pool_idx {
                let ty = dex.get_type_descriptor(tidx).unwrap_or("?");
                let args: Vec<String> = insn.uses.iter().map(|v| emit_use(v, ctx)).collect();
                format!("new {}{{ {} }}", pretty_class_name(ty), args.join(", "))
            } else {
                "new ?[]{}".to_string()
            }
        }
        FillArrayData => {
            let a = use0(insn, ctx);
            format!("/* fill-array-data {a} */")
        }

        // Control flow (should be handled at Stmt level, fallback)
        Nop => "/* nop */".to_string(),
        Goto | Goto16 | Goto32 => "/* goto */".to_string(),
        IfEq | IfNe | IfLt | IfGe | IfGt | IfLe | IfEqz | IfNez | IfLtz | IfGez | IfGtz | IfLez
        | PackedSwitch | SparseSwitch => "/* branch */".to_string(),
        ReturnVoid | Return | ReturnWide | ReturnObject => "/* return */".to_string(),
        Throw => "/* throw */".to_string(),

        ConstMethodHandle | ConstMethodType => "/* method-handle */".to_string(),
    }
}

fn emit_binop(insn: &SsaInsn, op: &str, ctx: &EmitCtx) -> String {
    let a = use0(insn, ctx);
    let b = use1(insn, ctx);
    format!("{a} {op} {b}")
}

fn emit_litop(insn: &SsaInsn, op: &str, ctx: &EmitCtx) -> String {
    let a = use0(insn, ctx);
    format!("{a} {op} {}", insn.insn.literal)
}

fn emit_cast(insn: &SsaInsn, target: &str, ctx: &EmitCtx) -> String {
    let a = use0(insn, ctx);
    // Always parenthesize the operand so that e.g. `(byte) x ^ y` is not
    // mis-parsed as `((byte)x) ^ y` when the expression is later inlined.
    format!("({target})({a})")
}

/// Return the argument VarIds for an invoke, skipping the high-half register of
/// each wide (long/double) parameter.  In Dalvik, a wide instruction writes the
/// same SSA VarId to both the low and the high register of the pair, so both
/// `uses` entries are identical.  Emitting them both produces `foo(v0, v0)` for
/// a single long; we need `foo(v0)`.
// WHY: `use_idx += 1` advances over the `uses` slice in tandem with the
// proto_param_types iteration; bounded by `uses.len()` checked before
// each increment.
#[allow(clippy::arithmetic_side_effects, reason = "`use_idx += 1` advances over the `uses` slice in tandem with the proto_param_types iteration; bounded by `uses.len()` checked before each increment.")]
fn args_skipping_wide_halves<'a>(
    uses: &'a [VarId],
    proto_param_types: &[DexType],
) -> Vec<&'a VarId> {
    let mut result = Vec::new();
    let mut use_idx = 0;
    for ty in proto_param_types {
        if use_idx >= uses.len() {
            break;
        }
        result.push(&uses[use_idx]);
        use_idx += 1;
        if matches!(ty, DexType::Long | DexType::Double) {
            use_idx += 1; // skip the high-half register
        }
    }
    // If the proto is empty or we ran out of typed params but still have uses,
    // fall through: just emit the remaining uses as-is.
    if result.is_empty() {
        return uses.iter().collect();
    }
    result
}

/// Discriminates non-static method invokes for emit-time lowering. The
/// kind is read from `insn.insn.op` at the call site (`emit_expr`'s
/// dispatch) so `emit_invoke` doesn't need to reach back into the opcode
/// table. Static invokes ignore this kind and use the static branch.
///
/// `Range` opcode variants classify the same as their non-range siblings
/// — they take the same lowering decision (the only delta is calling
/// convention, not method-resolution semantics).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum InvokeKind {
    Virtual,
    Super,
    Direct,
    Interface,
    Static,
}

impl InvokeKind {
    fn from_opcode(op: Opcode) -> Self {
        use Opcode::*;
        match op {
            InvokeVirtual | InvokeVirtualRange => Self::Virtual,
            InvokeSuper | InvokeSuperRange => Self::Super,
            InvokeDirect | InvokeDirectRange => Self::Direct,
            InvokeInterface | InvokeInterfaceRange => Self::Interface,
            InvokeStatic | InvokeStaticRange => Self::Static,
            // Polymorphic and Custom go through their own emit paths;
            // emit_invoke is never invoked for them. Default to Virtual
            // for any unexpected opcode so the existing `{recv}.{name}()`
            // lowering applies — no semantic change vs. pre-stream behavior.
            _ => Self::Virtual,
        }
    }
}

fn emit_invoke(insn: &SsaInsn, dex: &DexFile, kind: InvokeKind, ctx: &EmitCtx) -> String {
    let is_static = kind == InvokeKind::Static;
    if let Some(PoolIndex::Method(midx)) = insn.insn.pool_idx {
        if let Some(method) = dex.methods.get(midx.0 as usize) {
            let raw_name = dex.get_string(method.name_idx).unwrap_or("?");
            let name = if raw_name == "<init>" || raw_name == "<clinit>" {
                raw_name
            } else {
                &sanitize_id(raw_name)
            };
            let target_class_desc = dex.get_type_descriptor(method.class_idx).unwrap_or("?");
            let class = pretty_class_name(target_class_desc);

            // Collect the proto's parameter types so we can skip high-half
            // registers of wide (long/double) arguments.
            let proto_param_types: Vec<DexType> = dex
                .protos
                .get(method.proto_idx.0 as usize)
                .and_then(|proto| {
                    if proto.parameters_off != 0 {
                        dex.type_lists.get(&proto.parameters_off)
                    } else {
                        None
                    }
                })
                .map(|tl| {
                    tl.iter()
                        .filter_map(|tidx| {
                            dex.get_type_descriptor(*tidx)
                                .ok()
                                .map(DexType::from_descriptor)
                        })
                        .collect()
                })
                .unwrap_or_default();

            if is_static {
                let arg_vars = args_skipping_wide_halves(&insn.uses, &proto_param_types);
                let args: Vec<String> = arg_vars.iter().map(|v| emit_use(v, ctx)).collect();
                // <clinit> / <init> cannot appear in Java source as an explicit call
                if name == "<clinit>" || name == "<init>" {
                    format!("/* {class}.{name}({}) */", args.join(", "))
                } else {
                    format!("{class}.{name}({})", args.join(", "))
                }
            } else {
                if insn.uses.is_empty() {
                    // No receiver present — emit a best-effort placeholder so
                    // we don't slice out of bounds. Hit in practice on
                    // `invoke-custom {}` (pool_idx mis-classified as Method
                    // by the parser; correct classification is a CallSite,
                    // pending a dedicated stream). Keeping the class/name
                    // text in the placeholder preserves grep-ability.
                    return format!("/* {class}.{name}(???) */");
                }
                // First arg is `this`/receiver
                let receiver = use0(insn, ctx);
                let arg_vars =
                    args_skipping_wide_halves(&insn.uses[1..], &proto_param_types);
                let args: Vec<String> = arg_vars.iter().map(|v| emit_use(v, ctx)).collect();
                if name == "<init>" {
                    // Check if receiver is `this` → this is a super() or this() delegation
                    let is_this = ctx.this_var.as_ref() == insn.uses.first();
                    if is_this {
                        // Constructor delegation: super(args)
                        format!("super({})", args.join(", "))
                    } else {
                        // Object allocation: new ClassName(args)
                        format!("new {class}({})", args.join(", "))
                    }
                } else {
                    // Discriminate non-`<init>` invokes by opcode kind so the
                    // emit-layer doesn't collapse `invoke-super` (`super.m()`)
                    // and `invoke-direct` on a private same-class target
                    // (bare `m()`) into the catch-all `{receiver}.{name}()`
                    // lowering. Without this, `invoke-super` on `this` would
                    // re-enter the same override at runtime — observable as
                    // unbounded recursion (SuperChain3Level / D.m in
                    // PrivateMethodCollision both hang at the per-process
                    // 20s wall-time cap before this fix).
                    // `ctx.this_var` is only Some(_) for constructors (see
                    // emit_method's per-method ctx setup); for non-constructor
                    // instance methods the receiver is identified by
                    // `ctx.var_names[v] == "this"` instead. Use the var-name
                    // mapping so this predicate works in both contexts.
                    let is_this = insn
                        .uses
                        .first()
                        .map(|v| {
                            ctx.var_names
                                .get(v)
                                .map(|n| n == "this")
                                .unwrap_or(false)
                        })
                        .unwrap_or(false);
                    let target_is_self_class = ctx
                        .own_class_desc
                        .as_deref()
                        .map(|own| own == target_class_desc)
                        .unwrap_or(false);
                    match kind {
                        // `invoke-super` on `this` → `super.m(args)`. Mirrors
                        // the existing `<init>` super-discrimination above.
                        InvokeKind::Super if is_this => {
                            format!("super.{name}({})", args.join(", "))
                        }
                        // `invoke-direct` on a same-class non-`<init>` target
                        // is javac's encoding for a private method call:
                        // d8/javac never emit `invoke-direct` cross-class for
                        // non-`<init>` targets, and never emit it within a
                        // class for non-private methods. Bare `m(args)` is
                        // the cleanest faithful re-encoding (`this.m(args)`
                        // would also be JLS-correct for private targets but
                        // leaves a redundant prefix). The opcode itself is
                        // the discriminator — no method-access-flags lookup
                        // needed.
                        InvokeKind::Direct if target_is_self_class => {
                            format!("{name}({})", args.join(", "))
                        }
                        // Virtual / Interface / cross-class Direct / Super on
                        // non-`this` receiver → existing receiver.method form.
                        _ => format!("{receiver}.{name}({})", args.join(", ")),
                    }
                }
            }
        } else {
            "?()".to_string()
        }
    } else {
        "?()".to_string()
    }
}

/// Emit an `invoke-custom` as a Java source expression. In practice the
/// only bootstrap that javac + d8 ever emit for an `invoke-custom` is
/// `java.lang.invoke.LambdaMetafactory.metafactory`, for lambda
/// expressions and method references. We pattern-match on that
/// bootstrap and lower the call site back to either a method-reference
/// expression (`ClassName::methodName`) when there are no captures, or
/// an explicit-call lambda (`(a, b) -> ClassName.methodName(cap1, a, b)`)
/// when captures or the impl-vs-SAM proto delta force explicit argument
/// threading.
///
/// Non-`LambdaMetafactory` bootstraps fall back to a placeholder
/// comment; this leaves emit output recompilable as long as the lambda
/// body is itself a standalone expression (the synthetic impl method
/// will be emitted by the normal class-member path).
fn emit_invoke_custom(insn: &SsaInsn, dex: &DexFile, ctx: &EmitCtx) -> String {
    let Some(PoolIndex::CallSite(cs_idx)) = insn.insn.pool_idx else {
        return "/* invoke-custom */".to_string();
    };
    let Some(&cs_off) = dex.call_site_ids.get(cs_idx.0 as usize) else {
        return "/* invoke-custom: unresolved call_site */".to_string();
    };
    let Some(cs) = dex.encoded_arrays.get(&cs_off) else {
        return "/* invoke-custom: encoded_array missing */".to_string();
    };
    // Canonical LambdaMetafactory bootstrap shape:
    //   [0] VALUE_METHOD_HANDLE → bootstrap method (LambdaMetafactory.metafactory)
    //   [1] VALUE_STRING        → SAM method name ("run", "apply", ...)
    //   [2] VALUE_METHOD_TYPE   → instantiated MT (generic-erased)
    //   [3] VALUE_METHOD_TYPE   → sam_proto (erased; same as [2] when no witness)
    //   [4] VALUE_METHOD_HANDLE → impl method handle (the synthetic lambda$main$N)
    //   [5] VALUE_METHOD_TYPE   → instantiated MT again
    if cs.len() < 5 {
        return "/* invoke-custom: truncated call_site */".to_string();
    }
    let EncodedValue::MethodHandle(bootstrap_h) = cs[0] else {
        return "/* invoke-custom: bootstrap not a method-handle */".to_string();
    };
    let EncodedValue::MethodHandle(impl_h) = cs[4] else {
        return "/* invoke-custom: impl-slot not a method-handle */".to_string();
    };
    let Some(impl_method_id) = resolve_method_handle(dex, bootstrap_h).and_then(
        |bootstrap_method| {
            // Confirm bootstrap is LambdaMetafactory.metafactory;
            // reject anything else so we don't misrender alternate
            // metafactory calls as lambdas.
            if !is_lambda_metafactory(dex, bootstrap_method) {
                return None;
            }
            resolve_method_handle(dex, impl_h)
        },
    ) else {
        return "/* invoke-custom: non-LambdaMetafactory bootstrap */".to_string();
    };
    let impl_class_desc = dex
        .get_type_descriptor(impl_method_id.class_idx)
        .unwrap_or("?");
    let impl_class = pretty_class_name(impl_class_desc);
    let raw_impl_name = dex.get_string(impl_method_id.name_idx).unwrap_or("?");
    let impl_name = sanitize_id(raw_impl_name);

    // Per JVM spec §LambdaMetafactory.metafactory, the call_site's
    // encoded_array indices [2] and [3] are:
    //   [2] invokedType   — factory's return-type; its parameters are
    //                       the captures threaded into the factory
    //                       (zero params = non-capturing lambda).
    //   [3] samMethodType — SAM signature (what the returned functional
    //                       interface's single abstract method takes).
    // capture_count thus = arity(invokedType); sam_arity = arity(samMT).
    let EncodedValue::MethodType(invoked_ty) = cs[2] else {
        return "/* invoke-custom: non-MT invokedType */".to_string();
    };
    let EncodedValue::MethodType(sam_mt) = cs[3] else {
        return "/* invoke-custom: non-MT samMethodType */".to_string();
    };
    let capture_count = proto_arity(dex, invoked_ty);
    let sam_arity = proto_arity(dex, sam_mt);

    // `insn.uses` holds the captured locals (Dalvik reg order). For a
    // non-capturing lambda, `uses` is empty. Wide captures (long/
    // double) occupy two register slots but one SSA VarId — the
    // args_skipping_wide_halves helper reuses the impl proto's first
    // `capture_count` param types to skip high halves.
    let impl_params = proto_param_types(dex, impl_method_id.proto_idx);
    let capture_param_types: Vec<DexType> = impl_params
        .iter()
        .take(capture_count)
        .cloned()
        .collect();
    let capture_vars = args_skipping_wide_halves(&insn.uses, &capture_param_types);
    let capture_args: Vec<String> =
        capture_vars.iter().map(|v| emit_use(v, ctx)).collect();

    // Always emit explicit-lambda form rather than a method reference.
    // Method references assign cleanly against a parameterized SAM
    // (`Function<Integer,Integer>`), but invoke-custom is lowered long
    // before generic signatures are preserved in DEX — the target
    // variable ends up typed as the raw `Function` (no type args),
    // under which javac enforces the raw-erasure SAM
    // (`Object apply(Object)`). That rejects
    // `Lambdas::lambda$main$1` (since `Integer` is not exactly
    // `Object`). An explicit lambda with per-argument casts works:
    // `(a) -> Lambdas.lambda$main$1((Integer) a)` — inference picks
    // `Function<Object,Object>` against the raw target, then the cast
    // restores the impl's declared type.
    let sam_param_names: Vec<String> =
        (0..sam_arity).map(|i| format!("_a{i}")).collect();
    let sam_impl_types: Vec<DexType> = impl_params
        .iter()
        .skip(capture_count)
        .cloned()
        .collect();
    let sam_call_args: Vec<String> = sam_param_names
        .iter()
        .enumerate()
        .map(|(i, name)| match sam_impl_types.get(i) {
            Some(ty) if needs_sam_cast(ty) => format!("({}) {}", emit_type(ty), name),
            _ => name.clone(),
        })
        .collect();
    let mut call_args = capture_args;
    call_args.extend(sam_call_args);
    let sam_sig = if sam_arity == 1 {
        sam_param_names.join(", ")
    } else {
        format!("({})", sam_param_names.join(", "))
    };
    format!(
        "{sam_sig} -> {impl_class}.{impl_name}({})",
        call_args.join(", ")
    )
}

/// Does a SAM-argument need an explicit cast from `Object` back to its
/// impl-declared type? `true` when the impl expects a non-Object reference
/// type (so raw-SAM's erased `Object` would be rejected); `false` when
/// the impl parameter is a primitive (auto-unboxing handles the cast)
/// or is already Object (no cast needed).
fn needs_sam_cast(ty: &DexType) -> bool {
    match ty {
        DexType::Ref(s) => &**s != "Ljava/lang/Object;",
        _ => false,
    }
}

fn emit_invoke_polymorphic(insn: &SsaInsn, dex: &DexFile, ctx: &EmitCtx) -> String {
    // `invoke-polymorphic` is signature-polymorphic: the declared
    // method's proto (always `([Object)Object` for
    // `MethodHandle.invokeExact`) differs from the per-call-site
    // proto encoded in `PoolIndex::MethodAndProto`. To recompile,
    // we have to both (a) skip the declared method's proto for
    // argument typing and (b) cast the result to the call-site
    // proto's return type — raw `Object` won't satisfy a
    // `String s = ...` LHS, and javac enforces the exact-signature
    // contract via a required source-level cast on invokeExact.
    let Some(PoolIndex::MethodAndProto(midx, call_site_proto)) = insn.insn.pool_idx
    else {
        return emit_invoke(insn, dex, InvokeKind::from_opcode(insn.insn.op), ctx);
    };
    let Some(method) = dex.methods.get(midx.0 as usize) else {
        return "?()".to_string();
    };
    let raw_name = dex.get_string(method.name_idx).unwrap_or("?");
    let name = sanitize_id(raw_name);
    // Use the call-site proto to type SAM args (not the declared
    // proto's `Object[] varargs` blob).
    let cs_params = proto_param_types(dex, call_site_proto);
    if insn.uses.is_empty() {
        return "/* invoke-polymorphic: missing receiver */".to_string();
    }
    let receiver = use0(insn, ctx);
    let arg_vars = args_skipping_wide_halves(&insn.uses[1..], &cs_params);
    let args: Vec<String> = arg_vars.iter().map(|v| emit_use(v, ctx)).collect();
    let call_expr = format!("{receiver}.{name}({})", args.join(", "));
    // Return cast. invokeExact's compile-time rule says each call site
    // must cast the result to the declared LHS type. The call-site
    // proto carries the exact type the bytecode expects.
    let cs_return = match dex.protos.get(call_site_proto.0 as usize) {
        Some(p) => resolve_type_desc(dex, p.return_type_idx),
        None => return call_expr,
    };
    match cs_return.as_deref() {
        Some("V") | None => call_expr,
        Some(desc) => {
            let ty = emit_type(&DexType::from_descriptor(desc));
            format!("({ty}) {call_expr}")
        }
    }
}

/// Fetch a type descriptor by index. Thin shim around
/// `DexFile::get_type_descriptor` that returns owned `Option<String>`
/// so the borrow doesn't outlive the caller (used inside
/// `emit_invoke_polymorphic`'s pattern-match on the proto's return
/// type, where the subsequent `DexType::from_descriptor` clones the
/// string anyway).
fn resolve_type_desc(dex: &DexFile, idx: crate::ids::TypeIdx) -> Option<String> {
    dex.get_type_descriptor(idx).ok().map(str::to_string)
}

/// Resolve a method_handle index to the underlying `MethodIdItem`
/// (when the handle refers to a method; returns `None` for field
/// handles, since lambda bootstraps never use those).
fn resolve_method_handle(
    dex: &DexFile,
    h: crate::ids::MethodHandleIdx,
) -> Option<&crate::ids::MethodIdItem> {
    let handle = dex.method_handles.get(h.0 as usize)?;
    // Spec method_handle_type_codes 4..=8 are method-invoke kinds.
    // 0..=3 are field getter/setter — not possible via javac lambdas.
    if !(4..=8).contains(&handle.kind) {
        return None;
    }
    dex.methods.get(handle.field_or_method_id as usize)
}

/// `true` iff the given method refers to
/// `java.lang.invoke.LambdaMetafactory.metafactory`. We do NOT accept
/// `altMetafactory` — its argument shape is different (serialization-
/// flags + marker interfaces) and would require additional plumbing.
fn is_lambda_metafactory(dex: &DexFile, m: &crate::ids::MethodIdItem) -> bool {
    let class = dex.get_type_descriptor(m.class_idx).unwrap_or("");
    let name = dex.get_string(m.name_idx).unwrap_or("");
    class == "Ljava/lang/invoke/LambdaMetafactory;" && name == "metafactory"
}

/// Arity of a proto (its positional parameters count), treating a
/// missing `parameters_off` as zero. Wide (long/double) params count
/// as 1 arg each for source-level purposes — same convention the
/// args_skipping_wide_halves helper uses.
fn proto_arity(dex: &DexFile, proto: crate::ids::ProtoIdx) -> usize {
    let Some(p) = dex.protos.get(proto.0 as usize) else {
        return 0;
    };
    if p.parameters_off == 0 {
        return 0;
    }
    dex.type_lists
        .get(&p.parameters_off)
        .map(|tl| tl.len())
        .unwrap_or(0)
}

/// Parameter types for a proto; empty when parameters_off is zero or
/// the type_list is missing. Mirrors the local collection in
/// `emit_invoke` but factored out for reuse.
fn proto_param_types(dex: &DexFile, proto: crate::ids::ProtoIdx) -> Vec<DexType> {
    let Some(p) = dex.protos.get(proto.0 as usize) else {
        return Vec::new();
    };
    if p.parameters_off == 0 {
        return Vec::new();
    }
    let Some(tl) = dex.type_lists.get(&p.parameters_off) else {
        return Vec::new();
    };
    tl.iter()
        .filter_map(|tidx| {
            dex.get_type_descriptor(*tidx)
                .ok()
                .map(DexType::from_descriptor)
        })
        .collect()
}

fn resolve_field_name(dex: &DexFile, pool_idx: &Option<PoolIndex>) -> String {
    if let Some(PoolIndex::Field(fidx)) = pool_idx {
        if let Some(field) = dex.fields.get(fidx.0 as usize) {
            sanitize_id(dex.get_string(field.name_idx).unwrap_or("?"))
        } else {
            "?".to_string()
        }
    } else {
        "?".to_string()
    }
}

fn emit_condition_typed(
    cond: &crate::structure::Condition,
    env: Option<&crate::types::TypeEnv>,
    ctx: &EmitCtx,
) -> String {
    use crate::structure::Condition;
    match cond {
        Condition::TestZero { var, op } => {
            let v = emit_use(var, ctx);
            // Boolean variables: use !v / v instead of v == 0 / v != 0
            let is_bool = env
                .and_then(|e| e.types.get(var))
                .is_some_and(|t| *t == crate::types::DexType::Boolean);
            if is_bool {
                return match op {
                    Opcode::IfEqz => format!("!{v}"),
                    Opcode::IfNez => v,
                    _ => format!("{v} {}", match op {
                        Opcode::IfLtz => "< 0",
                        Opcode::IfGez => ">= 0",
                        Opcode::IfGtz => "> 0",
                        Opcode::IfLez => "<= 0",
                        _ => "!= 0",
                    }),
                };
            }
            // Reference types: use null instead of 0
            let is_ref = env
                .and_then(|e| e.types.get(var))
                .is_some_and(|t| t.is_reference());
            if is_ref {
                return match op {
                    Opcode::IfEqz => format!("{v} == null"),
                    Opcode::IfNez => format!("{v} != null"),
                    _ => format!("{v} == null"), // other ops don't apply to refs
                };
            }
            match op {
                Opcode::IfEqz => format!("{v} == 0"),
                Opcode::IfNez => format!("{v} != 0"),
                Opcode::IfLtz => format!("{v} < 0"),
                Opcode::IfGez => format!("{v} >= 0"),
                Opcode::IfGtz => format!("{v} > 0"),
                Opcode::IfLez => format!("{v} <= 0"),
                _ => v,
            }
        }
        Condition::Compare { left, right, op } => {
            let l = emit_use(left, ctx);
            let r = emit_use(right, ctx);
            match op {
                Opcode::IfEq => format!("{l} == {r}"),
                Opcode::IfNe => format!("{l} != {r}"),
                Opcode::IfLt => format!("{l} < {r}"),
                Opcode::IfGe => format!("{l} >= {r}"),
                Opcode::IfGt => format!("{l} > {r}"),
                Opcode::IfLe => format!("{l} <= {r}"),
                _ => format!("{l} ? {r}"),
            }
        }
        Condition::Var(v) => emit_use(v, ctx),
    }
}

/// Simplify "int v1 = v1 + 1" or "v1 = v1 + 1" → "v1++"
// WHY: byte-offset arithmetic `eq_pos + 1` for next-byte index after `=`;
// bounded by surrounding `find('=')` having returned a valid position
// < s.len().
#[allow(clippy::arithmetic_side_effects, reason = "byte-offset arithmetic `eq_pos + 1` for next-byte index after `=`; bounded by surrounding `find('=')` having returned a valid position < s.len().")]
fn simplify_increment(s: &str) -> String {
    let s = s.trim();
    // Strip leading type declaration: "int v1 = v1 + 1" → "v1 = v1 + 1"
    let assignment = if let Some(eq_pos) = s.find('=') {
        let before_eq = s[..eq_pos].trim();
        // The var name is the last word before '='
        let var_name = before_eq
            .rsplit_once(' ')
            .map(|(_, v)| v)
            .unwrap_or(before_eq);
        let after_eq = s[eq_pos + 1..].trim();
        (var_name, after_eq)
    } else {
        return s.to_string();
    };

    let (var, expr) = assignment;
    // Check "v + 1" pattern
    if expr == format!("{var} + 1") {
        return format!("{var}++");
    }
    if expr == format!("{var} - 1") {
        return format!("{var}--");
    }
    // Default: strip type, keep assignment
    format!("{var} = {expr}")
}

/// Sanitize an identifier to be valid Java (replace - with _, $ prefix for leading digits)
/// Escape a string for Java string literal (handle newlines, quotes, backslashes)
pub fn escape_java_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Word-boundary-aware, string-literal-aware multi-key replacement.
///
/// Walks `haystack` once. Inside a Java string or character literal, every
/// byte is copied through verbatim (escapes are tracked so the literal
/// terminates correctly). Outside literals, max-munch identifier-shaped
/// tokens (`[A-Za-z_$][A-Za-z0-9_$]*`) are extracted at each word boundary
/// and looked up in `table`; on a hit the replacement is emitted, otherwise
/// the original token is copied through.
///
/// The string-literal guard is essential for the inline-expression
/// substitution: `ctx.inline_exprs` maps SSA tokens like `v0_1` to arbitrary
/// expression strings. Without the guard, a legitimate class containing a
/// literal like `"v0_1 is the first register"` would have `v0_1` replaced
/// with whatever expression the inliner chose. If the replacement contains
/// quotes or parentheses, the closing quote of the literal is corrupted and
/// subsequent parsing fails.
///
/// Replaces the prior `replace_word`-in-a-loop pattern, which was O(N×M)
/// (N needles, M haystack length) and dominated emit CPU (~25% self-time
/// in samply flamegraph). The single-pass form is O(M) plus O(1) hashmap
/// lookup per identifier token. Longest-needle-wins is implicit: identifier
/// max-munch consumes the whole token before lookup, so overlapping needles
/// (`v0` vs `v0_1`) cannot collide — each position yields exactly one token.
// WHY: byte-scanner over `haystack.as_bytes()`. Arithmetic shapes:
// `i += 1` / `i += 2` / `i += token.len()` cursor advance, each preceded
// by `i < bytes.len()` check (or token slice derived from bounds-checked
// `&bytes[i..end]`); `String::with_capacity(out.len() + 1)` capacity from
// String len bounded by isize::MAX; `bytes[i - 1]` look-back guarded by
#[allow(clippy::arithmetic_side_effects, reason = "byte-scanner over `haystack.as_bytes()`. Arithmetic shapes: `i += 1` / `i += 2` / `i += token.len()` cursor advance, each preceded by `i < bytes.len()` check (or token slice derived from bounds-checked `&bytes[i..end]`); `String::with_capacity(out.len() + 1)` capacity from String len bounded by isize::MAX; `bytes[i - 1]` look-back guarded by `i > 0` check above. All sites operate on parser-validated identifier tokens with bounded length (DexString interner cap).")]
fn replace_words(haystack: &str, table: &HashMap<&str, &str>) -> String {
    if table.is_empty() {
        return haystack.to_string();
    }
    let bytes = haystack.as_bytes();
    let mut result = String::with_capacity(haystack.len());
    let mut i = 0;
    let mut chunk_start = 0;
    let mut in_string = false;
    let mut in_char = false;

    while i < bytes.len() {
        let b = bytes[i];

        if in_string {
            // Handle `\"` and other escapes so we don't exit a string on an
            // escaped quote.
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if in_char {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'\'' {
                in_char = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        if b == b'\'' {
            in_char = true;
            i += 1;
            continue;
        }

        // Outside string/char literal. If `i` starts an identifier (with a
        // left word boundary), max-munch the token and look it up.
        let before_ok = i == 0 || {
            let pb = bytes[i - 1];
            !pb.is_ascii_alphanumeric() && pb != b'_' && pb != b'$'
        };
        let is_ident_start = b.is_ascii_alphabetic() || b == b'_' || b == b'$';
        if before_ok && is_ident_start {
            let start = i;
            i += 1;
            while i < bytes.len() {
                let c = bytes[i];
                if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' {
                    i += 1;
                } else {
                    break;
                }
            }
            let token = &haystack[start..i];
            if let Some(&repl) = table.get(token) {
                result.push_str(&haystack[chunk_start..start]);
                result.push_str(repl);
                chunk_start = i;
            }
            continue;
        }

        // Advance by the full char width so the next iteration always lands
        // on a char boundary. bare `i += 1` would put us inside a multibyte
        // sequence (e.g. ⊤ U+22A4 = 3 bytes) and panic on `haystack[i..]`.
        i += haystack[i..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
    }
    result.push_str(&haystack[chunk_start..]);
    result
}

/// Java reserved words + literals. Any identifier matching one of these
/// gets a `$` prefix so it becomes a legal Java identifier. R8 aggressive
/// obfuscation (seen on Binance, iproov SDK) emits class/package/method
/// names like `boolean`, `while`, `new`, `do`, `int`, etc.
const JAVA_KEYWORDS: &[&str] = &[
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "try",
    "void",
    "volatile",
    "while",
    "true",
    "false",
    "null",
    "_",
];

fn is_java_keyword(s: &str) -> bool {
    JAVA_KEYWORDS.contains(&s)
}

/// Java identifier grammar for [`droidsaw_common::identifier::sanitize`].
///
/// Supplies the dialect-specific predicates that the generic algorithm
/// needs: ASCII identifier-start + identifier-part character sets per
/// JLS §3.8 (ASCII-only subset — Unicode identifiers are out of scope
/// for v1 since javac accepts the ASCII subset and the codomain stays
/// auditable), the [`JAVA_KEYWORDS`] reserved-word table, and the
/// `lambda$` → `dsaw$lambda$` prefix rewrite needed for javac symbol
/// disambiguation. Holding the trait invariants of
/// [`droidsaw_common::identifier::IdentifierGrammar`]:
///
/// - `is_start_char('$')` ⇒ `true` (yes, `'$'` is alphanumeric +`$` set).
/// - `is_part_char('_')` ⇒ `true` (yes).
/// - `is_part_char('$')` ⇒ `true` (yes).
/// - `prefix_rewrite` output (`"dsaw$lambda$<rest>"`) is a valid Java
///   identifier whenever `<rest>` is composed of identifier-part
///   characters — which is the case for every `lambda$…` symbol javac
///   ever synthesizes.
pub struct JavaGrammar;

impl droidsaw_common::identifier::IdentifierGrammar for JavaGrammar {
    fn is_start_char(c: char) -> bool {
        c.is_ascii_alphabetic() || c == '_' || c == '$'
    }

    fn is_part_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '_' || c == '$'
    }

    fn is_reserved(token: &str) -> bool {
        is_java_keyword(token)
    }

    fn prefix_rewrite(raw: &str) -> Option<String> {
        // javac reserves `lambda$<enclosing>$<counter>` for its own
        // invokedynamic-lowered synthetic methods. If our decompiled
        // class declares a method of the same name AND uses a lambda
        // / method-ref inside the same enclosing method, javac fails
        // with "the symbol lambda$… conflicts with a compiler-
        // synthesized symbol". Prefix the name so the emitted method
        // still compiles and the invoke-custom call-sites (which
        // pass through the same helper) agree on the renamed symbol.
        raw.strip_prefix("lambda$")
            .map(|rest| format!("dsaw$lambda${rest}"))
    }
}

/// Sanitize a DEX-supplied string into a valid Java identifier.
///
/// Thin wrapper over [`droidsaw_common::identifier::sanitize`] with
/// the [`JavaGrammar`] dialect. The codomain is provably the valid-
/// Java-identifier set (ASCII subset): every output is non-empty,
/// starts with a JLS §3.8 identifier-start character, has only
/// identifier-part characters thereafter, and is not a reserved
/// keyword or literal.
///
/// Built on the common allowlist-by-construction impl. Behaviour:
/// leading digit → `$<digit>`; `-`/`+` → `_`; keyword → `$<token>`;
/// `lambda$` prefix → `dsaw$lambda$<rest>`. Pass-through-unsafe chars
/// (`;`, `\n`, `\r`, `\0`, `<`, `>`, `{`, `}`, `(`, `)`, `[`, `]`,
/// whitespace, U+202E + other Unicode non-letter chars, control chars)
/// are replaced with `_` in part position, or escaped to `$_` if the sole
/// character. Empty input now produces `$_` (was: empty string).
#[must_use]
pub fn sanitize_id(name: &str) -> String {
    droidsaw_common::identifier::sanitize::<JavaGrammar>(name)
}

// WHY: `desc[1..desc.len() - 1]` strips `L`/`;` from a JVM class
// descriptor. Caller guarantees descriptor is well-formed (`L<fqcn>;`,
// len ≥ 2); subtraction safe.
#[allow(clippy::arithmetic_side_effects, reason = "`desc[1..desc.len() - 1]` strips `L`/`;` from a JVM class descriptor. Caller guarantees descriptor is well-formed (`L<fqcn>;`, len ≥ 2); subtraction safe.")]
fn pretty_class_name(desc: &str) -> String {
    if let Some(elem) = desc.strip_prefix('[') {
        format!("{}[]", pretty_class_name(elem))
    } else if desc.starts_with('L') && desc.ends_with(';') {
        let name = desc[1..desc.len() - 1].replace('/', ".");
        // Rewrite `Outer$Inner` (bytecode form) to `Outer.Inner`
        // (source form) for type references to standard-library
        // classes where we can't emit an `Outer$Inner.java` file
        // ourselves. `$` at index 0 is left alone — anonymous-class
        // synthetic prefixes look like `$1`, which sanitize_id
        // handles below. Limiting this to std-lib namespaces
        // preserves the nested-class-emission contract for the
        // StaticNestedClass / AnonymousInnerClass / LocalInnerClass
        // fixtures, which rely on `Outer$Inner.java` filenames.
        let is_stdlib = matches!(
            name.split('.').next(),
            Some("java") | Some("javax") | Some("kotlin") | Some("kotlinx")
        );
        let name = if is_stdlib {
            name.replace('$', ".")
        } else {
            name
        };
        // Sanitize segments that have invalid Java identifier chars
        name.split('.')
            .map(sanitize_id)
            .collect::<Vec<_>>()
            .join(".")
    } else {
        // Primitive descriptors
        match desc {
            "I" => "int".to_string(),
            "J" => "long".to_string(),
            "F" => "float".to_string(),
            "D" => "double".to_string(),
            "Z" => "boolean".to_string(),
            "B" => "byte".to_string(),
            "C" => "char".to_string(),
            "S" => "short".to_string(),
            "V" => "void".to_string(),
            _ => desc.to_string(),
        }
    }
}

/// Kotlin source-form rendering of a JVM type descriptor. Mirrors
/// `pretty_class_name` but unconditionally rewrites `Outer$Inner`
/// (bytecode form) → `Outer.Inner` (Kotlin source form), regardless of
/// namespace. Java's emit must preserve `$` for non-stdlib types so the
/// `Outer$Inner.java` filename contract holds; Kotlin has no such
/// contract — every nested-class reference in Kotlin source uses `.`.
///
/// Used by `render_arm_predicate_kotlin` for sealed-class /
/// sealed-object arm typenames, where Kotlin source form is load-bearing.
// WHY: same shape as pretty_class_name; strips `L`/`;` after the
// caller-validated `desc.starts_with('L') && desc.ends_with(';')`
// guard above. Subtraction safe.
#[allow(clippy::arithmetic_side_effects, reason = "same shape as pretty_class_name; strips `L`/`;` after the caller-validated `desc.starts_with('L') && desc.ends_with(';')` guard above. Subtraction safe.")]
fn pretty_class_name_kotlin(desc: &str) -> String {
    if let Some(elem) = desc.strip_prefix('[') {
        format!("Array<{}>", pretty_class_name_kotlin(elem))
    } else if desc.starts_with('L') && desc.ends_with(';') {
        let name = desc[1..desc.len() - 1].replace(['/', '$'], ".");
        name.split('.')
            .map(sanitize_id)
            .collect::<Vec<_>>()
            .join(".")
    } else {
        // Primitive descriptors → Kotlin names. Note: at JVM level
        // these are unboxed; Kotlin source-form may be `Int` / `Long`
        // / `Boolean` etc. Used only for arm-predicate type rendering
        // currently, which won't see primitives.
        match desc {
            "I" => "Int".to_string(),
            "J" => "Long".to_string(),
            "F" => "Float".to_string(),
            "D" => "Double".to_string(),
            "Z" => "Boolean".to_string(),
            "B" => "Byte".to_string(),
            "C" => "Char".to_string(),
            "S" => "Short".to_string(),
            "V" => "Unit".to_string(),
            _ => desc.to_string(),
        }
    }
}

// ── Phi pre-declaration helpers ──────────────────────────────────────

/// Collect the set of registers that are defined (assigned to) in a Stmt tree.
fn collect_defined_regs(stmt: &Stmt) -> BTreeSet<u16> {
    let mut regs = BTreeSet::new();
    collect_defined_regs_inner(stmt, &mut regs);
    regs
}

fn collect_defined_regs_inner(stmt: &Stmt, regs: &mut BTreeSet<u16>) {
    match stmt {
        Stmt::Expr(insn) => {
            if let Some(ref dst) = insn.dst {
                regs.insert(dst.reg());
            }
        }
        Stmt::Seq(stmts) => {
            for s in stmts {
                collect_defined_regs_inner(s, regs);
            }
        }
        Stmt::If { then_body, else_body, .. } => {
            collect_defined_regs_inner(then_body, regs);
            if let Some(eb) = else_body {
                collect_defined_regs_inner(eb, regs);
            }
        }
        Stmt::While { body, .. } => collect_defined_regs_inner(body, regs),
        Stmt::DoWhile { body, .. } => collect_defined_regs_inner(body, regs),
        _ => {}
    }
}

/// Find the first VarId defined on a given register in a Stmt tree.
fn find_first_def_on_reg(stmt: &Stmt, reg: u16) -> Option<VarId> {
    match stmt {
        Stmt::Expr(insn) => insn.dst.as_ref().filter(|d| d.reg() == reg).cloned(),
        Stmt::Seq(stmts) => stmts.iter().find_map(|s| find_first_def_on_reg(s, reg)),
        Stmt::If { then_body, else_body, .. } => {
            find_first_def_on_reg(then_body, reg)
                .or_else(|| else_body.as_ref().and_then(|eb| find_first_def_on_reg(eb, reg)))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => find_first_def_on_reg(body, reg),
        _ => None,
    }
}

// ── Expression inlining pre-pass ─────────────────────────────────────

/// Count uses of each VarId in a Stmt tree (for inlining decisions).
// WHY: thin entry; delegates to count_uses_in_stmt_depth at depth 0.
// No arithmetic of its own.
fn count_uses_in_stmt(stmt: &Stmt, counts: &mut BTreeMap<VarId, usize>) {
    count_uses_in_stmt_depth(stmt, counts, 0);
}

// WHY: depth-bounded recursion (`if depth > MAX_STMT_DEPTH { return; }` +
// `depth.saturating_add(1)` at entry). Body sites are exclusively
// `*counts.entry(VarId).or_insert(0) += 1` — BTreeMap counter increments
// over IR-bounded VarId references. Each VarId appears at most once per
// parser-validated Stmt node; total counts bounded by `parse_budgeted`
// step limits (u32-bounded). Cannot overflow usize within input limits.
#[allow(clippy::arithmetic_side_effects, reason = "depth-bounded recursion (`if depth > MAX_STMT_DEPTH { return; }` + `depth.saturating_add(1)` at entry). Body sites are exclusively `*counts.entry(VarId).or_insert(0) += 1` — BTreeMap counter increments over IR-bounded VarId references. Each VarId appears at most once per parser-validated Stmt node; total counts bounded by `parse_budgeted` step limits (u32-bounded). Cannot overflow usize within input limits.")]
fn count_uses_in_stmt_depth(stmt: &Stmt, counts: &mut BTreeMap<VarId, usize>, depth: usize) {
    if depth > MAX_STMT_DEPTH {
        return;
    }
    let depth = depth.saturating_add(1);
    match stmt {
        Stmt::Expr(insn) => {
            for u in &insn.uses {
                *counts.entry(u.clone()).or_insert(0) += 1;
            }
        }
        Stmt::Seq(stmts) => {
            for s in stmts {
                count_uses_in_stmt_depth(s, counts, depth);
            }
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            count_uses_in_condition(cond, counts);
            count_uses_in_stmt_depth(then_body, counts, depth);
            if let Some(eb) = else_body {
                count_uses_in_stmt_depth(eb, counts, depth);
            }
        }
        Stmt::While { cond, body } => {
            count_uses_in_condition(cond, counts);
            count_uses_in_stmt_depth(body, counts, depth);
        }
        Stmt::DoWhile { body, cond } => {
            count_uses_in_stmt_depth(body, counts, depth);
            count_uses_in_condition(cond, counts);
        }
        Stmt::Switch {
            value,
            cases,
            default,
        } => {
            *counts.entry(value.clone()).or_insert(0) += 1;
            for (_, body) in cases {
                count_uses_in_stmt_depth(body, counts, depth);
            }
            if let Some(d) = default {
                count_uses_in_stmt_depth(d, counts, depth);
            }
        }
        Stmt::StringSwitch {
            value,
            cases,
            default,
        } => {
            *counts.entry(value.clone()).or_insert(0) += 1;
            for (_, body) in cases {
                count_uses_in_stmt_depth(body, counts, depth);
            }
            if let Some(d) = default {
                count_uses_in_stmt_depth(d, counts, depth);
            }
        }
        Stmt::TryCatch { body, catches } => {
            count_uses_in_stmt_depth(body, counts, depth);
            for c in catches {
                count_uses_in_stmt_depth(&c.body, counts, depth);
            }
        }
        Stmt::Synchronized { lock, body } => {
            *counts.entry(lock.clone()).or_insert(0) += 1;
            count_uses_in_stmt_depth(body, counts, depth);
        }
        Stmt::Return(Some(v)) | Stmt::Throw(v) => {
            *counts.entry(v.clone()).or_insert(0) += 1;
        }
        Stmt::InlinedReturn(insn) | Stmt::InlinedThrow(insn) => {
            for u in &insn.uses {
                *counts.entry(u.clone()).or_insert(0) += 1;
            }
        }
        Stmt::InlinedReturnConcat(parts) | Stmt::StringConcat { parts, .. } => {
            for p in parts {
                if let ConcatPart::Var(v) = p {
                    *counts.entry(v.clone()).or_insert(0) += 1;
                }
            }
        }
        Stmt::ForEach {
            var: _,
            iterable,
            body,
        } => {
            *counts.entry(iterable.clone()).or_insert(0) += 1;
            count_uses_in_stmt_depth(body, counts, depth);
        }
        Stmt::BooleanAssign { cond, .. } => {
            count_uses_in_condition(cond, counts);
        }
        _ => {}
    }
}

// ── Catch-var escape detection (cross-catch SSA-scope leak fix) ────
//
// An SSA catch-binding VarId has its legitimate Java-source scope as the
// *union* of all catch bodies in which it's bound (MultiCatch-shape IR
// can bind the same VarId in multiple sibling TypedCatches of one
// TryCatch). If the var has uses *outside* that legitimate scope, emit
// as-is leaks an undefined identifier (Java catch-clause scope rejects
// the reference). Example: `try-with-resources` → Dalvik lowering has a
// synthetic primary-Throwable reg defined by `move-exception` in one
// handler and re-used in a sibling handler's `addSuppressed` — the uses
// span two different TryCatches in our IR. Fix: hoist such vars to a
// method-scope local `{T} v = null;`, rebind the catch clause to a fresh
// tmp, and prologue the body with `v = tmp;`.
//
// Bail out (leave emit broken rather than silently wrong) if the var
// is bound at more than one catch site in the method — SSA normally
// renumbers per move-exception, so a double binding indicates a
// coalescing edge case we don't want to paper over.

/// Collect VarIds that are catch-bound but have uses outside their
/// legitimate scope. Result: `(var, resolved_type)` pairs for the
/// caller to emit method-scope declarations.
fn collect_escaped_catch_vars(
    stmt: &Stmt,
    env: &TypeEnv,
) -> Vec<(VarId, crate::types::DexType)> {
    let mut total_uses: BTreeMap<VarId, usize> = BTreeMap::new();
    count_uses_in_stmt(stmt, &mut total_uses);

    let mut binding_sites: BTreeMap<VarId, usize> = BTreeMap::new();
    let mut inside_uses: BTreeMap<VarId, usize> = BTreeMap::new();
    enumerate_catch_bindings(stmt, &mut binding_sites, &mut inside_uses);

    let mut escaped: Vec<(VarId, crate::types::DexType)> = Vec::new();
    for (v, count) in binding_sites {
        if count != 1 {
            continue;
        }
        // SEMANTICS-DEFAULT-EMPTY: absent var in use-count map → 0 uses, which is
        // the correct count for vars that appear in no tracked position.
        let total = total_uses.get(&v).copied().unwrap_or(0);
        let inside = inside_uses.get(&v).copied().unwrap_or(0);
        if total > inside {
            let ty = env
                .types
                .get(&v)
                .cloned()
                .unwrap_or_else(|| crate::types::DexType::Ref(std::sync::Arc::from("Ljava/lang/Exception;")));
            escaped.push((v, ty));
        }
    }
    escaped
}

/// Walk the Stmt tree; for each TypedCatch with a Some(var) binding, bump
/// `binding_sites[var]` and fold the var's in-body use count into
/// `inside_uses[var]`. Same structural recursion as `count_uses_in_stmt`.
// WHY: thin entry; delegates to enumerate_catch_bindings_depth at depth 0.
fn enumerate_catch_bindings(
    stmt: &Stmt,
    binding_sites: &mut BTreeMap<VarId, usize>,
    inside_uses: &mut BTreeMap<VarId, usize>,
) {
    enumerate_catch_bindings_depth(stmt, binding_sites, inside_uses, 0);
}

// WHY: depth-bounded recursion (same shape as count_uses_in_stmt_depth).
// Body sites are catch-binding counter increments over IR-bounded VarIds;
// bounded by `parse_budgeted` step limits.
#[allow(clippy::arithmetic_side_effects, reason = "depth-bounded recursion (same shape as count_uses_in_stmt_depth). Body sites are catch-binding counter increments over IR-bounded VarIds; bounded by `parse_budgeted` step limits.")]
fn enumerate_catch_bindings_depth(
    stmt: &Stmt,
    binding_sites: &mut BTreeMap<VarId, usize>,
    inside_uses: &mut BTreeMap<VarId, usize>,
    depth: usize,
) {
    if depth > MAX_STMT_DEPTH {
        return;
    }
    let depth = depth.saturating_add(1);
    match stmt {
        Stmt::Seq(stmts) => {
            for s in stmts {
                enumerate_catch_bindings_depth(s, binding_sites, inside_uses, depth);
            }
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            enumerate_catch_bindings_depth(then_body, binding_sites, inside_uses, depth);
            if let Some(eb) = else_body {
                enumerate_catch_bindings_depth(eb, binding_sites, inside_uses, depth);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            enumerate_catch_bindings_depth(body, binding_sites, inside_uses, depth);
        }
        Stmt::Switch { cases, default, .. } => {
            for (_, body) in cases {
                enumerate_catch_bindings_depth(body, binding_sites, inside_uses, depth);
            }
            if let Some(d) = default {
                enumerate_catch_bindings_depth(d, binding_sites, inside_uses, depth);
            }
        }
        Stmt::StringSwitch { cases, default, .. } => {
            for (_, body) in cases {
                enumerate_catch_bindings_depth(body, binding_sites, inside_uses, depth);
            }
            if let Some(d) = default {
                enumerate_catch_bindings_depth(d, binding_sites, inside_uses, depth);
            }
        }
        Stmt::TryCatch { body, catches } => {
            enumerate_catch_bindings_depth(body, binding_sites, inside_uses, depth);
            for c in catches {
                if let Some(v) = &c.var {
                    *binding_sites.entry(v.clone()).or_insert(0) += 1;
                    let mut local = BTreeMap::new();
                    count_uses_in_stmt(&c.body, &mut local);
                    // SEMANTICS-DEFAULT-EMPTY: var not used in the catch body → 0 uses
                    // in `local`; adding 0 correctly leaves inside_uses unchanged.
                    let n = local.get(v).copied().unwrap_or(0);
                    *inside_uses.entry(v.clone()).or_insert(0) += n;
                }
                enumerate_catch_bindings_depth(&c.body, binding_sites, inside_uses, depth);
            }
        }
        Stmt::Synchronized { body, .. } => {
            enumerate_catch_bindings_depth(body, binding_sites, inside_uses, depth);
        }
        Stmt::ForEach { body, .. } => {
            enumerate_catch_bindings_depth(body, binding_sites, inside_uses, depth);
        }
        Stmt::For {
            init,
            update,
            body,
            ..
        } => {
            enumerate_catch_bindings_depth(init, binding_sites, inside_uses, depth);
            enumerate_catch_bindings_depth(update, binding_sites, inside_uses, depth);
            enumerate_catch_bindings_depth(body, binding_sites, inside_uses, depth);
        }
        _ => {}
    }
}

/// For the multicatch-collapse rewrite: find the VarId the body uses
/// for "the caught exception" — i.e., the phi-merge result of the
/// N same-register catch-bound vars. Detection: walk the body's USES
/// for any VarId whose reg matches the catch-bound var's reg; return
/// the FIRST such use seen in execution order. If the body neither uses
/// the reg nor defines a replacement, fall back to returning the
/// catch's own var.
fn catch_binding_from_body_phi(body: &Stmt, catch_var: &Option<VarId>) -> Option<VarId> {
    let catch_reg = catch_var.as_ref()?.reg();
    first_use_of_reg(body, catch_reg).or_else(|| catch_var.clone())
}

/// Walk `stmt` in execution order; return the first VarId used that
/// lives in `reg`. Stops at the first hit. Handles Expr / Seq / If /
/// While / DoWhile / Switch / Return / Throw / InlinedReturn /
/// InlinedThrow / StringConcat / ForEach / For / TryCatch / Synchronized.
fn first_use_of_reg(stmt: &Stmt, reg: u16) -> Option<VarId> {
    match stmt {
        Stmt::Expr(insn) => insn.uses.iter().find(|v| v.reg() == reg).cloned(),
        Stmt::Seq(stmts) => stmts.iter().find_map(|s| first_use_of_reg(s, reg)),
        Stmt::If { cond, then_body, else_body } => {
            first_use_in_condition(cond, reg)
                .or_else(|| first_use_of_reg(then_body, reg))
                .or_else(|| else_body.as_ref().and_then(|e| first_use_of_reg(e, reg)))
        }
        Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
            first_use_in_condition(cond, reg)
                .or_else(|| first_use_of_reg(body, reg))
        }
        Stmt::Switch { value, cases, default } => {
            if value.reg() == reg {
                return Some(value.clone());
            }
            for (_, b) in cases {
                if let Some(v) = first_use_of_reg(b, reg) {
                    return Some(v);
                }
            }
            default.as_ref().and_then(|d| first_use_of_reg(d, reg))
        }
        Stmt::TryCatch { body, catches } => {
            first_use_of_reg(body, reg)
                .or_else(|| catches.iter().find_map(|c| first_use_of_reg(&c.body, reg)))
        }
        Stmt::Synchronized { lock, body } => {
            if lock.reg() == reg {
                Some(lock.clone())
            } else {
                first_use_of_reg(body, reg)
            }
        }
        Stmt::Return(Some(v)) | Stmt::Throw(v) => {
            if v.reg() == reg {
                Some(v.clone())
            } else {
                None
            }
        }
        Stmt::InlinedReturn(insn) | Stmt::InlinedThrow(insn) => {
            insn.uses.iter().find(|v| v.reg() == reg).cloned()
        }
        Stmt::InlinedReturnConcat(parts) | Stmt::StringConcat { parts, .. } => {
            parts.iter().find_map(|p| match p {
                ConcatPart::Var(v) if v.reg() == reg => Some(v.clone()),
                _ => None,
            })
        }
        Stmt::ForEach { iterable, body, .. } => {
            if iterable.reg() == reg {
                Some(iterable.clone())
            } else {
                first_use_of_reg(body, reg)
            }
        }
        Stmt::For { init, cond, update, body } => {
            first_use_of_reg(init, reg)
                .or_else(|| first_use_in_condition(cond, reg))
                .or_else(|| first_use_of_reg(update, reg))
                .or_else(|| first_use_of_reg(body, reg))
        }
        _ => None,
    }
}

fn first_use_in_condition(cond: &crate::structure::Condition, reg: u16) -> Option<VarId> {
    use crate::structure::Condition;
    match cond {
        Condition::TestZero { var, .. } | Condition::Var(var) => {
            if var.reg() == reg { Some(var.clone()) } else { None }
        }
        Condition::Compare { left, right, .. } => {
            if left.reg() == reg {
                Some(left.clone())
            } else if right.reg() == reg {
                Some(right.clone())
            } else {
                None
            }
        }
    }
}

// WHY: counter increments over Condition's VarId references. Each
// Condition carries ≤2 VarIds (lhs / rhs); count walks the structure
// once. Bounded; cannot overflow usize.
#[allow(clippy::arithmetic_side_effects, reason = "counter increments over Condition's VarId references. Each Condition carries ≤2 VarIds (lhs / rhs); count walks the structure once. Bounded; cannot overflow usize.")]
fn count_uses_in_condition(
    cond: &crate::structure::Condition,
    counts: &mut BTreeMap<VarId, usize>,
) {
    use crate::structure::Condition;
    match cond {
        Condition::TestZero { var, .. } => {
            *counts.entry(var.clone()).or_insert(0) += 1;
        }
        Condition::Compare { left, right, .. } => {
            *counts.entry(left.clone()).or_insert(0) += 1;
            *counts.entry(right.clone()).or_insert(0) += 1;
        }
        Condition::Var(v) => {
            *counts.entry(v.clone()).or_insert(0) += 1;
        }
    }
}

/// True when `var` appears in `insn` in a *dereferencing* position — i.e. a
/// slot where replacing the var with a literal `null` / numeric constant would
/// produce a syntactically-invalid or obviously-wrong Java expression:
///
/// - `iget*` / `iput*` receiver (`foo.field` / `foo.field = v`)
/// - `aget*` / `aput*` array base (`foo[i]` / `foo[i] = v`)
/// - non-static invoke receiver (`foo.bar()`)
/// - `array-length` operand
/// - `monitor-enter` / `monitor-exit` operand
///
/// Slot positions follow the `RegUse` layout in `ssa.rs`:
///   iget:  uses = [receiver]
///   iput:  uses = [value, receiver]
///   aget:  uses = [array, index]
///   aput:  uses = [value, array, index]
///   invoke (non-static): uses = [this, args...]
fn is_dereferencing_use(insn: &SsaInsn, var: &VarId) -> bool {
    use Opcode::*;
    match insn.insn.op {
        Iget | IgetObject | IgetBoolean | IgetByte | IgetChar | IgetShort | IgetWide => {
            insn.uses.first() == Some(var)
        }
        Iput | IputObject | IputBoolean | IputByte | IputChar | IputShort | IputWide => {
            insn.uses.get(1) == Some(var)
        }
        Aget | AgetObject | AgetBoolean | AgetByte | AgetChar | AgetShort | AgetWide => {
            insn.uses.first() == Some(var)
        }
        Aput | AputObject | AputBoolean | AputByte | AputChar | AputShort | AputWide => {
            insn.uses.get(1) == Some(var)
        }
        InvokeVirtual
        | InvokeSuper
        | InvokeDirect
        | InvokeInterface
        | InvokeVirtualRange
        | InvokeSuperRange
        | InvokeDirectRange
        | InvokeInterfaceRange
        | InvokePolymorphic
        | InvokePolymorphicRange => insn.uses.first() == Some(var),
        ArrayLength | MonitorEnter | MonitorExit => insn.uses.first() == Some(var),
        _ => false,
    }
}

/// Walk a statement tree looking for any dereferencing use of `var`.
/// Used to veto inline-candidacy when the single use would produce
/// `null.field`, `null[i]`, `null.method()`, etc.
fn stmt_has_dereferencing_use(stmt: &Stmt, var: &VarId) -> bool {
    stmt_has_dereferencing_use_depth(stmt, var, 0)
}

// WHY: depth-bounded recursion (`if depth > MAX_STMT_DEPTH { return false; }`
// guard at entry). Arithmetic is `depth + 1` for recursion arg; bounded
// by MAX_STMT_DEPTH.
#[allow(clippy::arithmetic_side_effects, reason = "depth-bounded recursion (`if depth > MAX_STMT_DEPTH { return false; }` guard at entry). Arithmetic is `depth + 1` for recursion arg; bounded by MAX_STMT_DEPTH.")]
fn stmt_has_dereferencing_use_depth(stmt: &Stmt, var: &VarId, depth: usize) -> bool {
    if depth > MAX_STMT_DEPTH {
        return false;
    }
    let depth = depth.saturating_add(1);
    match stmt {
        Stmt::Expr(insn) | Stmt::InlinedReturn(insn) | Stmt::InlinedThrow(insn) => {
            is_dereferencing_use(insn, var)
        }
        Stmt::Seq(stmts) => stmts.iter().any(|s| stmt_has_dereferencing_use_depth(s, var, depth)),
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            stmt_has_dereferencing_use_depth(then_body, var, depth)
                || else_body
                    .as_deref()
                    .is_some_and(|e| stmt_has_dereferencing_use_depth(e, var, depth))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            stmt_has_dereferencing_use_depth(body, var, depth)
        }
        Stmt::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, b)| stmt_has_dereferencing_use_depth(b, var, depth))
                || default
                    .as_deref()
                    .is_some_and(|d| stmt_has_dereferencing_use_depth(d, var, depth))
        }
        Stmt::StringSwitch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, b)| stmt_has_dereferencing_use_depth(b, var, depth))
                || default
                    .as_deref()
                    .is_some_and(|d| stmt_has_dereferencing_use_depth(d, var, depth))
        }
        Stmt::TryCatch { body, catches } => {
            stmt_has_dereferencing_use_depth(body, var, depth)
                || catches
                    .iter()
                    .any(|c| stmt_has_dereferencing_use_depth(&c.body, var, depth))
        }
        Stmt::Synchronized { body, .. } => stmt_has_dereferencing_use_depth(body, var, depth),
        Stmt::ForEach { body, .. } | Stmt::For { body, .. } => {
            stmt_has_dereferencing_use_depth(body, var, depth)
        }
        _ => false,
    }
}

/// Pre-compute inline expressions for single-use variables.
/// Is `init_insn` an `invoke-direct <init>` on the type that `new_type` names?
/// Used by the new+init merge to confirm a reg-level (but version-mismatched)
/// receiver pair really does target the same instance.
fn invoke_is_init_for_type(
    init_insn: &SsaInsn,
    new_type: Option<crate::ids::TypeIdx>,
    dex: &DexFile,
) -> bool {
    let Some(new_type) = new_type else { return false; };
    let Some(PoolIndex::Method(midx)) = init_insn.insn.pool_idx else { return false; };
    let Some(method) = dex.methods.get(midx.0 as usize) else { return false; };
    if dex.get_string(method.name_idx).ok() != Some("<init>") {
        return false;
    }
    method.class_idx == new_type
}

/// A variable can be inlined if: (1) it has exactly 1 use, (2) its defining instruction is pure,
/// (3) it's not a parameter or phi variable.
fn compute_inline_exprs(stmt: &Stmt, env: &TypeEnv, dex: &DexFile, ctx: &mut EmitCtx) {
    let mut use_counts: BTreeMap<VarId, usize> = BTreeMap::new();
    count_uses_in_stmt(stmt, &mut use_counts);

    // Collect candidate expressions from Expr nodes
    collect_inline_candidates(stmt, &use_counts, env, dex, ctx);
}

// WHY: counter `binding_sites.entry(v).or_insert(0) += 1` and
// `inside_uses.entry(v).or_insert(0) += n` over IR-bounded VarIds; n
// is itself a use-count from a sibling map. Bounded by parser-validated
// IR size.
#[allow(clippy::arithmetic_side_effects, reason = "counter `binding_sites.entry(v).or_insert(0) += 1` and `inside_uses.entry(v).or_insert(0) += n` over IR-bounded VarIds; n is itself a use-count from a sibling map. Bounded by parser-validated IR size.")]
fn collect_inline_candidates(
    stmt: &Stmt,
    use_counts: &BTreeMap<VarId, usize>,
    env: &TypeEnv,
    dex: &DexFile,
    ctx: &mut EmitCtx,
) {
    match stmt {
        Stmt::Seq(stmts) => {
            for s in stmts {
                collect_inline_candidates(s, use_counts, env, dex, ctx);
            }
            // Pair invoke + MoveResult: store invoke expression for later /* move-result */ replacement
            for i in 0..stmts.len().saturating_sub(1) {
                if let (Stmt::Expr(invoke), Stmt::Expr(mro)) = (&stmts[i], &stmts[i + 1]) {
                    let is_invoke = matches!(
                        invoke.insn.op,
                        Opcode::InvokeVirtual
                            | Opcode::InvokeSuper
                            | Opcode::InvokeDirect
                            | Opcode::InvokeStatic
                            | Opcode::InvokeInterface
                            | Opcode::InvokeVirtualRange
                            | Opcode::InvokeSuperRange
                            | Opcode::InvokeDirectRange
                            | Opcode::InvokeStaticRange
                            | Opcode::InvokeInterfaceRange
                            | Opcode::InvokePolymorphic
                            | Opcode::InvokePolymorphicRange
                            | Opcode::InvokeCustom
                            | Opcode::InvokeCustomRange
                            | Opcode::FilledNewArray
                            | Opcode::FilledNewArrayRange
                    );
                    let is_mro = matches!(
                        mro.insn.op,
                        Opcode::MoveResult | Opcode::MoveResultWide | Opcode::MoveResultObject
                    );
                    if is_invoke && is_mro {
                        if let Some(ref dst) = mro.dst {
                            // Store in mro_map (separate from inline_exprs to avoid var-name conflicts)
                            ctx.mro_map.insert(dst.clone(), emit_expr(invoke, env, dex, ctx));
                        }
                    }
                }
            }

            // Suppress new-instance when followed by <init> on the same var
            // "ClassName v0 = new ClassName; new ClassName(args);" → "ClassName v0 = new ClassName(args);"
            for i in 0..stmts.len() {
                if let Stmt::Expr(insn) = &stmts[i] {
                    if insn.insn.op == Opcode::NewInstance {
                        if let Some(ref new_dst) = insn.dst {
                            // Look ahead for invoke-direct <init> that uses this var.
                            // Skip pure value-producing statements between new-instance and
                            // <init> (e.g. StringConcat that builds constructor args).
                            //
                            // Receiver match: same VarId OR same reg with type-soundness
                            // guard (the invoke must be `<init>` on the new-instance's
                            // type). The reg-with-type-guard relaxation handles SSA
                            // version drift across phi joins where the new-instance
                            // sits before a control-flow region (e.g. CtorCallGraphCycle's
                            // main: NewInstance v0_1 → ... if/else collapsing to
                            // BooleanAssigns ... → InvokeDirect uses=[v0_14, ...]).
                            let new_type = match insn.insn.pool_idx {
                                Some(PoolIndex::Type(t)) => Some(t),
                                _ => None,
                            };
                            for s in stmts.iter().skip(i + 1).take(15) {
                                if let Stmt::Expr(init_insn) = s {
                                    if init_insn.insn.op == Opcode::InvokeDirect {
                                        let receiver = init_insn.uses.first();
                                        let same_var = receiver == Some(new_dst);
                                        let same_reg_and_init = !same_var
                                            && receiver.is_some_and(|r| r.reg() == new_dst.reg())
                                            && invoke_is_init_for_type(init_insn, new_type, dex);
                                        if same_var || same_reg_and_init {
                                            ctx.inlined.insert(new_dst.clone());
                                            // Also mark the invoke receiver as inlined so
                                            // the InvokeDirect emit binds the
                                            // `Type v = new T(args);` form to the receiver
                                            // (the LATER emit-site predicate keys on the
                                            // receiver's VarId, not the new-instance's).
                                            if let Some(r) = receiver {
                                                ctx.inlined.insert(r.clone());
                                            }
                                            break;
                                        }
                                    }
                                    // Stop if an intervening expr uses new_dst
                                    if init_insn.uses.contains(new_dst) {
                                        break;
                                    }
                                } else if matches!(
                                    s,
                                    Stmt::StringConcat { .. } | Stmt::BooleanAssign { .. }
                                ) {
                                    // Allow scan to pass through pure
                                    // value-producing stmts that build ctor args.
                                    // BooleanAssign is the lifted form of
                                    // `(a == b)` → boolean — see
                                    // `sugar::lift_comparison_as_value_in_seq`.
                                } else {
                                    // Stop at control flow or other complex statements
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            // In a Seq, check if any Expr defines a var used exactly once in subsequent stmts
            for (i, s) in stmts.iter().enumerate() {
                if let Stmt::Expr(insn) = s {
                    if let Some(ref dst) = insn.dst {
                        // SEMANTICS-DEFAULT-EMPTY: dst absent from use_counts → used nowhere;
                        // the `uses == 1` guard below correctly rejects zero-use vars.
                        let uses = use_counts.get(dst).copied().unwrap_or(0);
                        if uses == 1
                            && crate::optimize::is_pure_op(insn.insn.op)
                            && !ctx.declared.contains(dst)
                            && !matches!(
                                insn.insn.op,
                                Opcode::MoveResult
                                    | Opcode::MoveResultWide
                                    | Opcode::MoveResultObject
                                    | Opcode::MoveException
                            )
                        {
                            // Check that the use is AFTER this definition (not before).
                            // SEMANTICS-DEFAULT-EMPTY: dst absent from per-stmt count `c`
                            // means the stmt doesn't use it; treating as 0 is correct.
                            let use_after = stmts[i + 1..].iter().any(|s2| {
                                let mut c = BTreeMap::new();
                                count_uses_in_stmt(s2, &mut c);
                                c.get(dst).copied().unwrap_or(0) > 0
                            });
                            // Receiver-context guard: refuse to inline when the
                            // def is a numeric const (which may emit as `null`
                            // for ref-typed zero, or as a literal like `0`)
                            // AND the single use is a dereferencing position.
                            // Without this, a `Const4 0` typed as a ref would
                            // be inlined as `null.field` / `null[i]` /
                            // `null.method()`. String / class / new-instance
                            // literals are legitimate receivers and are
                            // unaffected.
                            let is_numeric_const = matches!(
                                insn.insn.op,
                                Opcode::Const4
                                    | Opcode::Const16
                                    | Opcode::Const
                                    | Opcode::ConstHigh16
                                    | Opcode::ConstWide16
                                    | Opcode::ConstWide32
                                    | Opcode::ConstWide
                                    | Opcode::ConstWideHigh16
                            );
                            let deref_use = is_numeric_const
                                && stmts[i + 1..]
                                    .iter()
                                    .any(|s2| stmt_has_dereferencing_use(s2, dst));
                            if use_after && !deref_use {
                                // Render the expression with the thread-local
                                // already populated, so any earlier inlined
                                // vars referenced by `insn` resolve transitively.
                                let expr = emit_expr(insn, env, dex, ctx);
                                ctx.inline_exprs.insert(dst.clone(), expr);
                                ctx.inlined.insert(dst.clone());
                            }
                        }
                    }
                }
            }
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            collect_inline_candidates(then_body, use_counts, env, dex, ctx);
            if let Some(eb) = else_body {
                collect_inline_candidates(eb, use_counts, env, dex, ctx);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            // Allow inlining inside loop bodies for vars defined+used within same sequence
            collect_inline_candidates(body, use_counts, env, dex, ctx);
        }
        Stmt::TryCatch { body, catches, .. } => {
            collect_inline_candidates(body, use_counts, env, dex, ctx);
            for c in catches {
                collect_inline_candidates(&c.body, use_counts, env, dex, ctx);
            }
        }
        _ => {}
    }
}

// ── AST-level invoke + move-result merge ────────────────────────────

/// Closed-set tag for the single-use invoke-result inlining loop in
/// `merge_invoke_moveresult_depth`. Replaces a prior `&str` discriminant
/// (`"throw"` / `"return"`) whose wildcard match arm forced an
/// `unreachable!()`; the enum makes the producer/consumer total by
/// construction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum InlineKind {
    Throw,
    Return,
}

/// Merge adjacent [invoke, move-result] pairs in Seq nodes.
/// The move-result SsaInsn takes on the invoke's opcode and uses,
/// so emit produces the actual call expression with the correct dst.
/// Also inlines single-use invoke results into Throw/Return statements.
pub fn merge_invoke_moveresult(stmt: &mut Stmt) {
    merge_invoke_moveresult_depth(stmt, 0);
}

// WHY: depth-bounded recursion (same shape as count_uses_in_stmt_depth).
// Body sites are pattern-matching indexing into `stmts[i]` / `stmts[i+1]`
// with `i + 1 < stmts.len()` checks immediately above; `depth + 1` for
// recursion arg bounded by MAX_STMT_DEPTH.
#[allow(clippy::arithmetic_side_effects, reason = "depth-bounded recursion (same shape as count_uses_in_stmt_depth). Body sites are pattern-matching indexing into `stmts[i]` / `stmts[i+1]` with `i + 1 < stmts.len()` checks immediately above; `depth + 1` for recursion arg bounded by MAX_STMT_DEPTH.")]
fn merge_invoke_moveresult_depth(stmt: &mut Stmt, depth: usize) {
    if depth > MAX_STMT_DEPTH {
        return;
    }
    let depth = depth.saturating_add(1);
    match stmt {
        Stmt::Seq(stmts) => {
            // First, recurse into children
            for s in stmts.iter_mut() {
                merge_invoke_moveresult_depth(s, depth);
            }
            // Then merge invoke+move-result pairs in this Seq
            let mut i = 0;
            while i + 1 < stmts.len() {
                let is_pair =
                    if let (Stmt::Expr(invoke), Stmt::Expr(mro)) = (&stmts[i], &stmts[i + 1]) {
                        let is_invoke = matches!(
                            invoke.insn.op,
                            Opcode::InvokeVirtual
                                | Opcode::InvokeSuper
                                | Opcode::InvokeDirect
                                | Opcode::InvokeStatic
                                | Opcode::InvokeInterface
                                | Opcode::InvokeVirtualRange
                                | Opcode::InvokeSuperRange
                                | Opcode::InvokeDirectRange
                                | Opcode::InvokeStaticRange
                                | Opcode::InvokeInterfaceRange
                                | Opcode::InvokePolymorphic
                                | Opcode::InvokePolymorphicRange
                                | Opcode::InvokeCustom
                                | Opcode::InvokeCustomRange
                                | Opcode::FilledNewArray
                                | Opcode::FilledNewArrayRange
                        );
                        let is_mro = matches!(
                            mro.insn.op,
                            Opcode::MoveResult | Opcode::MoveResultWide | Opcode::MoveResultObject
                        );
                        is_invoke && is_mro
                    } else {
                        false
                    };

                if is_pair {
                    if let Stmt::Expr(invoke) = &stmts[i] {
                        let invoke_insn = invoke.insn.clone();
                        let invoke_uses = invoke.uses.clone();
                        if let Stmt::Expr(mro) = &mut stmts[i + 1] {
                            mro.insn = invoke_insn;
                            mro.uses = invoke_uses;
                        }
                    }
                    stmts.remove(i);
                } else {
                    i += 1;
                }
            }

            // Inline single-use invoke results into Throw/Return
            // Pattern: [Expr(invoke with dst=v), Throw(v)] → [InlinedThrow(invoke)]
            // Pattern: [Expr(invoke with dst=v), Return(Some(v))] → [InlinedReturn(invoke)]
            let mut i = 0;
            while i + 1 < stmts.len() {
                let inline_target = if let Stmt::Expr(ref expr) = stmts[i] {
                    if let Some(ref dst) = expr.dst {
                        match &stmts[i + 1] {
                            Stmt::Throw(v) if v == dst => Some((InlineKind::Throw, dst.clone())),
                            Stmt::Return(Some(v)) if v == dst => {
                                Some((InlineKind::Return, dst.clone()))
                            }
                            _ => None,
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some((kind, _)) = inline_target {
                    let expr_stmt = stmts.remove(i);
                    if let Stmt::Expr(insn) = expr_stmt {
                        stmts[i] = match kind {
                            InlineKind::Throw => Stmt::InlinedThrow(insn),
                            InlineKind::Return => Stmt::InlinedReturn(insn),
                        };
                    }
                } else {
                    i += 1;
                }
            }
        }
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            merge_invoke_moveresult_depth(then_body, depth);
            if let Some(eb) = else_body {
                merge_invoke_moveresult_depth(eb, depth);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            merge_invoke_moveresult_depth(body, depth);
        }
        Stmt::TryCatch { body, catches, .. } => {
            merge_invoke_moveresult_depth(body, depth);
            for c in catches {
                merge_invoke_moveresult_depth(&mut c.body, depth);
            }
        }
        Stmt::Switch { cases, default, .. } => {
            for (_, body) in cases {
                merge_invoke_moveresult_depth(body, depth);
            }
            if let Some(d) = default {
                merge_invoke_moveresult_depth(d, depth);
            }
        }
        Stmt::StringSwitch { cases, default, .. } => {
            for (_, body) in cases {
                merge_invoke_moveresult_depth(body, depth);
            }
            if let Some(d) = default {
                merge_invoke_moveresult_depth(d, depth);
            }
        }
        Stmt::Synchronized { body, .. } => {
            merge_invoke_moveresult_depth(body, depth);
        }
        Stmt::For {
            init, body, update, ..
        } => {
            merge_invoke_moveresult_depth(init, depth);
            merge_invoke_moveresult_depth(body, depth);
            merge_invoke_moveresult_depth(update, depth);
        }
        _ => {}
    }
}

// ── Statement emitter ───────────────────────────────────────────────

/// If `stmt` represents an else-arm whose entire content is a single
/// `Stmt::If`, return its (cond, then_body, else_body) so the caller
/// can render it as `else if (...)` rather than `else { if (...) }`.
/// Returns `None` for shapes that are NOT safe to collapse: an else
/// arm containing multiple statements (the Seq's tail would lose
/// context if we unrolled the head into an else-if), or a non-If
/// terminal arm.
///
/// Safe shapes:
/// - `Stmt::If { cond, then_body, else_body }` — direct
/// - `Stmt::Seq([Stmt::If { ... }])` — single-element Seq wrapper
fn peel_else_if(stmt: &Stmt) -> Option<(&crate::structure::Condition, &Stmt, Option<&Stmt>)> {
    match stmt {
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => Some((cond, then_body.as_ref(), else_body.as_deref())),
        Stmt::Seq(stmts) if stmts.len() == 1 => peel_else_if(&stmts[0]),
        _ => None,
    }
}

/// Emit a Stmt tree as Java source.
pub fn emit_stmt(
    stmt: &Stmt,
    env: &TypeEnv,
    dex: &DexFile,
    level: usize,
    ctx: &mut EmitCtx,
) -> String {
    emit_stmt_depth(stmt, env, dex, level, ctx, 0)
}

// WHY: per-fn allow covers the entire emit_stmt_depth recursion body.
// Three arithmetic shapes occur in this fn and they share the same
// dominator: (1) `level + N` for N ∈ {1, 2} — indent recursion arg;
// `level` is bounded above by MAX_STMT_DEPTH (512 per this module's
// declaration), so `level + 2 ≤ 514` cannot overflow usize on any
// supported target. (2) `depth + 1` — recursion-depth counter,
// short-circuited by the `if depth > MAX_STMT_DEPTH { return … }`
#[allow(clippy::arithmetic_side_effects, reason = "per-fn allow covers the entire emit_stmt_depth recursion body. Three arithmetic shapes occur in this fn and they share the same dominator: (1) `level + N` for N ∈ {1, 2} — indent recursion arg; `level` is bounded above by MAX_STMT_DEPTH (512 per this module's declaration), so `level + 2 ≤ 514` cannot overflow usize on any supported target. (2) `depth + 1` — recursion-depth counter, short-circuited by the `if depth > MAX_STMT_DEPTH { return … }` guard at the top of the fn, so `depth + 1 ≤ MAX_STMT_DEPTH + 1`. (3) Occasional `counter += 1` over IR-bounded references (e.g. uses-counts on Stmt nodes); the IR is parser-validated and bounded by parse_budgeted limits (u32-bounded pool sizes).")]
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "INTENT: bit-reinterpretation. The fill-array-data payload decoder synthesizes Java/Kotlin literals from raw byte slices. Casts here are deliberate width-narrowing reinterpretations: u16→i16 / u32→i32 / u64→i64 sign-extend the little-endian-decoded magnitude back to its source-level signedness; raw as u32 / raw as u64 feed f32::from_bits / f64::from_bits; raw as u8 as char extracts the ASCII printable code-point. Each cast is dominated by the matching `element_width` arm (1/2/4/8) so width-narrowing is exact, not lossy."
)]
fn emit_stmt_depth(
    stmt: &Stmt,
    env: &TypeEnv,
    dex: &DexFile,
    level: usize,
    ctx: &mut EmitCtx,
    depth: usize,
) -> String {
    if depth > MAX_STMT_DEPTH {
        ctx.record_error(crate::error::DexError::EmitRecursionDepthExceeded {
            depth,
            cap: MAX_STMT_DEPTH,
        });
        return String::new();
    }
    let depth = depth.saturating_add(1);
    let mut out = String::new();

    match stmt {
        Stmt::Seq(stmts) => {
            for s in stmts {
                out.push_str(&emit_stmt_depth(s, env, dex, level, ctx, depth));
            }
        }

        Stmt::Expr(insn) => {
            // Skip entirely if dst has been inlined into its single use.
            if let Some(ref dst) = insn.dst {
                if ctx.inlined.contains(dst) {
                    return out;
                }
            }
            ctx.emit_line_comment(&mut out, level, insn.insn.addr);

            // fill-array-data: emit individual element assignments.
            if insn.insn.op == Opcode::FillArrayData {
                if let (Some(payload_pc), Some(arr_var)) =
                    (insn.insn.target, insn.uses.first())
                {
                    let payload = ctx.fill_array_payloads.get(&payload_pc).cloned();
                    if let Some((element_width, data)) = payload {
                        let arr = emit_use(arr_var, ctx);
                        // Determine element type from the array variable's type.
                        let elem_ty = match env.types.get(arr_var) {
                            Some(crate::types::DexType::ArrayRef(inner)) => {
                                Some(inner.as_ref().clone())
                            }
                            _ => None,
                        };
                        let n = if element_width > 0 {
                            data.len() / element_width as usize
                        } else {
                            0
                        };
                        for i in 0..n {
                            let base = i * element_width as usize;
                            let raw: i64 = match element_width {
                                1 => i64::from(data[base] as i8),
                                2 => {
                                    let v = u16::from_le_bytes([data[base], data[base + 1]]);
                                    i64::from(v as i16)
                                }
                                4 => {
                                    let v = u32::from_le_bytes([
                                        data[base],
                                        data[base + 1],
                                        data[base + 2],
                                        data[base + 3],
                                    ]);
                                    i64::from(v as i32)
                                }
                                8 => {
                                    let v = u64::from_le_bytes([
                                        data[base],
                                        data[base + 1],
                                        data[base + 2],
                                        data[base + 3],
                                        data[base + 4],
                                        data[base + 5],
                                        data[base + 6],
                                        data[base + 7],
                                    ]);
                                    v as i64
                                }
                                _ => 0,
                            };
                            let val_str = match &elem_ty {
                                Some(crate::types::DexType::Byte) => {
                                    format!("(byte){raw}")
                                }
                                Some(crate::types::DexType::Char) => {
                                    if (32..=126).contains(&raw) {
                                        format!("'{}'", raw as u8 as char)
                                    } else {
                                        format!("(char){raw}")
                                    }
                                }
                                Some(crate::types::DexType::Short) => {
                                    format!("(short){raw}")
                                }
                                Some(crate::types::DexType::Float) => {
                                    let f = f32::from_bits(raw as u32);
                                    format!("{f}f")
                                }
                                Some(crate::types::DexType::Double) => {
                                    let f = f64::from_bits(raw as u64);
                                    format!("{f}")
                                }
                                _ => format!("{raw}"),
                            };
                            indent(&mut out, level);
                            let _ = writeln!(out, "{arr}[{i}] = {val_str};");
                        }
                        return out;
                    }
                }
                // Fallback if payload not found: skip silently.
                return out;
            }

            let expr = emit_expr(insn, env, dex, ctx);
            // Skip comment-only expressions (/* move-result */, /* nop */, etc.)
            if expr.starts_with("/*") && expr.ends_with("*/") {
                return out;
            }
            // Special case: invoke-direct <init> whose receiver was suppressed via
            // new-instance inlining. The expr is already "new X(args)" — bind it
            // to the receiver variable as its declaration.
            if insn.dst.is_none()
                && matches!(
                    insn.insn.op,
                    Opcode::InvokeDirect | Opcode::InvokeDirectRange
                )
            {
                if let Some(receiver) = insn.uses.first() {
                    if ctx.inlined.contains(receiver) {
                        if ctx.declared.insert(receiver.clone()) {
                            // Phi-inflated receivers may carry a SSA version that
                            // TypeEnv has no direct entry for. Fall back to the
                            // canonical (lowest-ver) type for the same reg before
                            // resorting to "Object" — matches the canonical-type
                            // rule used by other emit paths.
                            let ty = env
                                .types
                                .get(receiver)
                                .or_else(|| {
                                    env.types
                                        .iter()
                                        .filter(|(v, _)| v.reg() == receiver.reg())
                                        .min_by_key(|(v, _)| v.ver())
                                        .map(|(_, t)| t)
                                })
                                .map(emit_type)
                                .unwrap_or_else(|| "Object".to_string());
                            indent(&mut out, level);
                            let _ = writeln!(out, "{ty} {} = {expr};", emit_var(receiver));
                        } else {
                            indent(&mut out, level);
                            let _ = writeln!(out, "{} = {expr};", emit_var(receiver));
                        }
                        return out;
                    }
                }
            }
            // Variable declaration
            if let Some(ref dst) = insn.dst {
                // After SSA-version collapse, a variable `vR_V` is renamed to
                // `vR` only when its type matches the canonical type for
                // register R (the type of the lowest-version SSA var for R).
                // If it IS the canonical type, and some same-register
                // same-type variable is already declared, this is a
                // reassignment — emit without a `Type` prefix to avoid a
                // "variable already defined" Java error.
                // If it is NOT the canonical type, it stays versioned (`vR_V`)
                // and IS a new independent variable — it needs its own prefix.
                let dst_type = env.types.get(dst);
                let canonical_type_for_reg = env.types.iter()
                    .filter(|(v, _)| v.reg() == dst.reg())
                    .min_by_key(|(v, _)| v.ver())
                    .map(|(_, ty)| ty);
                let dst_is_canonical = dst_type == canonical_type_for_reg;
                let same_reg_type_already_declared = dst_is_canonical
                    && ctx.declared.iter().any(|v| {
                        v.reg() == dst.reg() && env.types.get(v) == dst_type
                    });
                if ctx.declared.insert(dst.clone()) && !same_reg_type_already_declared {
                    let ty = env
                        .types
                        .get(dst)
                        .map(emit_type)
                        .unwrap_or_else(|| "int".to_string());
                    indent(&mut out, level);
                    let _ = writeln!(out, "{ty} {} = {expr};", emit_var(dst));
                } else {
                    indent(&mut out, level);
                    let _ = writeln!(out, "{} = {expr};", emit_var(dst));
                }
            } else {
                indent(&mut out, level);
                let _ = writeln!(out, "{expr};");
            }
        }

        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            // Pre-declare variables that are defined in both branches (phi merges).
            // Without this, each branch declares its own scoped version, and the
            // post-if-else use of the phi result references an undeclared variable.
            if let Some(eb) = else_body {
                let then_defs = collect_defined_regs(then_body);
                let else_defs = collect_defined_regs(eb);
                for reg in then_defs.intersection(&else_defs) {
                    let var = find_first_def_on_reg(then_body, *reg)
                        .or_else(|| find_first_def_on_reg(eb, *reg));
                    if let Some(v) = var {
                        let var_ty = env.types.get(&v);
                        // Only pre-declare if this type matches the register's canonical
                        // type (i.e., the var will collapse to v{reg}).  When types differ
                        // the var stays versioned and scoped declarations are correct.
                        let canonical_ty = env.types.iter()
                            .filter(|(vid, _)| vid.reg() == *reg)
                            .min_by_key(|(vid, _)| vid.ver())
                            .map(|(_, ty)| ty);
                        if var_ty != canonical_ty {
                            continue;
                        }
                        if !ctx.declared.iter().any(|d: &VarId| d.reg() == *reg
                            && env.types.get(d) == var_ty)
                        {
                            let ty = var_ty
                                .map(emit_type)
                                .unwrap_or_else(|| "int".to_string());
                            indent(&mut out, level);
                            let _ = writeln!(out, "{ty} v{reg};");
                            ctx.declared.insert(v);
                        }
                    }
                }
            }
            indent(&mut out, level);
            let _ = writeln!(out, "if ({}) {{", emit_condition_typed(cond, Some(env), ctx));
            out.push_str(&emit_stmt_depth(then_body, env, dex, level + 1, ctx, depth));
            // Iterative else-chain peel. R8-released production output
            // produces if-else cascades 100+ deep (cascaded
            // switch-on-string + protocol-dispatch lowerings); recursing
            // into each `else { if (...) ... }` exhausts the test thread
            // stack at ~130 levels. The peel detects when `else_body`
            // is itself a single `Stmt::If` (direct or wrapped in a
            // single-element `Stmt::Seq`), unrolls it as
            // `} else if (cond) { ... }`, and continues iteratively
            // until the chain terminates in `None` or a non-If else.
            let mut current_else = else_body.as_deref();
            while let Some(eb) = current_else {
                match peel_else_if(eb) {
                    Some((next_cond, next_then, next_else)) => {
                        indent(&mut out, level);
                        let _ = writeln!(
                            out,
                            "}} else if ({}) {{",
                            emit_condition_typed(next_cond, Some(env), ctx)
                        );
                        out.push_str(&emit_stmt_depth(
                            next_then, env, dex, level + 1, ctx, depth,
                        ));
                        current_else = next_else;
                    }
                    None => {
                        indent(&mut out, level);
                        out.push_str("} else {\n");
                        out.push_str(&emit_stmt_depth(
                            eb, env, dex, level + 1, ctx, depth,
                        ));
                        break;
                    }
                }
            }
            indent(&mut out, level);
            out.push_str("}\n");
        }

        Stmt::While { cond, body } => {
            // Pre-declare any condition variables not yet in scope.  This prevents
            // forward-reference errors when a variable is assigned inside the loop
            // body but also appears in the loop-entry condition (common after SSA
            // version collapse when a phi merges an in-body definition with a
            // back-edge definition of the same register).
            use crate::structure::Condition;
            let cond_vars: Vec<&VarId> = match cond {
                Condition::TestZero { var, .. } | Condition::Var(var) => vec![var],
                Condition::Compare { left, right, .. } => vec![left, right],
            };
            for var in cond_vars {
                // Skip if this exact VarId is already declared.
                // Skip if any same-register same-type VarId is already declared:
                // after SSA collapse both would have the same name, so a
                // pre-declaration here would either duplicate a declaration or
                // shadow a parameter (e.g. the parameter `v3_0` already covers
                // every use of `v3_3` once versions are collapsed).
                let same_reg_type_declared = ctx.declared.iter().any(|v| {
                    v.reg() == var.reg()
                        && env.types.get(v) == env.types.get(var)
                });
                if !ctx.declared.contains(var)
                    && !same_reg_type_declared
                    && !ctx.inline_exprs.contains_key(var)
                {
                    let ty = env
                        .types
                        .get(var)
                        .map(emit_type)
                        .unwrap_or_else(|| "int".to_string());
                    // Try to find the initial value by looking at the first
                    // constant assignment to the same register in the loop body.
                    // This handles the common DEX pattern where a constant is
                    // loaded at the top of the loop header (which becomes the
                    // first statement of the while body): pre-declare with the
                    // actual constant so the first condition check is correct.
                    // SEMANTICS-DEFAULT-EMPTY: var not yet typed → treat as Int for
                    // `default_literal`; `render_as` uses `demand_ty` (the declared `ty`
                    // above) to absorb any mismatch, so `DexType::Int` is a safe fallback
                    // for choosing a zero-valued literal when no type is known.
                    let initial_val =
                        find_init_in_body(body, var.reg(), env, dex, ctx)
                            .unwrap_or_else(|| default_literal(env.types.get(var).unwrap_or(&DexType::Int)).to_string());
                    indent(&mut out, level);
                    let _ = writeln!(out, "{ty} {} = {initial_val};", emit_var(var));
                    ctx.declared.insert(var.clone());
                }
            }
            indent(&mut out, level);
            let _ = writeln!(out, "while ({}) {{", emit_condition_typed(cond, Some(env), ctx));
            out.push_str(&emit_stmt_depth(body, env, dex, level + 1, ctx, depth));
            indent(&mut out, level);
            out.push_str("}\n");
        }

        Stmt::DoWhile { body, cond } => {
            // Pre-declare condition variables defined inside the body,
            // since the do-while condition is outside the body scope in Java.
            let cond_vars: Vec<&VarId> = match cond {
                crate::structure::Condition::TestZero { var, .. }
                | crate::structure::Condition::Var(var) => vec![var],
                crate::structure::Condition::Compare { left, right, .. } => vec![left, right],
            };
            let body_defs = collect_defined_regs(body);
            for var in &cond_vars {
                if body_defs.contains(&var.reg())
                    && !ctx.declared.iter().any(|d: &VarId| d.reg() == var.reg()
                        && env.types.get(d) == env.types.get(*var))
                {
                    let ty = env
                        .types
                        .get(*var)
                        .map(emit_type)
                        .unwrap_or_else(|| "int".to_string());
                    indent(&mut out, level);
                    let _ = writeln!(out, "{ty} v{};", var.reg());
                    ctx.declared.insert((*var).clone());
                }
            }
            indent(&mut out, level);
            out.push_str("do {\n");
            out.push_str(&emit_stmt_depth(body, env, dex, level + 1, ctx, depth));
            indent(&mut out, level);
            let _ = writeln!(out, "}} while ({});", emit_condition_typed(cond, Some(env), ctx));
        }

        Stmt::Switch {
            value,
            cases,
            default,
        } => {
            indent(&mut out, level);
            let _ = writeln!(out, "switch ({}) {{", emit_use(value, ctx));
            for (keys, body) in cases {
                for key in keys {
                    indent(&mut out, level + 1);
                    let _ = writeln!(out, "case {key}:");
                }
                let body_str = emit_stmt_depth(body, env, dex, level + 2, ctx, depth);
                out.push_str(&body_str);
                if !body_str.trim_end().ends_with("return;") && !body_str.contains("return ") {
                    indent(&mut out, level + 2);
                    out.push_str("break;\n");
                }
            }
            if let Some(d) = default {
                indent(&mut out, level + 1);
                out.push_str("default:\n");
                let default_str = emit_stmt_depth(d, env, dex, level + 2, ctx, depth);
                out.push_str(&default_str);
                if !default_str.trim_end().ends_with("return;") && !default_str.contains("return ")
                {
                    indent(&mut out, level + 2);
                    out.push_str("break;\n");
                }
            }
            indent(&mut out, level);
            out.push_str("}\n");
        }

        Stmt::StringSwitch {
            value,
            cases,
            default,
        } => {
            indent(&mut out, level);
            let _ = writeln!(out, "switch ({}) {{", emit_use(value, ctx));
            for (literals, body) in cases {
                for lit in literals {
                    indent(&mut out, level + 1);
                    let _ = writeln!(out, "case \"{}\":", escape_java_string(lit));
                }
                let body_str = emit_stmt_depth(body, env, dex, level + 2, ctx, depth);
                out.push_str(&body_str);
                if !body_str.trim_end().ends_with("return;") && !body_str.contains("return ") {
                    indent(&mut out, level + 2);
                    out.push_str("break;\n");
                }
            }
            if let Some(d) = default {
                indent(&mut out, level + 1);
                out.push_str("default:\n");
                let default_str = emit_stmt_depth(d, env, dex, level + 2, ctx, depth);
                out.push_str(&default_str);
                if !default_str.trim_end().ends_with("return;") && !default_str.contains("return ")
                {
                    indent(&mut out, level + 2);
                    out.push_str("break;\n");
                }
            }
            indent(&mut out, level);
            out.push_str("}\n");
        }

        Stmt::TryCatch { body, catches } => {
            // Each catch arm and the try body is a disjoint Java scope: a var
            // declared in catch #1 isn't in scope for catch #2, and a var
            // declared in the try body isn't in scope for any catch. After
            // SSA-collapse renames `vN_X` (in catch #1) and `vN_Y` (in catch
            // #2) both to the bare `vN`, the flat method-scope `ctx.declared`
            // would let catch #2 emit `vN = …;` without a type prefix —
            // javac then rejects with "cannot find symbol" because catch #1's
            // decl is out of scope. Snapshot+restore makes each sibling scope
            // see a fresh declared-set, so each scope emits its own typed
            // declaration and javac accepts.
            //
            // Vars added by enclosing pre-decl passes (Stmt::If phi-merge,
            // Stmt::While cond, Stmt::DoWhile cond) are in `entry_declared`
            // and remain visible to every sibling scope below.
            let entry_declared = ctx.declared.clone();

            indent(&mut out, level);
            out.push_str("try {\n");
            out.push_str(&emit_stmt_depth(body, env, dex, level + 1, ctx, depth));
            ctx.declared = entry_declared.clone();
            indent(&mut out, level);

            // Multicatch collapse (dex-decompile-multicatch). Javac's
            // `catch (A | B | C e)` lowers to N Dalvik exception_handler
            // entries all pointing at the same handler_off. Our
            // structurer emits them as N sibling CatchClauses with
            // byte-identical bodies (except each catch's `var` is a
            // different SSA version of the same register — the move-
            // exception dest). Collapse consecutive same-body catches
            // into a single `catch (T1 | T2 | T3 binding)` clause.
            //
            // Binding choice: the identical bodies already reference a
            // phi-merged VarId (e.g. v1_14 when three move-exception
            // dests v1_11/12/13 phi-merge at the shared handler-body
            // entry). That VarId appears in the body's USES but is
            // defined nowhere inside the body — it's the implicit phi
            // entry. Picking it as the merged catch binding makes the
            // body's reference resolve without rewriting. Fallback: the
            // first catch's own `var` if no phi-use found.
            let mut i = 0usize;
            while i < catches.len() {
                let c = &catches[i];
                let body_key = format!("{:?}", c.body);
                // Scan consecutive catches with byte-identical body.
                let mut group_end = i + 1;
                while group_end < catches.len()
                    && format!("{:?}", catches[group_end].body) == body_key
                {
                    group_end += 1;
                }
                let group_len = group_end - i;

                // Union of exception types (or "Exception" fallback).
                let type_union: Vec<String> = (i..group_end)
                    .map(|j| {
                        catches[j]
                            .exception_type
                            .and_then(|tidx| dex.get_type_descriptor(tidx).ok())
                            .map(pretty_class_name)
                            .unwrap_or_else(|| "Exception".to_string())
                    })
                    .collect();
                let types_joined = type_union.join(" | ");

                // Binding: if the group collapses (len > 1) and the body
                // references a phi-merged VarId not defined inside, use
                // that. Else, use the catch's own var per the existing
                // single-catch code path (hoisted / var / "e" fallback).
                let (binding_name, prologue): (String, Option<String>) = if group_len > 1 {
                    let phi_merged = catch_binding_from_body_phi(&c.body, &c.var);
                    (
                        phi_merged
                            .as_ref()
                            .map(emit_var)
                            .unwrap_or_else(|| "e".to_string()),
                        None,
                    )
                } else {
                    match &c.var {
                        Some(v) if ctx.hoisted_catch_vars.contains(v) => {
                            let tmp = format!("_c_{}_{}", v.reg(), v.ver());
                            let mut p = String::new();
                            indent(&mut p, level + 1);
                            let _ = writeln!(p, "{} = {tmp};", emit_var(v));
                            (tmp, Some(p))
                        }
                        Some(v) => (emit_var(v), None),
                        None => ("e".to_string(), None),
                    }
                };

                let _ = writeln!(out, "}} catch ({types_joined} {binding_name}) {{");
                if let Some(p) = prologue {
                    out.push_str(&p);
                }
                // Restore declared so this catch's decls don't leak into the
                // next sibling catch arm (each catch is a disjoint Java scope
                // — see comment at the top of Stmt::TryCatch).
                out.push_str(&emit_stmt_depth(&c.body, env, dex, level + 1, ctx, depth));
                ctx.declared = entry_declared.clone();
                indent(&mut out, level);

                i = group_end;
            }
            out.push_str("}\n");
        }

        Stmt::Synchronized { lock, body } => {
            indent(&mut out, level);
            let _ = writeln!(out, "synchronized ({}) {{", emit_use(lock, ctx));
            out.push_str(&emit_stmt_depth(body, env, dex, level + 1, ctx, depth));
            indent(&mut out, level);
            out.push_str("}\n");
        }

        Stmt::Return(None) => {
            indent(&mut out, level);
            out.push_str("return;\n");
        }
        Stmt::Return(Some(v)) => {
            indent(&mut out, level);
            // SEMANTICS-DEFAULT-EMPTY: v absent from env.types → Int; `render_as` uses
            // `demand_ty` (the method's declared return type) to absorb any val_ty mismatch,
            // so a Bottom/absent val_ty is handled correctly by the render_as coercion path
            // (documented at emit.rs:2871 `demand_ty` comment).
            let val_ty = env.types.get(v).cloned().unwrap_or(DexType::Int);
            let demand_ty = ctx.return_type.clone().unwrap_or(DexType::Void);
            let val = emit_use(v, ctx);
            let ret_expr = render_as(&val, &val_ty, &demand_ty);
            let _ = writeln!(out, "return {ret_expr};");
        }
        Stmt::InlinedReturn(insn) => {
            ctx.emit_line_comment(&mut out, level, insn.insn.addr);
            indent(&mut out, level);
            let expr = emit_expr(insn, env, dex, ctx);
            // SEMANTICS-DEFAULT-EMPTY: InlinedReturn dst absent or untyped → Int;
            // `render_as` uses `demand_ty` to absorb the mismatch (same pattern as
            // Stmt::Return above; documented at emit.rs:2871 `demand_ty` comment).
            let val_ty = insn
                .dst
                .as_ref()
                .and_then(|d| env.types.get(d))
                .cloned()
                .unwrap_or(DexType::Int);
            let demand_ty = ctx.return_type.clone().unwrap_or(DexType::Void);
            let ret_expr = render_as(&expr, &val_ty, &demand_ty);
            let _ = writeln!(out, "return {ret_expr};");
        }
        Stmt::InlinedReturnConcat(parts) => {
            indent(&mut out, level);
            let expr: Vec<String> = parts
                .iter()
                .map(|p| match p {
                    ConcatPart::Literal(s) => format!("\"{}\"", escape_java_string(s)),
                    ConcatPart::Var(v) => emit_use(v, ctx),
                })
                .collect();
            let _ = writeln!(out, "return {};", expr.join(" + "));
        }
        Stmt::Throw(v) => {
            indent(&mut out, level);
            let _ = writeln!(out, "throw {};", emit_use(v, ctx));
        }
        Stmt::InlinedThrow(insn) => {
            ctx.emit_line_comment(&mut out, level, insn.insn.addr);
            indent(&mut out, level);
            let expr = emit_expr(insn, env, dex, ctx);
            let _ = writeln!(out, "throw {expr};");
        }
        Stmt::Break => {
            indent(&mut out, level);
            out.push_str("break;\n");
        }
        Stmt::Continue => {
            indent(&mut out, level);
            out.push_str("continue;\n");
        }
        Stmt::Goto(block) => {
            indent(&mut out, level);
            let _ = writeln!(out, "/* goto block {} */", block.0);
        }

        Stmt::BooleanAssign { dst, cond } => {
            indent(&mut out, level);
            // Cond is in positive polarity — render directly.
            let expr = emit_condition_typed(cond, Some(env), ctx);
            // Emit `boolean v = expr;` on first declaration; `v = expr;`
            // afterwards. Mirrors `Stmt::StringConcat`'s declared-or-redeclared
            // logic but force-types as boolean (lift implies boolean by
            // construction; sidesteps any lingering int-leak in `env.types`).
            let canonical_for_reg = env.types.iter()
                .filter(|(v, _)| v.reg() == dst.reg())
                .min_by_key(|(v, _)| v.ver())
                .map(|(_, t)| t);
            let already_boolean_declared = ctx.declared.iter().any(|v| {
                v.reg() == dst.reg()
                    && env.types.get(v) == Some(&crate::types::DexType::Boolean)
            });
            // First declaration of a reg only emits the type prefix when this
            // dst is the canonical (lowest-ver) entry for the reg AND no prior
            // boolean-typed declaration of the same reg already happened.
            let dst_is_canonical = env.types.get(dst) == canonical_for_reg
                || canonical_for_reg.is_none();
            if ctx.declared.insert(dst.clone())
                && dst_is_canonical
                && !already_boolean_declared
            {
                let _ = writeln!(out, "boolean {} = {expr};", emit_var(dst));
            } else {
                let _ = writeln!(out, "{} = {expr};", emit_var(dst));
            }
        }

        Stmt::StringConcat { dst, parts } => {
            indent(&mut out, level);
            let expr: Vec<String> = parts
                .iter()
                .map(|p| match p {
                    ConcatPart::Literal(s) => format!("\"{}\"", escape_java_string(s)),
                    ConcatPart::Var(v) => emit_use(v, ctx),
                })
                .collect();
            let concat_expr = expr.join(" + ");
            if let Some(d) = dst {
                let dst_type = env.types.get(d);
                let canonical_type_for_reg = env.types.iter()
                    .filter(|(v, _)| v.reg() == d.reg())
                    .min_by_key(|(v, _)| v.ver())
                    .map(|(_, ty)| ty);
                let dst_is_canonical = dst_type == canonical_type_for_reg;
                let same_reg_type_already_declared = dst_is_canonical
                    && ctx.declared.iter().any(|v| {
                        v.reg() == d.reg() && env.types.get(v) == dst_type
                    });
                if ctx.declared.insert(d.clone()) && !same_reg_type_already_declared {
                    let ty = env
                        .types
                        .get(d)
                        .map(emit_type)
                        .unwrap_or_else(|| "String".to_string());
                    let _ = writeln!(out, "{ty} {} = {concat_expr};", emit_var(d));
                } else {
                    let _ = writeln!(out, "{} = {concat_expr};", emit_var(d));
                }
            } else {
                let _ = writeln!(out, "{concat_expr};");
            }
        }

        Stmt::For {
            init,
            cond,
            update,
            body,
        } => {
            let init_str = emit_stmt_depth(init, env, dex, 0, ctx, depth)
                .trim()
                .trim_end_matches(';')
                .to_string();
            let cond_str = emit_condition_typed(cond, Some(env), ctx);
            // Pre-declare the update variable so it doesn't get a type prefix
            // (the variable is already declared by init or a prior statement)
            if let Stmt::Expr(upd_insn) = update.as_ref() {
                if let Some(ref dst) = upd_insn.dst {
                    ctx.declared.insert(dst.clone());
                }
            }
            let update_str = emit_stmt_depth(update, env, dex, 0, ctx, depth)
                .trim()
                .trim_end_matches(';')
                .to_string();
            indent(&mut out, level);
            let _ = writeln!(out, "for ({init_str}; {cond_str}; {update_str}) {{");
            out.push_str(&emit_stmt_depth(body, env, dex, level + 1, ctx, depth));
            indent(&mut out, level);
            out.push_str("}\n");
        }

        Stmt::ForEach {
            var,
            iterable,
            body,
        } => {
            indent(&mut out, level);
            let ty = env
                .types
                .get(var)
                .map(emit_type)
                .unwrap_or_else(|| "int".to_string());
            let _ = writeln!(
                out,
                "for ({ty} {} : {}) {{",
                emit_var(var),
                emit_use(iterable, ctx)
            );
            ctx.declared.insert(var.clone());
            out.push_str(&emit_stmt_depth(body, env, dex, level + 1, ctx, depth));
            indent(&mut out, level);
            out.push_str("}\n");
        }

        Stmt::MultiArm {
            discriminant,
            arms,
            default,
            provenance,
        } => {
            // Per-dialect rendering — Java uses `switch` for switch-
            // compatible (Int/String + matching literals) shapes and
            // an `if/else if` chain otherwise (#40); Kotlin renders
            // `when (var) { ... }` for subject-bearing discriminants
            // and subject-less `when { cond -> ... }` for BooleanChain
            // (PR-8 of #41b `dex-signatures-kotlinc-recognizers`).
            let body_str = match provenance.source_dialect {
                SourceDialect::Java(_) => emit_multiarm_java(
                    discriminant,
                    arms,
                    default.as_deref(),
                    env,
                    dex,
                    level,
                    ctx,
                    depth,
                ),
                SourceDialect::Kotlin(_) => emit_multiarm_kotlin(
                    discriminant,
                    arms,
                    default.as_deref(),
                    env,
                    dex,
                    level,
                    ctx,
                    depth,
                ),
            };
            out.push_str(&body_str);
        }

        Stmt::Unrecognized {
            cfg_region,
            reason,
            raw,
        } => {
            out.push_str(&emit_unrecognized(cfg_region.0, reason, raw, level));
        }

        Stmt::Let {
            bindings,
            source,
            provenance,
        } => {
            // Per-dialect rendering — Kotlin recovers the source-level
            // `val (a, b, ...) = source` destructure form; Java has no
            // analogous syntax so it stays at the `componentN()`
            // expansion (kotlinc's lowered form).
            match provenance.source_dialect {
                SourceDialect::Kotlin(_) => {
                    if bindings.is_empty() {
                        // Degenerate IR shape — recognizer enforces
                        // MIN_BINDINGS=2, so this is unreachable from
                        // the producer. Defensive empty emit.
                    } else {
                        indent(&mut out, level);
                        let parts: Vec<String> =
                            bindings.iter().map(|b| emit_use(b, ctx)).collect();
                        let _ = writeln!(
                            out,
                            "val ({}) = {}",
                            parts.join(", "),
                            emit_use(source, ctx)
                        );
                    }
                }
                SourceDialect::Java(_) => {
                    for (i, binding) in bindings.iter().enumerate() {
                        indent(&mut out, level);
                        let n = i.saturating_add(1);
                        out.push_str(&format!(
                            "Object {} = {}.component{}();\n",
                            emit_use(binding, ctx),
                            emit_use(source, ctx),
                            n
                        ));
                    }
                }
            }
        }

        Stmt::OutlinedBlock {
            synthetic_target,
            origin,
        } => {
            // R8-block-outlining recogniser marker. Render a single-line
            // doc-comment banner naming the synthetic helper and the
            // recogniser's confidence. The trampoline body itself emits
            // immediately after (the marker is PREPENDED to the
            // method-body Seq by `r8_inversion::apply`, not a
            // replacement of it).
            //
            // Helper-class resolution is bounded by `dex.methods.len()`
            // (the recogniser stores a `MethodIdx` already validated
            // against the pool at construction time). The class
            // descriptor lookup chain (`method.class_idx → types →
            // strings`) uses `.get()` per slot, so a stale pool index
            // surfaces as `<unknown>` rather than a panic.
            let helper_method = dex
                .methods
                .get(synthetic_target.0 as usize);
            let helper_desc: &str = helper_method
                .and_then(|m| dex.type_descriptors.get(m.class_idx.0 as usize))
                .map(String::as_str)
                .unwrap_or("<unknown>");
            let helper_name: &str = helper_method
                .and_then(|m| dex.strings.get(m.name_idx.0 as usize))
                .map(crate::DexString::as_str_lossy)
                .unwrap_or("<unknown>");
            // Variant name is rendered verbatim so the analyst can
            // distinguish trampoline-side vs helper-side markers
            // without consulting the IR. The substring "BlockOutlined"
            // is preserved in both variant names so the
            // `emit_method` comment-strip exception
            // (`!contains("@droidsaw")`) keeps preserving these
            // markers; analyst-facing distinction is the variant
            // SUFFIX (`Trampoline` vs `Helper`).
            // mapping_confirmed surfaces in the marker text only for
            // the BlockOutlinedHelper variant. None for other
            // variants leaves the banner field absent rather than
            // emitting a meaningless `mapping_confirmed=false` on a
            // variant whose semantic isn't oracle-paired.
            let (variant_name, mapping_confirmed): (&str, Option<bool>) = match origin.variant {
                crate::r8_inversion::R8Transform::BlockOutlinedHelper {
                    mapping_confirmed,
                } => ("BlockOutlinedHelper", Some(mapping_confirmed)),
                crate::r8_inversion::R8Transform::StructurallyOutlineLike => {
                    ("StructurallyOutlineLike", None)
                }
                crate::r8_inversion::R8Transform::EnumValuesCached => {
                    ("EnumValuesCached", None)
                }
                // MethodInlined recogniser is a documented stub (see
                // `r8_inversion::recognise_method_inlined`); it never
                // produces a marker from in-DEX evidence today. The
                // variant is wired here so the match stays exhaustive
                // and downstream tooling that constructs an
                // `R8Origin { variant: MethodInlined, .. }` via an
                // external oracle (mapping file) emits a stable banner
                // rather than hitting an `unreachable!`. The rendered
                // banner intentionally elides `helper=<class>-><name>`
                // because the helper name is unrecoverable post-inlining
                // (the whole point of the annotation-only carve-out).
                crate::r8_inversion::R8Transform::MethodInlined => ("MethodInlined", None),
                // Wired for exhaustiveness only — the recogniser
                // for this variant is a structural stub today (see
                // `r8_inversion::recognise_dead_branch_stripped`),
                // so no `Stmt::OutlinedBlock` with this variant is
                // produced by the pipeline. If/when an empirical
                // signal lands the stub fills in; emit already
                // renders the marker without further changes.
                crate::r8_inversion::R8Transform::DeadBranchStripped => {
                    ("DeadBranchStripped", None)
                }
            };
            indent(&mut out, level);
            match mapping_confirmed {
                Some(confirmed) => {
                    let _ = writeln!(
                        out,
                        "/* @droidsaw R8Origin({}, mapping_confirmed={}, helper={}->{}, callers={}, confidence={}) */",
                        variant_name,
                        confirmed,
                        helper_desc,
                        helper_name,
                        origin.caller_count,
                        origin.confidence,
                    );
                }
                None => {
                    let _ = writeln!(
                        out,
                        "/* @droidsaw R8Origin({}, helper={}->{}, callers={}, confidence={}) */",
                        variant_name,
                        helper_desc,
                        helper_name,
                        origin.caller_count,
                        origin.confidence,
                    );
                }
            }
        }

        Stmt::ResolvedFragment {
            dst,
            resolved,
            fragments,
            signature_id,
        } => {
            // Render the *resolved* literal — author intent — plus a
            // banner-comment carrying the fragmentation evidence so the
            // analyst sees both: the recovered string (atom-level grep
            // finds it) and the fact that THIS string was deliberately
            // hidden via fragmented compile-time concatenation.
            indent(&mut out, level);
            let frag_pieces: Vec<String> =
                fragments.iter().map(|f| format!("{f:?}")).collect();
            let _ = writeln!(
                out,
                "// recognized as fragmented literal (sig #{}); fragments: {}",
                signature_id.0,
                frag_pieces.join(" + "),
            );
            indent(&mut out, level);
            match dst {
                Some(v) => {
                    let _ = writeln!(
                        out,
                        "String {} = {:?};",
                        emit_use(v, ctx),
                        resolved,
                    );
                }
                None => {
                    // Inline-use form — emit just the literal as a
                    // statement; caller is expected to consume it as
                    // an argument. Conservative shape; the recognizer
                    // currently always sets `dst` (the StringConcat it
                    // matches has a `dst` field).
                    let _ = writeln!(out, "{:?};", resolved);
                }
            }
        }
    }

    out
}

/// Iterative emit for `Stmt::MultiArm` in the Java dialect. Walks `arms`
/// with a `for` loop — does NOT recurse on the arm vector. This is the
/// load-bearing discipline for the inversion-driven decompilation track:
/// even though no producer wires `MultiArm` yet, the emitter never falls
/// into a recursive shape. The recursion-depth cap can be removed
/// once legacy nested-If chain producers are removed.
///
/// Body emission of each arm DOES call `emit_stmt_depth` — that's
/// recursion into the arm body, not into the arm chain. The chain
/// itself is unrolled iteratively.
///
/// 8-arg signature mirrors the broader `emit.rs` convention of
/// passing `(env, dex, level, ctx, depth)` plus per-fn payload as
/// flat args. Bundling into a context struct is a cross-cutting
/// refactor deferred.
///
/// **Dispatch:** switch-compatible MultiArm shapes (Int/String
/// discriminant + matching IntLiterals/StringLiterals patterns) render
/// as Java `switch (var) { case L: body; break; ... }`. Other shapes
/// (Enum/SealedSubtype awaiting name resolution; BooleanChain — not a
/// `switch` subject) fall back to an `if/else-if` chain.
#[allow(clippy::too_many_arguments, clippy::arithmetic_side_effects, reason = "8-arg signature mirrors emit.rs convention. `level + N` (N ∈ {1, 2}) for emit-indent recursion; `level` is bounded above by MAX_STMT_DEPTH (512) via the calling emit_stmt_depth recursion guard, so `level + 2 ≤ 514` cannot overflow usize. Counter increments over `arms` bounded by the arms slice length, itself bounded by the validated discriminant pool.")]
fn emit_multiarm_java(
    discriminant: &Discriminant,
    arms: &[MultiArm],
    default: Option<&Stmt>,
    env: &TypeEnv,
    dex: &DexFile,
    level: usize,
    ctx: &mut EmitCtx,
    depth: usize,
) -> String {
    if is_java_switch_compatible(discriminant, arms) {
        return emit_multiarm_as_java_switch(
            discriminant,
            arms,
            default,
            env,
            dex,
            level,
            ctx,
            depth,
        );
    }
    emit_multiarm_as_if_else_chain(discriminant, arms, default, env, dex, level, ctx, depth)
}

/// True iff the (discriminant, arms) pair is renderable as a Java
/// `switch (...) { case L: ... }` statement. Today: Int/String
/// discriminants paired with IntLiterals/StringLiterals patterns.
/// Enum-constant emit needs name resolution (deferred to #41); sealed-
/// subtype emit needs `instanceof Sub` patterns or pattern-switch
/// (Java 21 preview); BooleanChain has no switch form.
fn is_java_switch_compatible(discriminant: &Discriminant, arms: &[MultiArm]) -> bool {
    match discriminant {
        Discriminant::Int(_) => arms
            .iter()
            .all(|a| matches!(a.pattern, ArmPattern::IntLiterals(_))),
        Discriminant::String(_) => arms
            .iter()
            .all(|a| matches!(a.pattern, ArmPattern::StringLiterals(_))),
        Discriminant::Enum { .. }
        | Discriminant::SealedSubtype { .. }
        | Discriminant::BooleanChain(_) => false,
    }
}

/// Emit a switch-compatible MultiArm as Java `switch (var) { ... }`.
/// The compatibility gate (`is_java_switch_compatible`) ensures
/// discriminant + pattern types align; this fn unwraps via assertions
/// the caller has already validated.
#[allow(clippy::too_many_arguments, clippy::arithmetic_side_effects, reason = "8-arg signature mirrors emit.rs convention. `level + N` (N ∈ {1, 2}) for emit-indent recursion bounded by MAX_STMT_DEPTH via the calling emit_stmt_depth guard.")]
fn emit_multiarm_as_java_switch(
    discriminant: &Discriminant,
    arms: &[MultiArm],
    default: Option<&Stmt>,
    env: &TypeEnv,
    dex: &DexFile,
    level: usize,
    ctx: &mut EmitCtx,
    depth: usize,
) -> String {
    let var = match discriminant {
        Discriminant::Int(v) | Discriminant::String(v) => emit_use(v, ctx),
        _ => return String::new(),
    };
    let mut out = String::new();
    indent(&mut out, level);
    let _ = writeln!(out, "switch ({var}) {{");
    for arm in arms {
        match &arm.pattern {
            ArmPattern::IntLiterals(labels) => {
                for k in labels {
                    indent(&mut out, level + 1);
                    let _ = writeln!(out, "case {k}:");
                }
            }
            ArmPattern::StringLiterals(literals) => {
                for s in literals {
                    indent(&mut out, level + 1);
                    let _ = writeln!(out, "case \"{}\":", escape_java_string(s));
                }
            }
            // Gated by `is_java_switch_compatible`; unreachable in
            // practice. Defensive empty-string fall-through.
            _ => return String::new(),
        }
        let body_str = emit_stmt_depth(&arm.body, env, dex, level + 2, ctx, depth);
        out.push_str(&body_str);
        // Heuristic: emit `break;` unless the body already terminates
        // (return / throw / continue). Mirrors the existing
        // Stmt::Switch / Stmt::StringSwitch emit logic.
        if !body_terminates(&body_str) {
            indent(&mut out, level + 2);
            out.push_str("break;\n");
        }
    }
    if let Some(d) = default {
        indent(&mut out, level + 1);
        out.push_str("default:\n");
        let default_str = emit_stmt_depth(d, env, dex, level + 2, ctx, depth);
        out.push_str(&default_str);
        if !body_terminates(&default_str) {
            indent(&mut out, level + 2);
            out.push_str("break;\n");
        }
    }
    indent(&mut out, level);
    out.push_str("}\n");
    out
}

/// True iff the rendered body string already ends with a Java statement
/// that terminates control flow (return / throw / continue), so that no
/// trailing `break;` is needed before the next `case` label.
fn body_terminates(body: &str) -> bool {
    let trimmed = body.trim_end();
    trimmed.ends_with("return;")
        || trimmed.ends_with(';') && body.contains("return ")
        || trimmed.ends_with("throw") // unusual but harmless
        || trimmed.ends_with("continue;")
}

/// Original if/else-if/else fallback rendering, retained for
/// MultiArm shapes that are not Java-switch compatible (Enum awaiting
/// name resolution, SealedSubtype, BooleanChain).
#[allow(clippy::too_many_arguments, clippy::arithmetic_side_effects, reason = "8-arg signature mirrors emit.rs convention. `level + N` for emit-indent recursion bounded by MAX_STMT_DEPTH.")]
fn emit_multiarm_as_if_else_chain(
    discriminant: &Discriminant,
    arms: &[MultiArm],
    default: Option<&Stmt>,
    env: &TypeEnv,
    dex: &DexFile,
    level: usize,
    ctx: &mut EmitCtx,
    depth: usize,
) -> String {
    let mut out = String::new();
    let mut first = true;
    for arm in arms {
        let cond = render_arm_predicate_java(discriminant, &arm.pattern, ctx);
        indent(&mut out, level);
        if first {
            let _ = writeln!(out, "if ({cond}) {{");
            first = false;
        } else {
            let _ = writeln!(out, "}} else if ({cond}) {{");
        }
        out.push_str(&emit_stmt_depth(&arm.body, env, dex, level + 1, ctx, depth));
    }
    if let Some(d) = default {
        if first {
            // No arms — emit just the default body.
            return emit_stmt_depth(d, env, dex, level, ctx, depth);
        }
        indent(&mut out, level);
        out.push_str("} else {\n");
        out.push_str(&emit_stmt_depth(d, env, dex, level + 1, ctx, depth));
    }
    if !first {
        indent(&mut out, level);
        out.push_str("}\n");
    }
    out
}

/// Iterative emit for `Stmt::MultiArm` in the Kotlin dialect. Renders
/// `when (var) { arm -> { body } ... else -> { default } }` for
/// discriminants with a single subject variable
/// (Int / String / Enum / SealedSubtype) and the subject-less
/// `when { cond -> { body } ... else -> { default } }` form for
/// `Discriminant::BooleanChain`.
///
/// Discipline mirrors `emit_multiarm_java`: arms walked iteratively
/// (no recursion on the arm vector); `emit_stmt_depth` recurses into
/// arm bodies only.
///
/// **Exhaustiveness banner.** A `default: None` MultiArm with arms is
/// non-exhaustive — kotlinc would warn. Emit prepends a
/// `// when not exhaustive — kotlinc would warn` line above the
/// `when` block so the analyst sees the encoding decision rather than
/// silently accepting code that wouldn't compile against a sealed
/// root. With `default: Some(_)`, the default lowers to `else -> { ... }`
/// (kotlinc's `else` arm; semantically equivalent to the Java
/// `default:` case).
#[allow(clippy::too_many_arguments, clippy::arithmetic_side_effects, reason = "8-arg signature mirrors emit.rs convention. `level + N` for emit-indent recursion bounded by MAX_STMT_DEPTH.")]
fn emit_multiarm_kotlin(
    discriminant: &Discriminant,
    arms: &[MultiArm],
    default: Option<&Stmt>,
    env: &TypeEnv,
    dex: &DexFile,
    level: usize,
    ctx: &mut EmitCtx,
    depth: usize,
) -> String {
    let mut out = String::new();

    // Empty arms with a default: kotlinc accepts `when (var) { else -> ... }`,
    // but if there's also no subject (BooleanChain), that's degenerate;
    // fall back to just emitting the default body.
    if arms.is_empty() {
        return match default {
            Some(d) => emit_stmt_depth(d, env, dex, level, ctx, depth),
            None => out,
        };
    }

    if default.is_none() {
        indent(&mut out, level);
        out.push_str("// when not exhaustive — kotlinc would warn\n");
    }

    // Subject form vs subject-less form depends on the discriminant.
    let subject = match discriminant {
        Discriminant::Int(v)
        | Discriminant::String(v)
        | Discriminant::Enum { var: v, .. }
        | Discriminant::SealedSubtype { var: v, .. } => Some(emit_use(v, ctx)),
        Discriminant::BooleanChain(_) => None,
    };

    indent(&mut out, level);
    match &subject {
        Some(s) => {
            let _ = writeln!(out, "when ({s}) {{");
        }
        None => {
            out.push_str("when {\n");
        }
    }

    for arm in arms {
        let predicate = render_arm_predicate_kotlin(discriminant, &arm.pattern, dex, ctx);
        indent(&mut out, level + 1);
        let _ = writeln!(out, "{predicate} -> {{");
        out.push_str(&emit_stmt_depth(&arm.body, env, dex, level + 2, ctx, depth));
        indent(&mut out, level + 1);
        out.push_str("}\n");
    }

    if let Some(d) = default {
        indent(&mut out, level + 1);
        out.push_str("else -> {\n");
        out.push_str(&emit_stmt_depth(d, env, dex, level + 2, ctx, depth));
        indent(&mut out, level + 1);
        out.push_str("}\n");
    }

    indent(&mut out, level);
    out.push_str("}\n");
    out
}

/// Render the predicate for one `MultiArm` arm in Java syntax.
///
/// Discriminant + pattern combinations that a recognizer would never
/// produce (e.g., `Discriminant::Int` paired with `ArmPattern::StringLiterals`)
/// fall through to a `/* mismatch */ true` form. The IR validator
/// (#42) will eventually forbid the misencoding; until then, defensive
/// emit avoids panicking on hand-constructed test IR.
fn render_arm_predicate_java(disc: &Discriminant, pat: &ArmPattern, ctx: &EmitCtx) -> String {
    match (disc, pat) {
        (Discriminant::Int(v), ArmPattern::IntLiterals(ks)) => {
            let var = emit_use(v, ctx);
            if ks.is_empty() {
                return "false".to_string();
            }
            ks.iter()
                .map(|k| format!("{var} == {k}"))
                .collect::<Vec<_>>()
                .join(" || ")
        }
        (Discriminant::String(v), ArmPattern::StringLiterals(lits)) => {
            let var = emit_use(v, ctx);
            if lits.is_empty() {
                return "false".to_string();
            }
            lits.iter()
                .map(|s| format!("{var}.equals(\"{}\")", escape_java_string(s)))
                .collect::<Vec<_>>()
                .join(" || ")
        }
        (Discriminant::Enum { var, .. }, ArmPattern::EnumConstants(consts)) => {
            // Resolving enum-constant names needs DexFile context (lookup
            // the field name for each EnumConstId). For the placeholder
            // emit, surface the count + a TODO so the reader knows what's
            // pending. #40 will replace this with proper enum-constant
            // qualified names.
            let var_str = emit_use(var, ctx);
            if consts.is_empty() {
                return "false".to_string();
            }
            format!(
                "{var_str} != null /* TODO #40: emit enum-constant comparisons (#consts={}) */",
                consts.len()
            )
        }
        (Discriminant::SealedSubtype { var, .. }, ArmPattern::SealedTypeIs(_t)) => {
            // Real type-name resolution lands in #41. Placeholder uses
            // `instanceof Object` so the predicate at least compiles.
            let var_str = emit_use(var, ctx);
            format!("{var_str} instanceof Object /* TODO #41: sealed-subtype name */")
        }
        (Discriminant::SealedSubtype { var, .. }, ArmPattern::SealedObjectIs(_t)) => {
            // Sealed-OBJECT (`Intrinsics.areEqual` lowering) — at the Java
            // source level there is no separate sealed-object form, so emit
            // collapses to the same `instanceof Object` placeholder pending
            // #40 (Kotlin emit handles the actual `Foo.Bar ->` bare-singleton
            // form via render_arm_predicate_kotlin in a later PR).
            let var_str = emit_use(var, ctx);
            format!("{var_str} instanceof Object /* TODO #41: sealed-object name */")
        }
        (Discriminant::BooleanChain(_), ArmPattern::Cond(cond)) => {
            emit_condition_typed(cond, None, ctx)
        }
        // Unreachable in practice once the IR validator is enforced. For
        // now (no producer + no validator), defensive fall-through.
        _ => "true /* multi-arm: discriminant/pattern type mismatch */".to_string(),
    }
}

/// Render the predicate for one `MultiArm` arm in Kotlin syntax.
///
/// Kotlin's `when` arms differ shape from Java's `if/else if` predicates
/// because the subject is named once at the top of the block; arms only
/// supply the literal/comparator form before `->`. So whereas Java
/// renders `var == 1 || var == 2`, Kotlin renders `1, 2`.
///
/// - `IntLiterals(ks)` → `1, 2, 3`
/// - `StringLiterals(lits)` → `"a", "b"`
/// - `EnumConstants(consts)` → `Enum.A, Enum.B` (full-qualified per
///   recognizer's resolved enum_type + per-const field name)
/// - `SealedTypeIs(t)` → `is X.Sub` (`is` keyword required for
///   sealed-CLASS arms; runtime test is `instanceof`)
/// - `SealedObjectIs(t)` → `X.Sub` (bare singleton; no `is`)
/// - `Cond(c)` → emitted condition form, used with subject-less
///   `when { ... }` for `BooleanChain` discriminants
///
/// Mismatched (discriminant, pattern) pairs fall through to the same
/// `true /* mismatch */` defensive form as the Java helper. The IR
/// validator (#42) will eventually forbid the misencoding.
fn render_arm_predicate_kotlin(
    disc: &Discriminant,
    pat: &ArmPattern,
    dex: &DexFile,
    ctx: &EmitCtx,
) -> String {
    match (disc, pat) {
        (Discriminant::Int(_), ArmPattern::IntLiterals(ks)) => {
            if ks.is_empty() {
                return "/* empty int arm */".to_string();
            }
            ks.iter()
                .map(|k| k.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
        (Discriminant::String(_), ArmPattern::StringLiterals(lits)) => {
            if lits.is_empty() {
                return "/* empty string arm */".to_string();
            }
            lits.iter()
                .map(|s| format!("\"{}\"", escape_java_string(s)))
                .collect::<Vec<_>>()
                .join(", ")
        }
        (Discriminant::Enum { enum_type, .. }, ArmPattern::EnumConstants(consts)) => {
            if consts.is_empty() {
                return "/* empty enum arm */".to_string();
            }
            let enum_name = dex
                .get_type_descriptor(*enum_type)
                .map(pretty_class_name_kotlin)
                .unwrap_or_else(|_| "?".to_string());
            // Per-const name resolution via the FieldIdx → FieldIdItem
            // → name_idx → string chain. Any failure surfaces as a
            // marker so emit is panic-free on adversarial pool indices.
            consts
                .iter()
                .map(|c| {
                    let name = dex
                        .fields
                        .get(c.field.0 as usize)
                        .and_then(|f| dex.get_string(f.name_idx).ok())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "/* bad field idx */".to_string());
                    format!("{enum_name}.{name}")
                })
                .collect::<Vec<_>>()
                .join(", ")
        }
        (Discriminant::SealedSubtype { .. }, ArmPattern::SealedTypeIs(t)) => {
            let name = dex
                .get_type_descriptor(*t)
                .map(pretty_class_name_kotlin)
                .unwrap_or_else(|_| "?".to_string());
            format!("is {name}")
        }
        (Discriminant::SealedSubtype { .. }, ArmPattern::SealedObjectIs(t)) => dex
            .get_type_descriptor(*t)
            .map(pretty_class_name_kotlin)
            .unwrap_or_else(|_| "?".to_string()),
        (Discriminant::BooleanChain(_), ArmPattern::Cond(cond)) => {
            // Kotlin condition syntax matches Java for our shapes
            // (`a && b`, `a == b`, etc.). Reuse the Java helper rather
            // than duplicate the entire condition lowering — Kotlin-
            // specific differences (`===` vs `==` for referential
            // equality, etc.) are out of PR-8 scope.
            emit_condition_typed(cond, None, ctx)
        }
        // Unreachable in practice once the IR validator is enforced. For
        // now (no producer + no validator), defensive fall-through.
        _ => "/* multi-arm: discriminant/pattern type mismatch */".to_string(),
    }
}

/// Emit the banner + raw-smali block for `Stmt::Unrecognized`.
/// The closest-signature hint is on by default — `--no-signature-hints`
/// suppression (when added) goes through `EmitCtx`, not this helper.
///
/// **Tagged-region special case.** When the engine wraps a recognized
/// region as `Stmt::Unrecognized` with `closest = Some(sig), distance = 0`
/// (per `RecognizedDexShape::TaggedRegion`), this is NOT a true
/// near-miss but a signal that the region was recognized as a shape
/// the IR has no first-class variant for. SignatureId(105) is the
/// kotlinc-1.9 `coroutine_suspend` state machine; emit renders a
/// coroutine-specific banner + the raw bytecode unfolded form rather
/// than the generic NoSignatureMatch banner.
// WHY: `level + N` for emit-indent recursion; bounded by MAX_STMT_DEPTH.
// Counter `i + 1` over raw[..] slice; bounded by `raw.len()` which is
// the parser-validated SsaInsn count.
#[allow(clippy::arithmetic_side_effects, reason = "`level + N` for emit-indent recursion; bounded by MAX_STMT_DEPTH. Counter `i + 1` over raw[..] slice; bounded by `raw.len()` which is the parser-validated SsaInsn count.")]
fn emit_unrecognized(
    cfg_region: u32,
    reason: &UnrecognizedReason,
    raw: &[SsaInsn],
    level: usize,
) -> String {
    use crate::signatures::kotlinc19::coroutine_suspend::COROUTINE_SUSPEND_SIGNATURE_ID;

    let mut out = String::new();

    // Tagged-region detection: NoSignatureMatch with distance == 0 is the
    // sentinel for `RecognizedDexShape::TaggedRegion` (PR-7 of #41b). The
    // only sentinel currently in use is SignatureId(105) for
    // coroutine_suspend; future tagged-regions follow the same shape.
    if let UnrecognizedReason::NoSignatureMatch {
        closest: Some(sig),
        distance: 0,
    } = reason
    {
        if *sig == COROUTINE_SUSPEND_SIGNATURE_ID {
            indent(&mut out, level);
            let _ = writeln!(
                out,
                "// region #{cfg_region}: recognized as kotlinc-1.9 suspend-fun state machine — original bytecode below"
            );
            for insn in raw {
                indent(&mut out, level);
                let _ = writeln!(
                    out,
                    "//   {:?} @ pc=0x{:x}",
                    insn.insn.op, insn.insn.addr
                );
            }
            return out;
        }
    }

    indent(&mut out, level);
    let _ = writeln!(
        out,
        "// region #{cfg_region}: bytecode signature unrecognized"
    );
    indent(&mut out, level);
    match reason {
        UnrecognizedReason::NoSignatureMatch {
            closest: Some(sig),
            distance,
        } => {
            let _ = writeln!(
                out,
                "//   closest match: signature #{} (distance {distance})",
                sig.0
            );
        }
        UnrecognizedReason::NoSignatureMatch { closest: None, .. } => {
            let _ = writeln!(out, "//   no near-miss");
        }
        UnrecognizedReason::AmbiguousSignature { candidates } => {
            let ids: Vec<String> =
                candidates.iter().map(|s| format!("#{}", s.0)).collect();
            let _ = writeln!(
                out,
                "//   ambiguous: {} candidates ({})",
                candidates.len(),
                ids.join(", ")
            );
        }
        UnrecognizedReason::StructurerInternalLimit { limit } => {
            let _ = writeln!(out, "//   structurer hit internal limit: {limit}");
        }
        UnrecognizedReason::DetectorIndeterminate { detector_name } => {
            let _ = writeln!(
                out,
                "//   detection silent: upstream detector ({detector_name}) returned Indeterminate"
            );
        }
    }
    indent(&mut out, level);
    let _ = writeln!(out, "//   raw smali follows:");
    for insn in raw {
        indent(&mut out, level);
        let _ = writeln!(
            out,
            "//     {:?} @ pc=0x{:x}",
            insn.insn.op, insn.insn.addr
        );
    }
    out
}

/// Method info for emit_method.
pub struct MethodInfo<'a> {
    pub name: &'a str,
    pub params: &'a [(VarId, DexType)],
    pub return_type: &'a DexType,
    pub access_flags: u32,
    /// Simple class name (e.g. "Foo" from "LFoo;"), used as constructor name.
    /// When None, falls back to deriving name from `params[0]` type.
    pub class_name: Option<String>,
    /// Type indices listed in the method's `dalvik.annotation.Throws`
    /// annotation, in encoded order (the source order javac emitted).
    /// Empty when no annotation is present. Caller in
    /// `classes.rs::emit_method` populates via
    /// `dex.method_throws(class_def.annotations_off, method_idx)`.
    /// Renders as ` throws T1, T2` after the parameter list, before
    /// the opening brace.
    pub throws: &'a [crate::ids::TypeIdx],
    /// When true, render the method as a Kotlin top-level `fun` —
    /// `fun name(p: T): R { ... }` rather than the Java
    /// `<flags> R name(T p) { ... }` shape. Set by `decompile_class`
    /// when the enclosing class is a kotlinc-1.9 top-level-fn synthetic
    /// facade (`<XxxKt>` with `@kotlin.Metadata`, zero instance fields,
    /// zero virtual methods, all direct methods static). PR-9b of
    /// #41b. Body emit (`emit_stmt`) is unchanged in PR-9b — Kotlin
    /// stmt-level emit lands in PR-9c.
    pub is_facade_method: bool,
}

/// Emit a complete method declaration.
/// Strip redundant type prefixes from repeated declarations of the same var.
///
/// After phi-name collapse, a method may emit e.g. `int v0 = 1;` and later
/// `int v0 = v0 + v1;`. The second should be `v0 = v0 + v1;`. We track
/// seen `(type, var)` pairs and strip the type prefix on re-declarations.
///
/// **Important guard.** The reference-type branch must only fire when the
/// LHS actually looks like `Type varname`. An LHS such as `v2[v4 + 3]` is
/// an aput, not a declaration — but `rfind(' ')` on it finds a space
/// inside the index expression, extracting `var_name = "3]"` and
/// `type_part = "v2[v4 +"`. Without the `is_java_identifier(var_name)`
/// check, any second aput with a matching tail would have its array base
/// stripped, turning `v2[v4 + 3] = v7;` into `3] = v7;`. This caused
/// 22 syntax errors on the production corpus before the guard was added.
// WHY: byte-scanner over emit output. Arithmetic shapes: depth counter
// `depth += 1` / `depth -= 1` on `{`/`}`; bounded by emitted source
// length (output buffer cannot exceed isize::MAX). `line.len() - trimmed.len()`
// for indent extraction; trimmed is a prefix of line so subtraction is
// safe by construction.
#[allow(clippy::arithmetic_side_effects, reason = "byte-scanner over emit output. Arithmetic shapes: depth counter `depth += 1` / `depth -= 1` on `{`/`}`; bounded by emitted source length (output buffer cannot exceed isize::MAX). `line.len() - trimmed.len()` for indent extraction; trimmed is a prefix of line so subtraction is safe by construction.")]
fn dedupe_type_declarations(out: &str) -> String {
    // Scope stack: each `{` opens a new lexical scope (innermost on top);
    // each `}` closes it. Sibling scopes (e.g. catch arms in a try-catch
    // chain, then-vs-else branches of an if) need disjoint seen-decls so
    // each can carry its own typed declaration of the same canonical
    // name. The previous flat single-set implementation merged sibling
    // scopes, stripping the type prefix from catch #2's
    // `StringBuilder v1 = …` after catch #1 already declared `v1` —
    // javac then rejects catch #2 with "cannot find symbol" because its
    // own scope has no `v1` decl. Lookup walks the WHOLE stack so an
    // outer-scope decl is still recognized; insertion only writes the
    // innermost scope so it doesn't leak sideways.
    let mut scopes: Vec<BTreeSet<String>> = vec![BTreeSet::new()];
    let java_types = [
        "int ", "long ", "float ", "double ", "boolean ", "byte ", "char ", "short ", "void ",
    ];
    let lines: Vec<String> = out
        .lines()
        .map(|line| {
            let trimmed = line.trim();

            // Close-brace at the START of the trimmed line ends the
            // current innermost scope. Catches `}`, `} else { … }`,
            // `} catch (…) {`, `} while (…);`. For a `} … {` line we
            // first pop (closing the previous sibling), then later push
            // (opening the new one) at the end-of-line check.
            if trimmed.starts_with('}') && scopes.len() > 1 {
                scopes.pop();
            }

            let mut output_line = line.to_string();
            let mut handled = false;

            if !trimmed.starts_with("for ") {
                for ty in &java_types {
                    if trimmed.starts_with(ty) && trimmed.contains(" = ") {
                        let var_end =
                            trimmed[ty.len()..].find(' ').unwrap_or(0) + ty.len();
                        let var_name = &trimmed[ty.len()..var_end];
                        let decl_key = format!("{ty}{var_name}");
                        let already_in_scope =
                            scopes.iter().any(|s| s.contains(&decl_key));
                        if already_in_scope {
                            let indent_str = &line[..line.len() - trimmed.len()];
                            output_line = format!(
                                "{indent_str}{}",
                                &trimmed[ty.len()..]
                            );
                        } else if let Some(top) = scopes.last_mut() {
                            top.insert(decl_key);
                        }
                        handled = true;
                        break;
                    }
                }
            }

            // Reference types: `ClassName v0 = ...`
            if !handled
                && trimmed.contains(" = ")
                && !trimmed.starts_with("for ")
                && !trimmed.starts_with("if ")
            {
                if let Some(eq_pos) = trimmed.find(" = ") {
                    let before_eq = &trimmed[..eq_pos];
                    if let Some(space_pos) = before_eq.rfind(' ') {
                        let var_name = &before_eq[space_pos + 1..];
                        let type_part = &before_eq[..space_pos];
                        if !type_part.is_empty()
                            && !var_name.is_empty()
                            && !type_part.contains('(')
                            && is_java_identifier(var_name)
                        {
                            let decl_key = format!("ref_{var_name}");
                            let already_in_scope =
                                scopes.iter().any(|s| s.contains(&decl_key));
                            if already_in_scope {
                                let indent_str = &line[..line.len() - trimmed.len()];
                                output_line = format!(
                                    "{indent_str}{var_name} = {}",
                                    &trimmed[eq_pos + 3..]
                                );
                            } else if let Some(top) = scopes.last_mut() {
                                top.insert(decl_key);
                            }
                        }
                    }
                }
            }

            // Open-brace at the END of the line opens a new scope.
            // Handles `try {`, `} catch (…) {`, `} else {`, `if (…) {`,
            // `while (…) {`, `do {`, etc.
            if line.trim_end().ends_with('{') {
                scopes.push(BTreeSet::new());
            }

            output_line
        })
        .collect();
    lines.join("\n") + "\n"
}

/// Rewrite `var = var OP expr;` to `var OP= expr;` for each of the Java
/// compound assignment operators.
///
/// **Important guard.** The naive `find(" = ")` matches inside string
/// literals too. For a line like
///
/// ```text
/// X.$179.A0k(v1, "UPDATE log_event_dropped SET events_dropped_count = events_dropped_count + ");
/// ```
///
/// the first ` = ` sits inside the string literal, and the split produces
/// `var_name = "events_dropped_count"` via `rsplit_once(' ')` on the
/// truncated `lhs`. The prefix-strip match on `rhs` then succeeds on the
/// tail `events_dropped_count + ")`, rewriting the line to
/// `events_dropped_count += ");` — complete corruption.
///
/// Fix: if `lhs` contains a `"` character, skip the rewrite. A legitimate
/// compound-assignment target is always `var` or `Type var`; Java
/// identifiers cannot contain a quote, so any quote in `lhs` means the
/// split landed inside a string literal.
// WHY: byte-offset arithmetic on `find('=')` result for `=` lookahead;
// bounded by surrounding find returning a position < line.len().
// `last_semi + 1` for next-char index; bounded same way.
#[allow(clippy::arithmetic_side_effects, reason = "byte-offset arithmetic on `find('=')` result for `=` lookahead; bounded by surrounding find returning a position < line.len(). `last_semi + 1` for next-char index; bounded same way.")]
fn rewrite_compound_assignments(out: &str) -> String {
    let ops = [
        " + ", " - ", " * ", " / ", " % ", " & ", " | ", " ^ ", " << ", " >> ", " >>> ",
    ];
    let cop = [
        "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>=",
    ];
    // Operators that have LOWER precedence than each entry in `ops` above.
    // If the operand (RHS after stripping `var OP`) contains any of these at
    // the top level, the compound-assignment rewrite would change semantics
    // because `var OP= a LOWER b` means `var = var OP (a LOWER b)` in Java,
    // not `var = (var OP a) LOWER b`.
    //
    // Precedence (low → high): |  ^  &  <</>>/>>>  +/-  */%
    // For each op index we list the ops of strictly lower precedence:
    const LOWER_PREC: [&[&str]; 11] = [
        // +=  (precedence of +): lower = | ^ & shifts (but + itself is ok)
        &[" | ", " ^ ", " & "],
        // -=  (precedence of -): same as +=
        &[" | ", " ^ ", " & "],
        // *=  (precedence of *): lower = + - | ^ & shifts
        &[" + ", " - ", " | ", " ^ ", " & "],
        // /=  (precedence of /): same as *=
        &[" + ", " - ", " | ", " ^ ", " & "],
        // %=  (precedence of %): same as *=
        &[" + ", " - ", " | ", " ^ ", " & "],
        // &=  (precedence of &): lower = | ^
        &[" | ", " ^ "],
        // |=  (precedence of |): nothing lower in our set
        &[],
        // ^=  (precedence of ^): lower = |
        &[" | "],
        // <<=  (precedence of <<): lower = + - | ^ &
        &[" + ", " - ", " | ", " ^ ", " & "],
        // >>=  same
        &[" + ", " - ", " | ", " ^ ", " & "],
        // >>>=  same
        &[" + ", " - ", " | ", " ^ ", " & "],
    ];

    let lines: Vec<String> = out
        .lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("for ") || trimmed.contains("; ") {
                return line.to_string();
            }
            if let Some(eq_pos) = trimmed.find(" = ") {
                let lhs = trimmed[..eq_pos].trim();
                // Guard: if lhs contains a string-literal delimiter, the
                // ` = ` we found is inside a string literal, not a real
                // assignment. Don't rewrite.
                if lhs.contains('"') {
                    return line.to_string();
                }
                let rhs = &trimmed[eq_pos + 3..].trim_end_matches(';');
                let var_name = if lhs.contains(' ') {
                    lhs.rsplit_once(' ').map(|(_, v)| v).unwrap_or(lhs)
                } else {
                    lhs
                };
                for (i, op) in ops.iter().enumerate() {
                    if let Some(rest) = rhs.strip_prefix(var_name) {
                        if let Some(operand) = rest.strip_prefix(op) {
                            // Safety check: the operand must not contain any
                            // operator of lower precedence than `op`, otherwise
                            // the compound assignment changes associativity.
                            // e.g. `v3 = v3 * 3 + v1` MUST NOT become
                            // `v3 *= 3 + v1` because `*=` binds tighter than `+`.
                            if LOWER_PREC[i].iter().any(|lower| operand.contains(lower)) {
                                continue;
                            }
                            let indent_str = &line[..line.len() - trimmed.len()];
                            return format!("{indent_str}{var_name} {} {operand};", cop[i]);
                        }
                    }
                }
            }
            line.to_string()
        })
        .collect();
    lines.join("\n") + "\n"
}

/// In a constructor body, hoist the first `super(...)`/`this(...)` call to
/// be the first statement **and** drop any subsequent lines that are
/// textually identical to it.
///
/// R8 sometimes emits `invoke-direct <init>` in each branch of an if/else
/// inside an inner class constructor. The branches collapse into Java like:
///
/// ```text
/// public Foo(int v) {
///     this.$t = v;
///     if (v == 60) {
///         super();
///         ...
///     } else {
///         super();     // illegal duplicate
///         ...
///     }
/// }
/// ```
///
/// Java requires exactly one super()/this() call, as the first statement.
/// We (1) move the first occurrence to position 0 of the body, (2) drop
/// later lines whose trimmed form equals the hoisted call, (3) replace any
/// *non-identical* remaining super(...)/this(...) lines with a
/// `/* R8 class-merge: originally super(...) */` comment.
///
/// The comment rewrite handles R8's horizontal class-merge + post-merge
/// constructor inliner pathology (`LX/2J0;`, `LX/6A4;` shapes), where
/// one Dalvik constructor reaches distinct `super(args)` forms on
/// different switch cases. Pre-JEP-447 Java cannot express conditional
/// super(), and there is no legal local rewrite that preserves runtime
/// semantics from a single public entry point. Replacing with a comment
/// yields syntactically-valid Java while keeping the original call text
/// visible for investigation — the rule "do not silently pick one form"
/// is honored because the comment is explicit about every dropped call.
// WHY: `line.len() - trimmed.len()` for indent width; trimmed is a
// prefix of line so subtraction is safe. Bounded by line length.
#[allow(clippy::arithmetic_side_effects, reason = "`line.len() - trimmed.len()` for indent width; trimmed is a prefix of line so subtraction is safe. Bounded by line length.")]
fn hoist_constructor_super(out: &str) -> String {
    let Some(body_start) = out.find("{\n").map(|p| p + 2) else {
        return out.to_string();
    };
    let (prefix, body) = out.split_at(body_start);
    let lines: Vec<&str> = body.lines().collect();

    let first_super = lines.iter().enumerate().find(|(_, line)| {
        let t = line.trim();
        t.starts_with("super(") || t.starts_with("this(")
    });

    let Some((idx, super_line_ref)) = first_super else {
        return out.to_string();
    };

    let super_line = *super_line_ref;
    let super_trimmed = super_line.trim();

    let mut new_body = String::new();
    new_body.push_str(super_line);
    new_body.push('\n');
    for (i, line) in lines.iter().enumerate() {
        if i == idx {
            continue;
        }
        let t = line.trim();
        if t == super_trimmed {
            continue;
        }
        if t.starts_with("super(") || t.starts_with("this(") {
            let indent_len = line.len() - line.trim_start().len();
            new_body.push_str(&line[..indent_len]);
            new_body.push_str("/* R8 class-merge: originally ");
            new_body.push_str(t);
            new_body.push_str(" */\n");
            continue;
        }
        new_body.push_str(line);
        new_body.push('\n');
    }
    format!("{prefix}{new_body}")
}

fn is_java_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_' || first == '$') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// Strip `kotlin.jvm.internal.Intrinsics.*` runtime-guard calls from
/// a facade method body (PR-9c.5 of #41b). kotlinc-1.9.22
/// auto-inserts three intrinsics for null-safety enforcement at
/// JVM-call boundaries; these have no Kotlin source-level analogue
/// and kotlinc rejects them as input.
///
/// Stripped patterns (each must occupy an entire line, possibly
/// with leading indent + trailing `;`):
/// - `kotlin.jvm.internal.Intrinsics.checkNotNullParameter(<expr>, <expr>)`
///   — inserted at the entry of every fn / method that takes a
///   non-nullable reference parameter.
/// - `kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(<expr>, <expr>)`
///   — inserted after expressions whose nullability the compiler
///   can't statically prove (e.g. Java-interop returns).
/// - `kotlin.jvm.internal.Intrinsics.checkNotNull(<expr>)` — inserted
///   on `!!` (non-null assertion) operator usage.
///
/// **Byte-equality preservation**: stripping is safe under the
/// kotlinc roundtrip-gate `D1 == D2` because the intrinsics are
/// auto-inserted on recompile. So if D1 has the line stripped,
/// kotlinc re-emits the intrinsics in bytecode A', then decompile
/// re-renders the intrinsics line, then this post-pass strips it
/// again → D2 has no intrinsics. D1 == D2 ✓.
///
/// Pre-condition for PR-9d (data class), PR-9e (sealed class /
/// object), and the when_string multi-arm shapes: those fixture
/// classes carry intrinsics calls that block kotlinc-recompile
/// regardless of any other body-shape work. Landing the strip
/// independently keeps the fix surface contained to a single
/// post-pass invocation.
fn strip_kotlin_intrinsics(body: &str) -> String {
    let intrinsics_prefixes = [
        "kotlin.jvm.internal.Intrinsics.checkNotNullParameter(",
        "kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(",
        "kotlin.jvm.internal.Intrinsics.checkNotNull(",
    ];
    let mut out = String::with_capacity(body.len());
    for line in body.lines() {
        let trimmed = line.trim_start();
        let is_intrinsics = intrinsics_prefixes
            .iter()
            .any(|p| trimmed.starts_with(p))
            && trimmed.ends_with(");");
        if !is_intrinsics {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Kotlinify post-pass for kotlinc-1.9 top-level-fn facade method
/// bodies (PR-9c of #41b). Rewrites the
/// `<when-with-arm-assigns> + return v` pattern as a single
/// `return when (...) { ... }` form so that kotlinc accepts the
/// decompile output as valid Kotlin source.
///
/// The raw Java-shape body that PR-9b's facade emit produces:
/// ```text
///     when (i) {
///         5 -> {
///             String v0 = "v5";
///         }
///         4 -> {
///             v0 = "v4";
///         }
///         else -> {
///             v0 = "other";
///         }
///     }
///     return v0;
/// ```
/// kotlinc rejects this for two reasons: (a) `String v0 = "v5"` is
/// Java-syntax, not Kotlin; (b) a var declared inside one `when` arm
/// is NOT visible in sibling arms (Kotlin scope rule). The
/// post-pass sidesteps both by lifting the arm bodies' RHS expressions
/// into a single `return when (...)` form:
/// ```text
///     return when (i) {
///         5 -> "v5"
///         4 -> "v4"
///         else -> "other"
///     }
/// ```
///
/// Pattern (string-level, indent-tolerant):
/// 1. Some prefix (params, hoisted vars, etc — anything that's NOT
///    the `when` line + `return v`).
/// 2. A `when (<subj>) {` line at indent level N.
/// 3. Zero or more arms, each shaped as 4 lines:
///    `<lit> -> {`, `(<Type> )?<var> = <expr>;`, `}`, optional blank.
///    Arms use literal int / string / `else`. Body must be a single
///    assignment to a consistent `<var>` across all arms.
/// 4. A `}` closing the `when` at indent N.
/// 5. `return <var>;` at indent N.
///
/// Returns the body unchanged if any leg of the pattern fails. The
/// rewrite is **deterministic** + **fixed-point**: when applied to
/// already-rewritten output (`return when ...`), no `when ... return v;`
/// shape remains, so the post-pass is a no-op on the second pass.
/// Required for the kotlinc roundtrip-gate `D1 == D2` byte-equality.
///
/// Out of scope (deferred to PR-9c.5 / PR-9d / PR-9e):
/// - String-`when` ≥5 arms (`hashCode + tableswitch` form with
///   nested `equals` in arms — multi-stmt arm bodies).
/// - String-`when` 2-arm linear `Intrinsics.areEqual` chain (recognizer
///   doesn't fire today — different fix layer).
/// - Sealed-class / sealed-object / data-class facades.
/// - Single-expression fn bodies (`fun foo() = expr`); the
///   `{ return expr }` form lands first; collapsing block-with-
///   single-return to expression-body is a future cosmetic fix.
// WHY: indent arithmetic over emit output (`line.len() - trimmed.len()`,
// `when_open_line.len() - trim_start.len()`, etc.). In every case the
// subtrahend is `trim_start()` / `trim_end()` of the same line, hence
// a prefix/suffix; subtraction is safe by construction.
#[allow(clippy::arithmetic_side_effects, reason = "indent arithmetic over emit output (`line.len() - trimmed.len()`, `when_open_line.len() - trim_start.len()`, etc.). In every case the subtrahend is `trim_start()` / `trim_end()` of the same line, hence a prefix/suffix; subtraction is safe by construction.")]
fn kotlinify_facade_when_return(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();

    // Locate the `when (subj) {` line + its closing `}`.
    let when_open_idx = match lines.iter().position(|l| {
        let trimmed = l.trim_start();
        trimmed.starts_with("when (") && trimmed.ends_with(") {")
    }) {
        Some(i) => i,
        None => return body.to_string(),
    };

    let when_open_line = lines[when_open_idx];
    let when_indent = when_open_line.len() - when_open_line.trim_start().len();
    let arm_indent = when_indent.saturating_add(4);

    // Extract subject text between "when (" and ") {".
    let subj = {
        let trimmed = when_open_line.trim_start();
        let inner = trimmed
            .strip_prefix("when (")
            .and_then(|s| s.strip_suffix(") {"));
        match inner {
            Some(s) => s,
            None => return body.to_string(),
        }
    };

    // Walk forward parsing 4-line arm blocks at `arm_indent` until we
    // hit the closing `}` at `when_indent`.
    #[derive(Debug)]
    struct Arm<'a> {
        head: &'a str, // the literal or `else`
        expr: String,  // RHS of the single assignment, `;` stripped
    }
    let mut arms: Vec<Arm<'_>> = Vec::new();
    let mut var_name: Option<String> = None;
    let mut i = when_open_idx.saturating_add(1);
    let when_close_idx;
    loop {
        let Some(line) = lines.get(i) else {
            return body.to_string();
        };
        // Closing `}` at when_indent ends the when block.
        let trimmed = line.trim_start();
        let line_indent = line.len() - trimmed.len();
        if trimmed == "}" && line_indent == when_indent {
            when_close_idx = i;
            break;
        }
        // Otherwise expect arm-header line at `arm_indent`.
        if line_indent != arm_indent || !trimmed.ends_with(" -> {") {
            return body.to_string();
        }
        let head = match trimmed.strip_suffix(" -> {") {
            Some(h) => h,
            None => return body.to_string(),
        };
        // Arm body: single assignment line at arm_indent + 4.
        let body_idx = i.saturating_add(1);
        let close_idx = i.saturating_add(2);
        let Some(body_line) = lines.get(body_idx) else {
            return body.to_string();
        };
        let Some(close_line) = lines.get(close_idx) else {
            return body.to_string();
        };
        let body_trim = body_line.trim_start();
        let body_line_indent = body_line.len() - body_trim.len();
        if body_line_indent != arm_indent.saturating_add(4) {
            return body.to_string();
        }
        // Body must end with `;` and be exactly one assignment statement.
        let body_no_semi = match body_trim.strip_suffix(';') {
            Some(s) => s,
            None => return body.to_string(),
        };
        let eq_pos = match body_no_semi.find(" = ") {
            Some(p) => p,
            None => return body.to_string(),
        };
        let lhs = body_no_semi[..eq_pos].trim();
        let rhs = body_no_semi[eq_pos.saturating_add(3)..].trim();
        // LHS is `<var>` or `<Type> <var>`. Take the last whitespace
        // token as the var name.
        let lhs_var = lhs.split_whitespace().last().unwrap_or(lhs);
        if lhs_var.is_empty() || !is_java_identifier(lhs_var) {
            return body.to_string();
        }
        // All arms must reference the same var.
        match &var_name {
            None => var_name = Some(lhs_var.to_string()),
            Some(prev) if prev != lhs_var => return body.to_string(),
            Some(_) => {}
        }
        // Closing `}` at arm_indent.
        let close_trim = close_line.trim_start();
        let close_line_indent = close_line.len() - close_trim.len();
        if close_line_indent != arm_indent || close_trim != "}" {
            return body.to_string();
        }
        arms.push(Arm {
            head,
            expr: rhs.to_string(),
        });
        i = close_idx.saturating_add(1);
    }

    // After the `when`'s closing brace we expect `return <var>;` at
    // `when_indent`. Skip any single blank line between them.
    let mut return_idx = when_close_idx.saturating_add(1);
    while lines.get(return_idx).is_some_and(|l| l.trim().is_empty()) {
        return_idx = return_idx.saturating_add(1);
    }
    let Some(return_line) = lines.get(return_idx) else {
        return body.to_string();
    };
    let return_trim = return_line.trim_start();
    let return_line_indent = return_line.len() - return_trim.len();
    if return_line_indent != when_indent {
        return body.to_string();
    }
    let Some(var) = var_name else {
        // Zero-arm `when` — pattern doesn't match.
        return body.to_string();
    };
    let expected_return = format!("return {var};");
    if return_trim != expected_return {
        return body.to_string();
    }

    // Rewrite. Rebuild output preserving prefix lines, replacing the
    // `when ... }` + `return v;` block with a `return when (...) { ... }`
    // form.
    let mut out = String::with_capacity(body.len());
    for line in lines.iter().take(when_open_idx) {
        out.push_str(line);
        out.push('\n');
    }
    let when_pad = " ".repeat(when_indent);
    let arm_pad = " ".repeat(arm_indent);
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!("{when_pad}return when ({subj}) {{\n"),
    );
    for arm in &arms {
        let _ = std::fmt::Write::write_fmt(
            &mut out,
            format_args!("{arm_pad}{} -> {}\n", arm.head, arm.expr),
        );
    }
    let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{when_pad}}}\n"));
    // Suffix: lines AFTER the `return <var>;` line.
    for line in lines.iter().skip(return_idx.saturating_add(1)) {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Kotlinify post-pass for kotlinc-1.9 facade bodies whose `when` block
/// has a `return <var>;` INSIDE the last arm rather than after the
/// closing `}` (PR-9e of #41b). This is the shape kotlinc emits for
/// sealed-when fixtures whose source uses single-expression syntax —
/// e.g.:
///
/// ```kotlin
/// fun describe(c: Color): String = when (c) {
///     Color.Red -> "red"
///     Color.Green -> "green"
///     ...
/// }
/// ```
///
/// kotlinc + d8 lower this so each arm originally had its own `areturn`
/// at the JVM level. The structurer's single-exit normalization
/// rewrites all-but-the-last to `<var> = <expr>` assigning a shared
/// SSA tail var, leaving the LAST arm with `<var> = <expr>; return <var>;`.
/// The post-pass detects this exact shape and rewrites the whole
/// method body as `return when (...) { PAT -> EXPR; ... }` — the
/// shape kotlinc accepts as input.
///
/// Pattern (string-level, indent-tolerant):
/// 1. Some prefix (params, hoisted vars, comments — anything that's NOT
///    the `when` line).
/// 2. A `when (<subj>) {` line at indent level N.
/// 3. Arms 1..n-1: each shaped as 4 lines:
///    `<head> -> {`, `(<Type> )?<var> = <expr>;`, `}`, optional blank.
/// 4. Arm n (last arm): 5 lines:
///    `<head> -> {`, `(<Type> )?<var> = <expr>;`, `return <var>;`, `}`.
/// 5. A `}` closing the `when` at indent N.
/// 6. NO `return <var>;` outside the when block (would be already
///    handled by [`kotlinify_facade_when_return`]; this helper runs
///    after it and only sees shapes that didn't fit the prior post-pass).
///
/// Returns the body unchanged on any pattern mismatch — fixed-point +
/// idempotent. Required for the kotlinc roundtrip-gate `D1 == D2`
/// byte-equality.
///
/// Out of scope (separate streams):
/// - Multi-stmt arm bodies (sealed-CLASS fixtures with `(Type) sh`
///   casts + getter calls + arithmetic — the
///   `dex-decompile-sealed-class-multistmt-shape` follow-up).
/// - 2-arm shapes (recognizer's `MIN_ARMS=3` gate prevents lift —
///   the `dex-decompile-sealed-when-min-arms-relax` follow-up).
// WHY: same indent arithmetic shape as kotlinify_facade_when_return
// (`line.len() - trim*.len()`, subtrahend is a trim-prefix/suffix).
#[allow(clippy::arithmetic_side_effects, reason = "same indent arithmetic shape as kotlinify_facade_when_return (`line.len() - trim*.len()`, subtrahend is a trim-prefix/suffix).")]
fn kotlinify_facade_when_inline_return(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();

    let when_open_idx = match lines.iter().position(|l| {
        let trimmed = l.trim_start();
        trimmed.starts_with("when (") && trimmed.ends_with(") {")
    }) {
        Some(i) => i,
        None => return body.to_string(),
    };

    let when_open_line = lines[when_open_idx];
    let when_indent = when_open_line.len() - when_open_line.trim_start().len();
    let arm_indent = when_indent.saturating_add(4);

    let subj = {
        let trimmed = when_open_line.trim_start();
        let inner = trimmed
            .strip_prefix("when (")
            .and_then(|s| s.strip_suffix(") {"));
        match inner {
            Some(s) => s,
            None => return body.to_string(),
        }
    };

    #[derive(Debug)]
    struct Arm<'a> {
        head: &'a str,
        expr: String,
    }
    let mut arms: Vec<Arm<'_>> = Vec::new();
    let mut var_name: Option<String> = None;
    let mut last_arm_had_return = false;
    let mut i = when_open_idx.saturating_add(1);
    let when_close_idx;
    loop {
        let Some(line) = lines.get(i) else {
            return body.to_string();
        };
        let trimmed = line.trim_start();
        let line_indent = line.len() - trimmed.len();
        if trimmed == "}" && line_indent == when_indent {
            when_close_idx = i;
            break;
        }
        if line_indent != arm_indent || !trimmed.ends_with(" -> {") {
            return body.to_string();
        }
        let head = match trimmed.strip_suffix(" -> {") {
            Some(h) => h,
            None => return body.to_string(),
        };
        let body_idx = i.saturating_add(1);
        let Some(body_line) = lines.get(body_idx) else {
            return body.to_string();
        };
        let body_trim = body_line.trim_start();
        let body_line_indent = body_line.len() - body_trim.len();
        if body_line_indent != arm_indent.saturating_add(4) {
            return body.to_string();
        }
        let body_no_semi = match body_trim.strip_suffix(';') {
            Some(s) => s,
            None => return body.to_string(),
        };
        let eq_pos = match body_no_semi.find(" = ") {
            Some(p) => p,
            None => return body.to_string(),
        };
        let lhs = body_no_semi[..eq_pos].trim();
        let rhs = body_no_semi[eq_pos.saturating_add(3)..].trim();
        let lhs_var = lhs.split_whitespace().last().unwrap_or(lhs);
        if lhs_var.is_empty() || !is_java_identifier(lhs_var) {
            return body.to_string();
        }
        match &var_name {
            None => var_name = Some(lhs_var.to_string()),
            Some(prev) if prev != lhs_var => return body.to_string(),
            Some(_) => {}
        }
        // After the assignment line: either `}` (regular arm) OR
        // `return <var>;` then `}` (last arm).
        let after_body_idx = body_idx.saturating_add(1);
        let Some(after_body_line) = lines.get(after_body_idx) else {
            return body.to_string();
        };
        let after_body_trim = after_body_line.trim_start();
        let after_body_indent = after_body_line.len() - after_body_trim.len();
        if after_body_trim == "}" && after_body_indent == arm_indent {
            // Regular arm.
            arms.push(Arm {
                head,
                expr: rhs.to_string(),
            });
            i = after_body_idx.saturating_add(1);
            continue;
        }
        // Else: must be `return <var>;` at body-line-indent followed
        // by `}` at arm_indent.
        let var_ref = match var_name.as_ref() {
            Some(v) => v,
            None => return body.to_string(),
        };
        let expected_return = format!("return {var_ref};");
        if after_body_trim != expected_return || after_body_indent != arm_indent.saturating_add(4) {
            return body.to_string();
        }
        let close_idx = after_body_idx.saturating_add(1);
        let Some(close_line) = lines.get(close_idx) else {
            return body.to_string();
        };
        let close_trim = close_line.trim_start();
        let close_line_indent = close_line.len() - close_trim.len();
        if close_line_indent != arm_indent || close_trim != "}" {
            return body.to_string();
        }
        // Last arm with inline return — must be the FINAL arm before
        // when's closing `}`. Verify by peeking the next line.
        let after_close_idx = close_idx.saturating_add(1);
        let Some(after_close_line) = lines.get(after_close_idx) else {
            return body.to_string();
        };
        let after_close_trim = after_close_line.trim_start();
        let after_close_indent = after_close_line.len() - after_close_trim.len();
        if after_close_trim != "}" || after_close_indent != when_indent {
            // More arms follow this "terminal" arm — pattern is
            // ambiguous (which arm has the real return?). Bail.
            return body.to_string();
        }
        arms.push(Arm {
            head,
            expr: rhs.to_string(),
        });
        last_arm_had_return = true;
        when_close_idx = after_close_idx;
        break;
    }

    // The shape this post-pass targets requires a return in the LAST
    // arm. If we exited the walk loop on the regular `}`-at-when-indent
    // exit (no inline return seen), the shape is the
    // `kotlinify_facade_when_return`-handled pattern (or no pattern at
    // all) — leave the body alone.
    if !last_arm_had_return {
        return body.to_string();
    }

    let Some(_var) = var_name else {
        return body.to_string();
    };

    // Rewrite. Prefix lines verbatim; replace the whole `when` block
    // with `return when (...) { ... }`.
    let mut out = String::with_capacity(body.len());
    for line in lines.iter().take(when_open_idx) {
        out.push_str(line);
        out.push('\n');
    }
    let when_pad = " ".repeat(when_indent);
    let arm_pad = " ".repeat(arm_indent);
    let _ = std::fmt::Write::write_fmt(
        &mut out,
        format_args!("{when_pad}return when ({subj}) {{\n"),
    );
    for arm in &arms {
        let _ = std::fmt::Write::write_fmt(
            &mut out,
            format_args!("{arm_pad}{} -> {}\n", arm.head, arm.expr),
        );
    }
    let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{when_pad}}}\n"));
    for line in lines.iter().skip(when_close_idx.saturating_add(1)) {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Strip the trailing implicit `return;` line from a void method /
/// constructor body. Caller is responsible for the void/constructor
/// predicate; this helper only handles the mechanical strip.
///
/// The `trim_end().ends_with("return;")` gate proves the substring
/// sits at `trimmed.len() - "return;".len()` in `out` (trimmed is a
/// prefix-`&str` view of `out`). The `replace_range` upper bound is
/// clamped to `out.len()` so the bare-`return;` shape (no trailing
/// newline) does not OOB — common-path semantics (strip the full
/// `    return;\n` line including indent + newline) are preserved
/// when the trailing newline is present.
// WHY: `out.len() - "return;".len()` produces the strip start position.
// The `ends_with("return;")` gate proves out.len() >= "return;".len()
// before the subtraction, so it cannot underflow.
#[allow(clippy::arithmetic_side_effects, reason = "`out.len() - \"return;\".len()` produces the strip start position. The `ends_with(\"return;\")` gate proves out.len() >= \"return;\".len() before the subtraction, so it cannot underflow.")]
fn strip_trailing_void_return(out: &mut String) {
    let trimmed = out.trim_end();
    if trimmed.ends_with("return;") {
        let return_pos = trimmed.len() - "return;".len();
        let line_start = out[..return_pos].rfind('\n').map_or(return_pos, |p| p + 1);
        let end = (return_pos + "return;\n".len()).min(out.len());
        out.replace_range(line_start..end, "");
    }
}

// WHY: `level + 1` indent recursion (bounded by MAX_STMT_DEPTH via
// the calling emit_stmt_depth guard) and `last_super_idx + 1` for
// post-super() insertion index (bounded by stmts.len() check above).
// String index arithmetic on emit output uses `out.len() - X` shapes
// with X = known suffix length from `ends_with` / `find`.
#[allow(clippy::arithmetic_side_effects, reason = "`level + 1` indent recursion (bounded by MAX_STMT_DEPTH via the calling emit_stmt_depth guard) and `last_super_idx + 1` for post-super() insertion index (bounded by stmts.len() check above). String index arithmetic on emit output uses `out.len() - X` shapes with X = known suffix length from `ends_with` / `find`.")]
pub fn emit_method(
    stmt: &mut Stmt,
    env: &TypeEnv,
    dex: &DexFile,
    info: &MethodInfo<'_>,
    ctx: &mut EmitCtx,
    payloads: &BTreeMap<u32, crate::decode::PayloadData>,
) -> String {
    // AST-level: merge invoke + move-result pairs before any emission
    merge_invoke_moveresult(stmt);

    // Reset thread-locals at method entry. compute_inline_exprs will populate
    // them as it walks the Stmt tree; emit_use / emit_stmt consult them.

    // Store fill-array-data payloads for this method.
    ctx.fill_array_payloads.clear();
    for (pc, payload) in payloads {
        if let crate::decode::PayloadData::FillArrayData { element_width, data } = payload {
            ctx.fill_array_payloads.insert(*pc, (*element_width, data.clone()));
        }
    }

    // Store declared return type so Stmt::Return can cast Int → boolean/byte/char/short.
    ctx.return_type = Some(info.return_type.clone());

    let mut out = String::new();

    let method_name = info.name;
    let params = info.params;
    let return_type = info.return_type;
    let access_flags = info.access_flags;

    // Handle <clinit> as a static initializer block
    if method_name == "<clinit>" {
        // Clear this_var so invoke-direct <init> inside static blocks
        // emits "new Foo()" instead of "super()" (EMIT_THIS_VAR may be
        // stale from a previous constructor method).
        ctx.this_var = None;
        out.push_str("static {\n");
        compute_inline_exprs(stmt, env, dex, ctx);
        let body = emit_stmt(stmt, env, dex, 1, ctx);
        // Java forbids `return;` inside static initializer blocks.
        // DEX <clinit> always ends with return-void; strip it.
        let body: String = body
            .lines()
            .filter(|l| l.trim() != "return;")
            .map(|l| format!("{l}\n"))
            .collect();
        out.push_str(&body);
        out.push_str("}\n");

        // Apply mro_map replacements (same as normal methods)
        for (var, invoke_expr) in &ctx.mro_map {
            let var_name = var.to_string();
            let lines: Vec<String> = out
                .lines()
                .map(|l| {
                    if l.contains(&format!("{var_name} = /* move-result */")) {
                        l.replace("/* move-result */", invoke_expr)
                    } else {
                        l.to_string()
                    }
                })
                .collect();
            out = lines.join("\n") + "\n";
        }

        // Fix remaining throw/return with /* move-result */ by inlining prev invoke
        let lines: Vec<String> = out.lines().map(|s| s.to_string()).collect();
        let mut fixed: Vec<String> = Vec::new();
        for i in 0..lines.len() {
            let t = lines[i].trim();
            if (t.starts_with("throw ") || t.starts_with("return "))
                && t.contains("/* move-result */")
            {
                if let Some(prev) = fixed.last().cloned() {
                    let prev_t = prev.trim().trim_end_matches(';').to_string();
                    if prev_t.contains('(') && !prev_t.starts_with("//") {
                        let indent_str = &lines[i][..lines[i].len() - t.len()];
                        let keyword = if t.starts_with("throw") {
                            "throw"
                        } else {
                            "return"
                        };
                        fixed.pop(); // remove standalone invoke
                        fixed.push(format!("{indent_str}{keyword} {prev_t};"));
                        continue;
                    }
                }
            }
            // Remove standalone comment statements
            let t_no_semi = t.trim_end_matches(';').trim();
            if t_no_semi.starts_with("/*") && t_no_semi.ends_with("*/") {
                continue;
            }
            // Remove "Type v = /* ... */;"
            if t.contains("= /*") && t.contains("*/;") {
                continue;
            }
            fixed.push(lines[i].clone());
        }
        out = fixed.join("\n") + "\n";

        droidsaw_common::diag::stage_dump("emit", &out);
        return out;
    }

    let is_constructor = method_name == "<init>";
    // Method-context access flag mask: drop ACC_CONSTRUCTOR (0x10000,
    // dex-internal), ACC_BRIDGE (0x0040, shares with ACC_VOLATILE
    // field-only — synthetic, not source-level), ACC_VARARGS (0x0080,
    // shares with ACC_TRANSIENT field-only — surfaced via `int...`
    // parameter syntax). See `src/classes.rs::emit_abstract_method`
    // for the mirror mask on abstract methods.
    let flags = emit_access_flags(access_flags & !0x10000 & !0x0040 & !0x0080);
    let is_static = access_flags & 0x0008 != 0;

    // For non-static methods, first param is `this` — suppress from signature
    let visible_params: &[(VarId, DexType)] = if !is_static && !params.is_empty() {
        ctx.this_var = Some(params[0].0.clone());
        ctx.var_names
            .insert(params[0].0.clone(), "this".to_string());
        if is_constructor {
            ctx.this_var = Some(params[0].0.clone());
        } else {
            ctx.this_var = None;
        }
        &params[1..]
    } else {
        ctx.this_var = None;
        params
    };

    // Facade methods (kotlinc-1.9 top-level-fn `<XxxKt>` synthetic
    // class) render with Kotlin `fun name(p: Type): RetType {` shape;
    // all other methods render with the Java `<flags> RetType name(Type p) {`
    // shape. PR-9b of #41b. Constructors (`<init>`) are guaranteed
    // absent in the facade class by the structural gate at the
    // call-site, so the `is_constructor` legs below are reached only
    // on Java-shape methods.
    let ret_str = if info.is_facade_method {
        ctx.simple_type_kotlin(return_type)
    } else {
        ctx.simple_type(return_type)
    };
    let display_name = if is_constructor {
        // Priority: explicit class_name > params[0] type > fallback "<init>"
        if let Some(ref cn) = info.class_name {
            cn.clone()
        } else if !is_static && !params.is_empty() {
            match &params[0].1 {
                DexType::Ref(desc) if desc.starts_with('L') && desc.ends_with(';') => sanitize_id(
                    desc[1..desc.len() - 1]
                        .rsplit('/')
                        .next()
                        .unwrap_or(method_name),
                ),
                _ => method_name.to_string(),
            }
        } else {
            method_name.to_string()
        }
    } else {
        method_name.to_string()
    };

    let param_strs: Vec<String> = visible_params
        .iter()
        .map(|(v, t)| {
            let name = ctx.var_name(v);
            if info.is_facade_method {
                let ty = ctx.simple_type_kotlin(t);
                format!("{name}: {ty}")
            } else {
                let ty = ctx.simple_type(t);
                format!("{ty} {name}")
            }
        })
        .collect();

    // Render the per-method `throws T1, T2` clause from the parsed
    // `dalvik.annotation.Throws` annotation (populated by the caller
    // in `classes.rs::emit_method` via `dex.method_throws`). Empty
    // string when the annotation is absent or empty. Per-method
    // narrow throws is strictly more precise than the class-level
    // `throws Throwable` cascade in `patch_throws_throwable_on_method_signatures`;
    // the cascade still fires as a fallback for hoist-bearing classes
    // where the annotation lookup misses.
    let throws_clause = if info.throws.is_empty() {
        String::new()
    } else {
        let names: Vec<String> = info
            .throws
            .iter()
            .filter_map(|t| dex.get_type_descriptor(*t).ok())
            .map(pretty_class_name)
            .collect();
        if names.is_empty() {
            String::new()
        } else {
            format!(" throws {}", names.join(", "))
        }
    };

    if is_constructor {
        let _ = writeln!(
            out,
            "{flags} {display_name}({}){throws_clause} {{",
            param_strs.join(", ")
        );
    } else if info.is_facade_method {
        // Kotlin top-level `fun name(p: Type): RetType { ... }`.
        // `Unit` return type is conventionally omitted in Kotlin
        // source; inserting `: Unit` is legal but kotlinc style
        // strips it for void-returning fns. We elide `: Unit` to
        // match kotlinc's source-form output.
        if ret_str == "Unit" {
            let _ = writeln!(
                out,
                "fun {display_name}({}) {{",
                param_strs.join(", ")
            );
        } else {
            let _ = writeln!(
                out,
                "fun {display_name}({}): {ret_str} {{",
                param_strs.join(", ")
            );
        }
    } else {
        let _ = writeln!(
            out,
            "{flags} {ret_str} {display_name}({}){throws_clause} {{",
            param_strs.join(", ")
        );
    }

    // Mark params as declared
    for (v, _) in visible_params {
        ctx.declared.insert(v.clone());
    }
    if let Some(ref tv) = ctx.this_var {
        ctx.declared.insert(tv.clone());
    }

    // Pre-pass: find single-use vars that can be inlined
    compute_inline_exprs(stmt, env, dex, ctx);

    // Pre-pass: hoist catch-bound SSA vars whose uses escape the catch
    // body's legitimate scope. See `collect_escaped_catch_vars` for the
    // rationale + TryResources fixture.
    //
    // Hoisted type is `Throwable` — semantically accurate for the Dalvik
    // catchall source. Java's checked-exception rule forces the
    // enclosing method to declare `throws Throwable`; the class-level
    // post-pass in `classes.rs` patches every method signature in a
    // hoist-bearing class with `throws Throwable` (over-declarative but
    // correct — any method in the class might transitively call the
    // hoist-bearing one). Earlier narrowing via `RuntimeException +
    // (RuntimeException) cast` was a runtime-fragile pragma;
    // throws-cascade is the clean form.
    ctx.hoisted_catch_vars.clear();
    let escaped_catches = collect_escaped_catch_vars(stmt, env);
    for (v, _ty) in &escaped_catches {
        indent(&mut out, 1);
        let _ = writeln!(out, "Throwable {} = null;", emit_var(v));
        ctx.declared.insert(v.clone());
        ctx.hoisted_catch_vars.insert(v.clone());
    }
    if !escaped_catches.is_empty() {
        ctx.class_has_hoist = true;
    }

    out.push_str(&emit_stmt(stmt, env, dex, 1, ctx));

    // In constructors, hoist the first super()/this() call to position 0
    // and drop subsequent exact-duplicate super()/this() lines.
    if is_constructor {
        out = hoist_constructor_super(&out);
    }

    // Remove trailing implicit `return;` from void methods / constructors.
    if is_constructor || *return_type == DexType::Void {
        strip_trailing_void_return(&mut out);
    }

    out.push_str("}\n");

    // Replace /* move-result */ with actual invoke expressions
    for (var, invoke_expr) in &ctx.mro_map {
        let var_name = var.to_string();
        // Find the line that has "varName = /* move-result */" and replace the RHS
        let lines: Vec<String> = out
            .lines()
            .map(|l| {
                if l.contains(&format!("{var_name} = /* move-result */")) {
                    l.replace("/* move-result */", invoke_expr)
                } else {
                    l.to_string()
                }
            })
            .collect();
        out = lines.join("\n") + "\n";
    }

    // Replace any remaining /* move-result */ that was inlined into throw/return
    // (happens when single-use var is inlined but its invoke expr wasn't substituted)
    if out.contains("/* move-result */") {
        // Find the invoke expression on the line immediately before
        let lines: Vec<String> = out.lines().map(|s| s.to_string()).collect();
        let mut new_lines: Vec<String> = Vec::with_capacity(lines.len());
        let mut skip_next_standalone = false;
        for line in &lines {
            if skip_next_standalone {
                skip_next_standalone = false;
                continue;
            }
            if line.contains("/* move-result */") {
                // Look at the previous line for the invoke expression
                if let Some(prev) = new_lines.last() {
                    let prev_trimmed = prev.trim().trim_end_matches(';');
                    if prev_trimmed.contains('(') && !prev_trimmed.starts_with("//") {
                        let replaced = line.replace("/* move-result */", prev_trimmed);
                        new_lines.pop(); // remove the standalone invoke
                        new_lines.push(replaced);
                        continue;
                    }
                }
            }
            new_lines.push(line.clone());
        }
        out = new_lines.join("\n") + "\n";
    }

    // Remove standalone invoke lines that are followed by MoveResult (their result is now captured)
    // These appear as "    someMethod(args);" lines that are immediately followed by "    Type v = someMethod(args);"
    // After the above replacement, we have duplicate invoke expressions. Remove the standalone one.
    let lines: Vec<&str> = out.lines().collect();
    let mut keep = vec![true; lines.len()];
    for i in 0..lines.len().saturating_sub(1) {
        let cur = lines[i].trim().trim_end_matches(';');
        let next = lines[i + 1].trim();
        // If next line contains " = cur" (the same invoke expression as an assignment RHS)
        if !cur.is_empty() && next.contains(&format!("= {cur};")) {
            keep[i] = false;
        }
    }
    out = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| keep[*i])
        .map(|(_, l)| *l)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    // (Inline expressions are now substituted at AST emit time via emit_use,
    // so the legacy post-emit inline-replacement and def-line removal passes
    // have been deleted. ctx.inlined is still consulted by emit_stmt::Stmt::Expr
    // to skip emission of inlined defs, via the EMIT_INLINED_VARS thread-local.)

    // Build (reg, ver) → type-string map for type-mismatch detection.
    // When two SSA versions of the same register have different Java types (e.g.
    // v0 is first String then int), collapsing both to "v{R}" produces an illegal
    // Java assignment.  We track the "canonical" type for each register (the type
    // of its lowest-versioned VarId, with parameter types taking precedence) and
    // refuse to collapse any VarId whose type differs.
    let var_type_str: BTreeMap<(u16, u32), String> = env
        .types
        .iter()
        .map(|(v, ty)| ((v.reg(), v.ver()), emit_type(ty)))
        .collect();
    // Canonical type per register: lowest-versioned VarId wins, then parameters override.
    let mut reg_canonical_type: BTreeMap<u16, String> = BTreeMap::new();
    for ((reg, _ver), ty_str) in &var_type_str {
        reg_canonical_type.entry(*reg).or_insert_with(|| ty_str.clone());
    }
    // Parameters always own their register's canonical type.
    for (v, ty) in params.iter() {
        reg_canonical_type.insert(v.reg(), emit_type(ty));
    }

    // Build register → canonical name map.
    // Priority: debug info name > var_names entry > "v{reg}" (no version suffix).
    //
    // The `this` alias only applies to the specific parameter VarId,
    // NOT to every SSA version of its register. R8 frequently reuses
    // register 0/1 for other SSA defs within a method (cashapp corpus:
    // `kotlin.jvm.internal.Intrinsics.areEqual(this, v5)` stored back
    // into the `this` register), and renaming those later defs to
    // "this" produces illegal `this = ...` assignments. Skip "this"
    // when building reg_names — the per-VarId pass below still renames
    // the real this_var correctly.
    let mut reg_names: BTreeMap<u16, String> = BTreeMap::new();
    for (var, name) in &ctx.var_names {
        if name == "this" {
            continue;
        }
        reg_names.entry(var.reg()).or_insert_with(|| name.clone());
    }

    // Collect all VarIds that appear in the output
    // For each, if not already named via var_names/inline_exprs, map to register canonical name
    let mut replacements: Vec<(String, String)> = Vec::new();

    // Inline expressions were applied at AST emit time, not here.
    // Explicit var_names (debug info, this) still need post-emit substitution
    // because emit_var renders the bare SSA name for non-inlined vars.
    for (var, name) in &ctx.var_names {
        if !ctx.inline_exprs.contains_key(var) {
            replacements.push((var.to_string(), name.clone()));
        }
    }

    // Third: collapse SSA versions — scan output for v{R}_{V} patterns not yet mapped
    // Use regex-free approach: find all "v{digits}_{digits}" tokens in the output
    let mut i = 0;
    let out_bytes = out.as_bytes();
    while i < out_bytes.len() {
        if out_bytes[i] == b'v' && i + 1 < out_bytes.len() && out_bytes[i + 1].is_ascii_digit() {
            let start = i;
            i += 1;
            // Parse reg digits
            let reg_start = i;
            while i < out_bytes.len() && out_bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i < out_bytes.len() && out_bytes[i] == b'_' {
                let reg_end = i;
                i += 1;
                let ver_start = i;
                while i < out_bytes.len() && out_bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i > ver_start {
                    // Found v{reg}_{ver}
                    let token = std::str::from_utf8(&out_bytes[start..i]).unwrap_or("");
                    let reg_str = std::str::from_utf8(&out_bytes[reg_start..reg_end]).unwrap_or("");
                    let ver_str = std::str::from_utf8(&out_bytes[ver_start..i]).unwrap_or("");
                    if let Ok(reg) = reg_str.parse::<u16>() {
                        if let Ok(ver) = ver_str.parse::<u32>() {
                            // Keep versioned if this VarId's type differs from the
                            // register's canonical type.  This prevents type-unsafe
                            // collapses such as collapsing a PrintStream variable
                            // onto a String[] parameter register.
                            let is_type_mismatch = var_type_str
                                .get(&(reg, ver))
                                .and_then(|token_ty| {
                                    reg_canonical_type
                                        .get(&reg)
                                        .map(|canon_ty| token_ty != canon_ty)
                                })
                                .unwrap_or(false);

                            if !is_type_mismatch {
                                // Skip if already in replacements
                                if !replacements.iter().any(|(from, _)| from == token) {
                                    let canonical = reg_names
                                        .get(&reg)
                                        .cloned()
                                        .unwrap_or_else(|| format!("v{reg}"));
                                    if canonical != token {
                                        replacements.push((token.to_string(), canonical));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            i += 1;
        }
    }

    // Apply all replacements in a single haystack pass. Identifier max-munch
    // inside replace_words makes "longest first" implicit (each position
    // yields exactly one token, looked up whole in the table), so we don't
    // need to sort/dedup. First-insert wins on key collisions to match the
    // prior sort-stable + dedup_by behavior.
    let mut table: HashMap<&str, &str> = HashMap::with_capacity(replacements.len());
    for (from, to) in &replacements {
        table.entry(from.as_str()).or_insert(to.as_str());
    }
    out = replace_words(&out, &table);

    // Post-process: simplify increments in for-loop headers
    // "for (...; ...; int v1 = v1 + 1)" → "for (...; ...; v1++)"
    let lines: Vec<String> = out
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("for (") {
                if let Some(last_semi) = line.rfind(';') {
                    let before = &line[..last_semi + 1];
                    let after = line[last_semi + 1..].trim_end_matches(") {");
                    let simplified = simplify_increment(after.trim());
                    format!("{before} {simplified}) {{")
                } else {
                    line.to_string()
                }
            } else {
                line.to_string()
            }
        })
        .collect();
    out = lines.join("\n") + "\n";

    out = rewrite_compound_assignments(&out);

    out = dedupe_type_declarations(&out);

    // Final cleanup: remove or fix comment artifacts
    // 1. Remove standalone comment statements: "    /* move-result */;"
    // 2. Fix embedded comments: "throw /* move-result */;" → remove the line
    // 3. Fix embedded comments: "return /* move-result */;" → "return;"
    let lines: Vec<String> = out
        .lines()
        .filter_map(|line| {
            let t = line.trim();
            let t_no_semi = t.trim_end_matches(';').trim();
            // Standalone comment statement — strip move-result artifacts etc.,
            // but preserve recogniser-provenance markers emitted by passes
            // whose entire purpose IS the comment: the `R8 class-merge`
            // marker from `hoist_constructor_super`, and the
            // `@droidsaw R8Origin(...)` markers from the R8 inversion
            // pass (`r8_inversion::apply` → `Stmt::OutlinedBlock`
            // emit arm). New recogniser-marker prefixes added to this
            // exception list as they land.
            if t_no_semi.starts_with("/*")
                && t_no_semi.ends_with("*/")
                && !t_no_semi.contains("R8 class-merge")
                && !t_no_semi.contains("@droidsaw")
            {
                return None;
            }
            // "throw /* ... */;" → remove (can't throw a comment)
            if t.starts_with("throw ") && t.contains("/*") {
                return None;
            }
            // "return /* ... */;" → "return;"
            if t.starts_with("return ") && t.contains("/*") && t.contains("*/") {
                let indent_str = &line[..line.len() - t.len()];
                return Some(format!("{indent_str}return;"));
            }
            // "Type v = /* ... */;" → remove (can't assign a comment)
            if t.contains("= /*") && t.contains("*/;") {
                return None;
            }
            Some(line.to_string())
        })
        .collect();
    out = lines.join("\n") + "\n";

    // Final pass: re-run for-loop simplification after all name replacements
    let lines: Vec<String> = out
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("for (") {
                if let Some(last_semi) = line.rfind(';') {
                    let before = &line[..last_semi + 1];
                    let after = line[last_semi + 1..].trim_end_matches(") {");
                    let simplified = simplify_increment(after.trim());
                    format!("{before} {simplified}) {{")
                } else {
                    line.to_string()
                }
            } else {
                line.to_string()
            }
        })
        .collect();
    out = lines.join("\n") + "\n";

    // Kotlin facade post-pass chain (#41b). Order is load-bearing:
    //
    // 1. PR-9c.5 — strip auto-inserted `kotlin.jvm.internal.Intrinsics.*`
    //    runtime guards. These have no Kotlin source analogue and
    //    block kotlinc-recompile on every fixture that takes a
    //    non-null parameter (which is most of them).
    //
    // 2. PR-9c — `<when-with-arm-assigns> + return v` rewrite. Today's
    //    post-pass covers `when_int/*` (3 fixtures) +
    //    `when_int_sparse/*` (1 fixture). Other facade shapes
    //    (string-when ≥5 arms, sealed-class/object, data-class,
    //    single-expression bodies) fall through unchanged — picked
    //    up by future PRs in the multi-PR roadmap. Idempotent on
    //    already-rewritten output, required for the kotlinc
    //    roundtrip-gate.
    //
    // Both passes are byte-equality-safe under the kotlinc
    // recompile-decompile-decompile round-trip.
    if info.is_facade_method {
        out = strip_kotlin_intrinsics(&out);
        out = kotlinify_facade_when_return(&out);
        out = kotlinify_facade_when_inline_return(&out);
    }

    droidsaw_common::diag::stage_dump("emit", &out);
    out
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_id_mangles_java_keywords() {
        // R8 aggressive obfuscation (Binance, iproov SDK) emits class /
        // package / method names like these. Each needs a `$` prefix to
        // become a legal Java identifier.
        assert_eq!(sanitize_id("boolean"), "$boolean");
        assert_eq!(sanitize_id("while"), "$while");
        assert_eq!(sanitize_id("new"), "$new");
        assert_eq!(sanitize_id("int"), "$int");
        assert_eq!(sanitize_id("case"), "$case");
        assert_eq!(sanitize_id("default"), "$default");
        assert_eq!(sanitize_id("do"), "$do");
        assert_eq!(sanitize_id("for"), "$for");
        assert_eq!(sanitize_id("if"), "$if");
        assert_eq!(sanitize_id("null"), "$null");
        assert_eq!(sanitize_id("true"), "$true");
        assert_eq!(sanitize_id("false"), "$false");
        assert_eq!(sanitize_id("_"), "$_");
        // Non-keywords pass through untouched.
        assert_eq!(sanitize_id("foo"), "foo");
        assert_eq!(sanitize_id("boolean_"), "boolean_");
        assert_eq!(sanitize_id("newClass"), "newClass");
        // Existing sanitization still applies.
        assert_eq!(sanitize_id("0foo"), "$0foo");
        assert_eq!(sanitize_id("foo-bar"), "foo_bar");
    }

    #[test]
    fn emit_access_flags_test() {
        assert_eq!(emit_access_flags(0x0001), "public");
        assert_eq!(emit_access_flags(0x0009), "public static");
        assert_eq!(emit_access_flags(0x0002), "private");
        assert_eq!(emit_access_flags(0x0012), "private final");
        assert_eq!(emit_access_flags(0x0401), "public abstract");
    }

    #[test]
    fn emit_literal_int() {
        assert_eq!(emit_literal(42, &DexType::Int), "42");
        assert_eq!(emit_literal(-1, &DexType::Int), "-1");
        assert_eq!(emit_literal(0, &DexType::Int), "0");
    }

    #[test]
    fn emit_literal_long() {
        assert_eq!(emit_literal(42, &DexType::Long), "42L");
        assert_eq!(emit_literal(0, &DexType::Long), "0L");
    }

    #[test]
    fn emit_literal_boolean() {
        assert_eq!(emit_literal(0, &DexType::Boolean), "false");
        assert_eq!(emit_literal(1, &DexType::Boolean), "true");
    }

    #[test]
    fn emit_literal_char() {
        assert_eq!(emit_literal(65, &DexType::Char), "'A'");
    }

    #[test]
    fn pretty_class_name_test() {
        assert_eq!(pretty_class_name("Ljava/lang/String;"), "java.lang.String");
        assert_eq!(pretty_class_name("I"), "int");
        assert_eq!(pretty_class_name("[I"), "int[]");
        assert_eq!(
            pretty_class_name("[Ljava/lang/Object;"),
            "java.lang.Object[]"
        );
    }

    #[test]
    fn emit_type_test() {
        assert_eq!(emit_type(&DexType::Int), "int");
        assert_eq!(
            emit_type(&DexType::Ref(std::sync::Arc::from("Ljava/lang/String;"))),
            "String"
        );
        assert_eq!(
            emit_type(&DexType::ArrayRef(Box::new(DexType::Int))),
            "int[]"
        );
    }

    #[test]
    fn emit_return_void() {
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let s = emit_stmt(&Stmt::Return(None), &env, &dex, 0, &mut ctx);
        assert_eq!(s, "return;\n");
    }

    #[test]
    fn emit_return_var() {
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let v = VarId::new(0, 1);
        let s = emit_stmt(&Stmt::Return(Some(v)), &env, &dex, 0, &mut ctx);
        assert_eq!(s, "return v0_1;\n");
    }

    #[test]
    fn emit_line_comment_gates_off_by_default() {
        // Without ctx.line_debug, emit_stmt must not emit any `// line N`
        // comment. This is the golden-stable path — flipping on the env
        // var flag must stay opt-in.
        use crate::decode::{Instruction, RegList};
        use crate::opcodes::Opcode;
        use crate::ssa::SsaInsn;

        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let insn = SsaInsn {
            insn: Instruction {
                addr: 4,
                op: Opcode::Const,
                size: 3,
                dst: Some(0),
                src: RegList::empty(),
                literal: 42,
                target: None,
                pool_idx: None,
            },
            dst: Some(VarId::new(0, 1)),
            uses: vec![],
        };
        let mut ctx = EmitCtx::new();
        let s = emit_stmt(&Stmt::Expr(insn), &env, &dex, 0, &mut ctx);
        assert!(!s.contains("// line"), "default path must not emit line comment: {s:?}");
    }

    #[test]
    fn emit_line_comment_emits_when_debug_set() {
        // Populate ctx.line_debug with a minimal line_table and confirm
        // emit_stmt prepends `// line N` before the statement body.
        // Dedupe: a second emission at the same line must NOT re-emit.
        use crate::debug::DebugInfo;
        use crate::decode::{Instruction, RegList};
        use crate::opcodes::Opcode;
        use crate::ssa::SsaInsn;

        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let debug = DebugInfo {
            line_start: 10,
            parameter_names: vec![],
            line_table: vec![(0, 10), (4, 11)],
            locals: vec![],
        };
        let insn = |addr: u32, ver: u32| SsaInsn {
            insn: Instruction {
                addr,
                op: Opcode::Const,
                size: 3,
                dst: Some(0),
                src: RegList::empty(),
                literal: 42,
                target: None,
                pool_idx: None,
            },
            dst: Some(VarId::new(0, ver)),
            uses: vec![],
        };

        let mut ctx = EmitCtx::new();
        ctx.line_debug = Some(debug);

        // First emission at pc=4 → line 11.
        let s1 = emit_stmt(&Stmt::Expr(insn(4, 1)), &env, &dex, 0, &mut ctx);
        assert!(s1.contains("// line 11"), "must emit line 11 comment: {s1:?}");
        // Second emission at pc=5 (still on line 11) → no duplicate comment.
        let s2 = emit_stmt(&Stmt::Expr(insn(5, 2)), &env, &dex, 0, &mut ctx);
        assert!(!s2.contains("// line"), "dedupe must suppress same-line repeat: {s2:?}");
    }

    #[test]
    fn emit_string_concat() {
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let stmt = Stmt::StringConcat {
            dst: Some(VarId::new(3, 0)),
            parts: vec![
                ConcatPart::Literal("hello ".to_string()),
                ConcatPart::Var(VarId::new(2, 0)),
            ],
        };
        let s = emit_stmt(&stmt, &env, &dex, 0, &mut ctx);
        assert!(
            s.contains("\"hello \" + v2_0"),
            "should contain concat: {s}"
        );
        assert!(s.contains("v3_0"), "should declare dst var: {s}");
    }

    // ── dedupe_type_declarations ─────────────────────────────────────
    //
    // Regression tests for aput errors observed on a large-app corpus.
    // The pre-discipline pass would split `v2[v4 + 3]` at the space
    // inside the index expression, treating `3]` as a "variable name"
    // and `v2[v4 +` as a "type". On a second matching line, it would
    // strip the "type", producing `3] = v7;`.

    #[test]
    fn dedupe_preserves_repeated_aput_tails() {
        // Two aputs whose LHSs end in the same token after the last space.
        // Must NOT have the "type prefix" stripped.
        let input = "    v1[v4 + 3] = v6;\n    v2[v4 + 3] = v7;\n";
        let out = dedupe_type_declarations(input);
        assert!(
            out.contains("v1[v4 + 3] = v6;"),
            "first aput must survive: {out}"
        );
        assert!(
            out.contains("v2[v4 + 3] = v7;"),
            "second aput must survive intact (not `3] = v7;`): {out}"
        );
        assert!(
            !out.lines().any(|l| l.trim_start().starts_with("3] =")),
            "no line may begin with `3] =` (would mean array base was stripped): {out}"
        );
    }

    #[test]
    fn dedupe_preserves_aput_with_literal_index_tail() {
        let input = "    int[] x = new int[4];\n    x[1] = 1;\n    y[1] = 2;\n";
        let out = dedupe_type_declarations(input);
        assert!(out.contains("x[1] = 1;"), "first survives: {out}");
        assert!(out.contains("y[1] = 2;"), "second survives intact: {out}");
    }

    #[test]
    fn dedupe_still_strips_real_ref_redeclarations() {
        // The legitimate case: `Foo v0 = ...;` followed by `Foo v0 = ...;`
        // should still have the second type stripped.
        let input = "    Foo v0 = bar();\n    Foo v0 = baz();\n";
        let out = dedupe_type_declarations(input);
        assert!(out.contains("Foo v0 = bar();"), "first survives: {out}");
        assert!(
            out.contains("v0 = baz();") && !out.contains("Foo v0 = baz();"),
            "second loses the type prefix: {out}"
        );
    }

    #[test]
    fn dedupe_still_strips_real_primitive_redeclarations() {
        let input = "    int v0 = 1;\n    int v0 = v0 + 2;\n";
        let out = dedupe_type_declarations(input);
        assert!(out.contains("int v0 = 1;"), "first survives: {out}");
        assert!(
            out.contains("v0 = v0 + 2;") && !out.contains("int v0 = v0 + 2;"),
            "second loses the type prefix: {out}"
        );
    }

    // ── replace_words ────────────────────────────────────────────────

    fn single<'a>(needle: &'a str, replacement: &'a str) -> HashMap<&'a str, &'a str> {
        let mut t = HashMap::new();
        t.insert(needle, replacement);
        t
    }

    #[test]
    fn replace_words_basic() {
        assert_eq!(replace_words("v0_1 + v0_1", &single("v0_1", "x")), "x + x");
        assert_eq!(
            replace_words("v0_10", &single("v0_1", "x")),
            "v0_10"
        ); // identifier max-munch: v0_10 != v0_1
        assert_eq!(replace_words("foo", &single("v", "x")), "foo");
    }

    #[test]
    fn replace_words_respects_word_boundaries() {
        assert_eq!(
            replace_words("_v0_1 v0_1 v0_1x", &single("v0_1", "x")),
            "_v0_1 x v0_1x"
        );
    }

    #[test]
    fn replace_words_skips_string_literal() {
        let haystack = "String msg = \"v0_1 is the first register\";\nint x = v0_1 + 1;";
        let out = replace_words(haystack, &single("v0_1", "result.size()"));
        assert!(
            out.contains("\"v0_1 is the first register\""),
            "string literal contents must survive: {out}"
        );
        assert!(
            out.contains("int x = result.size() + 1;"),
            "outside the string, replacement must happen: {out}"
        );
    }

    #[test]
    fn replace_words_skips_char_literal() {
        let haystack = "char c = 'v';\nv = 1;";
        let out = replace_words(haystack, &single("v", "x"));
        assert!(out.contains("'v'"), "char literal must survive: {out}");
        assert!(out.contains("x = 1;"), "outside char, replace: {out}");
    }

    #[test]
    fn replace_words_handles_escaped_quote_in_string() {
        let haystack = "String s = \"foo \\\"v0_1\\\" bar\";\nv0_1.do();";
        let out = replace_words(haystack, &single("v0_1", "this"));
        assert!(
            out.contains("\"foo \\\"v0_1\\\" bar\""),
            "escaped quotes must not exit the string: {out}"
        );
        assert!(out.contains("this.do();"), "outside: {out}");
    }

    #[test]
    fn replace_words_handles_multiple_strings() {
        let haystack = "a = \"v\" + v + \"v\" + v;";
        let out = replace_words(haystack, &single("v", "x"));
        assert_eq!(out, "a = \"v\" + x + \"v\" + x;");
    }

    #[test]
    fn replace_words_replacement_can_contain_quotes_and_parens() {
        let haystack = "String s = \"v0_1\";\nassert(v0_1);";
        let out = replace_words(haystack, &single("v0_1", "foo(\"bar\")"));
        assert!(
            out.contains("\"v0_1\""),
            "original literal must survive: {out}"
        );
        assert!(
            out.contains("assert(foo(\"bar\"));"),
            "outside replacement happens: {out}"
        );
    }

    #[test]
    fn replace_words_multi_key_single_pass() {
        // The whole point of replace_words: many needles, ONE haystack walk.
        // Identifier max-munch makes "longest first" implicit — `v0` and
        // `v0_1` cannot collide at the same position because the lexer
        // consumes the maximal identifier token before lookup.
        let mut table = HashMap::new();
        table.insert("v0_1", "a");
        table.insert("v0_2", "b");
        table.insert("v1_1", "c");
        table.insert("v0", "z");
        let out = replace_words("v0_1 + v0_2 + v1_1 + v0;", &table);
        assert_eq!(out, "a + b + c + z;");
    }

    #[test]
    fn replace_words_empty_table_returns_unchanged() {
        let table: HashMap<&str, &str> = HashMap::new();
        assert_eq!(replace_words("anything goes", &table), "anything goes");
    }

    #[test]
    fn replace_words_overlap_prefix_does_not_match_longer_needle() {
        // Needle "v0_1" must not match a substring of "v0_10".
        let mut table = HashMap::new();
        table.insert("v0_1", "a");
        table.insert("v0_10", "b");
        let out = replace_words("v0_1 v0_10", &table);
        assert_eq!(out, "a b");
    }

    #[test]
    fn replace_words_utf8_safe() {
        // ⊤ U+22A4 is 3 bytes; bare i += 1 would split it and panic on the
        // next slice. Ensure the haystack walker stays on char boundaries.
        let out = replace_words("⊤ + v0_1 + ⊤", &single("v0_1", "x"));
        assert_eq!(out, "⊤ + x + ⊤");
    }

    // ── rewrite_compound_assignments ─────────────────────────────────
    //
    // Regression tests for a SQL StringBuilder rewriting bug. Without
    // the string-literal guard, the pass would find ` = ` inside a
    // string literal, split there, and rewrite the line to a bogus
    // compound assignment.

    #[test]
    fn compound_rewrites_simple_add() {
        let out = rewrite_compound_assignments("    v0 = v0 + 1;\n");
        assert!(out.contains("v0 += 1;"), "should rewrite to +=: {out}");
    }

    #[test]
    fn compound_rewrites_with_type_prefix() {
        let out = rewrite_compound_assignments("    int v0 = v0 * 2;\n");
        assert!(out.contains("v0 *= 2;"), "should rewrite to *=: {out}");
    }

    #[test]
    fn compound_skips_string_literal_with_equals_inside() {
        // The exact pattern from LX/7ie; — ` = ` inside a string literal
        // must not be rewritten.
        let input = "    X.$179.A0k(v1, \"UPDATE log_event_dropped SET events_dropped_count = events_dropped_count + \");\n";
        let out = rewrite_compound_assignments(input);
        assert_eq!(out, input, "line must survive intact: {out}");
        assert!(
            !out.contains("events_dropped_count +="),
            "must not rewrite inside string: {out}"
        );
    }

    #[test]
    fn compound_skips_string_literal_with_multiple_equals() {
        // The LX/7iw; pattern.
        let input = "    X.$179.A0k(v1, \"UPDATE events SET num_attempts = num_attempts + 1 WHERE _id in (\");\n";
        let out = rewrite_compound_assignments(input);
        assert_eq!(out, input);
        assert!(!out.contains("num_attempts +="));
    }

    #[test]
    fn compound_skips_for_loop_header() {
        let input = "    for (int v0 = 0; v0 < 10; v0 = v0 + 1) {\n";
        let out = rewrite_compound_assignments(input);
        assert_eq!(out, input);
    }

    // ── hoist_constructor_super ──────────────────────────────────────
    //
    // Regression tests for duplicate `super();` errors observed on
    // R8-shrunk corpora. R8 emits invoke-direct <init> in both
    // branches of an if/else inside inner class constructors,
    // producing two super() lines in the method body. The single-
    // hoist pass would lift only the first.

    #[test]
    fn hoist_super_drops_duplicate_in_else_branch() {
        let input = "public Foo(int v) {\n    this.$t = v;\n    if (v == 60) {\n        super();\n        this.put(\"a\", v);\n    } else {\n        super();\n        this.put(\"b\", v);\n    }\n";
        let out = hoist_constructor_super(input);
        // First super() is at position 0.
        let body_start = out.find("{\n").unwrap() + 2;
        let first_line = out[body_start..].lines().next().unwrap();
        assert_eq!(first_line.trim(), "super();");
        // Exactly one super() remains in the body.
        let count = out.matches("super();").count();
        assert_eq!(count, 1, "exactly one super() should remain: {out}");
    }

    #[test]
    fn hoist_super_drops_multiple_nested_duplicates() {
        // Pattern from LX/2cH; — nested if/else with super() in every branch.
        let input = "public Foo(int v) {\n    this.$t = v;\n    if (v == 1) {\n        super();\n    } else {\n        if (v == 2) {\n            super();\n        } else {\n            if (v == 3) {\n                super();\n            } else {\n                super();\n            }\n        }\n    }\n";
        let out = hoist_constructor_super(input);
        assert_eq!(
            out.matches("super();").count(),
            1,
            "all duplicate super() calls should be dropped: {out}"
        );
    }

    #[test]
    fn hoist_super_comments_out_different_args() {
        // R8 class-merge pathology: two distinct super() forms in one
        // constructor body. First hoisted; second replaced with a
        // comment so the body is valid Java while the original call
        // text remains visible.
        let input = "public Foo(int v) {\n    this.$t = v;\n    if (v == 1) {\n        super(1);\n    } else {\n        super(2);\n    }\n";
        let out = hoist_constructor_super(input);
        assert!(out.contains("super(1);"), "first super hoisted: {out}");
        assert!(
            out.contains("/* R8 class-merge: originally super(2); */"),
            "different super replaced with comment: {out}"
        );
        assert!(
            !out.contains("\n        super(2);\n"),
            "raw super(2); should be gone: {out}"
        );
    }

    #[test]
    fn hoist_super_comments_multiple_distinct_forms() {
        // LX/2J0; pattern: three distinct super() forms across
        // nested if/else branches.
        let input = "public Foo(int v) {\n    super(100);\n    this.$t = v;\n    if (v == 1) {\n        super();\n        return;\n    } else {\n        super(10, 0.75f, true);\n        return;\n    }\n";
        let out = hoist_constructor_super(input);
        assert!(
            out.contains("super(100);"),
            "hoisted super preserved: {out}"
        );
        assert!(
            out.contains("/* R8 class-merge: originally super(); */"),
            "bare super commented: {out}"
        );
        assert!(
            out.contains("/* R8 class-merge: originally super(10, 0.75f, true); */"),
            "three-arg super commented: {out}"
        );
    }

    #[test]
    fn hoist_super_is_noop_when_already_clean() {
        let input = "public Foo() {\n    super();\n    this.$t = 0;\n}\n";
        let out = hoist_constructor_super(input);
        assert!(out.contains("super();"));
        assert_eq!(out.matches("super();").count(), 1);
    }

    #[test]
    fn hoist_super_handles_this_call() {
        let input = "public Foo(int v) {\n    this.$t = v;\n    if (v == 1) {\n        this(5);\n    } else {\n        this(5);\n    }\n";
        let out = hoist_constructor_super(input);
        assert_eq!(
            out.matches("this(5);").count(),
            1,
            "dedupe this() too: {out}"
        );
        let body_start = out.find("{\n").unwrap() + 2;
        let first_line = out[body_start..].lines().next().unwrap();
        assert_eq!(first_line.trim(), "this(5);");
    }

    // ── is_dereferencing_use / stmt_has_dereferencing_use ────────────
    //
    // Job B — receiver-context guard. A `Const4 0` typed as a reference
    // emits as `null`. If such a const has a single use that is the
    // receiver of an iget/iput/aget/aput/invoke, inlining would produce
    // `null.field = x;`, `null[i]`, `null.method()`, etc. These tests
    // lock in the classification of dereferencing positions.

    fn mk_insn(op: Opcode, uses: Vec<VarId>) -> SsaInsn {
        SsaInsn {
            insn: crate::decode::Instruction {
                addr: 0,
                op,
                size: 1,
                dst: None,
                src: crate::decode::RegList::empty(),
                literal: 0,
                target: None,
                pool_idx: None,
            },
            dst: None,
            uses,
        }
    }

    #[test]
    fn deref_use_iget_receiver() {
        let v0 = VarId::new(0, 1);
        let insn = mk_insn(Opcode::IgetObject, vec![v0.clone()]);
        assert!(is_dereferencing_use(&insn, &v0));
    }

    #[test]
    fn deref_use_iput_receiver_is_second_use() {
        // iput value=v0, receiver=v1 → uses=[v0, v1]
        let v0 = VarId::new(0, 1);
        let v1 = VarId::new(1, 1);
        let insn = mk_insn(Opcode::IputObject, vec![v0.clone(), v1.clone()]);
        assert!(
            !is_dereferencing_use(&insn, &v0),
            "iput value slot is not a dereference"
        );
        assert!(
            is_dereferencing_use(&insn, &v1),
            "iput receiver slot is a dereference"
        );
    }

    #[test]
    fn deref_use_aget_array_base() {
        // aget array=v0, index=v1 → uses=[v0, v1]
        let v0 = VarId::new(0, 1);
        let v1 = VarId::new(1, 1);
        let insn = mk_insn(Opcode::Aget, vec![v0.clone(), v1.clone()]);
        assert!(is_dereferencing_use(&insn, &v0), "aget array base");
        assert!(!is_dereferencing_use(&insn, &v1), "aget index is not");
    }

    #[test]
    fn deref_use_aput_array_base_is_second_use() {
        // aput value=v0, array=v1, index=v2 → uses=[v0, v1, v2]
        let v0 = VarId::new(0, 1);
        let v1 = VarId::new(1, 1);
        let v2 = VarId::new(2, 1);
        let insn = mk_insn(Opcode::Aput, vec![v0.clone(), v1.clone(), v2.clone()]);
        assert!(!is_dereferencing_use(&insn, &v0), "aput value is not");
        assert!(is_dereferencing_use(&insn, &v1), "aput array base");
        assert!(!is_dereferencing_use(&insn, &v2), "aput index is not");
    }

    #[test]
    fn deref_use_invoke_virtual_receiver() {
        let v0 = VarId::new(0, 1);
        let v1 = VarId::new(1, 1);
        let insn = mk_insn(Opcode::InvokeVirtual, vec![v0.clone(), v1.clone()]);
        assert!(is_dereferencing_use(&insn, &v0), "invoke receiver");
        assert!(!is_dereferencing_use(&insn, &v1), "invoke arg is not");
    }

    #[test]
    fn deref_use_invoke_static_has_no_receiver() {
        let v0 = VarId::new(0, 1);
        let insn = mk_insn(Opcode::InvokeStatic, vec![v0.clone()]);
        assert!(
            !is_dereferencing_use(&insn, &v0),
            "invoke-static uses[0] is just an arg, not a receiver"
        );
    }

    #[test]
    fn deref_use_array_length_and_monitors() {
        let v0 = VarId::new(0, 1);
        assert!(is_dereferencing_use(
            &mk_insn(Opcode::ArrayLength, vec![v0.clone()]),
            &v0
        ));
        assert!(is_dereferencing_use(
            &mk_insn(Opcode::MonitorEnter, vec![v0.clone()]),
            &v0
        ));
        assert!(is_dereferencing_use(
            &mk_insn(Opcode::MonitorExit, vec![v0.clone()]),
            &v0
        ));
    }

    #[test]
    fn deref_use_pure_ops_are_not_dereferences() {
        let v0 = VarId::new(0, 1);
        let v1 = VarId::new(1, 1);
        assert!(!is_dereferencing_use(
            &mk_insn(Opcode::AddInt, vec![v0.clone(), v1]),
            &v0
        ));
        assert!(!is_dereferencing_use(
            &mk_insn(Opcode::CheckCast, vec![v0.clone()]),
            &v0
        ));
        assert!(!is_dereferencing_use(
            &mk_insn(Opcode::InstanceOf, vec![v0.clone()]),
            &v0
        ));
    }

    #[test]
    fn stmt_walker_finds_nested_deref_use() {
        let v0 = VarId::new(0, 1);
        let then_body = Stmt::Expr(mk_insn(Opcode::IgetObject, vec![v0.clone()]));
        let stmt = Stmt::If {
            cond: crate::structure::Condition::Var(VarId::new(99, 1)),
            then_body: Box::new(then_body),
            else_body: None,
        };
        assert!(stmt_has_dereferencing_use(&stmt, &v0));
    }

    #[test]
    fn stmt_walker_returns_false_when_only_safe_uses() {
        let v0 = VarId::new(0, 1);
        let v1 = VarId::new(1, 1);
        // `v2 = v0 + v1;` — not a dereference of v0.
        let body = Stmt::Expr(mk_insn(Opcode::AddInt, vec![v0.clone(), v1]));
        let stmt = Stmt::Seq(vec![body]);
        assert!(!stmt_has_dereferencing_use(&stmt, &v0));
    }

    #[test]
    fn is_java_identifier_basics() {
        assert!(is_java_identifier("v0"));
        assert!(is_java_identifier("v0_3"));
        assert!(is_java_identifier("_foo"));
        assert!(is_java_identifier("$bar"));
        assert!(is_java_identifier("classify"));
        assert!(!is_java_identifier(""));
        assert!(!is_java_identifier("3]"));
        assert!(!is_java_identifier("1]"));
        assert!(!is_java_identifier("0x20"));
        assert!(!is_java_identifier("v0 + 1"));
    }

    // ── MultiArm + Unrecognized emit tests (#38 dex-ir-multiarm) ─────

    #[test]
    fn emit_multiarm_string_produces_java_switch() {
        // Construct a MultiArm: switch (s) over 3 String literals + default,
        // assert emit produces a Java `switch (s) { case "lit": ...; ... }`
        // statement. The recognizer (#39) and structurer (#40) wiring is
        // not exercised here — this test covers only the
        // emit-side discipline: iterative walk over arms, switch-syntax
        // rendering for switch-compatible shapes (consolidation step
        // upgrade).
        use crate::structure::{
            ArmPattern, Discriminant, JavaVersion, MultiArm as MultiArmCase, SignatureProvenance,
            SignatureId, SourceDialect,
        };
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let v_s = VarId::new(0, 1);
        let stmt = Stmt::MultiArm {
            discriminant: Discriminant::String(v_s),
            arms: vec![
                MultiArmCase {
                    pattern: ArmPattern::StringLiterals(vec!["a".to_string()]),
                    body: Stmt::Return(None),
                },
                MultiArmCase {
                    pattern: ArmPattern::StringLiterals(vec!["b".to_string()]),
                    body: Stmt::Return(None),
                },
                MultiArmCase {
                    pattern: ArmPattern::StringLiterals(vec!["c".to_string()]),
                    body: Stmt::Return(None),
                },
            ],
            default: Some(Box::new(Stmt::Return(None))),
            provenance: SignatureProvenance {
                recognized_as: SignatureId(0),
                source_dialect: SourceDialect::Java(JavaVersion::V21),
            },
        };
        let out = emit_stmt(&stmt, &env, &dex, 0, &mut ctx);
        // Three arms + default → switch header + 3 case + default labels.
        assert!(out.contains("switch (v0_1)"), "switch header: {out}");
        assert!(out.contains("case \"a\":"), "first arm: {out}");
        assert!(out.contains("case \"b\":"), "second: {out}");
        assert!(out.contains("case \"c\":"), "third: {out}");
        assert!(out.contains("default:"), "default: {out}");
        // Discipline check: no nested-If shape leaks. The emit must not
        // contain a sequence like `} else {\n    if (` because that's
        // what the recursive emit would produce.
        let normalized: String = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            !normalized.contains("} else { if ("),
            "MultiArm emit must not collapse to nested-If shape; got: {normalized}",
        );
    }

    #[test]
    fn emit_multiarm_int_produces_switch_with_fall_through() {
        // Discriminant::Int with one arm carrying multiple literals. Renders
        // as Java `switch (x) { case 1: case 2: case 3: return; }` — each
        // literal becomes a `case` label sharing the body (Java fall-through
        // semantics).
        use crate::structure::{
            ArmPattern, Discriminant, JavaVersion, MultiArm as MultiArmCase, SignatureProvenance,
            SignatureId, SourceDialect,
        };
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let v_x = VarId::new(0, 1);
        let stmt = Stmt::MultiArm {
            discriminant: Discriminant::Int(v_x),
            arms: vec![MultiArmCase {
                pattern: ArmPattern::IntLiterals(vec![1, 2, 3]),
                body: Stmt::Return(None),
            }],
            default: None,
            provenance: SignatureProvenance {
                recognized_as: SignatureId(0),
                source_dialect: SourceDialect::Java(JavaVersion::V21),
            },
        };
        let out = emit_stmt(&stmt, &env, &dex, 0, &mut ctx);
        assert!(out.contains("switch (v0_1)"), "switch header: {out}");
        assert!(out.contains("case 1:"), "case 1: {out}");
        assert!(out.contains("case 2:"), "case 2: {out}");
        assert!(out.contains("case 3:"), "case 3: {out}");
    }

    #[test]
    fn emit_multiarm_kotlin_renders_when_block() {
        // PR-8: `SourceDialect::Kotlin` renders a real `when (var) { ... }`
        // block. String discriminant + StringLiterals arm renders as
        // `"literal" -> { body }`. With `default: None`, the
        // non-exhaustive banner precedes the `when`.
        use crate::structure::{
            ArmPattern, Discriminant, KotlinVersion, MultiArm as MultiArmCase, SignatureProvenance,
            SignatureId, SourceDialect,
        };
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let v_s = VarId::new(0, 1);
        let stmt = Stmt::MultiArm {
            discriminant: Discriminant::String(v_s),
            arms: vec![MultiArmCase {
                pattern: ArmPattern::StringLiterals(vec!["a".to_string()]),
                body: Stmt::Return(None),
            }],
            default: None,
            provenance: SignatureProvenance {
                recognized_as: SignatureId(0),
                source_dialect: SourceDialect::Kotlin(KotlinVersion::V19),
            },
        };
        let out = emit_stmt(&stmt, &env, &dex, 0, &mut ctx);
        assert!(
            out.contains("// when not exhaustive — kotlinc would warn"),
            "non-exhaustive banner: {out}"
        );
        assert!(out.contains("when (v0_1) {"), "when header: {out}");
        assert!(out.contains("\"a\" -> {"), "string-literal arm: {out}");
        assert!(!out.contains("switch ("), "must not emit Java switch: {out}");
        assert!(!out.contains("case \"a\":"), "must not emit Java case: {out}");
    }

    #[test]
    fn emit_multiarm_sealed_object_renders_distinct_placeholder() {
        // PR-2a: `ArmPattern::SealedObjectIs(_)` is the Kotlin sealed-OBJECT
        // arm form (lowering primitive: `Intrinsics.areEqual(<v>, <Sub>.INSTANCE)`).
        // Until #41's render_arm_predicate_kotlin lands the real `Foo.Bar ->`
        // bare-singleton form, Java emit collapses both `SealedTypeIs` and
        // `SealedObjectIs` to placeholder `instanceof Object` predicates,
        // distinguished by the trailing TODO comment. This test pins the
        // placeholder distinction so a future regression that drops the
        // `sealed-object name` comment surfaces immediately.
        use crate::ids::TypeIdx;
        use crate::structure::{
            ArmPattern, Discriminant, JavaVersion, MultiArm as MultiArmCase, SignatureProvenance,
            SignatureId, SourceDialect,
        };
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let v_s = VarId::new(0, 1);
        let stmt = Stmt::MultiArm {
            discriminant: Discriminant::SealedSubtype {
                var: v_s,
                sealed_root: TypeIdx(0),
            },
            arms: vec![
                MultiArmCase {
                    pattern: ArmPattern::SealedTypeIs(TypeIdx(1)),
                    body: Stmt::Return(None),
                },
                MultiArmCase {
                    pattern: ArmPattern::SealedObjectIs(TypeIdx(2)),
                    body: Stmt::Return(None),
                },
            ],
            default: None,
            provenance: SignatureProvenance {
                recognized_as: SignatureId(0),
                source_dialect: SourceDialect::Java(JavaVersion::V21),
            },
        };
        let out = emit_stmt(&stmt, &env, &dex, 0, &mut ctx);
        assert!(
            out.contains("sealed-subtype name"),
            "SealedTypeIs placeholder: {out}",
        );
        assert!(
            out.contains("sealed-object name"),
            "SealedObjectIs placeholder: {out}",
        );
    }

    #[test]
    fn emit_unrecognized_banner_includes_closest_signature_hint() {
        // The closest-signature hint is on by default. Verify
        // the banner shape.
        use crate::structure::{SignatureId, UnrecognizedReason};
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let stmt = Stmt::Unrecognized {
            cfg_region: crate::cfg::BlockIdx(7),
            reason: UnrecognizedReason::NoSignatureMatch {
                closest: Some(SignatureId(42)),
                distance: 5,
            },
            raw: vec![mk_insn(Opcode::AddInt, vec![])],
        };
        let out = emit_stmt(&stmt, &env, &dex, 0, &mut ctx);
        assert!(
            out.contains("// region #7: bytecode signature unrecognized"),
            "banner header: {out}",
        );
        assert!(
            out.contains("// region #7: bytecode signature unrecognized")
                && out.contains("//   closest match: signature #42 (distance 5)"),
            "closest-signature hint included: {out}",
        );
        assert!(
            out.contains("//   raw smali follows:"),
            "raw-smali marker: {out}",
        );
        assert!(out.contains("AddInt"), "raw insn rendered: {out}");
    }

    #[test]
    fn emit_unrecognized_no_near_miss() {
        // When no recognizer came close, the banner says "no near-miss"
        // rather than fabricating a hint.
        use crate::structure::UnrecognizedReason;
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let stmt = Stmt::Unrecognized {
            cfg_region: crate::cfg::BlockIdx(0),
            reason: UnrecognizedReason::NoSignatureMatch {
                closest: None,
                distance: 0,
            },
            raw: vec![],
        };
        let out = emit_stmt(&stmt, &env, &dex, 0, &mut ctx);
        assert!(out.contains("//   no near-miss"), "no-near-miss form: {out}");
    }

    // ── PR-8 (#41b emit) tests ──────────────────────────────────────────

    #[test]
    fn emit_unrecognized_coroutine_suspend_renders_banner() {
        // PR-8: SignatureId(105) at distance=0 is the
        // `RecognizedDexShape::TaggedRegion` sentinel (PR-7 of #41b) for
        // kotlinc-1.9 suspend-fun state machines. emit_unrecognized
        // renders a coroutine-specific banner instead of the generic
        // "bytecode signature unrecognized" one.
        use crate::signatures::kotlinc19::coroutine_suspend::COROUTINE_SUSPEND_SIGNATURE_ID;
        use crate::structure::UnrecognizedReason;
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let stmt = Stmt::Unrecognized {
            cfg_region: crate::cfg::BlockIdx(3),
            reason: UnrecognizedReason::NoSignatureMatch {
                closest: Some(COROUTINE_SUSPEND_SIGNATURE_ID),
                distance: 0,
            },
            raw: vec![mk_insn(Opcode::AddInt, vec![])],
        };
        let out = emit_stmt(&stmt, &env, &dex, 0, &mut ctx);
        assert!(
            out.contains("// region #3: recognized as kotlinc-1.9 suspend-fun state machine"),
            "coroutine banner: {out}",
        );
        // Generic "bytecode signature unrecognized" banner must NOT
        // appear when the tagged-region sentinel fires.
        assert!(
            !out.contains("bytecode signature unrecognized"),
            "must not emit generic banner: {out}",
        );
        // Raw bytecode list still present.
        assert!(out.contains("AddInt"), "raw insn rendered: {out}");
    }

    #[test]
    fn emit_unrecognized_distance_nonzero_keeps_generic_banner() {
        // PR-8: distance > 0 with SignatureId(105) is a TRUE near-miss,
        // not a tagged-region sentinel. Keep the generic "bytecode
        // signature unrecognized" banner — only distance=0 triggers
        // the coroutine-specific path.
        use crate::signatures::kotlinc19::coroutine_suspend::COROUTINE_SUSPEND_SIGNATURE_ID;
        use crate::structure::UnrecognizedReason;
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let stmt = Stmt::Unrecognized {
            cfg_region: crate::cfg::BlockIdx(0),
            reason: UnrecognizedReason::NoSignatureMatch {
                closest: Some(COROUTINE_SUSPEND_SIGNATURE_ID),
                distance: 7,
            },
            raw: vec![],
        };
        let out = emit_stmt(&stmt, &env, &dex, 0, &mut ctx);
        assert!(
            out.contains("bytecode signature unrecognized"),
            "generic banner: {out}",
        );
        assert!(
            out.contains("//   closest match: signature #105 (distance 7)"),
            "closest hint: {out}",
        );
    }

    #[test]
    fn emit_multiarm_kotlin_int_literals_use_comma_form() {
        // PR-8: Kotlin `when (var) { 1, 2 -> { body } }`. Distinct from
        // the Java if-else-chain form which emits `var == 1 || var == 2`.
        use crate::structure::{
            ArmPattern, Discriminant, KotlinVersion, MultiArm as MultiArmCase, SignatureProvenance,
            SignatureId, SourceDialect,
        };
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let v = VarId::new(0, 1);
        let stmt = Stmt::MultiArm {
            discriminant: Discriminant::Int(v),
            arms: vec![
                MultiArmCase {
                    pattern: ArmPattern::IntLiterals(vec![1, 2]),
                    body: Stmt::Return(None),
                },
                MultiArmCase {
                    pattern: ArmPattern::IntLiterals(vec![3]),
                    body: Stmt::Return(None),
                },
            ],
            default: Some(Box::new(Stmt::Return(None))),
            provenance: SignatureProvenance {
                recognized_as: SignatureId(103),
                source_dialect: SourceDialect::Kotlin(KotlinVersion::V19),
            },
        };
        let out = emit_stmt(&stmt, &env, &dex, 0, &mut ctx);
        assert!(out.contains("when (v0_1) {"), "when header: {out}");
        assert!(out.contains("1, 2 -> {"), "comma form for arm 1: {out}");
        assert!(out.contains("3 -> {"), "single-literal arm: {out}");
        assert!(out.contains("else -> {"), "else branch from default: {out}");
        // Java if-else-chain form must not appear.
        assert!(!out.contains("v0_1 == 1"), "must not emit Java equality: {out}");
    }

    #[test]
    fn emit_multiarm_kotlin_boolean_chain_is_subject_less() {
        // PR-8: `Discriminant::BooleanChain` lowers to subject-less
        // `when { cond -> { body } }` form. No subject after `when`.
        use crate::structure::{
            ArmPattern, Condition, Discriminant, KotlinVersion, MultiArm as MultiArmCase,
            SignatureProvenance, SignatureId, SourceDialect,
        };
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let v = VarId::new(0, 1);
        let cond = Condition::Var(v);
        let stmt = Stmt::MultiArm {
            discriminant: Discriminant::BooleanChain(vec![cond.clone()]),
            arms: vec![MultiArmCase {
                pattern: ArmPattern::Cond(cond),
                body: Stmt::Return(None),
            }],
            default: None,
            provenance: SignatureProvenance {
                recognized_as: SignatureId(0),
                source_dialect: SourceDialect::Kotlin(KotlinVersion::V19),
            },
        };
        let out = emit_stmt(&stmt, &env, &dex, 0, &mut ctx);
        assert!(out.contains("when {"), "subject-less when: {out}");
        // Subject form must NOT appear.
        assert!(
            !out.contains("when ("),
            "must not emit subject form for BooleanChain: {out}",
        );
    }

    #[test]
    fn emit_let_kotlin_renders_destructure_form() {
        // PR-8: `Stmt::Let` with Kotlin dialect renders
        // `val (a, b, ...) = source`. Java dialect keeps the
        // `componentN()` expansion.
        use crate::structure::{KotlinVersion, SignatureProvenance, SignatureId, SourceDialect};
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let a = VarId::new(0, 1);
        let b = VarId::new(0, 2);
        let src = VarId::new(0, 3);
        let stmt = Stmt::Let {
            bindings: vec![a, b],
            source: src,
            provenance: SignatureProvenance {
                recognized_as: SignatureId(104),
                source_dialect: SourceDialect::Kotlin(KotlinVersion::V19),
            },
        };
        let out = emit_stmt(&stmt, &env, &dex, 0, &mut ctx);
        assert!(
            out.contains("val (v0_1, v0_2) = v0_3"),
            "destructure form: {out}",
        );
        // Java's componentN() expansion must not appear on Kotlin dialect.
        assert!(
            !out.contains(".component1()"),
            "must not emit componentN for Kotlin: {out}",
        );
    }

    #[test]
    fn emit_let_java_keeps_component_expansion() {
        // PR-8: Java dialect of `Stmt::Let` keeps the original
        // `componentN()` expansion (Java has no destructure syntax).
        use crate::structure::{JavaVersion, SignatureProvenance, SignatureId, SourceDialect};
        let env = TypeEnv {
            types: rustc_hash::FxHashMap::default(),
            casts: vec![],
        };
        let fixture = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(fixture, None).unwrap();
        let mut ctx = EmitCtx::new();
        let a = VarId::new(0, 1);
        let src = VarId::new(0, 2);
        let stmt = Stmt::Let {
            bindings: vec![a],
            source: src,
            provenance: SignatureProvenance {
                recognized_as: SignatureId(104),
                source_dialect: SourceDialect::Java(JavaVersion::V21),
            },
        };
        let out = emit_stmt(&stmt, &env, &dex, 0, &mut ctx);
        assert!(
            out.contains("Object v0_1 = v0_2.component1();"),
            "componentN expansion preserved on Java: {out}",
        );
        // Kotlin destructure form must not leak into Java.
        assert!(!out.contains("val ("), "must not emit val (..) on Java: {out}");
    }

    #[test]
    fn pretty_class_name_kotlin_rewrites_dollar_to_dot() {
        // PR-8: Kotlin source uses `Outer.Inner` (dot-form), JVM-internal
        // is `LOuter$Inner;`. Inverse-mangling unconditionally rewrites
        // `$` → `.`, unlike the Java helper which preserves `$` for
        // non-stdlib types per the nested-class emit contract.
        assert_eq!(pretty_class_name_kotlin("LColor$Red;"), "Color.Red");
        assert_eq!(
            pretty_class_name_kotlin("Lkotlin/Pair$Entry;"),
            "kotlin.Pair.Entry",
        );
        // No `$` → identity-ish (still `/` → `.`).
        assert_eq!(pretty_class_name_kotlin("Ljava/lang/String;"), "java.lang.String");
        // Primitives → Kotlin source-form.
        assert_eq!(pretty_class_name_kotlin("I"), "Int");
        assert_eq!(pretty_class_name_kotlin("Z"), "Boolean");
        assert_eq!(pretty_class_name_kotlin("V"), "Unit");
    }

    #[test]
    fn simple_type_kotlin_renders_primitives_kotlin_form() {
        // PR-9b: parameter / return type rendering for the Kotlin
        // top-level-fn facade. Primitives map to Kotlin source names;
        // the Java helper would emit `int` / `void` / `boolean`.
        let mut ctx = EmitCtx::new();
        assert_eq!(ctx.simple_type_kotlin(&DexType::Int), "Int");
        assert_eq!(ctx.simple_type_kotlin(&DexType::Long), "Long");
        assert_eq!(ctx.simple_type_kotlin(&DexType::Float), "Float");
        assert_eq!(ctx.simple_type_kotlin(&DexType::Double), "Double");
        assert_eq!(ctx.simple_type_kotlin(&DexType::Boolean), "Boolean");
        assert_eq!(ctx.simple_type_kotlin(&DexType::Byte), "Byte");
        assert_eq!(ctx.simple_type_kotlin(&DexType::Char), "Char");
        assert_eq!(ctx.simple_type_kotlin(&DexType::Short), "Short");
        // Void → Unit (Kotlin's bottom-of-Any side; rendered in fun
        // signatures as `: Unit` or elided per kotlinc style).
        assert_eq!(ctx.simple_type_kotlin(&DexType::Void), "Unit");
        // No imports recorded for primitives.
        assert!(ctx.imports.is_empty(), "primitives: no imports");
    }

    #[test]
    fn simple_type_kotlin_renders_refs_with_simple_name_and_import() {
        // Reference types render as the simple name + record FQN for
        // the import block. `note_import` filters `java.lang.*` (and
        // would-be-implicit `kotlin.*` if it ever surfaced — kotlinc
        // maps `kotlin.String` → `java.lang.String` at JVM level).
        let mut ctx = EmitCtx::new();
        assert_eq!(
            ctx.simple_type_kotlin(&DexType::Ref(std::sync::Arc::from("Ljava/util/List;"))),
            "List",
        );
        assert!(
            ctx.imports.contains("java.util.List"),
            "expected java.util.List import: {:?}",
            ctx.imports
        );
        // `java.lang.String` import is filtered by `note_import` —
        // the simple name `String` still emits.
        let mut ctx2 = EmitCtx::new();
        assert_eq!(
            ctx2.simple_type_kotlin(&DexType::Ref(std::sync::Arc::from("Ljava/lang/String;"))),
            "String",
        );
        assert!(
            !ctx2.imports.contains("java.lang.String"),
            "java.lang.String should be filtered: {:?}",
            ctx2.imports
        );
    }

    #[test]
    fn simple_type_kotlin_renders_nested_class_with_dot_form() {
        // Mirrors `pretty_class_name_kotlin`: JVM `Outer$Inner` →
        // Kotlin source `Outer.Inner`. Java's helper preserves `$`.
        let mut ctx = EmitCtx::new();
        assert_eq!(
            ctx.simple_type_kotlin(&DexType::Ref(std::sync::Arc::from("LColor$Red;"))),
            "Red",
        );
        // Import records the dot-form FQN so a downstream import
        // block can render `import Color.Red` (single-component
        // names get filtered by `note_import` via the `!fqcn.contains('.')`
        // guard — but `Color.Red` contains a dot, so it's kept).
        assert!(
            ctx.imports.contains("Color.Red"),
            "expected Color.Red import: {:?}",
            ctx.imports
        );
    }

    #[test]
    fn note_import_sanitizes_r8_renamed_segments_with_leading_digit() {
        // R8/Proguard rename pass emits class identifiers like `LX/552;`
        // — valid DEX descriptors, invalid Java identifiers (leading
        // digit). Without per-segment sanitize on the import path, the
        // FQCN `X.552` lands in the import block verbatim as `import
        // X.552;` and javac rejects with `'.' expected`. The fix applies
        // sanitize_id per dot-segment in note_import.
        let mut ctx = EmitCtx::new();
        ctx.simple_type(&DexType::Ref(std::sync::Arc::from("LX/552;")));
        assert!(
            ctx.imports.contains("X.$552"),
            "expected leading-digit segment to be `$`-prefixed; got: {:?}",
            ctx.imports
        );
    }

    #[test]
    fn note_import_sanitizes_multi_invalid_r8_segments() {
        // Both segments leading-digit. Both must be `$`-prefixed.
        let mut ctx = EmitCtx::new();
        ctx.simple_type(&DexType::Ref(std::sync::Arc::from("L34Q/3Bj;")));
        assert!(
            ctx.imports.contains("$34Q.$3Bj"),
            "expected both segments `$`-prefixed; got: {:?}",
            ctx.imports
        );
    }

    #[test]
    fn note_import_leaves_well_formed_fqcn_unchanged() {
        // sanitize_id is idempotent + no-op on valid identifier
        // segments. A standard java.* FQCN must round-trip without
        // mutation through the per-segment sanitize pipeline.
        let mut ctx = EmitCtx::new();
        ctx.simple_type(&DexType::Ref(std::sync::Arc::from("Lokhttp3/Request;")));
        assert!(
            ctx.imports.contains("okhttp3.Request"),
            "expected verbatim FQCN preserved; got: {:?}",
            ctx.imports
        );
    }

    #[test]
    fn note_import_dollar_prefixes_java_keyword_segment() {
        // A package or class segment named after a Java reserved word
        // (e.g. `if`, `class`, `return`) must be `$`-prefixed per
        // sanitize_id's existing is_java_keyword arm. Unlikely from
        // javac/d8 output but possible from hand-crafted DEX or
        // aggressive obfuscators.
        let mut ctx = EmitCtx::new();
        ctx.simple_type(&DexType::Ref(std::sync::Arc::from("Lcom/if/Foo;")));
        assert!(
            ctx.imports.contains("com.$if.Foo"),
            "expected `if` keyword segment to be `$`-prefixed; got: {:?}",
            ctx.imports
        );
    }

    #[test]
    fn note_import_idempotent_on_already_sanitized_input() {
        // Property test: passing an already-sanitized fqcn through
        // note_import is a no-op. This proves the sanitize step is
        // composable — re-running it can never break a valid identifier.
        let mut ctx = EmitCtx::new();
        ctx.note_import("com.$552.Foo");
        ctx.note_import("com.$552.Foo");
        assert_eq!(ctx.imports.len(), 1);
        assert!(ctx.imports.contains("com.$552.Foo"));
    }

    #[test]
    fn strip_kotlin_intrinsics_removes_check_not_null_parameter() {
        // PR-9c.5: kotlinc-1.9 auto-inserts
        // `Intrinsics.checkNotNullParameter` for every non-null
        // reference parameter. Our facade post-pass strips them.
        let body = "fun foo(s: String): Int {\n\
                    \x20   kotlin.jvm.internal.Intrinsics.checkNotNullParameter(s, \"s\");\n\
                    \x20   return s.length\n\
                    }\n";
        let out = strip_kotlin_intrinsics(body);
        let expected = "fun foo(s: String): Int {\n\
                        \x20   return s.length\n\
                        }\n";
        assert_eq!(out, expected, "got:\n{out}");
    }

    #[test]
    fn strip_kotlin_intrinsics_removes_all_three_kinds() {
        // checkNotNullParameter + checkNotNullExpressionValue +
        // checkNotNull all match the same prefix-based gate.
        let body = "fun foo() {\n\
                    \x20   kotlin.jvm.internal.Intrinsics.checkNotNullParameter(p, \"p\");\n\
                    \x20   kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(x, \"foo()\");\n\
                    \x20   kotlin.jvm.internal.Intrinsics.checkNotNull(y);\n\
                    \x20   return\n\
                    }\n";
        let out = strip_kotlin_intrinsics(body);
        // All three intrinsics lines stripped; only the body
        // statement and braces remain.
        assert!(!out.contains("Intrinsics"), "intrinsics not stripped:\n{out}");
        assert!(out.contains("return"), "non-intrinsics body lost:\n{out}");
    }

    #[test]
    fn strip_kotlin_intrinsics_preserves_other_intrinsics_calls() {
        // `Intrinsics.areEqual(...)` is a legitimate Kotlin runtime
        // call that survives in the source-level form. Don't strip
        // it.
        let body = "fun foo(a: String, b: String): Boolean {\n\
                    \x20   boolean r = kotlin.jvm.internal.Intrinsics.areEqual(a, b);\n\
                    \x20   return r\n\
                    }\n";
        assert_eq!(strip_kotlin_intrinsics(body), body);
    }

    #[test]
    fn strip_kotlin_intrinsics_preserves_lines_without_trailing_semi() {
        // Defensive: only strip lines that look like
        // statement-terminated calls (`...);`). A multi-line
        // call expression that happens to start with the prefix
        // shouldn't be partially stripped (would corrupt output).
        let body = "fun foo() {\n\
                    \x20   kotlin.jvm.internal.Intrinsics.checkNotNullParameter(\n\
                    \x20       s, \"s\")\n\
                    }\n";
        // The first line doesn't end with `);` so it's preserved.
        assert_eq!(strip_kotlin_intrinsics(body), body);
    }

    #[test]
    fn strip_kotlin_intrinsics_idempotent() {
        // After one pass, no intrinsics lines remain, so a second
        // pass is a no-op. Required for the round-trip gate.
        let body = "fun foo(s: String): Int {\n\
                    \x20   kotlin.jvm.internal.Intrinsics.checkNotNullParameter(s, \"s\");\n\
                    \x20   return s.length\n\
                    }\n";
        let once = strip_kotlin_intrinsics(body);
        let twice = strip_kotlin_intrinsics(&once);
        assert_eq!(once, twice, "non-idempotent");
    }

    #[test]
    fn strip_trailing_void_return_common_path_strips_indented_line() {
        // Common shape after `emit_stmt`: indented `return;` followed
        // by a trailing newline. Whole line (indent + statement +
        // newline) is removed.
        let mut out = String::from("void foo() {\n    int x = 1;\n    return;\n");
        strip_trailing_void_return(&mut out);
        assert_eq!(out, "void foo() {\n    int x = 1;\n");
    }

    #[test]
    fn strip_trailing_void_return_bare_return_no_newline_does_not_panic() {
        // Regression: prior shape OOB'd `replace_range` when `out`
        // ended exactly with `return;` (no trailing newline) — the
        // upper bound `return_pos + "return;\n".len()` exceeded
        // `out.len()` by one. The clamp keeps the strip in-bounds.
        let mut out = String::from("return;");
        strip_trailing_void_return(&mut out);
        assert_eq!(out, "");
    }

    #[test]
    fn strip_trailing_void_return_no_trailing_newline_after_return() {
        // Realistic regression shape: body contains other statements,
        // then bare `return;` at the tail with no trailing newline.
        // Clamp lets the strip remove `    return;` without OOB.
        let mut out = String::from("void foo() {\n    int x = 1;\n    return;");
        strip_trailing_void_return(&mut out);
        assert_eq!(out, "void foo() {\n    int x = 1;\n");
    }

    #[test]
    fn strip_trailing_void_return_trailing_whitespace_only() {
        // `trim_end` strips trailing whitespace before the
        // `ends_with` check, so `return;` preceded by indent +
        // followed by whitespace-only tail still triggers the strip.
        let mut out = String::from("void foo() {\n    return;\n   ");
        strip_trailing_void_return(&mut out);
        assert_eq!(out, "void foo() {\n   ");
    }

    #[test]
    fn strip_trailing_void_return_no_return_is_noop() {
        // Body that doesn't end with `return;` (after trim) is
        // unchanged.
        let mut out = String::from("int foo() {\n    return 1;\n");
        strip_trailing_void_return(&mut out);
        assert_eq!(out, "int foo() {\n    return 1;\n");
    }

    #[test]
    fn strip_trailing_void_return_idempotent() {
        // After one pass, the trailing `return;` is gone, so a second
        // pass is a no-op. (Body still ends in whitespace, but no
        // `return;` substring at the tail.)
        let mut out = String::from("void foo() {\n    return;\n");
        strip_trailing_void_return(&mut out);
        let after_once = out.clone();
        strip_trailing_void_return(&mut out);
        assert_eq!(out, after_once, "non-idempotent");
    }

    #[test]
    fn kotlinify_facade_when_return_rewrites_simple_pattern() {
        // PR-9c happy path: a `when` block with single-assign arms +
        // trailing `return v;` rewrites to `return when (...) { ... }`
        // with arm RHS expressions in the same source order.
        let body = "fun describe(i: Int): String {\n\
                    \x20   when (i) {\n\
                    \x20       2 -> {\n\
                    \x20           String v0 = \"v2\";\n\
                    \x20       }\n\
                    \x20       1 -> {\n\
                    \x20           v0 = \"v1\";\n\
                    \x20       }\n\
                    \x20       else -> {\n\
                    \x20           v0 = \"other\";\n\
                    \x20       }\n\
                    \x20   }\n\
                    \x20   return v0;\n\
                    }\n";
        let out = kotlinify_facade_when_return(body);
        let expected = "fun describe(i: Int): String {\n\
                        \x20   return when (i) {\n\
                        \x20       2 -> \"v2\"\n\
                        \x20       1 -> \"v1\"\n\
                        \x20       else -> \"other\"\n\
                        \x20   }\n\
                        }\n";
        assert_eq!(out, expected, "got:\n{out}");
    }

    #[test]
    fn kotlinify_facade_when_return_idempotent_on_rewritten_form() {
        // After the rewrite, no `when ... } return v;` shape remains
        // — the post-pass is a no-op on its own output. Required for
        // the kotlinc roundtrip-gate `D1 == D2` byte-equality.
        let already = "fun foo(i: Int): String {\n\
                       \x20   return when (i) {\n\
                       \x20       1 -> \"a\"\n\
                       \x20       else -> \"b\"\n\
                       \x20   }\n\
                       }\n";
        assert_eq!(kotlinify_facade_when_return(already), already);
    }

    #[test]
    fn kotlinify_facade_when_return_falls_through_on_multistmt_arms() {
        // when_string/05arms shape: arms have multiple statements
        // (the hashCode-bucket dispatch chain inside each arm). The
        // pattern doesn't match so the body is returned unchanged —
        // a future PR handles this shape.
        let body = "fun classify(s: String): Int {\n\
                    \x20   when (v0_2) {\n\
                    \x20       3370 -> {\n\
                    \x20           String v0 = \"k5\";\n\
                    \x20           s.equals(v0);\n\
                    \x20       }\n\
                    \x20   }\n\
                    \x20   return v0;\n\
                    }\n";
        // Arm body has two stmts, not one assignment — no rewrite.
        assert_eq!(kotlinify_facade_when_return(body), body);
    }

    #[test]
    fn kotlinify_facade_when_return_falls_through_without_when() {
        // No `when` block at all — pattern fails on the first leg.
        let body = "fun foo(): Int {\n\
                    \x20   return 42;\n\
                    }\n";
        assert_eq!(kotlinify_facade_when_return(body), body);
    }

    #[test]
    fn kotlinify_facade_when_return_falls_through_on_var_mismatch() {
        // Arms assign to DIFFERENT vars — the rewrite would silently
        // collapse to one var; instead we fall through and let the
        // recompile-gate flag the issue.
        let body = "fun foo(i: Int): String {\n\
                    \x20   when (i) {\n\
                    \x20       1 -> {\n\
                    \x20           String v0 = \"a\";\n\
                    \x20       }\n\
                    \x20       else -> {\n\
                    \x20           v9 = \"b\";\n\
                    \x20       }\n\
                    \x20   }\n\
                    \x20   return v0;\n\
                    }\n";
        assert_eq!(kotlinify_facade_when_return(body), body);
    }

    #[test]
    fn simple_type_kotlin_renders_primitive_arrays_unboxed() {
        // PR-9b: Kotlin source uses `IntArray` / `LongArray` / etc.
        // for primitive arrays, not `Array<Int>` (which would be
        // `Array<java.lang.Integer>` at runtime — distinct shape).
        let mut ctx = EmitCtx::new();
        assert_eq!(
            ctx.simple_type_kotlin(&DexType::ArrayRef(Box::new(DexType::Int))),
            "IntArray",
        );
        assert_eq!(
            ctx.simple_type_kotlin(&DexType::ArrayRef(Box::new(DexType::Long))),
            "LongArray",
        );
        assert_eq!(
            ctx.simple_type_kotlin(&DexType::ArrayRef(Box::new(DexType::Boolean))),
            "BooleanArray",
        );
        // Reference arrays use Array<T> form.
        assert_eq!(
            ctx.simple_type_kotlin(&DexType::ArrayRef(Box::new(DexType::Ref(
                std::sync::Arc::from("Ljava/lang/String;")
            )))),
            "Array<String>",
        );
    }
}
