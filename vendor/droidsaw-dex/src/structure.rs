//! Control flow structuring pass and decompiled AST node types.
#![allow(missing_docs, reason = "internal")]
#![cfg_attr(not(test), allow(clippy::as_conversions, reason = "PROOF (bulk allow, 11 sites): structure.rs runs structuring passes over the SSA + CFG, producing the decompiled AST. Casts cluster around (a) `BlockIdx (u32 newtype) as usize` widening for arena indexing, lossless on 64-bit (BlockIdx is internally minted by the CFG builder and bounded by `cfg.blocks.len()` by construction — invariant violations trip the debug_assert on minted indices); (b) `i64 literal as i32/u32/u16` Dalvik-defined narrowing for the literal-rendering helpers, where the cast IS the operation per the Dalvik spec. Per-site PROOF refinement deferred."))]

use std::collections::{BTreeMap, BTreeSet};

use crate::cfg::{BlockIdx, Cfg, EdgeKind};
use crate::ids::{FieldIdx, MethodIdx, TypeIdx};
use crate::opcodes::Opcode;
use crate::r8_inversion::R8Origin;
use crate::ssa::{SsaBody, SsaInsn, VarId};

// ── Stmt types ──────────────────────────────────────────────────────

/// Branch condition extracted from if/while.
#[derive(Debug, Clone, serde::Serialize)]
pub enum Condition {
    /// if-eqz, if-nez, if-ltz, if-gez, if-gtz, if-lez
    TestZero { var: VarId, op: Opcode },
    /// if-eq, if-ne, if-lt, if-ge, if-gt, if-le
    Compare {
        left: VarId,
        right: VarId,
        op: Opcode,
    },
    /// Fallback: bare variable (for synthetic conditions)
    Var(VarId),
}

impl Condition {
    /// Count how many times a VarId appears in this condition.
    #[allow(clippy::arithmetic_side_effects, reason = "`usize::from(bool) + usize::from(bool)` — sum is 0..=2, cannot overflow usize.")]
    pub fn count_uses(&self, var: &VarId) -> usize {
        match self {
            Condition::TestZero { var: v, .. } => usize::from(v == var),
            Condition::Compare { left, right, .. } => {
                usize::from(left == var) + usize::from(right == var)
            }
            Condition::Var(v) => usize::from(v == var),
        }
    }

    /// Accumulate per-`VarId` use counts from this condition into
    /// `counts`. Multi-var sibling of [`Self::count_uses`] used by
    /// the private `crate::sugar::build_use_count_table` helper to
    /// fill the cache in a single tree walk per pass.
    #[allow(clippy::arithmetic_side_effects, reason = "`*counts.entry(...).or_insert(0) += 1` — usize counter increment bounded by total VarId appearances in body (parser-bounded code size).")]
    pub fn accumulate_uses(&self, counts: &mut std::collections::BTreeMap<VarId, usize>) {
        match self {
            Condition::TestZero { var: v, .. } => {
                *counts.entry(v.clone()).or_insert(0) += 1;
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
}

/// High-level structured statement tree.
#[derive(Debug, Clone, serde::Serialize)]
pub enum Stmt {
    Seq(Vec<Stmt>),
    Expr(SsaInsn),
    If {
        cond: Condition,
        then_body: Box<Stmt>,
        else_body: Option<Box<Stmt>>,
    },
    While {
        cond: Condition,
        body: Box<Stmt>,
    },
    DoWhile {
        body: Box<Stmt>,
        cond: Condition,
    },
    Switch {
        value: VarId,
        cases: Vec<(Vec<i32>, Box<Stmt>)>,
        default: Option<Box<Stmt>>,
    },
    /// Java 7+ `switch(String)` reconstruction. javac lowers string
    /// switches to an outer `switch(s.hashCode())` + per-case
    /// `equals`-check + tag-store, followed by an inner `switch(tag)`
    /// dispatching to the user bodies. The sugar pass
    /// `reconstruct_string_switches` in `src/sugar.rs` pattern-matches
    /// that two-switch shape and synthesizes this variant.
    ///
    /// `value` is the String variable being switched on; case labels
    /// are the source-level string literals. Fails closed to the raw
    /// two-switch form on any pattern deviation.
    StringSwitch {
        value: VarId,
        cases: Vec<(Vec<String>, Box<Stmt>)>,
        default: Option<Box<Stmt>>,
    },
    TryCatch {
        body: Box<Stmt>,
        catches: Vec<CatchClause>,
    },
    Synchronized {
        lock: VarId,
        body: Box<Stmt>,
    },
    Return(Option<VarId>),
    /// `return expr;` where the expression was inlined from a single-use variable.
    InlinedReturn(SsaInsn),
    /// `return "a" + b;` where a string concat was inlined into return.
    InlinedReturnConcat(Vec<ConcatPart>),
    Throw(VarId),
    /// `throw expr;` where the expression was inlined.
    InlinedThrow(SsaInsn),
    Break,
    Continue,
    Goto(BlockIdx),
    /// "hello " + n → desugared string concatenation
    StringConcat {
        dst: Option<VarId>,
        parts: Vec<ConcatPart>,
    },
    /// for (Type var : iterable) { body }
    ForEach {
        var: VarId,
        iterable: VarId,
        body: Box<Stmt>,
    },
    /// for (init; cond; update) { body }
    For {
        init: Box<Stmt>,
        cond: Condition,
        update: Box<Stmt>,
        body: Box<Stmt>,
    },
    /// N-ary mutually-exclusive selection — the disciplined shape for a
    /// flat selection recovered from a recognized compiler lowering. The
    /// invariant is that any region whose bytecode signature matches a known
    /// compiler's lowering of `switch` / `when` / multi-arm
    /// pattern-match / chained `if/else if` is represented in this
    /// variant rather than as nested `Stmt::If` chains.
    ///
    /// SignatureProvenance ties the recovered shape back to the recognizer
    /// (#39 `dex-signature-engine`) and the source-level dialect
    /// (#40 javac21, #41 kotlinc) so the emitter can render the
    /// dialect-appropriate syntax (`switch` for Java, `when` for
    /// Kotlin).
    ///
    /// Producer: not yet wired — variants are emit-able and
    /// pattern-matchable but the structurer does not yet generate them.
    /// Wiring lands in #39 (engine) + #40/#41 (per-dialect signatures).
    MultiArm {
        discriminant: Discriminant,
        arms: Vec<MultiArm>,
        default: Option<Box<Stmt>>,
        provenance: SignatureProvenance,
    },
    /// Honest failure mode: a region whose bytecode signature did not
    /// match any recognizer in the table. Emit surfaces this as a
    /// banner block with the closest-signature hint (by default) followed
    /// by raw smali for the underlying instructions.
    ///
    /// `Stmt::Unrecognized` is NOT a graceful-recovery best-effort
    /// shape. It is the correct output when no signature matches: an
    /// analyst reading "best-effort Java" for a DexGuarded region is
    /// actively misled; a banner + raw bytecode tells them the truth.
    ///
    /// Producer: not yet wired. Wiring lands in #39 when
    /// the signature engine returns `SignatureResult::Unmatched`.
    Unrecognized {
        /// Entry block of the unrecognized region in the underlying
        /// CFG. Lets the analyst correlate the banner back to the
        /// CFG dump.
        cfg_region: BlockIdx,
        reason: UnrecognizedReason,
        /// Verbatim SSA insns for the region. Emit renders these as
        /// raw smali to preserve adversarial-input correctness.
        raw: Vec<SsaInsn>,
    },
    /// Kotlin `val (a, b, ...) = source` destructure. kotlinc lowers
    /// this to a sequence of synthetic `componentN()` calls on the
    /// same receiver: `val a = source.component1(); val b = source.component2();`
    /// etc. The recognizer (`signatures::kotlinc19::data_class_destructure`)
    /// pattern-matches that sequence and lifts to this variant so emit
    /// can recover the source-level destructure syntax.
    ///
    /// `bindings` is the ordered list of bound `VarId`s — first
    /// position is the result of `source.component1()`, second is
    /// `source.component2()`, etc. `_`-discard, lambda-param, and
    /// N>2-arity variants are deferred pending a real consumer; the
    /// simple destructure shape lifts to this single variant.
    ///
    /// `source` is the receiver `VarId` — the value being destructured.
    ///
    /// `provenance` carries the recognizer's id + source dialect for
    /// emit dispatch.
    ///
    /// Producer: only `kotlinc19::data_class_destructure`. Java has no
    /// source-level destructure; emit's Java path renders this variant
    /// as the original `val a = source.component1(); val b = source.component2();`
    /// expansion (or a placeholder banner if a fallback path lands in
    /// PR-8 emit). Kotlin path renders the source-level
    /// `val (a, b) = source` syntax.
    Let {
        /// Ordered list of bound destructure-position `VarId`s.
        /// `bindings[0]` = `source.component1()` result, etc.
        bindings: Vec<VarId>,
        /// Receiver `VarId` being destructured.
        source: VarId,
        /// Recognizer id + source dialect for emit dispatch.
        provenance: SignatureProvenance,
    },
    /// Boolean-typed assignment lifted from a `[if cmp { v=0/1 } else { v=1/0 }]`
    /// shape (or the asymmetric `const-0; if cmp { } else { v=1 }` shape) by the
    /// `lift_comparison_as_value` sugar pass.
    ///
    /// Dalvik has no comparison-as-value opcode, so source-level
    /// `boolean v = (a == b);` lowers to an if-branch + per-branch const-store
    /// with a phi merge at the join. The structurer faithfully reproduces this
    /// as `Stmt::If { cond, then=Const-K_a, else=Const-K_b }`. Without
    /// lifting, the result is a clumsy `int v; if (..) v=0; else v=1;`
    /// rendering AND the surrounding control flow blocks the new+init merge in
    /// emit.
    ///
    /// The lifted form carries the `Condition` in *positive polarity*: emit
    /// renders the cond directly without re-negation. The dst is typed as
    /// boolean by construction, sidestepping `TypeEnv` int-leak.
    ///
    /// Producer: `sugar::lift_comparison_as_value_in_seq`.
    BooleanAssign {
        /// SSA dst whose type is boolean. Emit resolves to the source-level name.
        dst: VarId,
        /// The boolean expression. In positive polarity — emit renders directly.
        cond: Condition,
    },
    /// A string literal that was *fragmented in source* (compile-time
    /// `"X" + "Y" + "Z"` concatenation that bypassed javac constant
    /// folding) and reassembled at runtime via `StringBuilder` /
    /// `invokedynamic StringConcatFactory`. The fragmentation is an
    /// IOC-grep-evasion technique: an analyst grepping decompiled output
    /// for `admin@cerberusapp.com` does not find the fragmented form;
    /// after recognition the `resolved` field carries the joined
    /// literal so atom-level grep + downstream IR pattern-matchers see
    /// the recovered string.
    ///
    /// The IR carries BOTH facts:
    /// - `resolved`: the reassembled literal (the author's intent).
    /// - `fragments`: the original literal pieces (evidence that this
    ///   string was deliberately hidden — distinct from a plain literal
    ///   that happens to have the same content).
    ///
    /// Producer: `signatures::protectors::fragmented_string_literal`
    /// (SignatureId 200), via the sugar pass that pattern-matches
    /// `Stmt::StringConcat` with all-`ConcatPart::Literal` parts.
    /// Emit renders `dst = "<resolved>";` plus a banner-comment listing
    /// the original fragments + recognizer provenance.
    ///
    /// Generic shape — not Cerberus-specific. Future protector
    /// recognizers that resolve fragmented constants (base64-decoded
    /// literals broken into parts, XOR-decoded literals where the XOR
    /// is statically provable, etc.) reuse this variant; the
    /// `signature_id` discriminates the recognizer.
    ResolvedFragment {
        /// Destination `VarId` if the fragmented expression was
        /// assigned; `None` for inline-use (e.g. as a method argument).
        dst: Option<VarId>,
        /// The reassembled source-level literal.
        resolved: String,
        /// The original literal fragments, in order. For
        /// `"admin@cerb" + "erusapp.com"`, this is
        /// `["admin@cerb", "erusapp.com"]`.
        fragments: Vec<String>,
        /// Identifier of the recognizing signature. `200` =
        /// `fragmented_string_literal`. Future protector recognizers
        /// that produce this variant use distinct ids in the
        /// `200..=299` namespace.
        signature_id: SignatureId,
    },
    /// R8 outlined block — a recognised trampoline whose body is a
    /// single `invoke-static $synthetic + return`, where `$synthetic`
    /// lives in R8's renamed namespace (`LX/<≤6 alphanumeric>;`). The
    /// recogniser ([`crate::r8_inversion::apply`]) PREPENDS this marker
    /// to the method-body `Seq` so emit can surface the R8 provenance
    /// without re-running shape detection at emit time. The original
    /// trampoline `Stmt`s remain in the Seq after the marker and emit
    /// normally — this slice does NOT inline the synthetic helper body
    /// at the call site (`dex-r8-block-outlining-inline` is the
    /// follow-up that does cross-method rewrites).
    ///
    /// This is a LEAF variant — it carries no nested `Stmt` and never
    /// holds a `VarId` def or use. Emit renders an indented doc-comment
    /// banner naming the synthetic helper + the recogniser confidence.
    OutlinedBlock {
        /// Pool index of the synthetic helper method R8 emitted to
        /// hold the outlined block. Emit resolves this against
        /// `dex.methods[...]` to print the helper's renamed identifier.
        synthetic_target: MethodIdx,
        /// Recogniser provenance carrying confidence + source-PC +
        /// repeated synthetic-helper reference + caller count. The
        /// variant identity is `R8Transform::StructurallyOutlineLike`
        /// when emitted from the production recogniser (no mapping
        /// access), or `R8Transform::BlockOutlinedHelper { mapping_confirmed }`
        /// when a mapping-paired harness elevates via
        /// `r8_inversion::elevate_with_oracle`. The marker is
        /// attached to the synthetic helper's body in both cases;
        /// `source_pc` is `None` because the marker covers the
        /// whole body, not one originating bytecode site.
        origin: R8Origin,
    },
}

// ── MultiArm support types ─────────────────────────────────────────

/// What the recovered selection switches on at the source level.
/// Distinct from the bytecode-level discriminant — for `switch_string`
/// the bytecode discriminant is `String.hashCode()` but the source
/// discriminant is `Discriminant::String(_)`.
#[derive(Debug, Clone, serde::Serialize)]
pub enum Discriminant {
    /// `switch (int)` / `when (Int)`.
    Int(VarId),
    /// `switch (String)` / `when (String)`.
    String(VarId),
    /// `switch (MyEnum)` over Java enum constants.
    Enum {
        var: VarId,
        enum_type: TypeIdx,
    },
    /// Kotlin `when (x) { is Sub1 -> ...; is Sub2 -> ... }` over a
    /// sealed root.
    SealedSubtype {
        var: VarId,
        sealed_root: TypeIdx,
    },
    /// Hand-written `if (a) ... else if (b) ... else if (c) ...` chain
    /// of unrelated boolean conditions. Distinct from the others —
    /// no single discriminant variable.
    BooleanChain(Vec<Condition>),
}

/// One arm of a `Stmt::MultiArm`. `pattern` describes which discriminant
/// values fall into this arm; `body` is the statements executed.
///
/// Multiple literal values can share an arm (the `IntLiterals` /
/// `StringLiterals` / `EnumConstants` variants of `ArmPattern` carry
/// `Vec<_>` for that reason — `case 1: case 2: foo();` collapses to
/// one arm with two literals).
#[derive(Debug, Clone, serde::Serialize)]
pub struct MultiArm {
    pub pattern: ArmPattern,
    pub body: Stmt,
}

/// What discriminant values match this arm.
#[derive(Debug, Clone, serde::Serialize)]
pub enum ArmPattern {
    IntLiterals(Vec<i32>),
    StringLiterals(Vec<String>),
    EnumConstants(Vec<EnumConstId>),
    /// Kotlin sealed-CLASS `when` arm — `is X.Sub ->`. Matches when the
    /// discriminant's runtime type is `Sub`. Lowering primitive at the
    /// bytecode level: `instanceof <Sub>`. kotlinc-1.9.22 emits this
    /// for sealed roots whose subtypes are `class`es (not `object`s).
    /// Source-level Kotlin syntax: `is X.Sub ->`.
    SealedTypeIs(TypeIdx),
    /// Kotlin sealed-OBJECT `when` arm — `X.Sub ->` (no `is` keyword).
    /// Matches when the discriminant's runtime identity equals the
    /// singleton `<Sub>.INSTANCE`. Lowering primitive at the bytecode
    /// level: `Intrinsics.areEqual(<v>, <Sub>.INSTANCE)`. kotlinc-1.9.22
    /// emits this for sealed roots whose subtypes are Kotlin `object`s.
    /// Source-level Kotlin syntax: `X.Sub ->` (bare singleton equality;
    /// `is` is not idiomatic for objects since equality is referential).
    /// Distinct from `SealedTypeIs` because emit must NOT prepend `is`.
    SealedObjectIs(TypeIdx),
    /// Boolean-chain arm — the `Condition` evaluated against the
    /// implicit chain discriminant. Used with
    /// `Discriminant::BooleanChain`.
    Cond(Condition),
}

/// Identifies an enum constant — the static field of the enum's class
/// holding the singleton instance. Two enum constants are equal iff
/// they live in the same enum type and have the same field index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct EnumConstId {
    pub enum_type: TypeIdx,
    pub field: FieldIdx,
}

// `SignatureProvenance`, `SignatureId`, `SourceDialect`, `JavaVersion`,
// `KotlinVersion`, and `UnrecognizedReason` are language-level concepts
// owned by the signature engine in `droidsaw-common::signature` (#39).
// Re-exported here so existing `use crate::structure::SourceDialect` /
// `use crate::structure::UnrecognizedReason` callers keep resolving;
// dex code may also import them directly from `droidsaw_common::signature`.
pub use droidsaw_common::signature::{
    JavaVersion, KotlinVersion, SignatureProvenance, SignatureId, SourceDialect, UnrecognizedReason,
};

/// Part of a string concatenation expression.
#[derive(Debug, Clone, serde::Serialize)]
pub enum ConcatPart {
    Literal(String),
    Var(VarId),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CatchClause {
    pub exception_type: Option<TypeIdx>,
    pub var: Option<VarId>,
    pub body: Stmt,
}

impl Stmt {
    pub fn is_empty_seq(&self) -> bool {
        matches!(self, Stmt::Seq(v) if v.is_empty())
    }
}

/// Collapse a single-element statement vector into that statement; otherwise
/// wrap in `Stmt::Seq`. Never panics — an empty input becomes `Stmt::Seq(vec![])`,
/// which downstream code already treats as a no-op.
pub(crate) fn flatten_single(mut stmts: Vec<Stmt>) -> Stmt {
    if stmts.len() == 1 {
        stmts
            .pop()
            .unwrap_or_else(|| Stmt::Seq(Vec::new()))
    } else {
        Stmt::Seq(stmts)
    }
}

// ── Dominator computation ───────────────────────────────────────────

/// Compute reverse postorder of the CFG, filtering exception edges.
///
/// Delegates to `common::graph::reverse_post_order` on the `NormalFlow` view.
pub fn reverse_postorder(cfg: &Cfg) -> Vec<BlockIdx> {
    if cfg.blocks.is_empty() {
        return Vec::new();
    }
    droidsaw_common::graph::reverse_post_order(&crate::cfg::NormalFlow(cfg))
}

/// Dominator tree: `idom[b]` = immediate dominator of `b`.
pub fn compute_dominators(cfg: &Cfg) -> BTreeMap<BlockIdx, BlockIdx> {
    if cfg.blocks.is_empty() {
        return BTreeMap::new();
    }
    // Delegate to common's gauge-invariant Cooper-Harvey-Kennedy implementation.
    // Use the NormalFlow view so exception edges are filtered out (structure
    // analysis doesn't see exception edges as normal predecessors).
    let mut idom = droidsaw_common::graph::dominators(&crate::cfg::NormalFlow(cfg));
    // Common omits the entry from the result (no dominator); dex uses
    // `entry → entry` as a self-loop sentinel. Add it back for
    // callers that expect it.
    idom.insert(cfg.entry, cfg.entry);
    idom
}

/// Reversed-CFG adapter used by [`compute_post_dominators`].
///
/// Wraps `&Cfg` and `virtual_exit` sentinel, implementing
/// `droidsaw_common::graph::Graph` such that:
///
/// - `entry()` returns the `virtual_exit` sentinel node.
/// - `nodes()` returns all real blocks plus the sentinel.
/// - `successors(n)` returns the normal-flow predecessors of `n` in the
///   forward CFG (= transpose of normal-flow successors).  For the sentinel
///   itself, it returns all non-empty real blocks that have no normal-flow
///   outgoing edge (the set of method terminals).
/// - `predecessors(n)` returns the normal-flow successors of `n` in the
///   forward CFG.  For the sentinel it returns an empty vec (no forward
///   predecessor edges point at the virtual node).
///
/// **Transpose invariant (ADAPTER-PROPERTY):** for every real block `n`:
/// ```text
/// reversed.successors(n) == { p : n ∈ normal_flow.successors(p) }
/// reversed.predecessors(n) == normal_flow.successors(n)
/// ```
/// Both directions are verified by `tests/reversed_cfg_property.rs`.
///
/// **PROOF (indexing safety):** BlockIdx values are minted only by
/// `Cfg::build` (yielding `0..blocks.len()`) plus the `virtual_exit =
/// BlockIdx(cfg.blocks.len() as u32)` sentinel.  Every entry-point guards
/// `node == self.virtual_exit` before indexing; every other `BlockIdx`
/// satisfies `node.0 < cfg.blocks.len()` by mint discipline.  An
/// out-of-range value is an internal-invariant violation, not adversarial
/// input; `debug_assert!` + direct index (`panic-on-bug`) is the correct
/// fail mode — `.get()` with silent-empty fallback would mask wrong
/// dominators.
#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: BlockIdx values are minted only by Cfg::build (yielding `0..blocks.len()`) plus this `ReversedCfg::virtual_exit = BlockIdx(cfg.blocks.len() as u32)` sentinel. The `node == self.virtual_exit` guard at every entry point handles the sentinel. Every other BlockIdx must satisfy `node.0 < cfg.blocks.len()` by mint discipline; an out-of-range value here is an internal-invariant violation, NOT adversarial input. Panic-on-bug is the correct fail mode for invariant violation: `.get()` with empty fallback would mask wrong dominators silently. Panic-on-bug is intentional: see `ReversedCfg` doc-comment for rationale."
)]
#[doc(hidden)]
pub struct ReversedCfg<'a> {
    pub cfg: &'a Cfg,
    pub virtual_exit: BlockIdx,
}

#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: BlockIdx values are minted only by Cfg::build (yielding `0..blocks.len()`) plus this `ReversedCfg::virtual_exit = BlockIdx(cfg.blocks.len() as u32)` sentinel. The `node == self.virtual_exit` guard at every entry point handles the sentinel. Every other BlockIdx must satisfy `node.0 < cfg.blocks.len()` by mint discipline; an out-of-range value here is an internal-invariant violation, NOT adversarial input. Panic-on-bug is the correct fail mode for invariant violation: `.get()` with empty fallback would mask wrong dominators silently. Panic-on-bug is intentional: see `ReversedCfg` doc-comment for rationale."
)]
impl<'a> droidsaw_common::graph::Graph for ReversedCfg<'a> {
    type Node = BlockIdx;

    fn entry(&self) -> BlockIdx {
        self.virtual_exit
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "PROOF: blocks.len() bounded by DEX code_item insns_size (u32 by spec)."
    )]
    fn nodes(&self) -> Vec<BlockIdx> {
        let mut ns: Vec<BlockIdx> = (0..self.cfg.blocks.len() as u32).map(BlockIdx).collect();
        ns.push(self.virtual_exit);
        ns
    }

    fn successors(&self, node: BlockIdx) -> Vec<BlockIdx> {
        // Reversed successors = original predecessors (normal flow only).
        if node == self.virtual_exit {
            self.cfg
                .blocks
                .iter()
                .filter(|block| {
                    let has_normal_succ = block.successors.iter().any(|e| {
                        !matches!(
                            e.kind,
                            EdgeKind::ExceptionHandler(_) | EdgeKind::ExceptionCatchAll
                        )
                    });
                    !has_normal_succ && !block.instructions.is_empty()
                })
                .map(|b| b.id)
                .collect()
        } else {
            debug_assert!(
                (node.0 as usize) < self.cfg.blocks.len(),
                "ReversedCfg::successors: BlockIdx({}) out of range for cfg with {} blocks",
                node.0,
                self.cfg.blocks.len()
            );
            let target = node;
            self.cfg.blocks[node.0 as usize]
                .predecessors
                .iter()
                .copied()
                .filter(|&p| {
                    debug_assert!(
                        (p.0 as usize) < self.cfg.blocks.len(),
                        "ReversedCfg::successors: predecessor BlockIdx({}) out of range",
                        p.0
                    );
                    self.cfg.blocks[p.0 as usize].successors.iter().any(|e| {
                        e.target == target
                            && !matches!(
                                e.kind,
                                EdgeKind::ExceptionHandler(_) | EdgeKind::ExceptionCatchAll
                            )
                    })
                })
                .collect()
        }
    }

    fn predecessors(&self, node: BlockIdx) -> Vec<BlockIdx> {
        if node == self.virtual_exit {
            return Vec::new();
        }
        debug_assert!(
            (node.0 as usize) < self.cfg.blocks.len(),
            "ReversedCfg::predecessors: BlockIdx({}) out of range for cfg with {} blocks",
            node.0,
            self.cfg.blocks.len()
        );
        let block = &self.cfg.blocks[node.0 as usize];
        let mut preds: Vec<BlockIdx> = block
            .successors
            .iter()
            .filter(|e| {
                !matches!(
                    e.kind,
                    EdgeKind::ExceptionHandler(_) | EdgeKind::ExceptionCatchAll
                )
            })
            .map(|e| e.target)
            .collect();
        let has_normal_succ = block.successors.iter().any(|e| {
            !matches!(
                e.kind,
                EdgeKind::ExceptionHandler(_) | EdgeKind::ExceptionCatchAll
            )
        });
        if !has_normal_succ && !block.instructions.is_empty() {
            preds.push(self.virtual_exit);
        }
        preds
    }
}

/// Compute post-dominators using a virtual exit node.
///
/// dex has a format-specific wrinkle: empty blocks (zero instructions) are
/// excluded from the virtual-exit attachment set. Only non-empty terminals
/// flow into virtual_exit. Common's `post_dominators_with_virtual_exit`
/// treats any empty-successors node as a terminal, which produces different
/// results on ~5 classes in the production corpus.
///
/// Falls back to a local ReversedCfg view that preserves dex's quirk and
/// calls `common::graph::dominators` directly.
#[allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: blocks.len() bounded by DEX code_item insns_size (u32 by spec); the virtual_exit BlockIdx is one past the real range."
)]
pub fn compute_post_dominators(cfg: &Cfg) -> BTreeMap<BlockIdx, droidsaw_common::PostDom<BlockIdx>> {
    if cfg.blocks.is_empty() {
        return BTreeMap::new();
    }

    let virtual_exit = BlockIdx(cfg.blocks.len() as u32);

    let view = ReversedCfg { cfg, virtual_exit };
    let ipdom = droidsaw_common::graph::dominators(&view);
    // virtual_exit is already absent as a key (dominators_with_rpo removes the entry).
    // Convert values: virtual_exit → PostDom::Exit, real block → PostDom::Node.
    ipdom.into_iter()
        .filter_map(|(k, v)| {
            if k == virtual_exit { return None; } // shouldn't appear, but be safe
            let postdom = if v == virtual_exit {
                droidsaw_common::PostDom::Exit
            } else {
                droidsaw_common::PostDom::Node(v)
            };
            Some((k, postdom))
        })
        .collect()
}

/// Check if `a` dominates `b` using the idom map.
///
/// Delegates to `common::graph::dominates`.
pub fn dominates(a: BlockIdx, b: BlockIdx, idom: &BTreeMap<BlockIdx, BlockIdx>) -> bool {
    droidsaw_common::graph::dominates(a, b, idom)
}

// ── Natural loop detection ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NaturalLoop {
    pub header: BlockIdx,
    pub body: BTreeSet<BlockIdx>,
}

pub fn find_natural_loops(cfg: &Cfg, idom: &BTreeMap<BlockIdx, BlockIdx>) -> Vec<NaturalLoop> {
    // Delegate to common's natural_loops on the NormalFlow view.
    // Common returns one NaturalLoop per back edge; dex merges loops with
    // the same header (multiple back edges to the same header = one loop).
    let common_loops = droidsaw_common::graph::natural_loops(&crate::cfg::NormalFlow(cfg), idom);

    let mut merged: Vec<NaturalLoop> = Vec::new();
    for cl in common_loops {
        if let Some(existing) = merged
            .iter_mut()
            .find(|l: &&mut NaturalLoop| l.header == cl.header)
        {
            existing.body.extend(cl.body);
        } else {
            merged.push(NaturalLoop {
                header: cl.header,
                body: cl.body,
            });
        }
    }
    merged
}

// ── Main structuring ────────────────────────────────────────────────

/// Negate a condition (for while loops: branch = exit, while needs continuation).
fn negate_condition(cond: Condition) -> Condition {
    match cond {
        Condition::TestZero { var, op } => {
            let negated_op = match op {
                Opcode::IfEqz => Opcode::IfNez,
                Opcode::IfNez => Opcode::IfEqz,
                Opcode::IfLtz => Opcode::IfGez,
                Opcode::IfGez => Opcode::IfLtz,
                Opcode::IfGtz => Opcode::IfLez,
                Opcode::IfLez => Opcode::IfGtz,
                other => other,
            };
            Condition::TestZero {
                var,
                op: negated_op,
            }
        }
        Condition::Compare { left, right, op } => {
            let negated_op = match op {
                Opcode::IfEq => Opcode::IfNe,
                Opcode::IfNe => Opcode::IfEq,
                Opcode::IfLt => Opcode::IfGe,
                Opcode::IfGe => Opcode::IfLt,
                Opcode::IfGt => Opcode::IfLe,
                Opcode::IfLe => Opcode::IfGt,
                other => other,
            };
            Condition::Compare {
                left,
                right,
                op: negated_op,
            }
        }
        other => other,
    }
}

/// Extract a Condition from the last instruction in an SSA block (if it's a branch).
/// Map an if-*z opcode to the equivalent two-operand if-* opcode for cmp fusion.
fn test_zero_to_compare_op(op: Opcode) -> Opcode {
    match op {
        Opcode::IfEqz => Opcode::IfEq,
        Opcode::IfNez => Opcode::IfNe,
        Opcode::IfLtz => Opcode::IfLt,
        Opcode::IfGez => Opcode::IfGe,
        Opcode::IfGtz => Opcode::IfGt,
        Opcode::IfLez => Opcode::IfLe,
        other => other,
    }
}

/// Check if `var` is defined by a cmp-long/cmpl-double/cmpg-float instruction
/// in the same block. If so, return the two operands of the comparison.
fn find_cmp_def_in_block(sb: &crate::ssa::SsaBlock, var: &VarId) -> Option<(VarId, VarId)> {
    for insn in &sb.insns {
        let is_cmp = matches!(
            insn.insn.op,
            Opcode::CmpLong
                | Opcode::CmplFloat
                | Opcode::CmpgFloat
                | Opcode::CmplDouble
                | Opcode::CmpgDouble
        );
        if is_cmp {
            if let Some(ref dst) = insn.dst {
                if dst == var {
                    if let [u0, u1, ..] = insn.uses.as_slice() {
                        return Some((u0.clone(), u1.clone()));
                    }
                }
            }
        }
    }
    None
}

fn extract_condition(ssa: &SsaBody, block_idx: BlockIdx) -> Condition {
    let sb = match ssa.blocks.get(&block_idx) {
        Some(b) => b,
        None => return Condition::Var(VarId::new(0, 0)),
    };
    let insn = match sb.insns.last() {
        Some(i) => i,
        None => return Condition::Var(VarId::new(0, 0)),
    };
    match insn.insn.op {
        Opcode::IfEqz
        | Opcode::IfNez
        | Opcode::IfLtz
        | Opcode::IfGez
        | Opcode::IfGtz
        | Opcode::IfLez => {
            let var = insn
                .uses
                .first()
                .cloned()
                .unwrap_or_else(|| VarId::new(0, 0));
            // Fuse cmp-long/cmpl-double/cmpg-float + if-*z into a direct Compare.
            // DEX emits: cmp-long v3, v4, v1; if-gtz v3, target
            // We recover: if (v4 > v1)
            if let Some((left, right)) = find_cmp_def_in_block(sb, &var) {
                return Condition::Compare {
                    left,
                    right,
                    op: test_zero_to_compare_op(insn.insn.op),
                };
            }
            Condition::TestZero {
                var,
                op: insn.insn.op,
            }
        }
        Opcode::IfEq | Opcode::IfNe | Opcode::IfLt | Opcode::IfGe | Opcode::IfGt | Opcode::IfLe => {
            let left = insn
                .uses
                .first()
                .cloned()
                .unwrap_or_else(|| VarId::new(0, 0));
            let right = insn
                .uses
                .get(1)
                .cloned()
                .unwrap_or_else(|| VarId::new(0, 0));
            Condition::Compare {
                left,
                right,
                op: insn.insn.op,
            }
        }
        _ => {
            let var = insn
                .uses
                .first()
                .cloned()
                .unwrap_or_else(|| VarId::new(0, 0));
            Condition::Var(var)
        }
    }
}

struct StructureCtx<'a> {
    cfg: &'a Cfg,
    ssa: &'a SsaBody,
    _idom: BTreeMap<BlockIdx, BlockIdx>,
    ipdom: BTreeMap<BlockIdx, droidsaw_common::PostDom<BlockIdx>>,
    loops: Vec<NaturalLoop>,
    visited: BTreeSet<BlockIdx>,
}

/// Structure the SSA body and CFG into a Stmt tree.
pub fn structure(ssa: &SsaBody, cfg: &Cfg) -> Stmt {
    if cfg.blocks.is_empty() {
        let out = Stmt::Seq(vec![]);
        droidsaw_common::diag::stage_dump("structure", &out);
        return out;
    }

    let idom = compute_dominators(cfg);
    let ipdom = compute_post_dominators(cfg);
    let loops = find_natural_loops(cfg, &idom);

    let mut ctx = StructureCtx {
        cfg,
        ssa,
        _idom: idom,
        ipdom,
        loops,
        visited: BTreeSet::new(),
    };

    let out = structure_region(&mut ctx, cfg.entry, None);
    let out = reconstruct_short_circuit_guards(out);
    droidsaw_common::diag::stage_dump("structure", &out);
    out
}

/// Post-structuring rewrite pass for short-circuit `||` reconstruction.
///
/// Pattern match at method body tail (last stmt in a Seq):
///
/// ```text
/// If { cond: A,
///      then: [Return(X)],
///      else: Some(If { cond: B, then: [Return(Y)], else: None }) }
/// ```
///
/// Rewrite to:
///
/// ```text
/// [
///   If { cond: A, then: [Return(X)], else: None },
///   If { cond: B, then: [Return(Y)], else: None },
///   Return(X),
/// ]
/// ```
///
/// This recovers the source-level shape `if (A || negate(B)) return X;
/// return Y;` without requiring a `LogicalOr` Condition variant: two
/// sibling if-guards plus a trailing duplicate of `Return(X)` cover the
/// same semantic.
///
/// **Why this fix is necessary.** The CFG structurer correctly emits
/// `If-then-else-If-then-fallthrough` for the javac-lowered short-circuit
/// `||` where BOTH branches of the OR return the same fallback. The
/// `else` of the inner `If` is empty (fall-through) and the
/// fall-through reaches a shared `:label1 return fallback` in Dalvik
/// that the outer-then absorbed — the inner-else was left with no
/// reachable return, producing javac's "missing return statement" on
/// recompile.
///
/// **Why duplicating Return(X) is safe.** `Stmt::Return(Option<VarId>)`
/// references an SSA name (or nothing for void) — no side effects on
/// duplication. `Stmt::InlinedReturn(insn)` with a method-call body
/// WOULD double-invoke, so this pattern match deliberately rejects
/// `InlinedReturn` / `InlinedThrow` / `StringConcat`-return shapes
/// outright. Only bare `Return(None)` / `Return(Some(VarId))` qualify.
///
/// **Depth bound.** Match only at one-level nesting for v1 per main's
/// directive. Chains deeper than two stacked ifs fall through untouched.
fn reconstruct_short_circuit_guards(stmt: Stmt) -> Stmt {
    /// Return-shape safe to DUPLICATE: bare `Stmt::Return(Option<VarId>)`
    /// references an SSA name or nothing (void). No side effects on
    /// re-evaluation. The trailing fallback slot of the rewrite uses this.
    fn is_simple_return(s: &Stmt) -> bool {
        matches!(s, Stmt::Return(_))
    }

    /// Return-shape safe to MOVE (but not duplicate): any return-like
    /// terminator, including inlined-expression returns whose side
    /// effects are performed exactly once in the original control flow.
    /// Only used as the INNER return in the rewrite (appears once).
    fn is_any_return(s: &Stmt) -> bool {
        matches!(
            s,
            Stmt::Return(_)
                | Stmt::InlinedReturn(_)
                | Stmt::InlinedReturnConcat(_)
                | Stmt::Throw(_)
                | Stmt::InlinedThrow(_)
        )
    }

    /// Normalize a Stmt to a flat Vec of its constituent sub-stmts.
    /// Stmt::Seq(v) unwraps; anything else is a single-element Vec.
    fn flatten(s: &Stmt) -> Vec<Stmt> {
        match s {
            Stmt::Seq(v) => v.clone(),
            other => vec![other.clone()],
        }
    }

    #[allow(clippy::arithmetic_side_effects, reason = "`3 + else_prefix.len()` — pre-sized Vec capacity; else_prefix.len() bounded by source AST size (parser-bounded code size).")]
    fn try_rewrite_tail_if(s: &Stmt) -> Option<Vec<Stmt>> {
        let Stmt::If {
            cond: cond_a,
            then_body: then_a,
            else_body: Some(else_a),
        } = s
        else {
            return None;
        };

        // outer then must be a single Return.
        let then_a_flat = flatten(then_a.as_ref());
        let [single] = then_a_flat.as_slice() else {
            return None;
        };
        if !is_simple_return(single) {
            return None;
        }
        let ret_x = then_a_flat.into_iter().next().unwrap_or(Stmt::Return(None));

        // outer else must end with an If{B, [Return(Y)], None}; any
        // preceding statements in the else_body become sibling prefix
        // (hoisted out to live at the same scope level as the rewrite
        // sibling-if chain — their side-effects must execute before B is
        // tested, same as the original control flow).
        let else_a_flat = flatten(else_a.as_ref());
        let (else_prefix, inner_if) = match else_a_flat.split_last() {
            Some((last, prefix)) => (prefix.to_vec(), last.clone()),
            None => return None,
        };
        // inner If's then_body may be either a bare return OR a Seq of
        // setup statements ending in a return. The preceding setup runs
        // only when B is true so it must stay INSIDE the preserved inner
        // If's then — not hoisted out like the outer else's prefix. We
        // just verify the tail is a return and keep the then_body as-is.
        let (cond_b, then_b) = match inner_if {
            Stmt::If {
                cond: cond_b,
                then_body: then_b,
                else_body: None,
            } => {
                let last_is_return = match then_b.as_ref() {
                    Stmt::Seq(v) => v.last().map(is_any_return).unwrap_or(false),
                    other => is_any_return(other),
                };
                if !last_is_return {
                    return None;
                }
                (cond_b, then_b)
            }
            _ => return None,
        };

        // Compose the rewrite: outer-guard, else-prefix setup, inner-guard
        // (preserving inner then_body intact including any setup + Return),
        // trailing fallback return.
        let mut out = Vec::with_capacity(3 + else_prefix.len());
        out.push(Stmt::If {
            cond: cond_a.clone(),
            then_body: Box::new(ret_x.clone()),
            else_body: None,
        });
        out.extend(else_prefix);
        out.push(Stmt::If {
            cond: cond_b,
            then_body: then_b,
            else_body: None,
        });
        out.push(ret_x);
        Some(out)
    }

    // Walk: for Seq's LAST element OR a bare top-level If, try the tail-If rewrite.
    match stmt {
        Stmt::Seq(mut stmts) => {
            if let Some(last) = stmts.last() {
                if let Some(replacement) = try_rewrite_tail_if(last) {
                    let _ = stmts.pop();
                    stmts.extend(replacement);
                }
            }
            // Recurse into remaining stmts (defensive — bodies inside If/While/etc.
            // are also method-scope reachable and may harbor the same shape).
            let stmts = stmts
                .into_iter()
                .map(reconstruct_short_circuit_guards)
                .collect();
            Stmt::Seq(stmts)
        }
        // Bare If at method body (no wrapping Seq): try the rewrite; if matches,
        // produce Stmt::Seq of the sibling guards + trailing return.
        Stmt::If {
            ref cond,
            ref then_body,
            ref else_body,
        } if else_body.is_some() => {
            if let Some(replacement) = try_rewrite_tail_if(&stmt) {
                return Stmt::Seq(replacement);
            }
            let then_body = Box::new(reconstruct_short_circuit_guards((**then_body).clone()));
            let else_body = else_body
                .as_ref()
                .map(|e| Box::new(reconstruct_short_circuit_guards((**e).clone())));
            Stmt::If {
                cond: cond.clone(),
                then_body,
                else_body,
            }
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => Stmt::If {
            cond,
            then_body: Box::new(reconstruct_short_circuit_guards(*then_body)),
            else_body: else_body.map(|e| Box::new(reconstruct_short_circuit_guards(*e))),
        },
        Stmt::While { cond, body } => Stmt::While {
            cond,
            body: Box::new(reconstruct_short_circuit_guards(*body)),
        },
        Stmt::DoWhile { body, cond } => Stmt::DoWhile {
            body: Box::new(reconstruct_short_circuit_guards(*body)),
            cond,
        },
        Stmt::Switch {
            value,
            cases,
            default,
        } => Stmt::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(keys, body)| (keys, Box::new(reconstruct_short_circuit_guards(*body))))
                .collect(),
            default: default.map(|d| Box::new(reconstruct_short_circuit_guards(*d))),
        },
        Stmt::TryCatch { body, catches } => Stmt::TryCatch {
            body: Box::new(reconstruct_short_circuit_guards(*body)),
            catches: catches
                .into_iter()
                .map(|c| CatchClause {
                    exception_type: c.exception_type,
                    var: c.var,
                    body: reconstruct_short_circuit_guards(c.body),
                })
                .collect(),
        },
        Stmt::Synchronized { lock, body } => Stmt::Synchronized {
            lock,
            body: Box::new(reconstruct_short_circuit_guards(*body)),
        },
        Stmt::ForEach {
            var,
            iterable,
            body,
        } => Stmt::ForEach {
            var,
            iterable,
            body: Box::new(reconstruct_short_circuit_guards(*body)),
        },
        Stmt::For {
            init,
            cond,
            update,
            body,
        } => Stmt::For {
            init: Box::new(reconstruct_short_circuit_guards(*init)),
            cond,
            update: Box::new(reconstruct_short_circuit_guards(*update)),
            body: Box::new(reconstruct_short_circuit_guards(*body)),
        },
        s => s,
    }
}

/// Iteratively structure a region of the CFG into a Stmt tree.
///
/// This is a trampoline over the block-walk that the recursive
/// formulation used to drive via the native call stack. Frame state
/// for each pending `Processing` / `Awaiting*` step lives on an
/// explicit `Vec<Frame>` so recursion depth is bounded by heap
/// memory, not stack size. A single `result: Option<Stmt>` slot
/// carries the Stmt produced by each completed child frame up to
/// the `Awaiting*` parent that consumes it.
///
/// Semantics are **identical to the recursive formulation** — same
/// block-visit order, same `ctx.visited` insertions in the same
/// sequence, same Stmt tree shape. Verified against the production
/// content-hash oracle: zero diff.
///
/// Depth scales with the nesting depth of control-flow constructs
/// (if / else / switch / loop), which real code bounds at ~20 and
/// even aggressive obfuscators rarely push past a few hundred. The
/// iterative formulation removes the theoretical stack-overflow
/// hazard that motivated the 16MB thread workaround in
/// `src/classes.rs`, though that wrapper remains as belt-and-braces
/// defense.
fn structure_region(ctx: &mut StructureCtx, start: BlockIdx, end: Option<BlockIdx>) -> Stmt {
    // Slot for the last-completed child's result. Consumed and
    // cleared by each `Awaiting*` frame as it runs.
    let mut result: Option<Stmt> = None;
    let mut stack: Vec<Frame> = Vec::new();
    stack.push(Frame::Processing {
        end,
        stmts: Vec::new(),
        current: Some(start),
    });

    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Processing {
                end,
                stmts,
                current,
            } => {
                drive_processing(ctx, end, stmts, current, &mut stack, &mut result);
            }
            Frame::AwaitingIfThen {
                end,
                stmts,
                cond,
                else_target,
                merge,
                continuation,
            } => {
                let then_body = result.take().unwrap_or_else(|| Stmt::Seq(vec![]));
                // Spawn else body if it exists and isn't collapsed to merge
                if let Some(et) = else_target {
                    if Some(et) != merge {
                        stack.push(Frame::AwaitingIfElse {
                            end,
                            stmts,
                            cond,
                            then_body,
                            continuation,
                        });
                        stack.push(Frame::Processing {
                            end: merge,
                            stmts: Vec::new(),
                            current: Some(et),
                        });
                        continue;
                    }
                }
                // No else body
                let mut stmts = stmts;
                stmts.push(Stmt::If {
                    cond,
                    then_body: Box::new(then_body),
                    else_body: None,
                });
                stack.push(Frame::Processing {
                    end,
                    stmts,
                    current: continuation,
                });
            }
            Frame::AwaitingIfElse {
                end,
                stmts,
                cond,
                then_body,
                continuation,
            } => {
                let else_body_raw = result.take().unwrap_or_else(|| Stmt::Seq(vec![]));
                let else_body = if else_body_raw.is_empty_seq() {
                    None
                } else {
                    Some(Box::new(else_body_raw))
                };
                let mut stmts = stmts;
                stmts.push(Stmt::If {
                    cond,
                    then_body: Box::new(then_body),
                    else_body,
                });
                stack.push(Frame::Processing {
                    end,
                    stmts,
                    current: continuation,
                });
            }
            Frame::AwaitingSwitchCase {
                end,
                stmts,
                value_var,
                merge,
                current_keys,
                mut completed_cases,
                mut remaining_cases,
                default_target,
                continuation,
            } => {
                // Splice the just-returned case body.
                let body = result.take().unwrap_or_else(|| Stmt::Seq(vec![]));
                completed_cases.push((current_keys, Box::new(body)));

                // Pop next non-collapsed case, emitting empty Seq for
                // any collapsed cases encountered in order.
                let next = loop {
                    match remaining_cases.pop_front() {
                        Some((t, k)) if Some(t) == merge => {
                            completed_cases.push((k, Box::new(Stmt::Seq(vec![]))));
                        }
                        Some((t, k)) => break Some((t, k)),
                        None => break None,
                    }
                };

                if let Some((next_target, next_keys)) = next {
                    stack.push(Frame::AwaitingSwitchCase {
                        end,
                        stmts,
                        value_var,
                        merge,
                        current_keys: next_keys,
                        completed_cases,
                        remaining_cases,
                        default_target,
                        continuation,
                    });
                    stack.push(Frame::Processing {
                        end: merge,
                        stmts: Vec::new(),
                        current: Some(next_target),
                    });
                    continue;
                }
                // All cases done — spawn default if present and non-collapsed
                if let Some(dt) = default_target {
                    if Some(dt) != merge {
                        stack.push(Frame::AwaitingSwitchDefault {
                            end,
                            stmts,
                            value_var,
                            cases: completed_cases,
                            continuation,
                        });
                        stack.push(Frame::Processing {
                            end: merge,
                            stmts: Vec::new(),
                            current: Some(dt),
                        });
                        continue;
                    }
                }
                // No default
                let mut stmts = stmts;
                stmts.push(Stmt::Switch {
                    value: value_var,
                    cases: completed_cases,
                    default: None,
                });
                stack.push(Frame::Processing {
                    end,
                    stmts,
                    current: continuation,
                });
            }
            Frame::AwaitingSwitchDefault {
                end,
                stmts,
                value_var,
                cases,
                continuation,
            } => {
                let default_body = result.take().unwrap_or_else(|| Stmt::Seq(vec![]));
                let mut stmts = stmts;
                stmts.push(Stmt::Switch {
                    value: value_var,
                    cases,
                    default: Some(Box::new(default_body)),
                });
                stack.push(Frame::Processing {
                    end,
                    stmts,
                    current: continuation,
                });
            }
            Frame::AwaitingWhileBody {
                end,
                stmts,
                cond,
                header_stmts,
                continuation,
            } => {
                let inner = result.take().unwrap_or_else(|| Stmt::Seq(vec![]));
                let body = if header_stmts.is_empty() {
                    inner
                } else {
                    // Loop rotation: header_stmts execute before each condition
                    // check in the original DEX (they're the first instructions
                    // of the loop header block, before the branch). In the
                    // emitted `while`, the condition runs before the body, so
                    // we emit header_stmts at both the START (so
                    // find_init_in_body sees the right initializer) and END of
                    // the body (so the condition variable is refreshed before
                    // the next check, after the body may have clobbered it).
                    let mut all = header_stmts.clone(); // at start
                    all.push(inner);
                    all.extend(header_stmts);           // at end (rotation)
                    Stmt::Seq(all)
                };
                let mut stmts = stmts;
                stmts.push(Stmt::While {
                    cond,
                    body: Box::new(body),
                });
                stack.push(Frame::Processing {
                    end,
                    stmts,
                    current: continuation,
                });
            }
            Frame::AwaitingDoWhileBlock {
                end,
                stmts,
                cond,
                header,
                mut body_stmts,
                mut remaining_blocks,
                continuation,
            } => {
                // Splice the just-returned sub-region into body_stmts if non-empty.
                let child = result.take().unwrap_or_else(|| Stmt::Seq(vec![]));
                if !child.is_empty_seq() {
                    body_stmts.push(child);
                }
                // Find the next body block that hasn't been visited yet.
                let next = loop {
                    match remaining_blocks.pop_front() {
                        Some(b) if ctx.visited.contains(&b) => continue,
                        Some(b) => break Some(b),
                        None => break None,
                    }
                };
                if let Some(b) = next {
                    stack.push(Frame::AwaitingDoWhileBlock {
                        end,
                        stmts,
                        cond,
                        header,
                        body_stmts,
                        remaining_blocks,
                        continuation,
                    });
                    stack.push(Frame::Processing {
                        end: Some(header),
                        stmts: Vec::new(),
                        current: Some(b),
                    });
                    continue;
                }
                // No more body blocks — assemble do-while
                let body = flatten_single(body_stmts);
                let mut stmts = stmts;
                stmts.push(Stmt::DoWhile {
                    body: Box::new(body),
                    cond,
                });
                stack.push(Frame::Processing {
                    end,
                    stmts,
                    current: continuation,
                });
            }
        }
    }

    // When the driver runs out of frames, `result` holds the top-level
    // region's Stmt. The initial Processing frame always produces one.
    result.unwrap_or_else(|| Stmt::Seq(vec![]))
}

/// Drive a single `Processing` frame forward: walk the block chain,
/// emitting instructions and following simple edges, until we either
/// hit a recursive-call site (at which point we push the appropriate
/// `Awaiting*` frame + new child `Processing` frame) or the region
/// finishes (at which point we set `result` to the assembled Stmt).
///
/// This is the hot inner loop extracted from what used to be the
/// body of the recursive `structure_region`. Every recursive call
/// in the original has been replaced by `push` + `return` here.
#[allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: blocks.len() bounded by DEX code_item insns_size (u32 by spec)."
)]
fn drive_processing(
    ctx: &mut StructureCtx,
    end: Option<BlockIdx>,
    mut stmts: Vec<Stmt>,
    mut current: Option<BlockIdx>,
    stack: &mut Vec<Frame>,
    result: &mut Option<Stmt>,
) {
    while let Some(block_idx) = current {
        if Some(block_idx) == end {
            break;
        }
        if !ctx.visited.insert(block_idx) {
            break;
        }

        // Loop header → enter loop structuring (may spawn a child frame)
        if let Some(loop_info) = ctx.loops.iter().find(|l| l.header == block_idx).cloned() {
            let continuation = ctx.ipdom.get(&block_idx).and_then(|pd| match pd {
                droidsaw_common::PostDom::Node(b) if Some(*b) != end => Some(*b),
                _ => None,
            }).or_else(|| {
                // ipdom is Exit (early return/throw in body) — fall back to
                // the header's exit-edge target as continuation.
                let hb = ctx.cfg.block(block_idx);
                hb.successors.iter()
                    .filter(|e| !matches!(e.kind, EdgeKind::ExceptionHandler(_) | EdgeKind::ExceptionCatchAll))
                    .find(|e| !loop_info.body.contains(&e.target))
                    .map(|e| e.target)
                    .filter(|b| Some(*b) != end)
            });
            enter_loop(ctx, &loop_info, end, stmts, continuation, stack);
            return;
        }

        let ssa_block = ctx.ssa.blocks.get(&block_idx);
        let cfg_block_opt = if block_idx.0 < ctx.cfg.blocks.len() as u32 {
            Some(ctx.cfg.block(block_idx))
        } else {
            None
        };

        // Emit instructions from this block
        if let Some(sb) = ssa_block {
            for insn in &sb.insns {
                match insn.insn.op {
                    Opcode::ReturnVoid => {
                        stmts.push(Stmt::Return(None));
                    }
                    Opcode::Return | Opcode::ReturnWide | Opcode::ReturnObject => {
                        let var = insn.uses.first().cloned();
                        stmts.push(Stmt::Return(var));
                    }
                    Opcode::Throw => {
                        if let Some(var) = insn.uses.first() {
                            stmts.push(Stmt::Throw(var.clone()));
                        }
                    }
                    Opcode::Goto | Opcode::Goto16 | Opcode::Goto32 => {
                        // Gotos are handled by edge following
                    }
                    Opcode::IfEq
                    | Opcode::IfNe
                    | Opcode::IfLt
                    | Opcode::IfGe
                    | Opcode::IfGt
                    | Opcode::IfLe
                    | Opcode::IfEqz
                    | Opcode::IfNez
                    | Opcode::IfLtz
                    | Opcode::IfGez
                    | Opcode::IfGtz
                    | Opcode::IfLez
                    | Opcode::PackedSwitch
                    | Opcode::SparseSwitch => {
                        // Handled below in edge analysis
                    }
                    _ => {
                        stmts.push(Stmt::Expr(insn.clone()));
                    }
                }
            }
        }

        let cfg_block = match cfg_block_opt {
            Some(b) => b,
            None => break,
        };

        let normal_succs: Vec<_> = cfg_block
            .successors
            .iter()
            .filter(|e| {
                !matches!(
                    e.kind,
                    EdgeKind::ExceptionHandler(_) | EdgeKind::ExceptionCatchAll
                )
            })
            .collect();

        // Check for if/else
        let has_branch = normal_succs
            .iter()
            .any(|e| matches!(e.kind, EdgeKind::Branch));
        let has_fallthrough = normal_succs
            .iter()
            .any(|e| matches!(e.kind, EdgeKind::FallThrough));

        if has_branch && has_fallthrough {
            let branch_target = normal_succs
                .iter()
                .find(|e| matches!(e.kind, EdgeKind::Branch))
                .map(|e| e.target);
            let fall_target = normal_succs
                .iter()
                .find(|e| matches!(e.kind, EdgeKind::FallThrough))
                .map(|e| e.target);

            let merge = ctx.ipdom.get(&block_idx).and_then(|pd| match pd {
                droidsaw_common::PostDom::Node(b) => Some(*b),
                droidsaw_common::PostDom::Exit => None,
            });
            let cond = extract_condition(ctx.ssa, block_idx);
            let then_target = branch_target.unwrap_or(block_idx);
            let else_target = fall_target.unwrap_or(block_idx);
            let continuation = merge.filter(|b| Some(*b) != end);

            // Spawn then-body frame (or short-circuit to empty if it
            // collapses to merge). The AwaitingIfThen frame picks up
            // the result and either spawns the else body or builds
            // Stmt::If directly.
            let then_body = if Some(then_target) == merge {
                Some(Stmt::Seq(vec![]))
            } else {
                None
            };

            stack.push(Frame::AwaitingIfThen {
                end,
                stmts,
                cond,
                else_target: Some(else_target),
                merge,
                continuation,
            });
            if let Some(tb) = then_body {
                // Synthetic completed child — set result directly
                // instead of spawning a Processing frame.
                *result = Some(tb);
            } else {
                stack.push(Frame::Processing {
                    end: merge,
                    stmts: Vec::new(),
                    current: Some(then_target),
                });
            }
            return;
        }

        // Switch
        let switch_cases: Vec<_> = normal_succs
            .iter()
            .filter(|e| matches!(e.kind, EdgeKind::SwitchCase(_)))
            .collect();

        if !switch_cases.is_empty() {
            let value_var = ssa_block
                .and_then(|sb| sb.insns.last())
                .and_then(|insn| {
                    if insn.insn.dst.is_some() {
                        Some(insn.uses.first()?.clone())
                    } else {
                        insn.uses.first().cloned()
                    }
                })
                .unwrap_or_else(|| VarId::new(0, 0));

            let merge = ctx.ipdom.get(&block_idx).and_then(|pd| match pd {
                droidsaw_common::PostDom::Node(b) => Some(*b),
                droidsaw_common::PostDom::Exit => None,
            });
            let continuation = merge.filter(|b| Some(*b) != end);

            // Group cases by target (BTreeMap preserves ordering by BlockIdx)
            let mut target_cases: BTreeMap<BlockIdx, Vec<i32>> = BTreeMap::new();
            for edge in &normal_succs {
                if let EdgeKind::SwitchCase(key) = edge.kind {
                    target_cases.entry(edge.target).or_default().push(key);
                }
            }
            let default_target = normal_succs
                .iter()
                .find(|e| matches!(e.kind, EdgeKind::SwitchDefault))
                .map(|e| e.target);

            // Preserve original BTreeMap iteration order (ascending by
            // target BlockIdx) so `ctx.visited` side effects from
            // earlier cases affect later cases the same way the
            // recursive code did. Push ALL cases onto pending, then
            // pop-and-advance to find the first non-collapsed one,
            // pre-filling collapsed cases with empty Seqs in order.
            let mut pending: std::collections::VecDeque<(BlockIdx, Vec<i32>)> =
                std::collections::VecDeque::new();
            for (target, keys) in target_cases {
                pending.push_back((target, keys));
            }

            let mut completed_cases: Vec<(Vec<i32>, Box<Stmt>)> = Vec::new();
            let first = loop {
                match pending.pop_front() {
                    Some((t, k)) if Some(t) == merge => {
                        completed_cases.push((k, Box::new(Stmt::Seq(vec![]))));
                    }
                    Some((t, k)) => break Some((t, k)),
                    None => break None,
                }
            };

            // If no non-collapsed cases, skip straight to default handling.
            if let Some((first_target, first_keys)) = first {
                stack.push(Frame::AwaitingSwitchCase {
                    end,
                    stmts,
                    value_var,
                    merge,
                    current_keys: first_keys,
                    completed_cases,
                    remaining_cases: pending,
                    default_target,
                    continuation,
                });
                stack.push(Frame::Processing {
                    end: merge,
                    stmts: Vec::new(),
                    current: Some(first_target),
                });
                return;
            }

            // All cases collapsed → handle default inline or emit Switch with no default
            if let Some(dt) = default_target {
                if Some(dt) != merge {
                    stack.push(Frame::AwaitingSwitchDefault {
                        end,
                        stmts,
                        value_var,
                        cases: completed_cases,
                        continuation,
                    });
                    stack.push(Frame::Processing {
                        end: merge,
                        stmts: Vec::new(),
                        current: Some(dt),
                    });
                    return;
                }
            }
            // No default
            stmts.push(Stmt::Switch {
                value: value_var,
                cases: completed_cases,
                default: None,
            });
            current = continuation;
            continue;
        }

        // Single successor: follow it
        if let [only] = normal_succs.as_slice() {
            current = Some(only.target);
            continue;
        }

        // No successors (terminal) or unconditional goto
        if let Some(branch_edge) = normal_succs
            .iter()
            .find(|e| matches!(e.kind, EdgeKind::Branch))
        {
            current = Some(branch_edge.target);
            continue;
        }

        break;
    }

    // Region walk finished — assemble Stmt from accumulated stmts.
    *result = Some(flatten_single(stmts));
}

/// Enter a loop construct. Replaces the old `structure_loop`
/// function — pushes the appropriate `Awaiting*` frame plus a child
/// `Processing` frame for the first recursive call site.
///
/// For the while pattern, spawns one Processing child on the
/// body_target (bounded by `Some(header)`). For the do-while /
/// infinite pattern, spawns one Processing child on the first
/// unvisited body block (bounded by `Some(header)`), and the
/// AwaitingDoWhileBlock frame iterates through the rest.
fn enter_loop(
    ctx: &mut StructureCtx,
    loop_info: &NaturalLoop,
    end: Option<BlockIdx>,
    stmts: Vec<Stmt>,
    continuation: Option<BlockIdx>,
    stack: &mut Vec<Frame>,
) {
    let header = loop_info.header;
    let header_block = ctx.cfg.block(header);

    let normal_succs: Vec<_> = header_block
        .successors
        .iter()
        .filter(|e| {
            !matches!(
                e.kind,
                EdgeKind::ExceptionHandler(_) | EdgeKind::ExceptionCatchAll
            )
        })
        .collect();

    let has_exit = normal_succs
        .iter()
        .any(|e| !loop_info.body.contains(&e.target));

    // Branch condition at header is the EXIT condition; while needs CONTINUATION (negated).
    let cond = negate_condition(extract_condition(ctx.ssa, header));

    if has_exit && normal_succs.len() == 2 {
        // While pattern
        let body_target = normal_succs
            .iter()
            .find(|e| loop_info.body.contains(&e.target) && e.target != header)
            .map(|e| e.target);

        ctx.visited.insert(header);

        // Emit header instructions (except the branch)
        let mut header_stmts = Vec::new();
        if let Some(sb) = ctx.ssa.blocks.get(&header) {
            for insn in &sb.insns {
                if !matches!(
                    insn.insn.op,
                    Opcode::IfEq
                        | Opcode::IfNe
                        | Opcode::IfLt
                        | Opcode::IfGe
                        | Opcode::IfGt
                        | Opcode::IfLe
                        | Opcode::IfEqz
                        | Opcode::IfNez
                        | Opcode::IfLtz
                        | Opcode::IfGez
                        | Opcode::IfGtz
                        | Opcode::IfLez
                        | Opcode::Goto
                        | Opcode::Goto16
                        | Opcode::Goto32
                ) {
                    header_stmts.push(Stmt::Expr(insn.clone()));
                }
            }
        }

        // SSA phi deconstruction — entry edge.
        //
        // For each phi at the loop header, if the entry-edge operand lives in a
        // different register than the phi itself, copy-propagation will have
        // replaced the operand directly in the phi while DCE'd the defining
        // Move, leaving the phi's register uninitialized before the loop.
        // Emit explicit assignments here so the Stmt tree carries the correct
        // initial values.  Assignments where src and dst share the same
        // register (i.e. would collapse to the same name) are skipped.
        let mut stmts = stmts;
        if let Some(sb) = ctx.ssa.blocks.get(&header) {
            for phi in &sb.phis {
                // Entry-edge operand: comes from a predecessor NOT inside the loop body.
                let entry_op = phi
                    .operands
                    .iter()
                    .find(|(pred, _)| !loop_info.body.contains(pred))
                    .map(|(_, v)| v);
                if let Some(src) = entry_op {
                    // Skip if src == phi.dst (trivial) or same register (collapses to
                    // the same name after SSA rename — no assignment needed).
                    if *src != phi.dst && src.reg() != phi.dst.reg() {
                        stmts.push(Stmt::Expr(crate::ssa::SsaInsn {
                            dst: Some(phi.dst.clone()),
                            uses: vec![src.clone()],
                            insn: crate::decode::Instruction {
                                addr: 0,
                                op: Opcode::Move,
                                size: 1,
                                dst: None,
                                src: crate::decode::RegList::empty(),
                                literal: 0,
                                target: None,
                                pool_idx: None,
                            },
                        }));
                    }
                }
            }
        }

        if let Some(bt) = body_target {
            stack.push(Frame::AwaitingWhileBody {
                end,
                stmts,
                cond,
                header_stmts,
                continuation,
            });
            stack.push(Frame::Processing {
                end: Some(header),
                stmts: Vec::new(),
                current: Some(bt),
            });
        } else {
            // No body target — body is just the header stmts
            let body = Stmt::Seq(header_stmts);
            stmts.push(Stmt::While {
                cond,
                body: Box::new(body),
            });
            stack.push(Frame::Processing {
                end,
                stmts,
                current: continuation,
            });
        }
    } else {
        // Do-while / infinite pattern — iterate body blocks
        ctx.visited.insert(header);
        let body_blocks: std::collections::VecDeque<BlockIdx> = loop_info
            .body
            .iter()
            .copied()
            .filter(|b| *b != header)
            .collect();

        let mut body_stmts = Vec::new();
        if let Some(sb) = ctx.ssa.blocks.get(&header) {
            for insn in &sb.insns {
                if !matches!(insn.insn.op, Opcode::Goto | Opcode::Goto16 | Opcode::Goto32) {
                    body_stmts.push(Stmt::Expr(insn.clone()));
                }
            }
        }

        // Find the first unvisited body block to start with
        let mut remaining_blocks = body_blocks;
        let first = loop {
            match remaining_blocks.pop_front() {
                Some(b) if ctx.visited.contains(&b) => continue,
                Some(b) => break Some(b),
                None => break None,
            }
        };

        if let Some(b) = first {
            stack.push(Frame::AwaitingDoWhileBlock {
                end,
                stmts,
                cond,
                header,
                body_stmts,
                remaining_blocks,
                continuation,
            });
            stack.push(Frame::Processing {
                end: Some(header),
                stmts: Vec::new(),
                current: Some(b),
            });
        } else {
            // No body blocks — just header stmts
            let body = flatten_single(body_stmts);
            let mut stmts = stmts;
            stmts.push(Stmt::DoWhile {
                body: Box::new(body),
                cond,
            });
            stack.push(Frame::Processing {
                end,
                stmts,
                current: continuation,
            });
        }
    }
}

/// One pending unit of work in the iterative structurer.
enum Frame {
    /// Main block-walk state. Drives `drive_processing`.
    Processing {
        end: Option<BlockIdx>,
        stmts: Vec<Stmt>,
        current: Option<BlockIdx>,
    },
    /// Just launched the then-body of an if/else. When it returns,
    /// either spawn the else-body or assemble Stmt::If with no else.
    AwaitingIfThen {
        end: Option<BlockIdx>,
        stmts: Vec<Stmt>,
        cond: Condition,
        else_target: Option<BlockIdx>,
        merge: Option<BlockIdx>,
        continuation: Option<BlockIdx>,
    },
    /// Just launched the else-body. When it returns, assemble Stmt::If.
    AwaitingIfElse {
        end: Option<BlockIdx>,
        stmts: Vec<Stmt>,
        cond: Condition,
        then_body: Stmt,
        continuation: Option<BlockIdx>,
    },
    /// Just launched a switch case body. When it returns, splice it
    /// into `completed_cases` and either spawn the next case or move
    /// on to the default.
    AwaitingSwitchCase {
        end: Option<BlockIdx>,
        stmts: Vec<Stmt>,
        value_var: VarId,
        merge: Option<BlockIdx>,
        current_keys: Vec<i32>,
        completed_cases: Vec<(Vec<i32>, Box<Stmt>)>,
        remaining_cases: std::collections::VecDeque<(BlockIdx, Vec<i32>)>,
        default_target: Option<BlockIdx>,
        continuation: Option<BlockIdx>,
    },
    /// Just launched the switch default body. When it returns,
    /// assemble Stmt::Switch.
    AwaitingSwitchDefault {
        end: Option<BlockIdx>,
        stmts: Vec<Stmt>,
        value_var: VarId,
        cases: Vec<(Vec<i32>, Box<Stmt>)>,
        continuation: Option<BlockIdx>,
    },
    /// Just launched the body of a while loop. When it returns,
    /// assemble Stmt::While (with optional header_stmts prepended).
    AwaitingWhileBody {
        end: Option<BlockIdx>,
        stmts: Vec<Stmt>,
        cond: Condition,
        header_stmts: Vec<Stmt>,
        continuation: Option<BlockIdx>,
    },
    /// Just launched one body block of a do-while / infinite loop.
    /// When it returns, append to body_stmts, check for more body
    /// blocks, either spawn the next one or assemble Stmt::DoWhile.
    AwaitingDoWhileBlock {
        end: Option<BlockIdx>,
        stmts: Vec<Stmt>,
        cond: Condition,
        header: BlockIdx,
        body_stmts: Vec<Stmt>,
        remaining_blocks: std::collections::VecDeque<BlockIdx>,
        continuation: Option<BlockIdx>,
    },
}

// ── Exception region structuring ────────────────────────────────────

/// Lowest DEX instruction address reachable from this Stmt, if any.
///
/// Used by `wrap_try_catch` to partition the method body by `ExceptionRegion`
/// bounds. Returns `None` for variants that do not carry an originating insn
/// (Return / Throw / InlinedReturnConcat / StringConcat / control-flow
/// markers); callers attach those to the surrounding addr-bearing group.
fn first_addr(stmt: &Stmt) -> Option<u32> {
    match stmt {
        Stmt::Expr(i) | Stmt::InlinedReturn(i) | Stmt::InlinedThrow(i) => Some(i.insn.addr),
        Stmt::Seq(v) => v.iter().find_map(first_addr),
        Stmt::If { then_body, else_body, .. } => {
            first_addr(then_body).or_else(|| else_body.as_deref().and_then(first_addr))
        }
        Stmt::While { body, .. }
        | Stmt::DoWhile { body, .. }
        | Stmt::Synchronized { body, .. }
        | Stmt::ForEach { body, .. }
        | Stmt::TryCatch { body, .. } => first_addr(body),
        Stmt::For { init, body, .. } => first_addr(init).or_else(|| first_addr(body)),
        Stmt::Switch { cases, default, .. } => cases
            .iter()
            .find_map(|(_, b)| first_addr(b))
            .or_else(|| default.as_deref().and_then(first_addr)),
        Stmt::StringSwitch { cases, default, .. } => cases
            .iter()
            .find_map(|(_, b)| first_addr(b))
            .or_else(|| default.as_deref().and_then(first_addr)),
        Stmt::MultiArm { arms, default, .. } => arms
            .iter()
            .find_map(|a| first_addr(&a.body))
            .or_else(|| default.as_deref().and_then(first_addr)),
        Stmt::Unrecognized { raw, .. } => raw.first().map(|i| i.insn.addr),
        Stmt::Let { .. } => None,
        Stmt::ResolvedFragment { .. } => None,
        Stmt::OutlinedBlock { .. } => None,
        Stmt::BooleanAssign { .. } => None,
        Stmt::Return(_)
        | Stmt::Throw(_)
        | Stmt::InlinedReturnConcat(_)
        | Stmt::StringConcat { .. }
        | Stmt::Break
        | Stmt::Continue
        | Stmt::Goto(_) => None,
    }
}

/// Partition a flat list of Stmts into (pre, in, post) by region address
/// bounds. Stmts without an addr attach to the surrounding group: once the
/// walk has entered `in_region` they stay with `in_region` (so terminators
/// like `Return` / `Throw` at the tail of the try region land correctly);
/// before entering, they stay with `pre`. After exiting, they stay with
/// `post`.
fn partition_by_region(
    seq: Vec<Stmt>,
    start_addr: u32,
    end_addr: u32,
) -> (Vec<Stmt>, Vec<Stmt>, Vec<Stmt>) {
    let mut pre = Vec::new();
    let mut in_region = Vec::new();
    let mut post = Vec::new();
    // 0 = before in, 1 = inside in, 2 = after in (post). Monotone.
    let mut state = 0u8;
    for s in seq {
        match first_addr(&s) {
            Some(a) if a < start_addr && state == 0 => pre.push(s),
            Some(a) if a < end_addr => {
                state = state.max(1);
                in_region.push(s);
            }
            Some(_) => {
                state = 2;
                post.push(s);
            }
            None => match state {
                0 => pre.push(s),
                1 => in_region.push(s),
                _ => post.push(s),
            },
        }
    }
    (pre, in_region, post)
}

/// Wrap a Stmt in TryCatch if the block range overlaps with exception regions.
///
/// Multiple DEX try_items can share an identical `(start_addr, end_addr)`
/// extent — d8 and r8 sometimes emit one try_item per catch arm, even though
/// javac emits one try_item per source-level `try {}` block with all handlers
/// merged. Without grouping, each region wraps the previous result, producing
/// an N-deep cascade `Try { Try { Try { ... } } }` that is parseable Java but
/// unreadable at depth (12-deep nests observed in real-world R8-released
/// APKs).
///
/// Regions are grouped by `(start_addr, end_addr)` BEFORE iteration so
/// sibling-extent regions merge into one `Stmt::TryCatch` with all handlers as
/// flat catch arms. Genuine nested try shapes — different extents — stay
/// nested, since the partition_by_region logic processes each unique extent
/// independently.
pub fn wrap_try_catch(stmt: Stmt, cfg: &Cfg, ssa: &SsaBody) -> Stmt {
    if cfg.exception_regions.is_empty() {
        return stmt;
    }

    let mut groups: BTreeMap<(u32, u32), Vec<&crate::cfg::ExceptionRegion>> = BTreeMap::new();
    let mut group_order: Vec<(u32, u32)> = Vec::new();
    for region in &cfg.exception_regions {
        let key = (region.start_addr, region.end_addr);
        if !groups.contains_key(&key) {
            group_order.push(key);
        }
        groups.entry(key).or_default().push(region);
    }

    let mut result = stmt;
    for key in &group_order {
        let Some(regions) = groups.get(key) else {
            continue;
        };
        let (group_start, group_end) = *key;
        let mut catches = Vec::new();
        for region in regions.iter().copied() {
            for (kind, handler_block) in &region.handler_blocks {
                let exception_type = match kind {
                    EdgeKind::ExceptionHandler(tidx) => Some(*tidx),
                    EdgeKind::ExceptionCatchAll => None,
                    _ => continue,
                };

                // Find MoveException var in handler block
                let var = ssa.blocks.get(handler_block).and_then(|sb| {
                    sb.insns
                        .iter()
                        .find(|i| i.insn.op == Opcode::MoveException)
                        .and_then(|i| i.dst.clone())
                });

                // Structure handler body — convert terminal opcodes to typed Stmts.
                // Follow goto chains to include successor blocks in the handler body.
                // A visited set terminates walks that cycle back into themselves
                // (produced by obfuscated bytecode where a handler body contains
                // an intra-handler loop); without it, a cycle grows handler_insns
                // unboundedly and allocates memory without terminating.
                let body = {
                    let mut handler_insns: Vec<&SsaInsn> = Vec::new();
                    let mut visited: std::collections::BTreeSet<_> =
                        std::collections::BTreeSet::new();
                    let mut cur_block = *handler_block;
                    while let Some(sb) = ssa.blocks.get(&cur_block) {
                        if !visited.insert(cur_block) {
                            break;
                        }
                        for insn in &sb.insns {
                            if insn.insn.op == Opcode::MoveException {
                                continue;
                            }
                            handler_insns.push(insn);
                        }
                        let last_op = sb.insns.last().map(|i| i.insn.op);
                        // If the block ends with a goto, follow it
                        if matches!(
                            last_op,
                            Some(Opcode::Goto | Opcode::Goto16 | Opcode::Goto32)
                        ) {
                            // Remove the goto we just pushed
                            handler_insns.pop();
                            // Follow to the goto target via CFG successors
                            if let Some(block) = cfg.blocks.get(cur_block.0 as usize) {
                                if let Some(edge) = block.successors.first() {
                                    cur_block = edge.target;
                                    continue;
                                }
                            }
                        }
                        // If the block doesn't end with a terminator, follow fall-through
                        let is_terminator = matches!(
                            last_op,
                            Some(
                                Opcode::ReturnVoid
                                    | Opcode::Return
                                    | Opcode::ReturnWide
                                    | Opcode::ReturnObject
                                    | Opcode::Throw
                                    | Opcode::Goto
                                    | Opcode::Goto16
                                    | Opcode::Goto32
                            )
                        );
                        if !is_terminator {
                            if let Some(block) = cfg.blocks.get(cur_block.0 as usize) {
                                // Follow the single fall-through successor
                                let fallthrough: Vec<_> = block
                                    .successors
                                    .iter()
                                    .filter(|e| e.kind == EdgeKind::FallThrough)
                                    .collect();
                                if let Some(edge) = fallthrough.first() {
                                    cur_block = edge.target;
                                    continue;
                                }
                            }
                        }
                        break;
                    }
                    let stmts: Vec<Stmt> = handler_insns
                        .iter()
                        .map(|i| match i.insn.op {
                            Opcode::ReturnVoid => Stmt::Return(None),
                            Opcode::Return | Opcode::ReturnWide | Opcode::ReturnObject => {
                                Stmt::Return(i.uses.first().cloned())
                            }
                            Opcode::Throw => i
                                .uses
                                .first()
                                .map_or(Stmt::Seq(vec![]), |v| Stmt::Throw(v.clone())),
                            _ => Stmt::Expr((*i).clone()),
                        })
                        .filter(|s| !matches!(s, Stmt::Seq(v) if v.is_empty()))
                        .collect();
                    flatten_single(stmts)
                };

                catches.push(CatchClause {
                    exception_type,
                    var,
                    body,
                });
            }
        }

        if !catches.is_empty() {
            // Partition the current body by this group's addr bounds. Pre- and
            // post-region Stmts stay at the enclosing scope; only the in-region
            // slice becomes the try body. This keeps DEX-level pre-try
            // definitions (e.g. a `const-string` that d8 hoisted to a common
            // dominator of the normal path and the handlers) in scope for both
            // the try body and sibling catch bodies.
            let flat: Vec<Stmt> = match result {
                Stmt::Seq(v) => v,
                other => vec![other],
            };
            let (pre, in_region, post) = partition_by_region(flat, group_start, group_end);
            if in_region.is_empty() {
                // Degenerate: no Stmt falls inside the region. Fall back to
                // wrapping the full body so the handlers are still surfaced.
                let body = if pre.is_empty() && post.is_empty() {
                    Stmt::Seq(Vec::new())
                } else {
                    let mut rest = pre;
                    rest.extend(post);
                    flatten_single(rest)
                };
                result = Stmt::TryCatch {
                    body: Box::new(body),
                    catches,
                };
            } else {
                let try_body = flatten_single(in_region);
                let try_stmt = Stmt::TryCatch {
                    body: Box::new(try_body),
                    catches,
                };
                let mut rebuilt = pre;
                rebuilt.push(try_stmt);
                rebuilt.extend(post);
                result = flatten_single(rebuilt);
            }
        }
    }

    result
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::BasicBlock;
    use crate::cfg::Edge;
    use crate::decode::{Instruction, RegList};
    use crate::ssa::{SsaBlock, SsaInsn};

    fn empty_cfg_block(id: u32) -> BasicBlock {
        BasicBlock {
            id: BlockIdx(id),
            start_addr: id,
            instructions: vec![],
            successors: vec![],
            predecessors: BTreeSet::new(),
        }
    }

    fn make_simple_insn(addr: u32, op: Opcode) -> crate::decode::Instruction {
        Instruction {
            addr,
            op,
            size: 1,
            dst: None,
            src: RegList::empty(),
            literal: 0,
            target: None,
            pool_idx: None,
        }
    }

    fn build_cfg_from_edges(num_blocks: u32, edges: &[(u32, u32, EdgeKind)]) -> Cfg {
        let mut blocks: Vec<BasicBlock> = (0..num_blocks)
            .map(|i| {
                let mut b = empty_cfg_block(i);
                b.instructions = vec![make_simple_insn(i, Opcode::Nop)];
                b
            })
            .collect();

        for (src, dst, kind) in edges {
            blocks[*src as usize].successors.push(Edge {
                target: BlockIdx(*dst),
                kind: kind.clone(),
            });
            blocks[*dst as usize].predecessors.insert(BlockIdx(*src));
        }

        Cfg {
            blocks,
            entry: BlockIdx(0),
            exception_regions: vec![],
            addr_to_block: BTreeMap::new(),
        }
    }

    // --- Dominator tests ---

    #[test]
    fn dom_linear_chain() {
        // A(0) -> B(1) -> C(2)
        let cfg = build_cfg_from_edges(
            3,
            &[(0, 1, EdgeKind::FallThrough), (1, 2, EdgeKind::FallThrough)],
        );
        let idom = compute_dominators(&cfg);
        assert_eq!(idom[&BlockIdx(0)], BlockIdx(0));
        assert_eq!(idom[&BlockIdx(1)], BlockIdx(0));
        assert_eq!(idom[&BlockIdx(2)], BlockIdx(1));
    }

    #[test]
    fn dom_diamond() {
        // A(0) -> {B(1), C(2)} -> D(3)
        let cfg = build_cfg_from_edges(
            4,
            &[
                (0, 1, EdgeKind::FallThrough),
                (0, 2, EdgeKind::Branch),
                (1, 3, EdgeKind::FallThrough),
                (2, 3, EdgeKind::FallThrough),
            ],
        );
        let idom = compute_dominators(&cfg);
        assert_eq!(idom[&BlockIdx(1)], BlockIdx(0));
        assert_eq!(idom[&BlockIdx(2)], BlockIdx(0));
        assert_eq!(idom[&BlockIdx(3)], BlockIdx(0));
    }

    #[test]
    fn dom_loop() {
        // A(0) -> B(1) -> C(2) -> B(1) (back-edge)
        //                C(2) -> D(3) (exit)
        let cfg = build_cfg_from_edges(
            4,
            &[
                (0, 1, EdgeKind::FallThrough),
                (1, 2, EdgeKind::FallThrough),
                (2, 1, EdgeKind::Branch),
                (2, 3, EdgeKind::FallThrough),
            ],
        );
        let idom = compute_dominators(&cfg);
        assert_eq!(idom[&BlockIdx(1)], BlockIdx(0));
        assert_eq!(idom[&BlockIdx(2)], BlockIdx(1));
        assert_eq!(idom[&BlockIdx(3)], BlockIdx(2));
    }

    // --- Post-dominator tests ---

    #[test]
    fn pdom_diamond() {
        let cfg = build_cfg_from_edges(
            4,
            &[
                (0, 1, EdgeKind::FallThrough),
                (0, 2, EdgeKind::Branch),
                (1, 3, EdgeKind::FallThrough),
                (2, 3, EdgeKind::FallThrough),
            ],
        );
        // Make block 3 terminal (return)
        let ipdom = compute_post_dominators(&cfg);
        assert_eq!(ipdom.get(&BlockIdx(0)), Some(&droidsaw_common::PostDom::Node(BlockIdx(3))));
        assert_eq!(ipdom.get(&BlockIdx(1)), Some(&droidsaw_common::PostDom::Node(BlockIdx(3))));
        assert_eq!(ipdom.get(&BlockIdx(2)), Some(&droidsaw_common::PostDom::Node(BlockIdx(3))));
    }

    // --- Natural loop tests ---

    #[test]
    fn loop_detection_simple() {
        // A(0) -> B(1) -> C(2) -> B(1)
        let cfg = build_cfg_from_edges(
            3,
            &[
                (0, 1, EdgeKind::FallThrough),
                (1, 2, EdgeKind::FallThrough),
                (2, 1, EdgeKind::Branch),
            ],
        );
        let idom = compute_dominators(&cfg);
        let loops = find_natural_loops(&cfg, &idom);
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].header, BlockIdx(1));
        assert!(loops[0].body.contains(&BlockIdx(1)));
        assert!(loops[0].body.contains(&BlockIdx(2)));
    }

    // --- Reverse postorder test ---

    #[test]
    fn rpo_order() {
        let cfg = build_cfg_from_edges(
            4,
            &[
                (0, 1, EdgeKind::FallThrough),
                (0, 2, EdgeKind::Branch),
                (1, 3, EdgeKind::FallThrough),
                (2, 3, EdgeKind::FallThrough),
            ],
        );
        let rpo = reverse_postorder(&cfg);
        // Entry should be first
        assert_eq!(rpo[0], BlockIdx(0));
        // Block 3 should be last (post-dom)
        assert_eq!(*rpo.last().unwrap(), BlockIdx(3));
    }

    // --- Structuring tests ---

    #[test]
    fn structure_linear_code() {
        // Single block with two instructions → Seq of Exprs
        let mut blocks = BTreeMap::new();
        blocks.insert(
            BlockIdx(0),
            SsaBlock {
                id: BlockIdx(0),
                phis: vec![],
                insns: vec![
                    SsaInsn {
                        insn: make_simple_insn(0, Opcode::Nop),
                        dst: None,
                        uses: vec![],
                    },
                    SsaInsn {
                        insn: Instruction {
                            addr: 1,
                            op: Opcode::ReturnVoid,
                            size: 1,
                            dst: None,
                            src: RegList::empty(),
                            literal: 0,
                            target: None,
                            pool_idx: None,
                        },
                        dst: None,
                        uses: vec![],
                    },
                ],
            },
        );
        let ssa = SsaBody {
            blocks,
            entry: BlockIdx(0),
            var_counter: 0,
            param_vars: vec![],
        };

        let cfg_block = BasicBlock {
            id: BlockIdx(0),
            start_addr: 0,
            instructions: vec![
                make_simple_insn(0, Opcode::Nop),
                make_simple_insn(1, Opcode::ReturnVoid),
            ],
            successors: vec![],
            predecessors: BTreeSet::new(),
        };
        let cfg = Cfg {
            blocks: vec![cfg_block],
            entry: BlockIdx(0),
            exception_regions: vec![],
            addr_to_block: BTreeMap::new(),
        };

        let stmt = structure(&ssa, &cfg);
        match stmt {
            Stmt::Seq(ref stmts) => {
                assert_eq!(stmts.len(), 2);
                assert!(matches!(stmts[0], Stmt::Expr(_)));
                assert!(matches!(stmts[1], Stmt::Return(None)));
            }
            _ => panic!("expected Seq, got {stmt:?}"),
        }
    }

    #[test]
    fn dominates_basic() {
        let mut idom = BTreeMap::new();
        idom.insert(BlockIdx(0), BlockIdx(0));
        idom.insert(BlockIdx(1), BlockIdx(0));
        idom.insert(BlockIdx(2), BlockIdx(1));

        assert!(dominates(BlockIdx(0), BlockIdx(2), &idom));
        assert!(dominates(BlockIdx(1), BlockIdx(2), &idom));
        assert!(!dominates(BlockIdx(2), BlockIdx(0), &idom));
    }

    /// P11 regression guard: `structure_region` must handle a deep
    /// nested-if ladder without blowing the stack. Prior to the
    /// iterative rewrite, the recursive formulation overflowed the
    /// default 2MB test-thread stack at roughly 5-6k levels of
    /// nesting. 10k here is ~2x headroom and still firmly past the
    /// overflow threshold.
    ///
    /// `#[ignore]`-gated because post-dominator computation on 10k
    /// blocks takes ~60s in debug mode, and the corpus oracle is
    /// the primary validation for this rewrite anyway. Run with
    /// `cargo test --release structure_region_handles_deep_nested_if_ladder -- --ignored`
    /// to exercise it.
    ///
    /// CFG shape: a chain of `N` conditional blocks where each block
    /// `i < N-1` branches to `i+1` (deeper) or falls through to the
    /// terminal block `M` (the merge for every level). Block `M` is
    /// the only terminal. Post-dominator of every branch block is
    /// `M`, so each level's if/else collapses the else-body to empty
    /// and recurses into the then-body — producing an N-deep stack
    /// of structure_region calls in the old code.
    #[test]
    #[ignore = "stress test: 10k blocks ~60s in debug; run via `cargo test --release -- --ignored`. Corpus oracle is the primary validation."]
    fn structure_region_handles_deep_nested_if_ladder() {
        use crate::ssa::SsaBody;

        const DEPTH: u32 = 10_000;
        const MERGE: u32 = DEPTH; // block index of the terminal merge

        let num_blocks = DEPTH + 1;
        let mut blocks: Vec<BasicBlock> = (0..num_blocks)
            .map(|i| {
                let mut b = empty_cfg_block(i);
                // Block content doesn't matter for the recursion-depth
                // test; a single Nop keeps SSA classification happy.
                b.instructions = vec![make_simple_insn(i, Opcode::Nop)];
                b
            })
            .collect();

        // Wire up edges: block i < DEPTH has (Branch → i+1, FallThrough → MERGE).
        // Block MERGE is terminal.
        for i in 0..DEPTH {
            blocks[i as usize].successors.push(Edge {
                target: BlockIdx(i + 1),
                kind: EdgeKind::Branch,
            });
            blocks[i as usize].successors.push(Edge {
                target: BlockIdx(MERGE),
                kind: EdgeKind::FallThrough,
            });
        }
        // Fill predecessors
        for i in 0..DEPTH {
            blocks[(i + 1) as usize].predecessors.insert(BlockIdx(i));
            blocks[MERGE as usize].predecessors.insert(BlockIdx(i));
        }

        let cfg = Cfg {
            blocks,
            entry: BlockIdx(0),
            exception_regions: vec![],
            addr_to_block: BTreeMap::new(),
        };

        // Empty SsaBody — `extract_condition` returns a default
        // Condition::Var(v0_0) when the block is absent, which is
        // fine for this stack-depth test.
        let ssa = SsaBody {
            blocks: BTreeMap::new(),
            entry: BlockIdx(0),
            var_counter: 0,
            param_vars: vec![],
        };

        // Must not stack-overflow on the default 2MB test thread stack.
        // With the iterative driver, the 20k-deep frame stack lives
        // on the heap.
        let stmt = structure(&ssa, &cfg);

        // Sanity: output must be a non-empty Stmt. We don't assert the
        // exact tree shape — that's covered by the corpus oracle — but
        // the top-level structure should at least contain an `If` at
        // some level.
        fn contains_if(s: &Stmt) -> bool {
            match s {
                Stmt::If { .. } => true,
                Stmt::Seq(ss) => ss.iter().any(contains_if),
                _ => false,
            }
        }
        assert!(
            contains_if(&stmt),
            "deep nested-if ladder should produce at least one Stmt::If"
        );
    }

    // ── wrap_try_catch: same-extent cascade collapsing ─────────────────

    fn make_ssa_insn(addr: u32) -> SsaInsn {
        SsaInsn {
            insn: make_simple_insn(addr, Opcode::Nop),
            dst: None,
            uses: vec![],
        }
    }

    fn cfg_with_regions(regions: Vec<crate::cfg::ExceptionRegion>) -> Cfg {
        Cfg {
            blocks: vec![],
            entry: BlockIdx(0),
            exception_regions: regions,
            addr_to_block: BTreeMap::new(),
        }
    }

    fn empty_ssa() -> SsaBody {
        SsaBody {
            blocks: BTreeMap::new(),
            entry: BlockIdx(0),
            var_counter: 0,
            param_vars: vec![],
        }
    }

    fn dummy_type(id: u16) -> TypeIdx {
        TypeIdx(u32::from(id))
    }

    fn count_try_depth(stmt: &Stmt) -> usize {
        match stmt {
            Stmt::TryCatch { body, .. } => 1 + count_try_depth(body),
            Stmt::Seq(v) => v.iter().map(count_try_depth).max().unwrap_or(0),
            _ => 0,
        }
    }

    #[test]
    fn wrap_try_catch_collapses_same_extent_cascade() {
        // 3 regions over identical extent (10, 20) — d8/r8 emitting one
        // try_item per catch arm. The collapse rule flattens the
        // would-be 3-deep cascade `Try{ Try{ Try{ X } catch A } catch B } catch C`
        // into `Try{ X } catch A catch B catch C`.
        let regions = vec![
            crate::cfg::ExceptionRegion {
                start_addr: 10,
                end_addr: 20,
                handler_blocks: vec![(EdgeKind::ExceptionHandler(dummy_type(1)), BlockIdx(100))],
            },
            crate::cfg::ExceptionRegion {
                start_addr: 10,
                end_addr: 20,
                handler_blocks: vec![(EdgeKind::ExceptionHandler(dummy_type(2)), BlockIdx(101))],
            },
            crate::cfg::ExceptionRegion {
                start_addr: 10,
                end_addr: 20,
                handler_blocks: vec![(EdgeKind::ExceptionHandler(dummy_type(3)), BlockIdx(102))],
            },
        ];
        let cfg = cfg_with_regions(regions);
        let ssa = empty_ssa();

        let body = Stmt::Seq(vec![Stmt::Expr(make_ssa_insn(15))]);
        let result = wrap_try_catch(body, &cfg, &ssa);

        assert_eq!(count_try_depth(&result), 1, "cascade must collapse to a single TryCatch level");
        match &result {
            Stmt::TryCatch { catches, .. } => {
                assert_eq!(catches.len(), 3, "all 3 handlers must merge as sibling catch arms");
                assert_eq!(catches[0].exception_type, Some(dummy_type(1)));
                assert_eq!(catches[1].exception_type, Some(dummy_type(2)));
                assert_eq!(catches[2].exception_type, Some(dummy_type(3)));
            }
            other => panic!("expected flat Stmt::TryCatch, got {other:?}"),
        }
    }

    #[test]
    fn wrap_try_catch_preserves_nested_extents() {
        // Region A covers (5, 30), region B covers (10, 20) — B is
        // structurally nested inside A. Different extents → must stay
        // nested. This guards against an over-aggressive collapser that
        // would merge any two regions regardless of extent.
        let regions = vec![
            crate::cfg::ExceptionRegion {
                start_addr: 5,
                end_addr: 30,
                handler_blocks: vec![(EdgeKind::ExceptionHandler(dummy_type(10)), BlockIdx(200))],
            },
            crate::cfg::ExceptionRegion {
                start_addr: 10,
                end_addr: 20,
                handler_blocks: vec![(EdgeKind::ExceptionHandler(dummy_type(11)), BlockIdx(201))],
            },
        ];
        let cfg = cfg_with_regions(regions);
        let ssa = empty_ssa();

        let body = Stmt::Seq(vec![
            Stmt::Expr(make_ssa_insn(7)),
            Stmt::Expr(make_ssa_insn(15)),
            Stmt::Expr(make_ssa_insn(25)),
        ]);
        let result = wrap_try_catch(body, &cfg, &ssa);

        assert!(
            count_try_depth(&result) >= 2,
            "different extents must remain nested, got depth {} in {result:?}",
            count_try_depth(&result),
        );
    }

    #[test]
    fn wrap_try_catch_single_region_multi_handler_unchanged() {
        // One region with two handler_blocks — javac's multi-catch shape.
        // The fix must not regress this path: still one TryCatch with two
        // catch arms.
        let regions = vec![crate::cfg::ExceptionRegion {
            start_addr: 10,
            end_addr: 20,
            handler_blocks: vec![
                (EdgeKind::ExceptionHandler(dummy_type(1)), BlockIdx(100)),
                (EdgeKind::ExceptionHandler(dummy_type(2)), BlockIdx(101)),
            ],
        }];
        let cfg = cfg_with_regions(regions);
        let ssa = empty_ssa();

        let body = Stmt::Seq(vec![Stmt::Expr(make_ssa_insn(15))]);
        let result = wrap_try_catch(body, &cfg, &ssa);

        assert_eq!(count_try_depth(&result), 1);
        match &result {
            Stmt::TryCatch { catches, .. } => assert_eq!(catches.len(), 2),
            other => panic!("expected Stmt::TryCatch, got {other:?}"),
        }
    }

    #[test]
    fn wrap_try_catch_collapses_mixed_per_type_and_catch_all() {
        // Mixed catch_all + per-type with same extent. The catch_all order
        // matters in Java (catch_all = `catch (Throwable)` semantically;
        // emit order is preserved from region order). All three must merge.
        let regions = vec![
            crate::cfg::ExceptionRegion {
                start_addr: 10,
                end_addr: 20,
                handler_blocks: vec![(EdgeKind::ExceptionHandler(dummy_type(1)), BlockIdx(100))],
            },
            crate::cfg::ExceptionRegion {
                start_addr: 10,
                end_addr: 20,
                handler_blocks: vec![(EdgeKind::ExceptionCatchAll, BlockIdx(101))],
            },
        ];
        let cfg = cfg_with_regions(regions);
        let ssa = empty_ssa();

        let body = Stmt::Seq(vec![Stmt::Expr(make_ssa_insn(15))]);
        let result = wrap_try_catch(body, &cfg, &ssa);

        assert_eq!(count_try_depth(&result), 1);
        match &result {
            Stmt::TryCatch { catches, .. } => {
                assert_eq!(catches.len(), 2);
                assert_eq!(catches[0].exception_type, Some(dummy_type(1)));
                assert_eq!(catches[1].exception_type, None, "catch_all emits as None");
            }
            other => panic!("expected Stmt::TryCatch, got {other:?}"),
        }
    }
}
