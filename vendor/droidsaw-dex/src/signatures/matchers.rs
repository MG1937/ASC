//! Composable matcher predicates shared across `signatures/<dialect>/*`.
//!
//! A small library of pure, allocation-free predicates / destructurers
//! each recognizer composes by hand instead of re-walking [`Stmt`] /
//! [`SsaInsn`] / [`DexFile`] pools by bespoke code.
//!
//! Combinator inventory (13, cap = 15):
//!
//! | Group | Combinator |
//! |---|---|
//! | Stmt destructurer | [`as_switch_at`] |
//! | Stmt predicates | [`matches_seq`], [`matches_seq_prefix`], [`matches_assign`], [`matches_throw_var`], [`matches_if_else`] |
//! | Insn predicates | [`matches_invoke_named`], [`matches_invoke_signature`], [`matches_new_instance_of`], [`matches_const_string`] |
//! | Var-flow predicates | [`var_eq`], [`var_used_in`], [`body_writes_var`] |
//!
//! All combinators take `&` borrows and either return `bool` or
//! `Option<&_>` / `Option<(&_, ...)>` (no `Vec`/`String` allocations on
//! the hot path). The `Stmt`-walking predicates (`body_writes_var`,
//! `matches_seq*`) recurse with bounded fan-out only — they descend into
//! direct sub-`Stmt` children of the supplied node, not through nested
//! sub-`Seq`s, matching the existing recognizer idiom.
//!
//! Predicate combinators that take an inner matcher accept `fn` pointers
//! (`fn(&Stmt) -> bool`, `fn(&SsaInsn) -> bool`, `fn(&Condition) -> bool`)
//! rather than `Box<dyn Fn>` to keep the surface allocation-free and the
//! type signatures inspectable. Captures-of-environment matchers are
//! out-of-scope for v1; if a recognizer needs to thread bindings through
//! a composition, it walks the IR by hand.

use crate::decode::PoolIndex;
use crate::ids::{MethodIdItem, ProtoIdItem};
use crate::opcodes::Opcode;
use crate::parser::DexFile;
use crate::ssa::{SsaInsn, VarId};
use crate::structure::{Condition, Stmt};

// ── Stmt destructurer ───────────────────────────────────────────────

/// Return `Some((value, cases, default))` if `stmts[position]` is a
/// non-empty `Stmt::Switch`, else `None`.
///
/// Collapses the bespoke `let Some(stmt) = stmts.get(position) else {
/// return NoMatch }` + `let Stmt::Switch { value, cases, default } = stmt
/// else { return NoMatch }` + `cases.is_empty()` triple into a single
/// `?`-friendly extractor. Used by the `switch (Int)` recognizers
/// (`javac21::switch_int`, `kotlinc19::when_int`).
///
/// ```
/// # use droidsaw_dex::signatures::matchers::as_switch_at;
/// # use droidsaw_dex::structure::Stmt;
/// # use droidsaw_dex::ssa::VarId;
/// let stmts: Vec<Stmt> = vec![Stmt::Switch {
///     value: VarId::new(0, 0),
///     cases: vec![(vec![1], Box::new(Stmt::Seq(vec![])))],
///     default: None,
/// }];
/// let (_v, cases, _d) = as_switch_at(&stmts, 0).expect("non-empty switch");
/// assert_eq!(cases.len(), 1);
/// assert!(as_switch_at(&stmts, 1).is_none());
/// ```
#[allow(clippy::type_complexity, reason = "Return type mirrors Stmt::Switch's three-arm tuple shape (scrutinee VarId, arm list, default branch); aliasing it would just relocate the complexity into a typedef declaration.")]
pub fn as_switch_at(
    stmts: &[Stmt],
    position: usize,
) -> Option<(&VarId, &Vec<(Vec<i32>, Box<Stmt>)>, &Option<Box<Stmt>>)> {
    match stmts.get(position)? {
        Stmt::Switch {
            value,
            cases,
            default,
        } if !cases.is_empty() => Some((value, cases, default)),
        _ => None,
    }
}

// ── Stmt predicates ─────────────────────────────────────────────────

/// `true` iff `body` is a `Stmt::Seq` whose contents pairwise satisfy
/// `matchers` AND the lengths are equal.
///
/// ```
/// # use droidsaw_dex::signatures::matchers::matches_seq;
/// # use droidsaw_dex::structure::Stmt;
/// let body = Stmt::Seq(vec![Stmt::Break, Stmt::Continue]);
/// fn is_break(s: &Stmt) -> bool { matches!(s, Stmt::Break) }
/// fn is_continue(s: &Stmt) -> bool { matches!(s, Stmt::Continue) }
/// assert!(matches_seq(&body, &[is_break, is_continue]));
/// assert!(!matches_seq(&body, &[is_break]));
/// ```
pub fn matches_seq(body: &Stmt, matchers: &[fn(&Stmt) -> bool]) -> bool {
    let Stmt::Seq(items) = body else {
        return false;
    };
    items.len() == matchers.len() && items.iter().zip(matchers.iter()).all(|(s, m)| m(s))
}

/// `true` iff `body` is a `Stmt::Seq` whose first `matchers.len()`
/// elements pairwise satisfy `matchers`. Trailing items are unconstrained.
///
/// ```
/// # use droidsaw_dex::signatures::matchers::matches_seq_prefix;
/// # use droidsaw_dex::structure::Stmt;
/// let body = Stmt::Seq(vec![Stmt::Break, Stmt::Continue, Stmt::Break]);
/// fn is_break(s: &Stmt) -> bool { matches!(s, Stmt::Break) }
/// assert!(matches_seq_prefix(&body, &[is_break]));
/// assert!(!matches_seq_prefix(&body, &[is_break, is_break]));
/// ```
pub fn matches_seq_prefix(body: &Stmt, matchers: &[fn(&Stmt) -> bool]) -> bool {
    let Stmt::Seq(items) = body else {
        return false;
    };
    items.len() >= matchers.len()
        && items
            .iter()
            .take(matchers.len())
            .zip(matchers.iter())
            .all(|(s, m)| m(s))
}

/// `true` iff `stmt` is `Stmt::Expr(insn)` with `insn.dst == Some(dst_var)`
/// and `expr_matcher(insn)` holds.
///
/// ```
/// # use droidsaw_dex::signatures::matchers::matches_assign;
/// # use droidsaw_dex::structure::Stmt;
/// # use droidsaw_dex::ssa::{SsaInsn, VarId};
/// # use droidsaw_dex::decode::{Instruction, RegList};
/// # use droidsaw_dex::opcodes::Opcode;
/// let v = VarId::new(0, 0);
/// let insn = SsaInsn {
///     insn: Instruction { addr: 0, op: Opcode::ConstString, size: 0, dst: None,
///         src: RegList::empty(), literal: 0, target: None, pool_idx: None },
///     dst: Some(v.clone()),
///     uses: vec![],
/// };
/// let stmt = Stmt::Expr(insn);
/// fn is_const_string(i: &SsaInsn) -> bool { i.insn.op == Opcode::ConstString }
/// assert!(matches_assign(&stmt, &v, is_const_string));
/// assert!(!matches_assign(&stmt, &VarId::new(1, 0), is_const_string));
/// ```
pub fn matches_assign(stmt: &Stmt, dst_var: &VarId, expr_matcher: fn(&SsaInsn) -> bool) -> bool {
    matches!(stmt, Stmt::Expr(insn) if insn.dst.as_ref() == Some(dst_var) && expr_matcher(insn))
}

/// `true` iff `stmt` is `Stmt::Throw(v)` with `v == expected`.
///
/// ```
/// # use droidsaw_dex::signatures::matchers::matches_throw_var;
/// # use droidsaw_dex::structure::Stmt;
/// # use droidsaw_dex::ssa::VarId;
/// let v = VarId::new(0, 0);
/// let other = VarId::new(1, 0);
/// assert!(matches_throw_var(&Stmt::Throw(v.clone()), &v));
/// assert!(!matches_throw_var(&Stmt::Throw(v.clone()), &other));
/// assert!(!matches_throw_var(&Stmt::Break, &v));
/// ```
pub fn matches_throw_var(stmt: &Stmt, expected: &VarId) -> bool {
    matches!(stmt, Stmt::Throw(v) if v == expected)
}

/// `true` iff `stmt` is `Stmt::If` with an `else_body` and `cond` /
/// `then_matcher` / `else_matcher` all hold. Bare `if` (no else) does not
/// match — use the explicit destructure for that shape.
///
/// ```
/// # use droidsaw_dex::signatures::matchers::matches_if_else;
/// # use droidsaw_dex::structure::{Condition, Stmt};
/// # use droidsaw_dex::ssa::VarId;
/// # use droidsaw_dex::opcodes::Opcode;
/// let v = VarId::new(0, 0);
/// let stmt = Stmt::If {
///     cond: Condition::TestZero { var: v, op: Opcode::IfNez },
///     then_body: Box::new(Stmt::Break),
///     else_body: Some(Box::new(Stmt::Continue)),
/// };
/// fn is_test_zero(c: &Condition) -> bool { matches!(c, Condition::TestZero { .. }) }
/// fn is_break(s: &Stmt) -> bool { matches!(s, Stmt::Break) }
/// fn is_continue(s: &Stmt) -> bool { matches!(s, Stmt::Continue) }
/// assert!(matches_if_else(&stmt, is_test_zero, is_break, is_continue));
/// ```
pub fn matches_if_else(
    stmt: &Stmt,
    cond_matcher: fn(&Condition) -> bool,
    then_matcher: fn(&Stmt) -> bool,
    else_matcher: fn(&Stmt) -> bool,
) -> bool {
    let Stmt::If {
        cond,
        then_body,
        else_body: Some(else_body),
    } = stmt
    else {
        return false;
    };
    cond_matcher(cond) && then_matcher(then_body) && else_matcher(else_body)
}

// ── Insn predicates ─────────────────────────────────────────────────

/// `true` iff `insn` is an invoke whose pool reference resolves to a
/// method whose **simple name** equals `method_name`. Class descriptor
/// is unconstrained — use `matches_invoke_signature` for the full form.
///
/// ```no_run
/// # use droidsaw_dex::signatures::matchers::matches_invoke_named;
/// # use droidsaw_dex::ssa::SsaInsn;
/// # use droidsaw_dex::parser::DexFile;
/// # let insn: SsaInsn = unimplemented!();
/// # let dex: &DexFile = unimplemented!();
/// // Recognizer-side composition: was this an invoke of any "close" method?
/// let _ = matches_invoke_named(&insn, dex, "close");
/// ```
pub fn matches_invoke_named(insn: &SsaInsn, dex: &DexFile, method_name: &str) -> bool {
    let Some(method) = resolve_invoke_method(insn, dex) else {
        return false;
    };
    dex.get_string(method.name_idx).ok() == Some(method_name)
}

/// `true` iff `insn` is an invoke whose pool reference resolves to the
/// method with full Java-form signature `class.method:proto`, e.g.
/// `Ljava/lang/AutoCloseable;.close:()V`.
///
/// Format: `<class_descriptor>.<simple_name>:<proto_descriptor>` (no
/// spaces). Comparison is byte-exact.
///
/// ```no_run
/// # use droidsaw_dex::signatures::matchers::matches_invoke_signature;
/// # use droidsaw_dex::ssa::SsaInsn;
/// # use droidsaw_dex::parser::DexFile;
/// # let insn: SsaInsn = unimplemented!();
/// # let dex: &DexFile = unimplemented!();
/// let _ = matches_invoke_signature(&insn, dex, "Ljava/lang/AutoCloseable;.close:()V");
/// ```
pub fn matches_invoke_signature(insn: &SsaInsn, dex: &DexFile, sig: &str) -> bool {
    let Some(method) = resolve_invoke_method(insn, dex) else {
        return false;
    };
    let class = dex.get_type_descriptor(method.class_idx).unwrap_or("");
    let name = dex.get_string(method.name_idx).unwrap_or("");
    // PROOF: ProtoIdx (u32 newtype) → usize widening, lossless on 64-bit;
    // `.get()` handles OOB by returning None.
    #[allow(clippy::as_conversions, reason = "PROOF: u32 → usize widening, lossless on 64-bit; .get() handles OOB.")]
    let Some(proto) = dex.protos.get(method.proto_idx.0 as usize) else {
        return false;
    };
    let proto_desc = format_proto_descriptor(dex, proto);
    let mut buf = String::with_capacity(
        class
            .len()
            .saturating_add(name.len())
            .saturating_add(proto_desc.len())
            .saturating_add(2),
    );
    buf.push_str(class);
    buf.push('.');
    buf.push_str(name);
    buf.push(':');
    buf.push_str(&proto_desc);
    buf == sig
}

/// `true` iff `insn` is `Opcode::NewInstance` with a pool ref to the
/// type whose descriptor equals `type_descriptor` (e.g.
/// `Ljava/lang/StringBuilder;`).
///
/// ```no_run
/// # use droidsaw_dex::signatures::matchers::matches_new_instance_of;
/// # use droidsaw_dex::ssa::SsaInsn;
/// # use droidsaw_dex::parser::DexFile;
/// # let insn: SsaInsn = unimplemented!();
/// # let dex: &DexFile = unimplemented!();
/// let _ = matches_new_instance_of(&insn, dex, "Ljava/lang/StringBuilder;");
/// ```
pub fn matches_new_instance_of(insn: &SsaInsn, dex: &DexFile, type_descriptor: &str) -> bool {
    if insn.insn.op != Opcode::NewInstance {
        return false;
    }
    let Some(PoolIndex::Type(t)) = insn.insn.pool_idx else {
        return false;
    };
    dex.get_type_descriptor(t).ok() == Some(type_descriptor)
}

/// `true` iff `insn` is `Opcode::ConstString` / `Opcode::ConstStringJumbo`
/// and (when `expected_text` is `Some`) the resolved pool string equals
/// the expected literal. `None` matches any string.
///
/// ```no_run
/// # use droidsaw_dex::signatures::matchers::matches_const_string;
/// # use droidsaw_dex::ssa::SsaInsn;
/// # use droidsaw_dex::parser::DexFile;
/// # let insn: SsaInsn = unimplemented!();
/// # let dex: &DexFile = unimplemented!();
/// let _ = matches_const_string(&insn, dex, Some("hello"));
/// let _ = matches_const_string(&insn, dex, None);
/// ```
pub fn matches_const_string(insn: &SsaInsn, dex: &DexFile, expected_text: Option<&str>) -> bool {
    if !matches!(insn.insn.op, Opcode::ConstString | Opcode::ConstStringJumbo) {
        return false;
    }
    let Some(PoolIndex::String(s)) = insn.insn.pool_idx else {
        return false;
    };
    match expected_text {
        None => true,
        Some(want) => dex.get_string(s).ok() == Some(want),
    }
}

// ── Var-flow predicates ─────────────────────────────────────────────

/// `true` iff `a` and `b` refer to the same SSA variable.
///
/// Trivial alias for `==`, exposed as a named predicate so recognizer
/// bodies read closer to the prose-level invariant ("var X equals var
/// Y") than to a raw equality on derived `VarId` fields.
///
/// ```
/// # use droidsaw_dex::signatures::matchers::var_eq;
/// # use droidsaw_dex::ssa::VarId;
/// let a = VarId::new(0, 0);
/// let b = VarId::new(0, 0);
/// let c = VarId::new(0, 1);
/// assert!(var_eq(&a, &b));
/// assert!(!var_eq(&a, &c));
/// ```
pub fn var_eq(a: &VarId, b: &VarId) -> bool {
    a == b
}

/// `true` iff `var` appears in `insn.uses`.
///
/// ```
/// # use droidsaw_dex::signatures::matchers::var_used_in;
/// # use droidsaw_dex::ssa::{SsaInsn, VarId};
/// # use droidsaw_dex::decode::{Instruction, RegList};
/// # use droidsaw_dex::opcodes::Opcode;
/// let v = VarId::new(0, 0);
/// let insn = SsaInsn {
///     insn: Instruction { addr: 0, op: Opcode::Nop, size: 0, dst: None,
///         src: RegList::empty(), literal: 0, target: None, pool_idx: None },
///     dst: None,
///     uses: vec![v.clone()],
/// };
/// assert!(var_used_in(&v, &insn));
/// assert!(!var_used_in(&VarId::new(1, 0), &insn));
/// ```
pub fn var_used_in(var: &VarId, insn: &SsaInsn) -> bool {
    insn.uses.iter().any(|u| u == var)
}

/// `true` iff `body` (or any of its direct child Stmts, recursively)
/// contains a [`Stmt::Expr`] whose `insn.dst == Some(var)`.
///
/// Used by recognizers (e.g. TWR) to verify that a variable is assigned
/// somewhere within a try-body region. Recurses into `Seq`, `If` then/else,
/// `While` / `DoWhile` / `Synchronized` / `For` / `ForEach` bodies, and
/// `TryCatch` body + catch handlers. Does NOT descend into `Switch` /
/// `MultiArm` arm bodies — those are out-of-region by recognizer
/// convention; if a TWR-style recognizer needs them, extend the walker.
///
/// ```
/// # use droidsaw_dex::signatures::matchers::body_writes_var;
/// # use droidsaw_dex::structure::Stmt;
/// # use droidsaw_dex::ssa::{SsaInsn, VarId};
/// # use droidsaw_dex::decode::{Instruction, RegList};
/// # use droidsaw_dex::opcodes::Opcode;
/// let v = VarId::new(0, 0);
/// let assign = Stmt::Expr(SsaInsn {
///     insn: Instruction { addr: 0, op: Opcode::Const, size: 0, dst: None,
///         src: RegList::empty(), literal: 0, target: None, pool_idx: None },
///     dst: Some(v.clone()),
///     uses: vec![],
/// });
/// let body = Stmt::Seq(vec![assign]);
/// assert!(body_writes_var(&body, &v));
/// assert!(!body_writes_var(&body, &VarId::new(1, 0)));
/// ```
pub fn body_writes_var(body: &Stmt, var: &VarId) -> bool {
    match body {
        Stmt::Expr(insn) => insn.dst.as_ref() == Some(var),
        Stmt::Seq(items) => items.iter().any(|s| body_writes_var(s, var)),
        Stmt::If {
            then_body,
            else_body,
            ..
        } => {
            body_writes_var(then_body, var)
                || else_body
                    .as_deref()
                    .is_some_and(|e| body_writes_var(e, var))
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body_writes_var(body, var),
        Stmt::Synchronized { body, .. } => body_writes_var(body, var),
        Stmt::ForEach { body, .. } => body_writes_var(body, var),
        Stmt::For {
            init, update, body, ..
        } => {
            body_writes_var(init, var) || body_writes_var(update, var) || body_writes_var(body, var)
        }
        Stmt::TryCatch { body, catches } => {
            body_writes_var(body, var) || catches.iter().any(|c| body_writes_var(&c.body, var))
        }
        _ => false,
    }
}

// ── Internal helpers (not part of the combinator surface) ───────────

/// Resolve an invoke-flavored insn to its target [`MethodIdItem`] pool
/// entry. Returns `None` if the insn is not an invoke, has no
/// `PoolIndex::Method` / `PoolIndex::MethodAndProto` ref, or the pool
/// index is out of bounds.
fn resolve_invoke_method<'a>(insn: &SsaInsn, dex: &'a DexFile) -> Option<&'a MethodIdItem> {
    if !is_invoke_opcode(insn.insn.op) {
        return None;
    }
    let method_idx = match insn.insn.pool_idx? {
        PoolIndex::Method(m) => m,
        PoolIndex::MethodAndProto(m, _) => m,
        _ => return None,
    };
    // PROOF: MethodIdx (u32 newtype) → usize widening, lossless on 64-bit;
    // `.get()` handles OOB by returning None.
    #[allow(clippy::as_conversions, reason = "PROOF: u32 → usize widening, lossless on 64-bit; .get() handles OOB.")]
    {
        dex.methods.get(method_idx.0 as usize)
    }
}

fn is_invoke_opcode(op: Opcode) -> bool {
    matches!(
        op,
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
    )
}

fn format_proto_descriptor(dex: &DexFile, proto: &ProtoIdItem) -> String {
    let mut out = String::from("(");
    if proto.parameters_off != 0 {
        if let Some(params) = dex.type_lists.get(&proto.parameters_off) {
            for &type_idx in params {
                if let Ok(d) = dex.get_type_descriptor(type_idx) {
                    out.push_str(d);
                }
            }
        }
    }
    out.push(')');
    if let Ok(ret) = dex.get_type_descriptor(proto.return_type_idx) {
        out.push_str(ret);
    }
    out
}
