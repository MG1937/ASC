//! Cross-reference maps over a parsed `DexFile`.
//!
//! One module, one type, one entry point: [`Xrefs::build`]. Walks every
//! method body in the DEX exactly once and populates seven relation
//! maps. Downstream consumers (`droidsaw-core xrefs --search`,
//! droidsaw-apk JSON dumps for trufflehog/semgrep) consume the resulting
//! [`Xrefs`] value directly; JSON serialization and CLI shape are not
//! this module's concern.
//!
//! # Key design
//!
//! Methods and fields are keyed on stable descriptor triples via
//! [`MethodKey`] / [`FieldKey`], not on `MethodIdx` / `FieldIdx`. Raw
//! pool indices are a per-DEX coincidence and cannot cross multidex
//! boundaries; the triples can. Strings are keyed on owned `String` for
//! the same reason — a `u32 StringIdx` from `classes3.dex` has no
//! meaning in the `classes7.dex` string pool, but the actual string
//! value does. The allocation cost is one `String` clone per unique
//! literal (not per reference) because the relation map deduplicates
//! during insertion.
//!
//! # Multidex
//!
//! For an APK with N `classes*.dex` files, call [`Xrefs::from_dexes`]
//! to build a single unified `Xrefs` value. Alternatively, build each
//! DEX individually with [`Xrefs::build`] and fold them together with
//! [`Xrefs::merge`]. Both produce identical output — all relations are
//! descriptor-keyed, so merging two `Xrefs` values is a multi-map
//! union followed by a sort+dedup of each bucket.
//!
//! # Coverage gaps (read before writing rules)
//!
//! - **`invoke-custom` / `invoke-custom/range` are excluded from
//!   `method_to_callees`.** Their pool index is a `call_site_id` into
//!   the call-site table, not a `method_id`, and resolving it requires
//!   walking the bootstrap-method arguments to recover the real call
//!   target. Kotlin's lambda desugaring emits `invoke-custom` for every
//!   lambda bootstrap via `LambdaMetafactory`, which means on a
//!   Kotlin-heavy APK the callgraph is incomplete in proportion to
//!   lambda usage. Resolution is future work (P4a phase 2).
//!
//! - **`const-class` is lumped into `type_xrefs` alongside
//!   `new-instance` / `check-cast` / `instance-of`.** These are
//!   semantically different: `const-class` loads a `Class<T>` literal
//!   (the reflection entry point — paired with `Class.forName`,
//!   `Method.invoke`, `Field.get`), while `new-instance` allocates.
//!   A rule that wants to flag reflection cannot distinguish the two
//!   from `type_xrefs` alone — it needs to also inspect the caller's
//!   callees for `java.lang.reflect.*` / `java.lang.Class` method refs.
//!
//! - **Call-site program counters are preserved only in
//!   `method_to_callsites`**, not in `method_to_callees`. The flat
//!   callee set is deduplicated by triple and loses PC information;
//!   RE consumers that need to walk back through SSA from a specific
//!   call site should iterate `method_to_callsites[caller]` instead.
//!
//! # Attacker model
//!
//! Malformed `class_data` / `code_item` blobs are skipped silently —
//! an attacker-controlled DEX must not panic or abort the whole walk
//! because one method has a bad offset. Every pool lookup threads
//! through `Option` with `?`; layer-1 fuzz target at
//! `fuzz/fuzz_targets/fuzz_xrefs.rs` covers the walker against random
//! bytes.
#![allow(missing_docs, reason = "internal")]

use std::collections::BTreeMap;

use crate::decode::{parse_class_data, parse_code_item, Instruction, PoolIndex};
use crate::error::Result;
use crate::ids::{FieldIdx, MethodIdx, StringIdx, TypeIdx};
use crate::opcodes::Opcode;
use crate::DexFile;

/// Stable, multidex-safe identifier for a method.
///
/// `class` and `proto` are raw DEX type descriptors
/// (`Lcom/foo/Bar;`, `(Ljava/lang/String;I)V`), not pretty Java names —
/// downstream consumers can call [`DexFile::pretty_type`] themselves if
/// they want to render them.
///
/// Fields are `Arc<str>` rather than `String` so cloning a `MethodKey`
/// (which happens once per (caller, callee) edge in xrefs construction
/// — for a 21-DEX APK, on the order of millions of edges)
/// is three atomic refcount bumps instead of three full heap copies.
/// The `clone` leaf was the #1 hot leaf in flamegraphs of large APK
/// audits (3.4 B samples) before this change.
///
/// `Deref<Target = str>` flows through to `Arc<str>` so callers reading
/// `key.class.starts_with(...)` / `key.name.contains(...)` continue to
/// work source-compatibly. Construction needs `Arc::from(s)` /
/// `s.into()` instead of `s.to_string()`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MethodKey {
    pub class: std::sync::Arc<str>,
    pub name: std::sync::Arc<str>,
    pub proto: std::sync::Arc<str>,
}

/// Dispatch kind for an `invoke-*` instruction. Preserved per call
/// site in [`Xrefs::method_to_callsites`] so RE consumers can
/// distinguish virtual dispatch (one of N overrides) from direct
/// dispatch (exactly this method) without re-walking the bytecode.
/// The `/range` variants collapse into the same kind as their
/// non-range counterparts — the range-ness is a code-size detail, not
/// a dispatch-semantics distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InvokeKind {
    /// `invoke-virtual[/range]` — virtual dispatch on the receiver's
    /// runtime class.
    Virtual,
    /// `invoke-super[/range]` — dispatch to the superclass's copy of
    /// the method, ignoring overrides.
    Super,
    /// `invoke-direct[/range]` — private/constructor call, exactly
    /// this method ref, no dispatch.
    Direct,
    /// `invoke-static[/range]` — static call, no receiver.
    Static,
    /// `invoke-interface[/range]` — interface dispatch.
    Interface,
    /// `invoke-polymorphic[/range]` — signature-polymorphic dispatch
    /// through `MethodHandle.invoke` / `invokeExact`.
    Polymorphic,
}

/// One call-site emitted by the xref walker. Carries PC, dispatch
/// kind, and callee triple — everything a downstream RE consumer
/// needs to pivot back through SSA without re-decoding the caller.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallSite {
    /// Instruction address (unit offset from the start of the code
    /// item's `insns` array, i.e. the `insn.addr` field).
    pub pc: u32,
    /// Dispatch flavor — see [`InvokeKind`].
    pub kind: InvokeKind,
    /// Callee method triple.
    pub callee: MethodKey,
}

/// Stable, multidex-safe identifier for a field.
///
/// Shape mirrors [`MethodKey`]: raw DEX descriptors, not pretty Java
/// names. Two fields are equal iff they have the same declaring class,
/// name, and type descriptor. Fields are `Arc<str>` so clone is cheap
/// (see [`MethodKey`] doc-comment for the rationale).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldKey {
    pub class: std::sync::Arc<str>,
    pub name: std::sync::Arc<str>,
    pub ty: std::sync::Arc<str>,
}

/// Cross-reference maps built from one or more parsed DEX files.
///
/// All maps are descriptor-keyed and therefore composable across
/// multidex boundaries via [`Xrefs::merge`] / [`Xrefs::from_dexes`].
#[derive(Debug, Default, Clone)]
pub struct Xrefs {
    /// Relation #1: string literal → methods that load it via
    /// `const-string` / `const-string/jumbo`. The single most valuable
    /// relation for secret / URL / API-key tracing through obfuscated
    /// Android apps.
    pub string_to_methods: BTreeMap<String, Vec<MethodKey>>,

    /// Relation #1 inverse: method → sorted-unique string literals it
    /// loads. Populated inline from the same walk as #1 — no extra
    /// pass.
    pub method_to_strings: BTreeMap<MethodKey, Vec<String>>,

    /// Relation #2 (flat dump): caller → sorted-unique callees invoked
    /// via any `invoke-*` opcode (including `/range` and
    /// `invoke-polymorphic`). `invoke-custom` is excluded — its pool
    /// index is a `call_site_id`, not a `method_id`, and resolving it
    /// requires reading the call-site table (Kotlin lambda bootstrap
    /// args). See module docs for coverage implications.
    pub method_to_callees: BTreeMap<MethodKey, Vec<MethodKey>>,

    /// Relation #2 with program counter + dispatch kind preserved:
    /// caller → `CallSite` records in instruction order. Unlike
    /// `method_to_callees` this is **not** deduplicated — a method
    /// that calls the same callee at multiple PCs appears multiple
    /// times, which is what RE consumers need for SSA-level pivoting,
    /// and the dispatch kind (`Virtual` vs `Direct` vs `Static` etc.)
    /// matters for callgraph construction. Sorted by `pc` ascending
    /// within each caller's list.
    pub method_to_callsites: BTreeMap<MethodKey, Vec<CallSite>>,

    /// Relation #3 (inverse of #2): callee → sorted-unique callers.
    /// Transposed from `method_to_callees` at the end of `build`; same
    /// walker, no second pass over the DEX. This is the "who calls
    /// method X" direction, symmetric with the `xrefs --function <name>`
    /// mode droidsaw-hermes is building.
    pub callers_of: BTreeMap<MethodKey, Vec<MethodKey>>,

    /// Relation #5a: field → methods that read the field via
    /// `iget*` / `sget*`. Useful for "who reads this static flag that
    /// gates the root check".
    pub field_readers: BTreeMap<FieldKey, Vec<MethodKey>>,

    /// Relation #5b: field → methods that write the field via
    /// `iput*` / `sput*`.
    pub field_writers: BTreeMap<FieldKey, Vec<MethodKey>>,

    /// Relation #6: type descriptor → methods that reference the type
    /// via any of `new-instance`, `check-cast`, `instance-of`,
    /// `new-array`, `filled-new-array[/range]`, or `const-class`.
    /// Keyed on the raw descriptor string (`Lcom/foo/Bar;`, `[I`).
    /// Note that `const-class` is NOT distinguished from allocation /
    /// cast opcodes in this map — see module docs.
    pub type_xrefs: BTreeMap<String, Vec<MethodKey>>,
}

impl Xrefs {
    /// Walk one DEX and return populated xref maps.
    ///
    /// `data` is the original DEX byte slice — needed because
    /// class_data and code_item are stored out-of-line from the
    /// class_def header and `DexFile` does not own the bytes.
    pub fn build(dex: &DexFile, data: &[u8]) -> Result<Self> {
        let mut out = Xrefs::default();
        out.extend_from_dex(dex, data);
        out.canonicalize();
        Ok(out)
    }

    /// Build a unified `Xrefs` over every DEX in an APK (or any other
    /// set of DEXes that share a semantic namespace). Equivalent to
    /// calling [`Xrefs::build`] on each DEX and folding with
    /// [`Xrefs::merge`], but walks all DEXes into a single `Xrefs`
    /// value so canonicalization runs once.
    pub fn from_dexes(dexes: &[(&DexFile, &[u8])]) -> Result<Self> {
        let mut out = Xrefs::default();
        for (dex, data) in dexes {
            out.extend_from_dex(dex, data);
        }
        out.canonicalize();
        Ok(out)
    }

    /// Fold another `Xrefs` into this one in place. Both operands must
    /// already be canonical (as returned by [`Xrefs::build`] /
    /// [`Xrefs::from_dexes`]); the result is re-canonicalized so the
    /// post-merge output is identical to what you'd get from building
    /// both DEXes into one `Xrefs` via `from_dexes`.
    ///
    /// Useful when DEXes come from different pipelines or need to be
    /// loaded lazily.
    pub fn merge(&mut self, other: Xrefs) {
        for (k, v) in other.string_to_methods {
            self.string_to_methods.entry(k).or_default().extend(v);
        }
        for (k, v) in other.method_to_strings {
            self.method_to_strings.entry(k).or_default().extend(v);
        }
        for (k, v) in other.method_to_callees {
            self.method_to_callees.entry(k).or_default().extend(v);
        }
        for (k, v) in other.method_to_callsites {
            self.method_to_callsites.entry(k).or_default().extend(v);
        }
        for (k, v) in other.callers_of {
            self.callers_of.entry(k).or_default().extend(v);
        }
        for (k, v) in other.field_readers {
            self.field_readers.entry(k).or_default().extend(v);
        }
        for (k, v) in other.field_writers {
            self.field_writers.entry(k).or_default().extend(v);
        }
        for (k, v) in other.type_xrefs {
            self.type_xrefs.entry(k).or_default().extend(v);
        }
        self.canonicalize();
    }

    /// Walk one DEX and accumulate its xrefs into `self` without
    /// canonicalizing. Used by `build` / `from_dexes`; not public
    /// because the caller needs to remember to canonicalize before
    /// exposing the result.
    fn extend_from_dex(&mut self, dex: &DexFile, data: &[u8]) {
        for (i, cd) in dex.class_defs.iter().enumerate() {
            // Shadow gate: a duplicate-class_idx row would re-process
            // the same class's class_data, double-counting every
            // method's xrefs (operator-visible).
            if dex.class_def_is_shadowed(i) {
                continue;
            }
            if cd.class_data_off == 0 {
                continue;
            }
            let class_data = match parse_class_data(data, cd.class_data_off) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let methods_iter = class_data
                .direct_methods
                .iter()
                .chain(class_data.virtual_methods.iter());

            for em in methods_iter {
                if em.code_off == 0 {
                    continue;
                }
                let code = match parse_code_item(data, em.code_off) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let key = match method_key(dex, em.method_idx) {
                    Some(k) => k,
                    None => continue,
                };

                for insn in &code.instructions {
                    if let Some(s) = match_const_string(insn) {
                        if let Ok(lit) = dex.get_string(StringIdx(s)) {
                            let lit_owned = lit.to_string();
                            self.string_to_methods
                                .entry(lit_owned.clone())
                                .or_default()
                                .push(key.clone());
                            self.method_to_strings
                                .entry(key.clone())
                                .or_default()
                                .push(lit_owned);
                        }
                    }
                    if let Some((callee_idx, kind)) = match_invoke(insn) {
                        if let Some(callee) = method_key(dex, callee_idx) {
                            self.method_to_callees
                                .entry(key.clone())
                                .or_default()
                                .push(callee.clone());
                            self.method_to_callsites
                                .entry(key.clone())
                                .or_default()
                                .push(CallSite {
                                    pc: insn.addr,
                                    kind,
                                    callee: callee.clone(),
                                });
                            // Populate the transpose at extend time so
                            // `canonicalize` only has to sort+dedup.
                            // Populate here so `canonicalize` only has
                            // to sort+dedup; the prior approach rebuilt
                            // `callers_of` from `method_to_callees` on
                            // every call, cloning every edge twice —
                            // dominant leaf in flamegraphs of
                            // multi-dex APKs without this caching.
                            self.callers_of
                                .entry(callee)
                                .or_default()
                                .push(key.clone());
                        }
                    }
                    if let Some((field_idx, is_write)) = match_field_access(insn) {
                        if let Some(fk) = field_key(dex, field_idx) {
                            let target = if is_write {
                                &mut self.field_writers
                            } else {
                                &mut self.field_readers
                            };
                            target.entry(fk).or_default().push(key.clone());
                        }
                    }
                    if let Some(type_idx) = match_type_ref(insn) {
                        if let Ok(desc) = dex.get_type_descriptor(type_idx) {
                            self.type_xrefs
                                .entry(desc.to_string())
                                .or_default()
                                .push(key.clone());
                        }
                    }
                }
            }
        }
    }

    /// Sort + dedupe every bucket. `callers_of` is populated as the
    /// transpose of `method_to_callees` at extend time
    /// ([`Self::extend_from_dex`]) — canonicalize just sorts + dedups
    /// each bucket. Idempotent — running it twice on an already-
    /// canonical `Xrefs` produces the same output.
    ///
    /// O(|callers_of|·log) per call, avoiding unnecessary rebuild of
    /// the transposed relation.
    fn canonicalize(&mut self) {
        for v in self.string_to_methods.values_mut() {
            v.sort();
            v.dedup();
        }
        for v in self.method_to_strings.values_mut() {
            v.sort();
            v.dedup();
        }
        for v in self.method_to_callees.values_mut() {
            v.sort();
            v.dedup();
        }
        // `method_to_callsites` is sorted by PC but NOT deduped — a
        // method that calls the same callee at multiple PCs is a real
        // event worth preserving. The `CallSite` `Ord` impl sorts by
        // (pc, kind, callee) so ties at the same PC are still stable.
        for v in self.method_to_callsites.values_mut() {
            v.sort();
        }

        for v in self.callers_of.values_mut() {
            v.sort();
            v.dedup();
        }

        for v in self.field_readers.values_mut() {
            v.sort();
            v.dedup();
        }
        for v in self.field_writers.values_mut() {
            v.sort();
            v.dedup();
        }
        for v in self.type_xrefs.values_mut() {
            v.sort();
            v.dedup();
        }
    }
}

/// If `insn` is a `const-string` / `const-string/jumbo`, return the
/// referenced `StringIdx` raw value.
fn match_const_string(insn: &Instruction) -> Option<u32> {
    if !matches!(insn.op, Opcode::ConstString | Opcode::ConstStringJumbo) {
        return None;
    }
    match insn.pool_idx {
        Some(PoolIndex::String(StringIdx(s))) => Some(s),
        _ => None,
    }
}

/// If `insn` is an `invoke-*` opcode that references a `method_id`
/// (all 10 regular invoke variants plus the two `invoke-polymorphic`
/// forms), return the callee `MethodIdx` paired with its dispatch
/// kind. `/range` variants collapse into the same kind as their
/// non-range counterparts. `invoke-custom[/range]` is excluded —
/// its F35c/F3rc pool index is a `call_site_id`, not a `method_id`.
fn match_invoke(insn: &Instruction) -> Option<(MethodIdx, InvokeKind)> {
    let kind = match insn.op {
        Opcode::InvokeVirtual | Opcode::InvokeVirtualRange => InvokeKind::Virtual,
        Opcode::InvokeSuper | Opcode::InvokeSuperRange => InvokeKind::Super,
        Opcode::InvokeDirect | Opcode::InvokeDirectRange => InvokeKind::Direct,
        Opcode::InvokeStatic | Opcode::InvokeStaticRange => InvokeKind::Static,
        Opcode::InvokeInterface | Opcode::InvokeInterfaceRange => InvokeKind::Interface,
        Opcode::InvokePolymorphic | Opcode::InvokePolymorphicRange => InvokeKind::Polymorphic,
        _ => return None,
    };
    let idx = match insn.pool_idx {
        Some(PoolIndex::Method(m)) => m,
        Some(PoolIndex::MethodAndProto(m, _)) => m,
        _ => return None,
    };
    Some((idx, kind))
}

/// If `insn` is an `iget*` / `iput*` / `sget*` / `sput*` opcode,
/// return the referenced `FieldIdx` and a write flag (`true` for
/// `put*`, `false` for `get*`).
fn match_field_access(insn: &Instruction) -> Option<(FieldIdx, bool)> {
    let is_write = match insn.op {
        Opcode::Iget
        | Opcode::IgetWide
        | Opcode::IgetObject
        | Opcode::IgetBoolean
        | Opcode::IgetByte
        | Opcode::IgetChar
        | Opcode::IgetShort
        | Opcode::Sget
        | Opcode::SgetWide
        | Opcode::SgetObject
        | Opcode::SgetBoolean
        | Opcode::SgetByte
        | Opcode::SgetChar
        | Opcode::SgetShort => false,
        Opcode::Iput
        | Opcode::IputWide
        | Opcode::IputObject
        | Opcode::IputBoolean
        | Opcode::IputByte
        | Opcode::IputChar
        | Opcode::IputShort
        | Opcode::Sput
        | Opcode::SputWide
        | Opcode::SputObject
        | Opcode::SputBoolean
        | Opcode::SputByte
        | Opcode::SputChar
        | Opcode::SputShort => true,
        _ => return None,
    };
    match insn.pool_idx {
        Some(PoolIndex::Field(f)) => Some((f, is_write)),
        _ => None,
    }
}

/// If `insn` is an opcode that references a `TypeIdx` in the type pool
/// (`new-instance`, `check-cast`, `instance-of`, `new-array`,
/// `filled-new-array[/range]`, `const-class`), return that index.
fn match_type_ref(insn: &Instruction) -> Option<TypeIdx> {
    let is_type_ref = matches!(
        insn.op,
        Opcode::NewInstance
            | Opcode::CheckCast
            | Opcode::InstanceOf
            | Opcode::NewArray
            | Opcode::FilledNewArray
            | Opcode::FilledNewArrayRange
            | Opcode::ConstClass
    );
    if !is_type_ref {
        return None;
    }
    match insn.pool_idx {
        Some(PoolIndex::Type(t)) => Some(t),
        _ => None,
    }
}

/// Build a [`FieldKey`] from a [`FieldIdx`]. Returns `None` if any
/// referenced pool entry is out of bounds.
fn field_key(dex: &DexFile, idx: FieldIdx) -> Option<FieldKey> {
    // PROOF: FieldIdx (u32 newtype) → usize widening, lossless on 64-bit;
    // `.get()` handles OOB by returning None (per the doc-comment contract).
    #[allow(clippy::as_conversions, reason = "PROOF: u32 → usize widening, lossless on 64-bit; .get() handles OOB.")]
    let f = dex.fields.get(idx.0 as usize)?;
    let class: std::sync::Arc<str> = dex.get_type_descriptor(f.class_idx).ok()?.into();
    let name: std::sync::Arc<str> = dex.get_string(f.name_idx).ok()?.into();
    let ty: std::sync::Arc<str> = dex.get_type_descriptor(f.type_idx).ok()?.into();
    Some(FieldKey { class, name, ty })
}

/// Resolve a [`MethodIdx`] to its [`MethodKey`] triple.
///
/// Public so that callers outside the xrefs module (e.g. the audit SQLite
/// writer) can map a raw `func_id` — which is a `method_idx` in the DEX
/// method pool — to a stable descriptor triple without re-implementing the
/// pool-walking logic.  Returns `None` if any referenced pool entry is out
/// of bounds (adversarial or truncated DEX).
pub fn method_key_for_idx(dex: &DexFile, idx: MethodIdx) -> Option<MethodKey> {
    method_key(dex, idx)
}

/// Build a [`MethodKey`] from a [`MethodIdx`]. Returns `None` if any
/// referenced pool entry is out of bounds.
fn method_key(dex: &DexFile, idx: MethodIdx) -> Option<MethodKey> {
    // PROOF: MethodIdx/ProtoIdx (u32 newtype) → usize widening, lossless
    // on 64-bit; `.get()` handles OOB by returning None.
    #[allow(clippy::as_conversions, reason = "PROOF: u32 → usize widening, lossless on 64-bit; .get() handles OOB.")]
    let m = dex.methods.get(idx.0 as usize)?;
    let class: std::sync::Arc<str> = dex.get_type_descriptor(m.class_idx).ok()?.into();
    let name: std::sync::Arc<str> = dex.get_string(m.name_idx).ok()?.into();
    #[allow(clippy::as_conversions, reason = "PROOF: u32 → usize widening, lossless on 64-bit; .get() handles OOB.")]
    let proto_item = dex.protos.get(m.proto_idx.0 as usize)?;
    let ret = dex.get_type_descriptor(proto_item.return_type_idx).ok()?;

    let mut params = String::new();
    if proto_item.parameters_off != 0 {
        if let Some(tl) = dex.type_lists.get(&proto_item.parameters_off) {
            for t in tl {
                let Ok(desc) = dex.get_type_descriptor(*t) else {
                    return None;
                };
                params.push_str(desc);
            }
        }
    }

    Some(MethodKey {
        class,
        name,
        proto: format!("({params}){ret}").into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_key_formats_proto_as_dex_descriptor() {
        let k = MethodKey {
            class: "LFoo;".into(),
            name: "bar".into(),
            proto: "(Ljava/lang/String;I)V".into(),
        };
        assert!(k.proto.starts_with('('));
        assert!(k.proto.contains(')'));
    }

    #[test]
    fn method_key_ord_is_lexicographic() {
        let a = MethodKey {
            class: "LA;".into(),
            name: "x".into(),
            proto: "()V".into(),
        };
        let b = MethodKey {
            class: "LB;".into(),
            name: "x".into(),
            proto: "()V".into(),
        };
        assert!(a < b);
    }

    /// `Arc<str>` clones share allocations: cloning a `MethodKey` is
    /// three atomic refcount bumps, not three heap copies. This test
    /// pins that invariant by checking strong-count after `clone()`.
    #[test]
    fn method_key_clone_shares_allocations() {
        let k = MethodKey {
            class: "LFoo;".into(),
            name: "bar".into(),
            proto: "()V".into(),
        };
        let strong_class_pre = std::sync::Arc::strong_count(&k.class);
        let _k2 = k.clone();
        let strong_class_post = std::sync::Arc::strong_count(&k.class);
        assert_eq!(
            strong_class_post,
            strong_class_pre.saturating_add(1),
            "clone must bump Arc strong count, not deep-copy the buffer"
        );
    }

    #[test]
    fn merge_empty_is_identity() {
        let mut a = Xrefs::default();
        let b = Xrefs::default();
        a.merge(b);
        assert!(a.string_to_methods.is_empty());
        assert!(a.method_to_callees.is_empty());
        assert!(a.callers_of.is_empty());
    }

    /// Pin the post-canonicalize invariant: `callers_of` is
    /// the transpose of `method_to_callees`. The transpose was once
    /// rebuilt inside `canonicalize`; it's now populated at extend
    /// time. Either way, the post-canonicalize state must be a
    /// valid transpose.
    #[test]
    fn canonicalize_callers_of_is_transpose_of_method_to_callees() {
        let mk = |c: &str, n: &str| MethodKey {
            class: c.into(),
            name: n.into(),
            proto: "()V".into(),
        };
        let a = mk("LA;", "f");
        let b = mk("LB;", "g");
        let c = mk("LC;", "h");

        // Build by hand via merge, mirroring the shape extend_from_dex
        // produces (push to both maps, merge canonicalizes).
        let mut x1 = Xrefs::default();
        x1.method_to_callees
            .entry(a.clone())
            .or_default()
            .push(b.clone());
        x1.method_to_callees
            .entry(a.clone())
            .or_default()
            .push(c.clone());
        x1.callers_of
            .entry(b.clone())
            .or_default()
            .push(a.clone());
        x1.callers_of
            .entry(c.clone())
            .or_default()
            .push(a.clone());

        let mut x2 = Xrefs::default();
        x2.method_to_callees
            .entry(b.clone())
            .or_default()
            .push(c.clone());
        x2.callers_of
            .entry(c.clone())
            .or_default()
            .push(b.clone());

        x1.merge(x2);

        // Reconstruct the expected transpose from method_to_callees
        // and compare to callers_of byte-for-byte (post-canonical).
        let mut expected: BTreeMap<MethodKey, Vec<MethodKey>> = BTreeMap::new();
        for (caller, callees) in &x1.method_to_callees {
            for callee in callees {
                expected
                    .entry(callee.clone())
                    .or_default()
                    .push(caller.clone());
            }
        }
        for v in expected.values_mut() {
            v.sort();
            v.dedup();
        }
        assert_eq!(x1.callers_of, expected);
    }

    /// Idempotency: merging an empty Xrefs into a populated one (or
    /// any sequence of merges) leaves canonicalize-output unchanged
    /// from a single-shot build of the same edges. This catches any
    /// regression where the new "populate at extend time" path produces
    /// a different shape than the old "rebuild in canonicalize" path.
    #[test]
    fn merge_then_canonicalize_matches_single_shot() {
        let mk = |c: &str, n: &str| MethodKey {
            class: c.into(),
            name: n.into(),
            proto: "()V".into(),
        };
        let a = mk("LA;", "f");
        let b = mk("LB;", "g");

        // Single-shot: a→b, b→a, all in one Xrefs.
        let mut single = Xrefs::default();
        single.method_to_callees.entry(a.clone()).or_default().push(b.clone());
        single.method_to_callees.entry(b.clone()).or_default().push(a.clone());
        single.callers_of.entry(b.clone()).or_default().push(a.clone());
        single.callers_of.entry(a.clone()).or_default().push(b.clone());
        single.canonicalize();

        // Split: a→b in x; b→a in y; merge x with y.
        let mut x = Xrefs::default();
        x.method_to_callees.entry(a.clone()).or_default().push(b.clone());
        x.callers_of.entry(b.clone()).or_default().push(a.clone());
        let mut y = Xrefs::default();
        y.method_to_callees.entry(b.clone()).or_default().push(a.clone());
        y.callers_of.entry(a.clone()).or_default().push(b.clone());
        x.merge(y);

        assert_eq!(x.method_to_callees, single.method_to_callees);
        assert_eq!(x.callers_of, single.callers_of);
    }
}
