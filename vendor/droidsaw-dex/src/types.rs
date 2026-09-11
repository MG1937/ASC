//! DEX type system representations.
#![allow(missing_docs, reason = "internal")]
#![cfg_attr(not(test), allow(clippy::as_conversions, reason = "PROOF (bulk allow, 8 sites): types.rs builds the type-inference environment + descriptor-resolution helpers. Casts cluster around (a) `u32 pool-index newtype (.0) as usize` for `.get()` on parser-validated pool arrays, lossless on 64-bit; (b) `BlockIdx/VarId (u32 newtype) as usize` for arena indexing into SSA/CFG arenas (internally minted, bounded by arena.len() by construction). Per-site PROOF refinement deferred."))]

use std::sync::Arc;

use rustc_hash::{FxHashMap, FxHashSet};

use crate::cfg::{BlockIdx, Cfg};
use crate::decode::{CodeItem, PoolIndex};
use crate::ids::*;
use crate::opcodes::Opcode;
use crate::parser::DexFile;
use crate::ssa::{SsaBody, VarId};

// DETERMINISM: FxHashMap/FxHashSet usage in this module is internal-only.
// Type inference (build_use_map, propagate, TypeEnv) indexes by VarId — it
// never iterates the maps for deterministic output. Output flows through
// the SSA + emit pipeline which carries its own ordering invariants
// (BTreeMap-keyed blocks, per-block Vec instructions). VarId is a
// `u32`-newtype minted at SSA-build time; FxHash is bijective on integer
// inputs (no uncraftable collisions), and the propagate fixpoint is
// order-insensitive (worklist algorithm reaches a unique fixed point
// regardless of pop order). HashMap avoids per-lookup log(n)
// pointer-chasing across the inner walks. Mirrors the rationale in
// `optimize.rs`.

// ── DexType lattice ─────────────────────────────────────────────────

/// DEX type lattice element.
///
/// # Ordering note
///
/// `Ord` is derived by declaration order for use as `BTreeMap`/`BTreeSet` keys.
/// It is **not** the lattice ≤ relation. `Boolean` and `Int` compare as
/// `Boolean < Int` in Rust's `Ord`, but are incomparable in the lattice.
/// Use [`DexType::meet`] for lattice operations; do not compare variants
/// with `<`/`>` to reason about type relationships.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DexType {
    Bottom,
    Void,
    Boolean,
    Byte,
    Char,
    Short,
    Int,
    Long,
    Float,
    Double,
    Null,
    Ref(Arc<str>),
    ArrayRef(Box<DexType>),
    Top,
}

/// Cached `Arc<str>` for `"Ljava/lang/Object;"`. Hot in `meet()` — every
/// Ref⊓Ref / Ref⊓ArrayRef / wide-array meet allocates this constant on
/// the original `String` path. Clone is a refcount bump, no malloc.
fn object_ref() -> Arc<str> {
    use std::sync::OnceLock;
    static CELL: OnceLock<Arc<str>> = OnceLock::new();
    CELL.get_or_init(|| Arc::from("Ljava/lang/Object;")).clone()
}

/// Cached `Arc<str>` for `"Ljava/lang/String;"`. Hit on every ConstString /
/// ConstStringJumbo seed.
fn string_ref() -> Arc<str> {
    use std::sync::OnceLock;
    static CELL: OnceLock<Arc<str>> = OnceLock::new();
    CELL.get_or_init(|| Arc::from("Ljava/lang/String;")).clone()
}

/// Cached `Arc<str>` for `"Ljava/lang/Class;"`. Hit on every ConstClass seed.
fn class_ref() -> Arc<str> {
    use std::sync::OnceLock;
    static CELL: OnceLock<Arc<str>> = OnceLock::new();
    CELL.get_or_init(|| Arc::from("Ljava/lang/Class;")).clone()
}

/// Cached `Arc<str>` for `"Ljava/lang/Throwable;"`. Hit on every MoveException.
fn throwable_ref() -> Arc<str> {
    use std::sync::OnceLock;
    static CELL: OnceLock<Arc<str>> = OnceLock::new();
    CELL.get_or_init(|| Arc::from("Ljava/lang/Throwable;")).clone()
}

impl DexType {
    /// Parse a DEX type descriptor into a DexType.
    pub fn from_descriptor(desc: &str) -> DexType {
        match desc {
            "V" => DexType::Void,
            "Z" => DexType::Boolean,
            "B" => DexType::Byte,
            "S" => DexType::Short,
            "C" => DexType::Char,
            "I" => DexType::Int,
            "J" => DexType::Long,
            "F" => DexType::Float,
            "D" => DexType::Double,
            s if s.starts_with('[') => DexType::ArrayRef(Box::new(DexType::from_descriptor(
                s.get(1..).unwrap_or(""),
            ))),
            s if s.starts_with('L') && s.ends_with(';') => DexType::Ref(Arc::from(s)),
            _ => DexType::Top,
        }
    }

    /// Lattice meet (greatest lower bound).
    pub fn meet(&self, other: &DexType) -> DexType {
        if self == other {
            return self.clone();
        }
        match (self, other) {
            (DexType::Bottom, t) | (t, DexType::Bottom) => t.clone(),
            (DexType::Top, _) | (_, DexType::Top) => DexType::Top,
            // Null meets any reference → that reference
            (DexType::Null, t @ (DexType::Ref(_) | DexType::ArrayRef(_)))
            | (t @ (DexType::Ref(_) | DexType::ArrayRef(_)), DexType::Null) => t.clone(),
            (DexType::Null, DexType::Null) => DexType::Null,
            // Two Refs → Object (conservative)
            (DexType::Ref(_), DexType::Ref(_)) => DexType::Ref(object_ref()),
            // ArrayRef + ArrayRef → meet element types, wrap
            (DexType::ArrayRef(a), DexType::ArrayRef(b)) => {
                let elem = a.meet(b);
                if elem == DexType::Top {
                    DexType::Ref(object_ref())
                } else {
                    DexType::ArrayRef(Box::new(elem))
                }
            }
            // Ref + ArrayRef → Object
            (DexType::Ref(_), DexType::ArrayRef(_)) | (DexType::ArrayRef(_), DexType::Ref(_)) => {
                DexType::Ref(object_ref())
            }
            // Different primitives → Top
            _ => DexType::Top,
        }
    }

    pub fn is_reference(&self) -> bool {
        matches!(self, DexType::Ref(_) | DexType::ArrayRef(_) | DexType::Null)
    }

    pub fn is_primitive(&self) -> bool {
        matches!(
            self,
            DexType::Boolean
                | DexType::Byte
                | DexType::Char
                | DexType::Short
                | DexType::Int
                | DexType::Long
                | DexType::Float
                | DexType::Double
        )
    }

    pub fn is_wide(&self) -> bool {
        matches!(self, DexType::Long | DexType::Double)
    }
}

impl std::fmt::Display for DexType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DexType::Bottom => write!(f, "⊥"),
            DexType::Void => write!(f, "void"),
            DexType::Boolean => write!(f, "boolean"),
            DexType::Byte => write!(f, "byte"),
            DexType::Char => write!(f, "char"),
            DexType::Short => write!(f, "short"),
            DexType::Int => write!(f, "int"),
            DexType::Long => write!(f, "long"),
            DexType::Float => write!(f, "float"),
            DexType::Double => write!(f, "double"),
            DexType::Null => write!(f, "null"),
            DexType::Ref(s) => {
                if let Some(inner) =
                    s.strip_prefix('L').and_then(|t| t.strip_suffix(';'))
                {
                    let name = inner.replace('/', ".");
                    let sanitized: String = name
                        .split('.')
                        .map(crate::emit::sanitize_id)
                        .collect::<Vec<_>>()
                        .join(".");
                    write!(f, "{sanitized}")
                } else {
                    write!(f, "{}", crate::emit::sanitize_id(s))
                }
            }
            DexType::ArrayRef(elem) => write!(f, "{elem}[]"),
            DexType::Top => write!(f, "⊤"),
        }
    }
}

// ── Type environment ────────────────────────────────────────────────

/// Type assignment for all VarIds in a method.
#[derive(Debug)]
pub struct TypeEnv {
    pub types: FxHashMap<VarId, DexType>,
    pub casts: Vec<(VarId, DexType)>,
}

// ── Use-map ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum UseLocation {
    /// Instruction at index `insn_idx` in block `block`.
    Insn { block: BlockIdx, insn_idx: usize },
    /// Phi node at index `phi_idx` in block `block`.
    Phi { block: BlockIdx, phi_idx: usize },
}

fn build_use_map(ssa: &SsaBody) -> FxHashMap<VarId, Vec<UseLocation>> {
    let mut map: FxHashMap<VarId, Vec<UseLocation>> = FxHashMap::default();

    for block in ssa.blocks.values() {
        for (phi_idx, phi) in block.phis.iter().enumerate() {
            for var in phi.operands.values() {
                map.entry(var.clone()).or_default().push(UseLocation::Phi {
                    block: block.id,
                    phi_idx,
                });
            }
        }
        for (insn_idx, insn) in block.insns.iter().enumerate() {
            for var in &insn.uses {
                map.entry(var.clone()).or_default().push(UseLocation::Insn {
                    block: block.id,
                    insn_idx,
                });
            }
        }
    }

    map
}

// ── Type seeding ────────────────────────────────────────────────────

fn resolve_type(dex: &DexFile, type_idx: TypeIdx) -> DexType {
    match dex.get_type_descriptor(type_idx) {
        Ok(desc) => DexType::from_descriptor(desc),
        Err(_) => DexType::Top,
    }
}

/// Safely look up a method's proto, returning None if indices are out of bounds.
fn get_method_proto(dex: &DexFile, method_idx: MethodIdx) -> Option<(&MethodIdItem, &ProtoIdItem)> {
    let method = dex.methods.get(method_idx.0 as usize)?;
    let proto = dex.protos.get(method.proto_idx.0 as usize)?;
    Some((method, proto))
}

#[allow(clippy::arithmetic_side_effects, reason = "`var_idx += 1` / `var_idx += 2` — usize register-pair stride bounded by ssa.param_vars.len() (parser-validated registers_size cap).")]
fn seed_from_signature(
    env: &mut TypeEnv,
    dex: &DexFile,
    method_idx: MethodIdx,
    ssa: &SsaBody,
    is_static: bool,
) {
    let (method, proto) = match get_method_proto(dex, method_idx) {
        Some(mp) => mp,
        None => return,
    };

    // Build parameter type list
    let mut param_types: Vec<DexType> = Vec::new();

    if !is_static {
        // First parameter is `this`
        param_types.push(resolve_type(dex, method.class_idx));
    }

    // Remaining parameters from proto
    if proto.parameters_off != 0 {
        if let Some(type_list) = dex.type_lists.get(&proto.parameters_off) {
            for &tidx in type_list {
                param_types.push(resolve_type(dex, tidx));
            }
        }
    }

    // Use param_vars from SSA builder — direct mapping, no scanning needed.
    // param_vars[i] corresponds to register (first_param_reg + i).
    // param_types may be shorter than param_vars if wide types occupy 2 registers.
    let mut var_idx = 0;
    for ty in &param_types {
        if let Some(pv) = ssa.param_vars.get(var_idx) {
            env.types.insert(pv.clone(), ty.clone());
        }
        if ty.is_wide() {
            var_idx += 2; // skip the high register
        } else {
            var_idx += 1;
        }
    }
}

fn opcode_result_type(op: Opcode, pool_idx: Option<&PoolIndex>, dex: &DexFile) -> DexType {
    use Opcode::*;
    match op {
        // Int-producing operations
        AddInt | SubInt | MulInt | DivInt | RemInt | AndInt | OrInt | XorInt | ShlInt | ShrInt
        | UshrInt | AddInt2Addr | SubInt2Addr | MulInt2Addr | DivInt2Addr | RemInt2Addr
        | AndInt2Addr | OrInt2Addr | XorInt2Addr | ShlInt2Addr | ShrInt2Addr | UshrInt2Addr
        | AddIntLit16 | RsubInt | MulIntLit16 | DivIntLit16 | RemIntLit16 | AndIntLit16
        | OrIntLit16 | XorIntLit16 | AddIntLit8 | RsubIntLit8 | MulIntLit8 | DivIntLit8
        | RemIntLit8 | AndIntLit8 | OrIntLit8 | XorIntLit8 | ShlIntLit8 | ShrIntLit8
        | UshrIntLit8 | NegInt | NotInt | FloatToInt | LongToInt | DoubleToInt | ArrayLength
        | CmplFloat | CmpgFloat | CmplDouble | CmpgDouble | CmpLong => DexType::Int,

        IntToByte => DexType::Byte,
        IntToChar => DexType::Char,
        IntToShort => DexType::Short,
        InstanceOf => DexType::Boolean,

        // Float-producing
        AddFloat | SubFloat | MulFloat | DivFloat | RemFloat | AddFloat2Addr | SubFloat2Addr
        | MulFloat2Addr | DivFloat2Addr | RemFloat2Addr | NegFloat | IntToFloat | LongToFloat
        | DoubleToFloat => DexType::Float,

        // Long-producing
        AddLong | SubLong | MulLong | DivLong | RemLong | AndLong | OrLong | XorLong | ShlLong
        | ShrLong | UshrLong | AddLong2Addr | SubLong2Addr | MulLong2Addr | DivLong2Addr
        | RemLong2Addr | AndLong2Addr | OrLong2Addr | XorLong2Addr | ShlLong2Addr
        | ShrLong2Addr | UshrLong2Addr | NegLong | NotLong | IntToLong | FloatToLong
        | DoubleToLong => DexType::Long,

        // Double-producing
        AddDouble | SubDouble | MulDouble | DivDouble | RemDouble | AddDouble2Addr
        | SubDouble2Addr | MulDouble2Addr | DivDouble2Addr | RemDouble2Addr | NegDouble
        | IntToDouble | LongToDouble | FloatToDouble => DexType::Double,

        // String constants
        ConstString | ConstStringJumbo => DexType::Ref(string_ref()),
        ConstClass => DexType::Ref(class_ref()),
        MoveException => DexType::Ref(throwable_ref()),

        // Pool-typed: NewInstance, NewArray, CheckCast
        NewInstance => {
            if let Some(PoolIndex::Type(tidx)) = pool_idx {
                resolve_type(dex, *tidx)
            } else {
                DexType::Top
            }
        }
        NewArray | FilledNewArray | FilledNewArrayRange => {
            if let Some(PoolIndex::Type(tidx)) = pool_idx {
                resolve_type(dex, *tidx)
            } else {
                DexType::Top
            }
        }
        CheckCast => {
            if let Some(PoolIndex::Type(tidx)) = pool_idx {
                resolve_type(dex, *tidx)
            } else {
                DexType::Top
            }
        }

        // Field get → field type
        Iget | IgetObject | IgetBoolean | IgetByte | IgetChar | IgetShort | IgetWide | Sget
        | SgetObject | SgetBoolean | SgetByte | SgetChar | SgetShort | SgetWide => {
            if let Some(PoolIndex::Field(fidx)) = pool_idx {
                if let Some(field) = dex.fields.get(fidx.0 as usize) {
                    resolve_type(dex, field.type_idx)
                } else {
                    DexType::Top
                }
            } else {
                DexType::Bottom
            }
        }

        // Array get → element type (unknown without array type, use opcode suffix)
        Aget => DexType::Int,
        AgetWide => DexType::Long, // could be double, but Long is safe default
        AgetObject => DexType::Ref(object_ref()),
        AgetBoolean => DexType::Boolean,
        AgetByte => DexType::Byte,
        AgetChar => DexType::Char,
        AgetShort => DexType::Short,

        // Moves propagate, not seed
        Move | MoveFrom16 | Move16 | MoveWide | MoveWideFrom16 | MoveWide16 | MoveObject
        | MoveObjectFrom16 | MoveObject16 => DexType::Bottom,

        // MoveResult: type comes from preceding invoke (handled separately)
        MoveResult => DexType::Bottom,
        MoveResultWide => DexType::Bottom,
        MoveResultObject => DexType::Bottom,

        // Numeric constants: ambiguous, resolved from context
        Const4 | Const16 | Const | ConstHigh16 => DexType::Bottom,
        ConstWide16 | ConstWide32 | ConstWide | ConstWideHigh16 => DexType::Bottom,
        ConstMethodHandle | ConstMethodType => DexType::Ref(object_ref()),

        // Non-defining opcodes — shouldn't be called for these
        _ => DexType::Bottom,
    }
}

fn seed_from_opcodes_and_pool(env: &mut TypeEnv, dex: &DexFile, ssa: &SsaBody) {
    for block in ssa.blocks.values() {
        let mut prev_invoke_method: Option<MethodIdx> = None;
        // filled-new-array / filled-new-array/range also produce a result via
        // move-result-object.  Track the array element type so that the
        // following MoveResultObject can be typed correctly.
        let mut prev_filled_array_type: Option<DexType> = None;
        // invoke-custom's pool_idx is a CallSiteIdx (not a MethodIdx), so
        // the prev_invoke_method channel can't carry it. The SSA return
        // type we want is the `invokedType` proto's return type — the
        // functional-interface class the metafactory produces (Runnable,
        // Function, ...). Threading it via a parallel channel lets
        // move-result-object inherit the correct Ref-type.
        let mut prev_call_site_return: Option<DexType> = None;

        for insn in &block.insns {
            // Track preceding invoke for MoveResult pairing
            match insn.insn.op {
                Opcode::InvokeVirtual
                | Opcode::InvokeSuper
                | Opcode::InvokeDirect
                | Opcode::InvokeStatic
                | Opcode::InvokeInterface
                | Opcode::InvokeVirtualRange
                | Opcode::InvokeSuperRange
                | Opcode::InvokeDirectRange
                | Opcode::InvokeStaticRange
                | Opcode::InvokeInterfaceRange => {
                    if let Some(PoolIndex::Method(midx)) = insn.insn.pool_idx {
                        prev_invoke_method = Some(midx);
                    }
                    prev_filled_array_type = None;
                    prev_call_site_return = None;
                }
                // invoke-polymorphic is signature-polymorphic: its
                // move-result type MUST come from the per-call-site
                // proto (encoded in `PoolIndex::MethodAndProto`'s
                // second slot), not from the declared method's
                // proto. `MethodHandle.invokeExact`'s declared proto
                // is `([Object)Object` but the call site above it
                // is e.g. `()String` — the runtime type check
                // enforces exact match between the two, and the
                // source-level form is `(String) mh.invokeExact()`.
                Opcode::InvokePolymorphic | Opcode::InvokePolymorphicRange => {
                    prev_invoke_method = None;
                    prev_filled_array_type = None;
                    prev_call_site_return =
                        invoke_polymorphic_return_type(dex, insn);
                }
                Opcode::InvokeCustom | Opcode::InvokeCustomRange => {
                    prev_invoke_method = None;
                    prev_filled_array_type = None;
                    prev_call_site_return = invoke_custom_return_type(dex, insn);
                }
                // filled-new-array produces a result via MoveResultObject
                Opcode::FilledNewArray | Opcode::FilledNewArrayRange => {
                    if let Some(PoolIndex::Type(tidx)) = insn.insn.pool_idx {
                        prev_filled_array_type = Some(resolve_type(dex, tidx));
                    }
                    prev_invoke_method = None;
                }
                _ => {}
            }

            if let Some(ref dst) = insn.dst {
                // MoveResult* gets return type from preceding invoke or filled-new-array
                let ty = match insn.insn.op {
                    Opcode::MoveResult | Opcode::MoveResultWide | Opcode::MoveResultObject => {
                        if let Some(midx) = prev_invoke_method {
                            if let Some((_method, proto)) = get_method_proto(dex, midx) {
                                resolve_type(dex, proto.return_type_idx)
                            } else {
                                DexType::Top
                            }
                        } else if let Some(ref cs_ret) = prev_call_site_return {
                            cs_ret.clone()
                        } else if let Some(ref arr_ty) = prev_filled_array_type {
                            arr_ty.clone()
                        } else {
                            DexType::Bottom
                        }
                    }
                    _ => opcode_result_type(insn.insn.op, insn.insn.pool_idx.as_ref(), dex),
                };

                if ty != DexType::Bottom {
                    // SEMANTICS-DEFAULT-EMPTY: `DexType::Bottom` is the lattice bottom
                    // (no information yet); absent entries are equivalent to Bottom in the
                    // type-inference fixed-point.
                    let existing = env.types.get(dst).cloned().unwrap_or(DexType::Bottom);
                    let merged = existing.meet(&ty);
                    env.types.insert(dst.clone(), merged);
                }
            }

            // Clear prev_invoke / prev_filled_array if this isn't a MoveResult
            if !matches!(
                insn.insn.op,
                Opcode::MoveResult | Opcode::MoveResultWide | Opcode::MoveResultObject
            ) {
                // Only clear if not an invoke or filled-new-array (to handle those
                // immediately followed by MoveResult)
                let is_invoke_or_filled = matches!(
                    insn.insn.op,
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
                if !is_invoke_or_filled {
                    prev_invoke_method = None;
                    prev_filled_array_type = None;
                    prev_call_site_return = None;
                }
            }
        }
    }
}

/// Resolve an `invoke-custom{,/range}` instruction's result type from
/// its `call_site`'s `invokedType` proto — the factory's return type,
/// i.e. the functional-interface class. Returns `None` when the call
/// site is unresolved / malformed.
fn invoke_custom_return_type(
    dex: &DexFile,
    insn: &crate::ssa::SsaInsn,
) -> Option<DexType> {
    let PoolIndex::CallSite(cs_idx) = insn.insn.pool_idx? else {
        return None;
    };
    let &cs_off = dex.call_site_ids.get(cs_idx.0 as usize)?;
    let cs = dex.encoded_arrays.get(&cs_off)?;
    // [2] is invokedType (factory return type + capture params).
    let invoked_ty = match cs.get(2)? {
        crate::annotation::EncodedValue::MethodType(p) => *p,
        _ => return None,
    };
    let proto = dex.protos.get(invoked_ty.0 as usize)?;
    Some(resolve_type(dex, proto.return_type_idx))
}

/// Resolve an `invoke-polymorphic{,/range}` instruction's result type
/// from its call-site proto (the second slot of
/// `PoolIndex::MethodAndProto`), NOT from the declared method's proto.
/// Returns `None` when the pool index is malformed.
fn invoke_polymorphic_return_type(
    dex: &DexFile,
    insn: &crate::ssa::SsaInsn,
) -> Option<DexType> {
    let PoolIndex::MethodAndProto(_, call_site_proto) = insn.insn.pool_idx? else {
        return None;
    };
    let proto = dex.protos.get(call_site_proto.0 as usize)?;
    Some(resolve_type(dex, proto.return_type_idx))
}

// ── Propagation ─────────────────────────────────────────────────────

#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: UseLocation::{Insn, Phi} carry (block, insn_idx | phi_idx) values minted by ssa::Builder during SSA construction. Every block ∈ ssa.blocks (BTreeMap key); every insn_idx < block_data.insns.len(); every phi_idx < block_data.phis.len(). Reaching propagate() implies SSA build succeeded."
)]
fn propagate(env: &mut TypeEnv, ssa: &SsaBody, use_map: &FxHashMap<VarId, Vec<UseLocation>>) {
    let mut worklist: Vec<VarId> = env.types.keys().cloned().collect();
    let mut in_worklist: FxHashSet<VarId> = worklist.iter().cloned().collect();

    while let Some(var) = worklist.pop() {
        in_worklist.remove(&var);
        let var_type = match env.types.get(&var) {
            Some(t) => t.clone(),
            None => continue,
        };

        if var_type == DexType::Bottom {
            continue;
        }

        if let Some(uses) = use_map.get(&var) {
            for loc in uses {
                match loc {
                    UseLocation::Insn { block, insn_idx } => {
                        let block_data = &ssa.blocks[block];
                        let insn = &block_data.insns[*insn_idx];

                        // Propagate through moves
                        match insn.insn.op {
                            Opcode::Move
                            | Opcode::MoveFrom16
                            | Opcode::Move16
                            | Opcode::MoveWide
                            | Opcode::MoveWideFrom16
                            | Opcode::MoveWide16
                            | Opcode::MoveObject
                            | Opcode::MoveObjectFrom16
                            | Opcode::MoveObject16 => {
                                if let Some(ref dst) = insn.dst {
                                    // SEMANTICS-DEFAULT-EMPTY: Bottom is the lattice floor;
                                    // absent dst means no type info yet, which equals Bottom.
                                    let old =
                                        env.types.get(dst).cloned().unwrap_or(DexType::Bottom);
                                    let new = old.meet(&var_type);
                                    if new != old {
                                        env.types.insert(dst.clone(), new);
                                        if !in_worklist.contains(dst) {
                                            worklist.push(dst.clone());
                                            in_worklist.insert(dst.clone());
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    UseLocation::Phi { block, phi_idx } => {
                        let block_data = &ssa.blocks[block];
                        let phi = &block_data.phis[*phi_idx];

                        // Recompute phi dst type as meet of all operands
                        let mut phi_type = DexType::Bottom;
                        for op_var in phi.operands.values() {
                            // SEMANTICS-DEFAULT-EMPTY: phi operand absent from env means no
                            // type information yet; Bottom is the correct lattice identity.
                            let op_type = env.types.get(op_var).cloned().unwrap_or(DexType::Bottom);
                            phi_type = phi_type.meet(&op_type);
                        }

                        // SEMANTICS-DEFAULT-EMPTY: phi dst absent means no prior type; Bottom
                        // is the correct starting point for the meet computation.
                        let old = env.types.get(&phi.dst).cloned().unwrap_or(DexType::Bottom);
                        let new = old.meet(&phi_type);
                        if new != old {
                            env.types.insert(phi.dst.clone(), new);
                            if !in_worklist.contains(&phi.dst) {
                                worklist.push(phi.dst.clone());
                                in_worklist.insert(phi.dst.clone());
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Const resolution ────────────────────────────────────────────────

/// Returns true if `op` is a narrow-integer arithmetic opcode (requires Int operands).
fn is_int_arithmetic_op(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::AddInt
            | Opcode::SubInt
            | Opcode::MulInt
            | Opcode::DivInt
            | Opcode::RemInt
            | Opcode::AndInt
            | Opcode::OrInt
            | Opcode::XorInt
            | Opcode::ShlInt
            | Opcode::ShrInt
            | Opcode::UshrInt
            | Opcode::AddInt2Addr
            | Opcode::SubInt2Addr
            | Opcode::MulInt2Addr
            | Opcode::DivInt2Addr
            | Opcode::RemInt2Addr
            | Opcode::AndInt2Addr
            | Opcode::OrInt2Addr
            | Opcode::XorInt2Addr
            | Opcode::ShlInt2Addr
            | Opcode::ShrInt2Addr
            | Opcode::UshrInt2Addr
            | Opcode::AddIntLit16
            | Opcode::RsubInt
            | Opcode::MulIntLit16
            | Opcode::DivIntLit16
            | Opcode::RemIntLit16
            | Opcode::AndIntLit16
            | Opcode::OrIntLit16
            | Opcode::XorIntLit16
            | Opcode::AddIntLit8
            | Opcode::RsubIntLit8
            | Opcode::MulIntLit8
            | Opcode::DivIntLit8
            | Opcode::RemIntLit8
            | Opcode::AndIntLit8
            | Opcode::OrIntLit8
            | Opcode::XorIntLit8
            | Opcode::ShlIntLit8
            | Opcode::ShrIntLit8
            | Opcode::UshrIntLit8
            | Opcode::NegInt
            | Opcode::NotInt
            | Opcode::IntToByte
            | Opcode::IntToChar
            | Opcode::IntToShort
            | Opcode::IntToFloat
            | Opcode::IntToLong
            | Opcode::IntToDouble
    )
}

/// Returns true if `op` is a long arithmetic opcode (requires Long operands).
fn is_long_arithmetic_op(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::AddLong
            | Opcode::SubLong
            | Opcode::MulLong
            | Opcode::DivLong
            | Opcode::RemLong
            | Opcode::AndLong
            | Opcode::OrLong
            | Opcode::XorLong
            | Opcode::ShlLong
            | Opcode::ShrLong
            | Opcode::UshrLong
            | Opcode::AddLong2Addr
            | Opcode::SubLong2Addr
            | Opcode::MulLong2Addr
            | Opcode::DivLong2Addr
            | Opcode::RemLong2Addr
            | Opcode::AndLong2Addr
            | Opcode::OrLong2Addr
            | Opcode::XorLong2Addr
            | Opcode::ShlLong2Addr
            | Opcode::ShrLong2Addr
            | Opcode::UshrLong2Addr
            | Opcode::NegLong
            | Opcode::NotLong
            | Opcode::CmpLong
    )
}

/// Returns true if `op` is a double arithmetic opcode (requires Double operands).
fn is_double_arithmetic_op(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::AddDouble
            | Opcode::SubDouble
            | Opcode::MulDouble
            | Opcode::DivDouble
            | Opcode::RemDouble
            | Opcode::AddDouble2Addr
            | Opcode::SubDouble2Addr
            | Opcode::MulDouble2Addr
            | Opcode::DivDouble2Addr
            | Opcode::RemDouble2Addr
            | Opcode::NegDouble
            | Opcode::CmplDouble
            | Opcode::CmpgDouble
    )
}

/// Returns true if `op` is a float arithmetic opcode (requires Float operands).
fn is_float_arithmetic_op(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::AddFloat
            | Opcode::SubFloat
            | Opcode::MulFloat
            | Opcode::DivFloat
            | Opcode::RemFloat
            | Opcode::AddFloat2Addr
            | Opcode::SubFloat2Addr
            | Opcode::MulFloat2Addr
            | Opcode::DivFloat2Addr
            | Opcode::RemFloat2Addr
            | Opcode::NegFloat
            | Opcode::CmplFloat
            | Opcode::CmpgFloat
    )
}

/// Resolve the type of a single Bottom/absent VarId by examining its use sites.
/// Returns the resolved type, or `DexType::Int` as default.
#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: same SSA-build invariant as `propagate` — UseLocation indices are minted at SSA construction time."
)]
fn resolve_one_const(
    var: &VarId,
    default: DexType,
    env: &TypeEnv,
    dex: &DexFile,
    method_idx: MethodIdx,
    ssa: &SsaBody,
    use_map: &FxHashMap<VarId, Vec<UseLocation>>,
) -> DexType {
    if let Some(uses) = use_map.get(var) {
        for loc in uses {
            if let UseLocation::Insn { block, insn_idx } = loc {
                let insn = &ssa.blocks[block].insns[*insn_idx];

                // Arithmetic context → derive type from opcode family
                if is_int_arithmetic_op(insn.insn.op) {
                    return DexType::Int;
                }
                if is_long_arithmetic_op(insn.insn.op) {
                    return DexType::Long;
                }
                if is_double_arithmetic_op(insn.insn.op) {
                    return DexType::Double;
                }
                if is_float_arithmetic_op(insn.insn.op) {
                    return DexType::Float;
                }

                // Invoke arg context → derive from method signature
                match insn.insn.op {
                    Opcode::InvokeVirtual
                    | Opcode::InvokeSuper
                    | Opcode::InvokeDirect
                    | Opcode::InvokeStatic
                    | Opcode::InvokeInterface
                    | Opcode::InvokeVirtualRange
                    | Opcode::InvokeSuperRange
                    | Opcode::InvokeDirectRange
                    | Opcode::InvokeStaticRange
                    | Opcode::InvokeInterfaceRange => {
                        if let Some(PoolIndex::Method(midx)) = insn.insn.pool_idx {
                            if let Some(ty) = find_invoke_param_type(dex, midx, var, insn) {
                                return ty;
                            }
                        }
                    }
                    // Field access: the receiver (uses[0] for iget, uses[1] for iput)
                    // must be the class that owns the field. A Const4 0 used as an
                    // iget receiver means `null` not `0` — without this arm, emit
                    // produces `0.mIntent` which is invalid Java. Seen on LX/QaD.
                    Opcode::Iget
                    | Opcode::IgetWide
                    | Opcode::IgetObject
                    | Opcode::IgetBoolean
                    | Opcode::IgetByte
                    | Opcode::IgetChar
                    | Opcode::IgetShort
                        if insn.uses.first() == Some(var) =>
                    {
                        if let Some(PoolIndex::Field(fidx)) = insn.insn.pool_idx {
                            if let Some(field) = dex.fields.get(fidx.0 as usize) {
                                return resolve_type(dex, field.class_idx);
                            }
                        }
                    }
                    Opcode::Iput
                    | Opcode::IputWide
                    | Opcode::IputObject
                    | Opcode::IputBoolean
                    | Opcode::IputByte
                    | Opcode::IputChar
                    | Opcode::IputShort => {
                        // uses[0] = value (field type), uses[1] = instance (owner class)
                        if let Some(PoolIndex::Field(fidx)) = insn.insn.pool_idx {
                            if let Some(field) = dex.fields.get(fidx.0 as usize) {
                                if insn.uses.get(1) == Some(var) {
                                    return resolve_type(dex, field.class_idx);
                                } else if insn.uses.first() == Some(var) {
                                    return resolve_type(dex, field.type_idx);
                                }
                            }
                        }
                    }
                    // Return-position uses: a `const/4 0` feeding `return-object`
                    // demands a reference type, and feeding `return` in a
                    // boolean-returning method demands `Boolean`. Without this
                    // arm, the const-def stayed typed `Int` (default) and emit
                    // rendered `return 0;` instead of `return null;` /
                    // `return false;`. The method's declared return type is the
                    // demanded type. Skipping `ReturnVoid` is correct: it has
                    // no source operand to type.
                    Opcode::Return | Opcode::ReturnWide | Opcode::ReturnObject
                        if insn.uses.first() == Some(var) =>
                    {
                        if let Some((_, proto)) = get_method_proto(dex, method_idx) {
                            return resolve_type(dex, proto.return_type_idx);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Phi context: if a phi that uses this var has a known type, inherit it
        for loc in uses {
            if let UseLocation::Phi { block, phi_idx } = loc {
                let phi = &ssa.blocks[block].phis[*phi_idx];
                // SEMANTICS-DEFAULT-EMPTY: phi dst not yet resolved → Bottom (no type info);
                // the lattice check below correctly skips Bottom/Top entries.
                let phi_ty = env.types.get(&phi.dst).cloned().unwrap_or(DexType::Bottom);
                if phi_ty != DexType::Bottom && phi_ty != DexType::Top {
                    return phi_ty;
                }
            }
        }
    }
    default
}

/// Resolve Const instructions that are still Bottom (or absent) by checking usage context.
fn resolve_consts(
    env: &mut TypeEnv,
    dex: &DexFile,
    method_idx: MethodIdx,
    ssa: &SsaBody,
    use_map: &FxHashMap<VarId, Vec<UseLocation>>,
) {
    // Gather (VarId, default_type) pairs for every const-opcode def that is
    // absent or Bottom in env.types.  Const4/Const16/Const/ConstHigh16 were
    // never inserted during seeding (opcode_result_type returns Bottom for them),
    // so they would be missed by a plain env.types iteration.
    let mut to_resolve: Vec<(VarId, DexType)> = Vec::new();

    for block in ssa.blocks.values() {
        for insn in &block.insns {
            let (is_narrow_const, is_wide_const) = match insn.insn.op {
                Opcode::Const4 | Opcode::Const16 | Opcode::Const | Opcode::ConstHigh16 => {
                    (true, false)
                }
                Opcode::ConstWide16
                | Opcode::ConstWide32
                | Opcode::ConstWide
                | Opcode::ConstWideHigh16 => (false, true),
                _ => (false, false),
            };

            if is_narrow_const || is_wide_const {
                if let Some(ref dst) = insn.dst {
                    // SEMANTICS-DEFAULT-EMPTY: const defs start with no type (Bottom); the
                    // missing-key case is identical to Bottom and feeds `to_resolve` below.
                    let current = env.types.get(dst).cloned().unwrap_or(DexType::Bottom);
                    if current == DexType::Bottom {
                        let default = if is_wide_const {
                            DexType::Long
                        } else {
                            DexType::Int
                        };
                        to_resolve.push((dst.clone(), default));
                    }
                }
            }
        }
    }

    // Also include any Bottom vars already in env.types (from other seeding paths)
    for (var, ty) in env.types.iter() {
        if *ty == DexType::Bottom {
            to_resolve.push((var.clone(), DexType::Int));
        }
    }

    // Deduplicate (a var might appear twice if it was both seeded-as-Bottom and scanned)
    to_resolve.sort_by(|a, b| a.0.cmp(&b.0));
    to_resolve.dedup_by(|a, b| a.0 == b.0);

    for (var, default) in to_resolve {
        // Skip if already resolved to something non-Bottom during a prior iteration.
        // SEMANTICS-DEFAULT-EMPTY: absent key means the const was never seeded → treat as
        // Bottom so `resolve_one_const` runs the context-narrowing pass.
        let current = env.types.get(&var).cloned().unwrap_or(DexType::Bottom);
        if current != DexType::Bottom {
            continue;
        }
        let resolved = resolve_one_const(&var, default, env, dex, method_idx, ssa, use_map);
        env.types.insert(var, resolved);
    }
}

fn find_invoke_param_type(
    dex: &DexFile,
    method_idx: MethodIdx,
    var: &VarId,
    insn: &crate::ssa::SsaInsn,
) -> Option<DexType> {
    let (method, proto) = get_method_proto(dex, method_idx)?;

    // Build parameter type list
    let mut param_types: Vec<DexType> = Vec::new();

    // For non-static invokes, first arg is `this` (skip for type matching)
    let is_static = matches!(
        insn.insn.op,
        Opcode::InvokeStatic | Opcode::InvokeStaticRange
    );

    if !is_static {
        param_types.push(resolve_type(dex, method.class_idx));
    }

    if proto.parameters_off != 0 {
        if let Some(type_list) = dex.type_lists.get(&proto.parameters_off) {
            for &tidx in type_list {
                param_types.push(resolve_type(dex, tidx));
            }
        }
    }

    // Expand param_types to register-level slots: wide types (J, D) occupy
    // two consecutive registers in the invoke argument list.
    let mut reg_types: Vec<DexType> = Vec::new();
    for ty in &param_types {
        reg_types.push(ty.clone());
        if matches!(ty, DexType::Long | DexType::Double) {
            reg_types.push(ty.clone()); // high-half register gets same type
        }
    }

    // Find which register position `var` is at
    for (i, use_var) in insn.uses.iter().enumerate() {
        if use_var == var {
            if let Some(rt) = reg_types.get(i) {
                return Some(rt.clone());
            }
        }
    }

    None
}

// ── Aget-object refinement ──────────────────────────────────────────

/// For each `aget-object` instruction, if the array operand has a known array
/// type (e.g. `ArrayRef(ArrayRef(Int))` for `[[I`), refine the result type
/// to the element type (`ArrayRef(Int)` for `[I`).
fn refine_aget_object_types(env: &mut TypeEnv, ssa: &SsaBody) {
    for block in ssa.blocks.values() {
        for insn in &block.insns {
            if insn.insn.op != Opcode::AgetObject {
                continue;
            }
            let Some(ref dst) = insn.dst else { continue };
            let Some(arr_var) = insn.uses.first() else {
                continue;
            };
            let Some(arr_ty) = env.types.get(arr_var).cloned() else {
                continue;
            };
            let elem_ty = match &arr_ty {
                DexType::ArrayRef(inner) => Some(inner.as_ref().clone()),
                DexType::Ref(desc) if desc.starts_with('[') => Some(
                    DexType::from_descriptor(desc.get(1..).unwrap_or("")),
                ),
                _ => None,
            };
            if let Some(ty) = elem_ty {
                env.types.insert(dst.clone(), ty);
            }
        }
    }
}

// ── Cast insertion ──────────────────────────────────────────────────

fn insert_casts(env: &mut TypeEnv, dex: &DexFile, ssa: &SsaBody) {
    // Check for type mismatches at use sites
    for block in ssa.blocks.values() {
        for insn in &block.insns {
            // Check invoke argument types
            match insn.insn.op {
                Opcode::InvokeVirtual
                | Opcode::InvokeSuper
                | Opcode::InvokeDirect
                | Opcode::InvokeStatic
                | Opcode::InvokeInterface => {
                    if let Some(PoolIndex::Method(midx)) = insn.insn.pool_idx {
                        check_invoke_casts(env, dex, midx, insn);
                    }
                }
                _ => {}
            }
        }
    }
}

fn check_invoke_casts(
    env: &mut TypeEnv,
    dex: &DexFile,
    method_idx: MethodIdx,
    insn: &crate::ssa::SsaInsn,
) {
    let (method, proto) = match get_method_proto(dex, method_idx) {
        Some(mp) => mp,
        None => return,
    };

    let is_static = matches!(
        insn.insn.op,
        Opcode::InvokeStatic | Opcode::InvokeStaticRange
    );

    let mut param_types: Vec<DexType> = Vec::new();
    if !is_static {
        param_types.push(resolve_type(dex, method.class_idx));
    }
    if proto.parameters_off != 0 {
        if let Some(type_list) = dex.type_lists.get(&proto.parameters_off) {
            for &tidx in type_list {
                param_types.push(resolve_type(dex, tidx));
            }
        }
    }

    // Expand to register-level slots for wide types
    let mut reg_types: Vec<DexType> = Vec::new();
    for ty in &param_types {
        reg_types.push(ty.clone());
        if matches!(ty, DexType::Long | DexType::Double) {
            reg_types.push(ty.clone());
        }
    }

    for (i, use_var) in insn.uses.iter().enumerate() {
        let Some(expected) = reg_types.get(i) else {
            break;
        };
        // SEMANTICS-DEFAULT-EMPTY: use_var not yet typed → Bottom; the narrowing-cast
        // comparison below correctly finds no cast needed when actual is Bottom.
        let actual = env.types.get(use_var).cloned().unwrap_or(DexType::Bottom);

        // Narrowing cast needed: int → byte/char/short
        if actual == DexType::Int
            && matches!(expected, DexType::Byte | DexType::Char | DexType::Short)
        {
            env.casts.push((use_var.clone(), expected.clone()));
        }
    }
}

// ── Public API ──────────────────────────────────────────────────────

/// Infer types for all VarIds in a method's SSA form.
pub fn infer_types(
    dex: &DexFile,
    method_idx: MethodIdx,
    ssa: &SsaBody,
    _code: &CodeItem,
    _cfg: &Cfg,
    is_static: bool,
) -> TypeEnv {
    let mut env = TypeEnv {
        types: FxHashMap::default(),
        casts: Vec::new(),
    };

    // Phase 1: Seed from method signature
    seed_from_signature(&mut env, dex, method_idx, ssa, is_static);

    // Phase 1b: Seed from opcodes and pool references
    seed_from_opcodes_and_pool(&mut env, dex, ssa);

    // Phase 2: Build use-map and propagate
    let use_map = build_use_map(ssa);
    propagate(&mut env, ssa, &use_map);

    // Phase 2b: Refine aget-object result types from array operand types
    refine_aget_object_types(&mut env, ssa);

    // Phase 2c: Resolve remaining const instructions
    resolve_consts(&mut env, dex, method_idx, ssa, &use_map);

    // Phase 3: Insert casts where needed
    insert_casts(&mut env, dex, ssa);

    env
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_descriptor_primitives() {
        assert_eq!(DexType::from_descriptor("I"), DexType::Int);
        assert_eq!(DexType::from_descriptor("J"), DexType::Long);
        assert_eq!(DexType::from_descriptor("F"), DexType::Float);
        assert_eq!(DexType::from_descriptor("D"), DexType::Double);
        assert_eq!(DexType::from_descriptor("Z"), DexType::Boolean);
        assert_eq!(DexType::from_descriptor("B"), DexType::Byte);
        assert_eq!(DexType::from_descriptor("C"), DexType::Char);
        assert_eq!(DexType::from_descriptor("S"), DexType::Short);
        assert_eq!(DexType::from_descriptor("V"), DexType::Void);
    }

    #[test]
    fn from_descriptor_ref() {
        assert_eq!(
            DexType::from_descriptor("Ljava/lang/String;"),
            DexType::Ref(Arc::from("Ljava/lang/String;"))
        );
    }

    #[test]
    fn from_descriptor_array() {
        assert_eq!(
            DexType::from_descriptor("[I"),
            DexType::ArrayRef(Box::new(DexType::Int))
        );
        assert_eq!(
            DexType::from_descriptor("[[B"),
            DexType::ArrayRef(Box::new(DexType::ArrayRef(Box::new(DexType::Byte))))
        );
        assert_eq!(
            DexType::from_descriptor("[Ljava/lang/Object;"),
            DexType::ArrayRef(Box::new(DexType::Ref(Arc::from("Ljava/lang/Object;"))))
        );
    }

    #[test]
    fn meet_bottom_identity() {
        assert_eq!(DexType::Bottom.meet(&DexType::Int), DexType::Int);
        assert_eq!(DexType::Int.meet(&DexType::Bottom), DexType::Int);
        assert_eq!(DexType::Bottom.meet(&DexType::Bottom), DexType::Bottom);
    }

    #[test]
    fn meet_same_type() {
        assert_eq!(DexType::Int.meet(&DexType::Int), DexType::Int);
        let r = DexType::Ref(Arc::from("Ljava/lang/String;"));
        assert_eq!(r.meet(&r), r);
    }

    #[test]
    fn meet_top_absorbs() {
        assert_eq!(DexType::Top.meet(&DexType::Int), DexType::Top);
        assert_eq!(DexType::Int.meet(&DexType::Top), DexType::Top);
    }

    #[test]
    fn meet_null_ref() {
        let r = DexType::Ref(Arc::from("Ljava/lang/String;"));
        assert_eq!(DexType::Null.meet(&r), r);
        assert_eq!(r.meet(&DexType::Null), r);
    }

    #[test]
    fn meet_null_array() {
        let a = DexType::ArrayRef(Box::new(DexType::Int));
        assert_eq!(DexType::Null.meet(&a), a);
    }

    #[test]
    fn meet_different_refs() {
        let a = DexType::Ref(Arc::from("Ljava/lang/String;"));
        let b = DexType::Ref(Arc::from("Ljava/lang/Integer;"));
        assert_eq!(a.meet(&b), DexType::Ref(Arc::from("Ljava/lang/Object;")));
    }

    #[test]
    fn meet_different_primitives() {
        assert_eq!(DexType::Int.meet(&DexType::Float), DexType::Top);
    }

    #[test]
    fn meet_prim_ref() {
        let r = DexType::Ref(Arc::from("Ljava/lang/String;"));
        assert_eq!(DexType::Int.meet(&r), DexType::Top);
    }

    #[test]
    fn display_types() {
        assert_eq!(format!("{}", DexType::Int), "int");
        assert_eq!(
            format!("{}", DexType::Ref(Arc::from("Ljava/lang/String;"))),
            "java.lang.String"
        );
        assert_eq!(
            format!("{}", DexType::ArrayRef(Box::new(DexType::Int))),
            "int[]"
        );
    }

    #[test]
    fn is_wide_types() {
        assert!(DexType::Long.is_wide());
        assert!(DexType::Double.is_wide());
        assert!(!DexType::Int.is_wide());
        assert!(!DexType::Float.is_wide());
    }

    #[test]
    fn is_reference_types() {
        assert!(DexType::Ref(Arc::from("Lfoo;")).is_reference());
        assert!(DexType::ArrayRef(Box::new(DexType::Int)).is_reference());
        assert!(DexType::Null.is_reference());
        assert!(!DexType::Int.is_reference());
    }

    // --- opcode_result_type direct tests ---

    fn ort(op: Opcode, pool: Option<&PoolIndex>) -> DexType {
        // Create a minimal DexFile for tests that don't need pool lookups
        let data = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(data, None).unwrap();
        opcode_result_type(op, pool, &dex)
    }

    #[test]
    fn ort_int_arithmetic() {
        assert_eq!(ort(Opcode::AddInt, None), DexType::Int);
        assert_eq!(ort(Opcode::SubInt, None), DexType::Int);
        assert_eq!(ort(Opcode::MulIntLit8, None), DexType::Int);
        assert_eq!(ort(Opcode::AddInt2Addr, None), DexType::Int);
        assert_eq!(ort(Opcode::NegInt, None), DexType::Int);
        assert_eq!(ort(Opcode::ArrayLength, None), DexType::Int);
    }

    #[test]
    fn ort_float_arithmetic() {
        assert_eq!(ort(Opcode::AddFloat, None), DexType::Float);
        assert_eq!(ort(Opcode::NegFloat, None), DexType::Float);
        assert_eq!(ort(Opcode::IntToFloat, None), DexType::Float);
    }

    #[test]
    fn ort_long_arithmetic() {
        assert_eq!(ort(Opcode::AddLong, None), DexType::Long);
        assert_eq!(ort(Opcode::IntToLong, None), DexType::Long);
    }

    #[test]
    fn ort_double_arithmetic() {
        assert_eq!(ort(Opcode::AddDouble, None), DexType::Double);
        assert_eq!(ort(Opcode::IntToDouble, None), DexType::Double);
    }

    #[test]
    fn ort_comparisons() {
        assert_eq!(ort(Opcode::CmplFloat, None), DexType::Int);
        assert_eq!(ort(Opcode::CmpgDouble, None), DexType::Int);
        assert_eq!(ort(Opcode::CmpLong, None), DexType::Int);
    }

    #[test]
    fn ort_narrowing() {
        assert_eq!(ort(Opcode::IntToByte, None), DexType::Byte);
        assert_eq!(ort(Opcode::IntToChar, None), DexType::Char);
        assert_eq!(ort(Opcode::IntToShort, None), DexType::Short);
        assert_eq!(ort(Opcode::InstanceOf, None), DexType::Boolean);
    }

    #[test]
    fn ort_string_constants() {
        assert_eq!(
            ort(Opcode::ConstString, None),
            DexType::Ref(Arc::from("Ljava/lang/String;"))
        );
        assert_eq!(
            ort(Opcode::ConstClass, None),
            DexType::Ref(Arc::from("Ljava/lang/Class;"))
        );
    }

    #[test]
    fn ort_field_get_with_pool() {
        // field@0 in fixture is Minimal.x: int
        let pool = PoolIndex::Field(FieldIdx(0));
        assert_eq!(ort(Opcode::Iget, Some(&pool)), DexType::Int);
        assert_eq!(ort(Opcode::Sget, Some(&pool)), DexType::Int);
    }

    #[test]
    fn ort_new_instance_with_pool() {
        // type@0 in fixture — look up what it is
        let data = include_bytes!("../tests/fixtures/classes.dex");
        let dex = crate::parser::DexFile::parse(data, None).unwrap();
        // Find StringBuilder type index
        let sb_idx = dex
            .type_descriptors
            .iter()
            .position(|d| d == "Ljava/lang/StringBuilder;")
            .map(|i| TypeIdx(i as u32));
        if let Some(tidx) = sb_idx {
            let pool = PoolIndex::Type(tidx);
            let ty = opcode_result_type(Opcode::NewInstance, Some(&pool), &dex);
            assert_eq!(ty, DexType::Ref(Arc::from("Ljava/lang/StringBuilder;")));
        }
    }

    #[test]
    fn ort_consts_are_bottom() {
        assert_eq!(ort(Opcode::Const4, None), DexType::Bottom);
        assert_eq!(ort(Opcode::Const16, None), DexType::Bottom);
        assert_eq!(ort(Opcode::ConstWide, None), DexType::Bottom);
    }

    #[test]
    fn ort_moves_are_bottom() {
        assert_eq!(ort(Opcode::Move, None), DexType::Bottom);
        assert_eq!(ort(Opcode::MoveObject, None), DexType::Bottom);
        assert_eq!(ort(Opcode::MoveResult, None), DexType::Bottom);
    }

    #[test]
    fn ort_oob_field_returns_top() {
        let pool = PoolIndex::Field(FieldIdx(9999));
        assert_eq!(ort(Opcode::Iget, Some(&pool)), DexType::Top);
    }

    // --- Lattice law property tests ---

    fn all_test_types() -> Vec<DexType> {
        vec![
            DexType::Bottom,
            DexType::Int,
            DexType::Long,
            DexType::Float,
            DexType::Double,
            DexType::Boolean,
            DexType::Byte,
            DexType::Char,
            DexType::Short,
            DexType::Void,
            DexType::Null,
            DexType::Ref(Arc::from("Ljava/lang/String;")),
            DexType::Ref(Arc::from("Ljava/lang/Integer;")),
            DexType::ArrayRef(Box::new(DexType::Int)),
            DexType::ArrayRef(Box::new(DexType::Ref(Arc::from("Ljava/lang/Object;")))),
            DexType::Top,
        ]
    }

    #[test]
    fn lattice_idempotent() {
        for t in all_test_types() {
            assert_eq!(t.meet(&t), t, "meet({t}, {t}) should be {t}");
        }
    }

    #[test]
    fn lattice_commutative() {
        let types = all_test_types();
        for a in &types {
            for b in &types {
                assert_eq!(a.meet(b), b.meet(a), "meet({a}, {b}) != meet({b}, {a})");
            }
        }
    }

    #[test]
    fn lattice_associative() {
        let types = all_test_types();
        for a in &types {
            for b in &types {
                for c in &types {
                    let ab_c = a.meet(b).meet(c);
                    let a_bc = a.meet(&b.meet(c));
                    assert_eq!(
                        ab_c, a_bc,
                        "meet(meet({a}, {b}), {c}) != meet({a}, meet({b}, {c}))"
                    );
                }
            }
        }
    }

    #[test]
    fn lattice_bottom_is_identity() {
        for t in all_test_types() {
            assert_eq!(DexType::Bottom.meet(&t), t, "Bottom ⊓ {t} should be {t}");
            assert_eq!(t.meet(&DexType::Bottom), t, "{t} ⊓ Bottom should be {t}");
        }
    }

    #[test]
    fn lattice_top_is_absorbing() {
        for t in all_test_types() {
            assert_eq!(
                DexType::Top.meet(&t),
                DexType::Top,
                "Top ⊓ {t} should be Top"
            );
            assert_eq!(
                t.meet(&DexType::Top),
                DexType::Top,
                "{t} ⊓ Top should be Top"
            );
        }
    }
}
