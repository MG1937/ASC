//! Structure-Preserving Representation (SPR) — obfuscation-invariant
//! Dalvik bytecode normalization.
//!
//! A method's instruction stream is tokenized through a ladder of
//! increasingly abstract representations so that *renaming* (R8 /
//! ProGuard minification) and encoding-form re-selection produce the
//! same token sequence. The ladder is BC → AR → NR → SPR → Fuzzy-SPR;
//! this module currently implements the bottom two rungs:
//!
//! - **BC** — concrete: full mnemonic (with width/encoding suffix),
//!   registers, immediate value, the *absolute* branch target, and the
//!   resolved pool reference. Name-dependent by design.
//! - **AR** — abstract: NOPs removed, the branch target reduced to a
//!   *direction* (forward / backward / zero), and the opcode's
//!   encoding-form suffix collapsed (so `invoke-virtual` and
//!   `invoke-virtual/range`, `const-string` and `const-string/jumbo`,
//!   the `const/{4,16,high16,…}` width family, etc. share one op-class).
//!   Registers and resolved names are preserved. AR is the rung at which
//!   R8's encoding-form choices (which it makes on register/index/value
//!   size, and which renaming/re-optimization perturbs) stop mattering.
//! - **NR** — name-erased: the AR structural skeleton (op / regs / lit /
//!   branch / NOP-drop) is unchanged, but the resolved pool *names* are
//!   erased so that R8/ProGuard *renaming* collapses to one token
//!   sequence. A method/field reference drops the member name and proto
//!   entirely and reduces to its *declaring type's* Android-API supertype
//!   set; a type-descriptor operand is replaced by its Android-API
//!   supertype set unless it is itself an Android-API (bootclasspath)
//!   type, which is kept verbatim (framework names are never renamed →
//!   already invariant). String constants are kept verbatim at NR
//!   (string-encryption is a later SPR concern, not a renaming one).
//!   The supertype set is computed by walking `superclass_idx` + the
//!   interface list in-dex (no android.jar hierarchy table is needed for
//!   the invariance property — shipped library types reach the framework
//!   boundary through in-dex edges).
//!
//! Operating contract: SPR consumes *canonical* application DEX. A
//! method whose decode desynced on an unmapped opcode byte
//! ([`CodeItemInvariantViolation::UnknownOpcodeByte`] — ODEX/quick or
//! unused bytes, which the tolerant decoder skips by one code unit while
//! the real instruction is wider) cannot be soundly tokenized: the
//! remainder of the stream is misaligned. Such a method is reported
//! [`Unencodable::DecodeDesync`] rather than emitting a fictional
//! partial sequence.

use core::fmt;
use std::collections::HashSet;

use crate::classes::TypeToClassDefMap;
use crate::decode::{insn_format, CodeItem, CodeItemInvariantViolation, InsnFormat, Instruction, PoolIndex};
use crate::ids::TypeIdx;
use crate::opcodes::Opcode;
use crate::parser::DexFile;

/// SPR ladder level. `Bc`, `Ar`, and `Nr` are implemented; `Spr`/
/// `FuzzySpr` follow in later rungs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Concrete bytecode: full mnemonic, absolute branch targets,
    /// NOPs retained, resolved names. Name-dependent.
    Bc,
    /// Abstract representation: NOPs removed, branch targets reduced to
    /// a direction, encoding-form suffixes collapsed. Names preserved.
    Ar,
    /// Name-erased representation: the AR skeleton with resolved names
    /// replaced by Android-API supertype sets, so renaming collapses to
    /// one token sequence. Strings are kept verbatim.
    Nr,
}

/// Why a method could not be encoded into a token sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unencodable {
    /// The method's instruction stream desynced on an unmapped opcode
    /// byte; tokenizing the misaligned remainder would be a fiction.
    DecodeDesync,
}

/// Branch operand at a given level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Branch {
    /// `target > addr` — a forward branch (AR spelling: `along`).
    Forward,
    /// `target < addr` — a backward branch (AR spelling: `back`).
    Backward,
    /// `target == addr` — a zero-offset self-branch.
    Zero,
    /// BC: the absolute resolved target code-unit address.
    Absolute(u32),
}

/// One normalized instruction token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Op-class spelling: at `Bc` the full mnemonic; at `Ar` the
    /// mnemonic truncated at its first `/` (encoding-form suffix
    /// collapsed).
    pub op: String,
    /// Register operands: the destination (if any) followed by the
    /// source registers, in order.
    pub regs: Vec<u16>,
    /// Immediate value, present only for formats that carry a real
    /// signed/zero-extended literal (not the range-invoke arg count,
    /// which shares the `literal` field in the decoded IR).
    pub lit: Option<i64>,
    /// Branch operand, present only for goto / if-* formats (switch and
    /// fill-array reference an out-of-band payload, not a branch).
    pub branch: Option<Branch>,
    /// Resolved pool reference (type descriptor, method/field
    /// signature, string value, or a kind tag for call sites /
    /// method-handle / method-type). `None` when the instruction
    /// carries no pool operand.
    pub pool: Option<String>,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.op)?;
        for r in &self.regs {
            write!(f, " v{r}")?;
        }
        if let Some(l) = self.lit {
            write!(f, " #{l}")?;
        }
        if let Some(b) = &self.branch {
            match b {
                Branch::Forward => write!(f, " along")?,
                Branch::Backward => write!(f, " back")?,
                Branch::Zero => write!(f, " zero")?,
                Branch::Absolute(a) => write!(f, " @{a}")?,
            }
        }
        if let Some(p) = &self.pool {
            write!(f, " {p}")?;
        }
        Ok(())
    }
}

/// Op-class spelling for `op` at `level`. At `Ar` the mnemonic's
/// encoding-form suffix (the part after the first `/`: `/from16`,
/// `/range`, `/jumbo`, `/high16`, `/2addr`, `/lit8`, …) is dropped, so
/// every encoding of the same semantic operation collapses to one
/// class. The Dalvik mnemonic grammar places the semantic op before the
/// `/` and the encoding modifier after it, so truncation is exact.
fn op_class(op: Opcode, level: Level) -> String {
    let m = op.mnemonic();
    match level {
        Level::Bc => m.to_string(),
        // NR keeps AR's suffix-collapsed op-class verbatim; it only
        // changes name/pool handling, not op / reg / lit / branch.
        Level::Ar | Level::Nr => m.split('/').next().unwrap_or(m).to_string(),
    }
}

/// True for formats whose `Instruction::literal` is a genuine immediate
/// value. `F3rc`/`F4rcc` also populate `literal` (with the arg count),
/// and `F31t` leaves it unused, so both are excluded.
fn format_has_immediate(fmt: InsnFormat) -> bool {
    matches!(
        fmt,
        InsnFormat::F11n
            | InsnFormat::F21s
            | InsnFormat::F21h
            | InsnFormat::F22s
            | InsnFormat::F22b
            | InsnFormat::F31i
            | InsnFormat::F51l
    )
}

/// True for goto / if-* formats — the ones whose `target` is a branch
/// destination. `F31t` (packed-switch / sparse-switch / fill-array)
/// stores a payload address in `target`, not a branch, so it is
/// excluded; its case targets live in `CodeItem.payloads`.
fn is_branch_format(fmt: InsnFormat) -> bool {
    matches!(
        fmt,
        InsnFormat::F10t
            | InsnFormat::F20t
            | InsnFormat::F30t
            | InsnFormat::F21t
            | InsnFormat::F22t
    )
}

fn branch_for(insn: &Instruction, level: Level) -> Option<Branch> {
    if !is_branch_format(insn_format(insn.op)) {
        return None;
    }
    let target = insn.target?;
    Some(match level {
        Level::Bc => Branch::Absolute(target),
        // NR reduces branches directionally exactly as AR does.
        Level::Ar | Level::Nr => {
            if target > insn.addr {
                Branch::Forward
            } else if target < insn.addr {
                Branch::Backward
            } else {
                Branch::Zero
            }
        }
    })
}

/// Bootclasspath L-prefixes: descriptors under these packages are
/// platform-provided — never shipped in the APK, never renamed by
/// R8/ProGuard — so they are rename-invariant anchors.
///
/// Deliberately EXCLUDED: `androidx/`, `kotlin/`, `kotlinx/`,
/// `com/google/`. Those are *bundled* into the APK and R8 can and does
/// rename their internals; treating them as API would break the
/// rename-invariance property. They are walked *through* (their shipped
/// class_def carries the in-dex super edge to the real framework
/// boundary), not treated as anchors.
const ANDROID_API_PREFIXES: &[&str] = &[
    "Landroid/",
    "Ldalvik/",
    "Ljava/",
    "Ljavax/",
    "Lorg/w3c/dom/",
    "Lorg/xml/sax/",
    "Lorg/xmlpull/",
    "Lorg/json/",
    "Lorg/apache/http/",
    "Ljunit/",
];

/// True iff `descriptor`, after unwrapping any leading `[` array
/// dimensions to its element type, is a class type under a bootclasspath
/// package (see [`ANDROID_API_PREFIXES`]). Primitive descriptors (`I`,
/// `V`, `[I`, …) carry no `L` and return `false` — callers do not
/// supertype-map them.
fn is_android_api(descriptor: &str) -> bool {
    let element = descriptor.trim_start_matches('[');
    ANDROID_API_PREFIXES.iter().any(|p| element.starts_with(p))
}

/// Upper bound on type-graph nodes the supertype walker visits before it
/// stops and returns what it has. A DoS guard: an adversarial class
/// hierarchy (deep or wide) cannot make the walk loop unbounded. The
/// `visited` set independently breaks cycles; this cap also bounds the
/// fan-out of a pathological interface lattice.
const NR_WALK_NODE_CAP: usize = 256;

/// Stable placeholder for a supertype edge that points at a type with no
/// `class_def` in this DEX (an external library type we cannot resolve
/// further). Honest-Unrecognized: we record that an unresolved boundary
/// was reached rather than dropping it or guessing.
const NR_EXT_PLACEHOLDER: &str = "<ext>";

/// Compute the nearest Android-API supertype set of `ty` by walking the
/// in-dex type graph (`superclass_idx` + the interface list).
///
/// - If `ty` is itself an Android-API type → `vec![its descriptor]` (it
///   is already rename-invariant).
/// - Otherwise BFS over supertype edges. At each parent: an API parent
///   is pushed and its edge stops climbing; a non-API in-dex parent
///   (resolvable via `ttm`) is recursed into; a non-API parent with no
///   `class_def` pushes [`NR_EXT_PLACEHOLDER`] and stops that edge.
/// - `ty` itself non-API with no `class_def` → `vec!["<ext>"]`.
///
/// The result is sorted + deduped so token output is deterministic.
/// No-panic + DoS guards: a `visited` set (cycle break) and
/// [`NR_WALK_NODE_CAP`] (iteration bound); all access is via `.get()` /
/// `ok_or`, never indexing.
fn nearest_api_supertype_set(dex: &DexFile, ttm: &TypeToClassDefMap, ty: TypeIdx) -> Vec<String> {
    // Resolve `ty`'s own descriptor first; an API type short-circuits.
    if let Ok(desc) = dex.get_type_descriptor(ty) {
        if is_android_api(desc) {
            return vec![desc.to_string()];
        }
    }

    let mut out: Vec<String> = Vec::new();
    let mut visited: HashSet<TypeIdx> = HashSet::new();
    let mut stack: Vec<TypeIdx> = vec![ty];
    let mut nodes = 0usize;

    while let Some(cur) = stack.pop() {
        if nodes >= NR_WALK_NODE_CAP {
            break;
        }
        if !visited.insert(cur) {
            continue;
        }
        nodes = nodes.saturating_add(1);

        // An API parent reached via an edge is the nearest API supertype
        // on that edge: emit it and stop climbing. (For `cur == ty` the
        // API short-circuit above already returned, so this only fires
        // on parents.)
        if let Ok(desc) = dex.get_type_descriptor(cur) {
            if cur != ty && is_android_api(desc) {
                out.push(desc.to_string());
                continue;
            }
        }

        // Non-API: resolve the in-dex class_def to climb its super edges.
        let Some(cd_idx) = ttm.lookup(cur) else {
            // No class_def: an external lib type. Emit the placeholder
            // for the boundary and stop this edge.
            out.push(NR_EXT_PLACEHOLDER.to_string());
            continue;
        };
        let Some(cd) = dex.class_defs.get(cd_idx) else {
            out.push(NR_EXT_PLACEHOLDER.to_string());
            continue;
        };

        // Superclass edge.
        if let Some(sup) = cd.superclass_idx {
            stack.push(sup);
        }
        // Interface-list edges.
        if cd.interfaces_off != 0 {
            if let Some(ifaces) = dex.type_lists.get(&cd.interfaces_off) {
                for iface in ifaces {
                    stack.push(*iface);
                }
            }
        }
    }

    // If a non-API type bottomed out with no resolvable supertype at all
    // (e.g. an unresolved root, or a class whose only super was already
    // visited), surface the honest external placeholder.
    if out.is_empty() {
        out.push(NR_EXT_PLACEHOLDER.to_string());
    }

    out.sort();
    out.dedup();
    out
}

/// Encode an Android-API supertype set as a single stable NR pool token:
/// the sorted descriptors joined with `+`. A singleton
/// `{Landroid/view/View;}` spells `"Landroid/view/View;"`; a pair spells
/// `"Landroid/view/View;+Ljava/io/Serializable;"`. The set is already
/// sorted + deduped by [`nearest_api_supertype_set`], so the join is
/// deterministic.
fn supertype_set_token(set: &[String]) -> String {
    set.join("+")
}

/// NR pool token for a declaring (or operand) type: its Android-API
/// supertype set, joined per [`supertype_set_token`].
fn nr_type_token(dex: &DexFile, ttm: &TypeToClassDefMap, ty: TypeIdx) -> String {
    supertype_set_token(&nearest_api_supertype_set(dex, ttm, ty))
}

/// NR resolution of an instruction's pool operand. Erases method/field
/// names and proto/type entirely, reducing each to the supertype-mapped
/// declaring type; supertype-maps bare type operands; keeps strings and
/// the call-site / method-handle / method-type placeholders verbatim.
fn pool_token_nr(dex: &DexFile, ttm: &TypeToClassDefMap, insn: &Instruction) -> Option<String> {
    let pi = insn.pool_idx.as_ref()?;
    // const-method-handle / const-method-type are mislabeled as Method in
    // the decoded IR (see `pool_token`); keep their placeholders and do
    // NOT supertype-map them.
    match insn.op {
        Opcode::ConstMethodHandle => return Some("<method-handle>".to_string()),
        Opcode::ConstMethodType => return Some("<method-type>".to_string()),
        _ => {}
    }
    Some(match pi {
        // Strings are kept verbatim at NR (string-encryption is a later
        // SPR concern, not a renaming one).
        PoolIndex::String(s) => format!("\"{}\"", dex.get_string(*s).unwrap_or("<?str>")),
        PoolIndex::Type(t) => nr_type_token(dex, ttm, *t),
        PoolIndex::Field(fld) => {
            #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; .get() returns None on OOB so the cast cannot index out of bounds or panic.")]
            let slot = dex.fields.get(fld.0 as usize);
            match slot {
                Some(f) => nr_type_token(dex, ttm, f.class_idx),
                None => "<?field>".to_string(),
            }
        }
        PoolIndex::Method(m) | PoolIndex::MethodAndProto(m, _) => {
            #[allow(clippy::as_conversions, reason = "PROOF: widen u32→usize; .get() returns None on OOB so the cast cannot index out of bounds or panic.")]
            let slot = dex.methods.get(m.0 as usize);
            match slot {
                Some(meth) => nr_type_token(dex, ttm, meth.class_idx),
                None => "<?method>".to_string(),
            }
        }
        PoolIndex::CallSite(_) => "<call-site>".to_string(),
    })
}

/// Resolve the pool reference to a stable string. Names survive at BC/AR
/// (they are erased at NR). Resolution failure on adversarial input
/// yields a placeholder rather than propagating an error — the token
/// stream is best-effort structural, never panicking.
fn pool_token(dex: &DexFile, insn: &Instruction) -> Option<String> {
    let pi = insn.pool_idx.as_ref()?;
    // The decoded IR routes both const-method-handle and const-method-type
    // through PoolIndex::Method, which is a mislabel (the operands are a
    // method-handle index and a proto index respectively). Key these off
    // the opcode so they are not resolved as method references.
    match insn.op {
        Opcode::ConstMethodHandle => return Some("<method-handle>".to_string()),
        Opcode::ConstMethodType => return Some("<method-type>".to_string()),
        _ => {}
    }
    Some(match pi {
        PoolIndex::String(s) => format!("\"{}\"", dex.get_string(*s).unwrap_or("<?str>")),
        PoolIndex::Type(t) => dex.get_type_descriptor(*t).unwrap_or("<?type>").to_string(),
        PoolIndex::Field(fld) => dex.format_field(*fld).unwrap_or_else(|_| "<?field>".to_string()),
        PoolIndex::Method(m) => dex.format_method(*m).unwrap_or_else(|_| "<?method>".to_string()),
        PoolIndex::MethodAndProto(m, _proto) => {
            dex.format_method(*m).unwrap_or_else(|_| "<?method>".to_string())
        }
        PoolIndex::CallSite(_) => "<call-site>".to_string(),
    })
}

fn token_for(
    dex: &DexFile,
    insn: &Instruction,
    level: Level,
    ttm: Option<&TypeToClassDefMap>,
) -> Token {
    let mut regs = Vec::new();
    if let Some(d) = insn.dst {
        regs.push(d);
    }
    regs.extend_from_slice(insn.src.as_slice());
    let lit = if format_has_immediate(insn_format(insn.op)) {
        Some(insn.literal)
    } else {
        None
    };
    // NR erases names through the supertype walker (needs the ttm); BC/AR
    // keep the resolved name. `ttm` is `Some` exactly when `level == Nr`.
    let pool = match (level, ttm) {
        (Level::Nr, Some(ttm)) => pool_token_nr(dex, ttm, insn),
        _ => pool_token(dex, insn),
    };
    Token {
        op: op_class(insn.op, level),
        regs,
        lit,
        branch: branch_for(insn, level),
        pool,
    }
}

/// Encode one method's instruction stream at `level`.
///
/// Returns [`Unencodable::DecodeDesync`] if the method's decode
/// desynced on an unmapped opcode byte — no partial token sequence is
/// ever produced for a misaligned stream (honest-Unrecognized). At
/// `Ar`, NOPs are omitted.
pub fn encode_method(dex: &DexFile, code: &CodeItem, level: Level) -> Result<Vec<Token>, Unencodable> {
    if code
        .invariant_violations
        .iter()
        .any(|v| matches!(v, CodeItemInvariantViolation::UnknownOpcodeByte { .. }))
    {
        return Err(Unencodable::DecodeDesync);
    }
    // NR needs the type→class_def map for the supertype walk. Building it
    // once per `encode_method` call is a known cost for v1 (one linear
    // pass over `dex.class_defs`); a future rung may thread a shared map
    // in. It is built only for NR — BC/AR pay nothing.
    let ttm = if level == Level::Nr {
        Some(TypeToClassDefMap::build(dex))
    } else {
        None
    };
    let mut out = Vec::with_capacity(code.instructions.len());
    for insn in &code.instructions {
        // NOPs are dropped at both AR and NR (NR builds on AR's skeleton).
        if matches!(level, Level::Ar | Level::Nr) && insn.op == Opcode::Nop {
            continue;
        }
        out.push(token_for(dex, insn, level, ttm.as_ref()));
    }
    Ok(out)
}

/// Encode one method's instruction stream to a newline-joined token
/// string (the form a fuzzy hash will consume at the Fuzzy-SPR rung).
pub fn encode_method_string(
    dex: &DexFile,
    code: &CodeItem,
    level: Level,
) -> Result<String, Unencodable> {
    let toks = encode_method(dex, code, level)?;
    let mut s = String::new();
    for (i, t) in toks.iter().enumerate() {
        if i != 0 {
            s.push('\n');
        }
        s.push_str(&t.to_string());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::RegList;
    use crate::parser::DexFile;

    fn fixture_dex() -> DexFile {
        let bytes = include_bytes!("../tests/fixtures/classes.dex");
        DexFile::parse(bytes, None).expect("fixture parses")
    }

    fn insn(op: Opcode, addr: u32, dst: Option<u16>, src: RegList, target: Option<u32>) -> Instruction {
        Instruction { addr, op, size: 1, dst, src, literal: 0, target, pool_idx: None }
    }

    #[test]
    fn ar_collapses_encoding_suffixes_bc_preserves_them() {
        // The AR rung must give the same op-class to every encoding of a
        // semantic operation; BC keeps them distinct. These are the
        // mandatory normalizations without which obfuscation invariance
        // fails (R8 re-selects encodings on register/index/value size).
        let pairs = [
            (Opcode::InvokeVirtual, Opcode::InvokeVirtualRange),
            (Opcode::ConstString, Opcode::ConstStringJumbo),
            (Opcode::Const4, Opcode::Const),
            (Opcode::Move, Opcode::MoveFrom16),
            (Opcode::Goto, Opcode::Goto32),
        ];
        for (a, b) in pairs {
            assert_eq!(
                op_class(a, Level::Ar),
                op_class(b, Level::Ar),
                "AR must collapse {a:?} and {b:?} to one class"
            );
            assert_ne!(
                op_class(a, Level::Bc),
                op_class(b, Level::Bc),
                "BC must keep {a:?} and {b:?} distinct"
            );
        }
        // And the collapsed class is the suffix-free semantic op.
        assert_eq!(op_class(Opcode::InvokeVirtualRange, Level::Ar), "invoke-virtual");
        assert_eq!(op_class(Opcode::ConstStringJumbo, Level::Ar), "const-string");
    }

    #[test]
    fn unknown_opcode_byte_method_is_unencodable() {
        // A desynced stream must bail, never tokenize a misaligned tail.
        let dex = fixture_dex();
        let code = CodeItem {
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            debug_info_off: 0,
            instructions: vec![insn(Opcode::Return, 0, Some(0), RegList::empty(), None)],
            tries: Vec::new(),
            catch_handlers: Vec::new(),
            payloads: std::collections::BTreeMap::new(),
            invariant_violations: vec![CodeItemInvariantViolation::UnknownOpcodeByte {
                source_pc: 0,
                opcode_byte: 0xE3,
            }],
        };
        assert_eq!(encode_method(&dex, &code, Level::Ar), Err(Unencodable::DecodeDesync));
        assert_eq!(encode_method(&dex, &code, Level::Bc), Err(Unencodable::DecodeDesync));
    }

    #[test]
    fn ar_drops_nops_bc_keeps_them() {
        let dex = fixture_dex();
        let code = CodeItem {
            registers_size: 2,
            ins_size: 0,
            outs_size: 0,
            debug_info_off: 0,
            instructions: vec![
                insn(Opcode::Nop, 0, None, RegList::empty(), None),
                insn(Opcode::Move, 1, Some(0), RegList::one(1), None),
                insn(Opcode::Nop, 2, None, RegList::empty(), None),
                insn(Opcode::ReturnVoid, 3, None, RegList::empty(), None),
            ],
            tries: Vec::new(),
            catch_handlers: Vec::new(),
            payloads: std::collections::BTreeMap::new(),
            invariant_violations: Vec::new(),
        };
        let bc = encode_method(&dex, &code, Level::Bc).expect("bc");
        let ar = encode_method(&dex, &code, Level::Ar).expect("ar");
        assert_eq!(bc.len(), 4, "BC retains NOPs");
        assert_eq!(ar.len(), 2, "AR drops both NOPs");
        assert!(ar.iter().all(|t| t.op != "nop"));
    }

    #[test]
    fn branch_is_directional_at_ar_absolute_at_bc() {
        let dex = fixture_dex();
        // A backward goto at addr 5 targeting addr 2.
        let back = insn(Opcode::Goto, 5, None, RegList::empty(), Some(2));
        // A forward goto at addr 5 targeting addr 9.
        let fwd = insn(Opcode::Goto, 5, None, RegList::empty(), Some(9));
        assert_eq!(token_for(&dex, &back, Level::Ar, None).branch, Some(Branch::Backward));
        assert_eq!(token_for(&dex, &fwd, Level::Ar, None).branch, Some(Branch::Forward));
        assert_eq!(token_for(&dex, &back, Level::Bc, None).branch, Some(Branch::Absolute(2)));
        // A non-branch op carries no branch even when target is set
        // (switch/fill use target for a payload pc, not a branch).
        let sw = insn(Opcode::PackedSwitch, 5, Some(0), RegList::empty(), Some(20));
        assert_eq!(token_for(&dex, &sw, Level::Ar, None).branch, None);
    }

    /// Route-A invariance gate (structural skeleton): renaming every type
    /// descriptor must change resolved pool references but leave the
    /// op-class / register / literal / branch skeleton byte-identical —
    /// the property NR then completes by erasing the names entirely.
    #[test]
    fn structural_skeleton_is_independent_of_type_names() {
        let mut dex = fixture_dex();

        let skeleton = |d: &DexFile| -> Vec<Vec<Token>> {
            d.code_items
                .values()
                .map(|c| {
                    encode_method(d, c, Level::Ar)
                        .expect("fixture methods encode")
                        .into_iter()
                        .map(|mut t| {
                            t.pool = None; // project away names
                            t
                        })
                        .collect()
                })
                .collect()
        };
        let full = |d: &DexFile| -> Vec<String> {
            d.code_items
                .values()
                .map(|c| encode_method_string(d, c, Level::Ar).expect("encodes"))
                .collect()
        };

        let before_skeleton = skeleton(&dex);
        let before_full = full(&dex);

        // Synthetic rename: prepend a marker into every class descriptor
        // (Lcom/x/Foo; -> Lren_/com/x/Foo;). Structure is untouched.
        for d in dex.type_descriptors.iter_mut() {
            if let Some(rest) = d.strip_prefix('L') {
                *d = format!("Lren_/{rest}");
            }
        }

        let after_skeleton = skeleton(&dex);
        let after_full = full(&dex);

        assert_eq!(
            before_skeleton, after_skeleton,
            "AR structural skeleton must be independent of type names"
        );
        assert_ne!(
            before_full, after_full,
            "the rename must actually have moved some resolved pool reference \
             (else the test is vacuous)"
        );
    }

    /// Route-A invariance gate at NR: renaming every *application* type
    /// descriptor must leave the FULL NR token stream byte-identical
    /// across all methods. NR erases names down to the Android-API
    /// supertype set, which is resolved through unrenamed bootclasspath
    /// anchors — so a pure rename collapses to one token sequence.
    ///
    /// Only NON-API descriptors are renamed: R8/ProGuard renames app and
    /// shipped-library internals but never bootclasspath types
    /// (`Landroid/`/`Ljava/`/…). Renaming those too would (correctly)
    /// change the emitted anchor and would not model real renaming.
    #[test]
    fn nr_token_stream_is_invariant_under_type_rename() {
        let mut dex = fixture_dex();

        let nr_full = |d: &DexFile| -> Vec<String> {
            d.code_items
                .values()
                .map(|c| encode_method_string(d, c, Level::Nr).expect("fixture methods encode"))
                .collect()
        };
        // BC is name-dependent: used only to prove the rename was
        // non-vacuous (it moved a resolved pool ref at the concrete rung).
        let bc_full = |d: &DexFile| -> Vec<String> {
            d.code_items
                .values()
                .map(|c| encode_method_string(d, c, Level::Bc).expect("encodes"))
                .collect()
        };

        let before_nr = nr_full(&dex);
        let before_bc = bc_full(&dex);

        // Synthetic rename of application types only (Lcom/x/Foo; ->
        // Lren_/com/x/Foo;). A prefix rename keeps the descriptor
        // non-API, so the supertype walk still terminates at the same
        // unrenamed Android-API anchors. Bootclasspath descriptors are
        // left untouched (R8 does not rename them).
        let mut renamed_any = false;
        for d in dex.type_descriptors.iter_mut() {
            if is_android_api(d) {
                continue;
            }
            if let Some(rest) = d.strip_prefix('L') {
                *d = format!("Lren_/{rest}");
                renamed_any = true;
            }
        }
        assert!(renamed_any, "fixture must carry at least one renameable app type");

        let after_nr = nr_full(&dex);
        let after_bc = bc_full(&dex);

        assert_eq!(
            before_nr, after_nr,
            "NR token stream must be byte-identical under application-type rename"
        );
        assert_ne!(
            before_bc, after_bc,
            "the rename must actually have moved a BC-level pool reference \
             (else the NR invariance test is vacuous)"
        );
    }

    #[test]
    fn is_android_api_truth_table() {
        // Bootclasspath packages → API.
        assert!(is_android_api("Landroid/view/View;"));
        assert!(is_android_api("Ljava/lang/Object;"));
        assert!(is_android_api("Ljavax/crypto/Cipher;"));
        assert!(is_android_api("Ldalvik/system/DexFile;"));
        assert!(is_android_api("Lorg/json/JSONObject;"));
        assert!(is_android_api("Lorg/w3c/dom/Node;"));
        assert!(is_android_api("Lorg/apache/http/HttpResponse;"));
        assert!(is_android_api("Ljunit/framework/TestCase;"));
        // Array-wrapped: unwrap dims, classify the element type.
        assert!(is_android_api("[Landroid/view/View;"));
        assert!(is_android_api("[[Ljava/lang/String;"));

        // Bundled + R8-renameable → NOT API (the sharp edge).
        assert!(!is_android_api("Landroidx/recyclerview/widget/RecyclerView;"));
        assert!(!is_android_api("Lkotlin/Unit;"));
        assert!(!is_android_api("Lkotlinx/coroutines/Job;"));
        assert!(!is_android_api("Lcom/google/gson/Gson;"));
        assert!(!is_android_api("Lcom/foo/Bar;"));

        // Primitives and primitive arrays carry no `L` → not class types.
        assert!(!is_android_api("I"));
        assert!(!is_android_api("V"));
        assert!(!is_android_api("[I"));
        assert!(!is_android_api("[[J"));
    }

    /// The supertype walker, exercised on hand-built dex inputs that the
    /// fixture may not contain: an app type whose super chain reaches an
    /// API anchor, an API type (self), an unresolved external type, and a
    /// cycle that must terminate.
    #[test]
    fn walker_resolves_api_supertypes_self_external_and_cycle() {
        use crate::ids::{ClassDefItem, StringIdx, TypeIdx};

        // Build a minimal synthetic DexFile by parsing the fixture, then
        // overwriting the type/class tables with a controlled hierarchy.
        let mut dex = fixture_dex();
        dex.type_descriptors = vec![
            "Lcom/app/A;".to_string(),         // 0: app, extends B
            "Lcom/app/B;".to_string(),         // 1: app, extends android.app.Activity
            "Landroid/app/Activity;".to_string(), // 2: API anchor
            "Lcom/ext/Unresolved;".to_string(), // 3: app, no class_def (external)
            "Lcom/app/C;".to_string(),         // 4: cycle C -> D
            "Lcom/app/D;".to_string(),         // 5: cycle D -> C
        ];
        let cd = |class: u32, sup: Option<u32>| ClassDefItem {
            class_idx: TypeIdx(class),
            access_flags: 0,
            superclass_idx: sup.map(TypeIdx),
            interfaces_off: 0,
            source_file_idx: Some(StringIdx(0)),
            annotations_off: 0,
            class_data_off: 0,
            static_values_off: 0,
        };
        // A -> B -> Activity(API). No class_def for type 2 (Activity is
        // external/API), 3 (unresolved). C <-> D cycle.
        dex.class_defs = vec![
            cd(0, Some(1)),
            cd(1, Some(2)),
            cd(4, Some(5)),
            cd(5, Some(4)),
        ];
        let ttm = TypeToClassDefMap::build(&dex);

        // App type whose chain reaches an API anchor → that anchor.
        assert_eq!(
            nearest_api_supertype_set(&dex, &ttm, TypeIdx(0)),
            vec!["Landroid/app/Activity;".to_string()],
        );
        // API type → itself.
        assert_eq!(
            nearest_api_supertype_set(&dex, &ttm, TypeIdx(2)),
            vec!["Landroid/app/Activity;".to_string()],
        );
        // Unresolved external app type (no class_def) → <ext>.
        assert_eq!(
            nearest_api_supertype_set(&dex, &ttm, TypeIdx(3)),
            vec![NR_EXT_PLACEHOLDER.to_string()],
        );
        // A cycle must terminate (visited-set guard) and surface <ext>
        // (no API anchor reachable on the cyclic edges).
        assert_eq!(
            nearest_api_supertype_set(&dex, &ttm, TypeIdx(4)),
            vec![NR_EXT_PLACEHOLDER.to_string()],
        );
    }

    /// The node cap bounds an adversarially deep/wide hierarchy: the walk
    /// stops and returns rather than looping unbounded or panicking.
    #[test]
    fn walker_node_cap_bounds_deep_chain() {
        use crate::ids::{ClassDefItem, StringIdx, TypeIdx};

        let mut dex = fixture_dex();
        // A long non-API chain T0 -> T1 -> ... -> T(N-1), none API, none
        // reaching an anchor. Length comfortably exceeds the node cap.
        let n: u32 = (NR_WALK_NODE_CAP as u32).saturating_add(64);
        dex.type_descriptors = (0..n).map(|i| format!("Lcom/deep/T{i};")).collect();
        dex.class_defs = (0..n)
            .map(|i| ClassDefItem {
                class_idx: TypeIdx(i),
                access_flags: 0,
                // Last node points nowhere; others point at the next.
                superclass_idx: if i + 1 < n { Some(TypeIdx(i + 1)) } else { None },
                interfaces_off: 0,
                source_file_idx: Some(StringIdx(0)),
                annotations_off: 0,
                class_data_off: 0,
                static_values_off: 0,
            })
            .collect();
        let ttm = TypeToClassDefMap::build(&dex);

        // Must terminate (no hang, no panic) and return a deterministic
        // result. The deepest non-API root with no API anchor yields the
        // honest external placeholder.
        let set = nearest_api_supertype_set(&dex, &ttm, TypeIdx(0));
        assert_eq!(set, vec![NR_EXT_PLACEHOLDER.to_string()]);
    }
}
