//! SSA form construction for DEX methods.
#![allow(missing_docs, reason = "internal")]

use std::collections::{BTreeMap, BTreeSet};

use droidsaw_common::ssa::{Builder as CommonBuilder, Var as CommonVar};

use crate::cfg::{BlockIdx, Cfg};
use crate::decode::{CodeItem, Instruction};
use crate::error::Result;
use crate::opcodes::Opcode;

// ── VarId ───────────────────────────────────────────────────────────

/// SSA variable identifier. Format: `v{reg}_{ver}` — always a valid Java identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct VarId {
    reg: u16,
    ver: u32,
}

impl VarId {
    pub fn new(reg: u16, ver: u32) -> Self {
        Self { reg, ver }
    }

    pub fn reg(&self) -> u16 {
        self.reg
    }

    pub fn ver(&self) -> u32 {
        self.ver
    }
}

impl std::fmt::Display for VarId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}_{}", self.reg, self.ver)
    }
}

impl From<CommonVar<u16>> for VarId {
    fn from(v: CommonVar<u16>) -> Self {
        VarId { reg: v.reg, ver: v.ver }
    }
}

// ── SSA types ───────────────────────────────────────────────────────

/// Phi node: one operand per predecessor block.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PhiNode {
    pub dst: VarId,
    pub operands: BTreeMap<BlockIdx, VarId>,
}

/// SSA instruction wrapping the original decoded instruction.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SsaInsn {
    pub insn: Instruction,
    pub dst: Option<VarId>,
    pub uses: Vec<VarId>,
}

/// A basic block in SSA form.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SsaBlock {
    pub id: BlockIdx,
    pub phis: Vec<PhiNode>,
    pub insns: Vec<SsaInsn>,
}

/// Complete SSA form for one method body.
#[derive(Debug, serde::Serialize)]
pub struct SsaBody {
    pub blocks: BTreeMap<BlockIdx, SsaBlock>,
    pub entry: BlockIdx,
    pub var_counter: u32,
    /// Parameter VarIds in register order, from first_param_reg to registers_size-1.
    pub param_vars: Vec<VarId>,
}

// ── Register use classification ─────────────────────────────────────

struct RegUse {
    def: Option<u16>,
    reads: Vec<u16>,
    def_wide: bool,
}

fn classify_reg_use(insn: &Instruction) -> RegUse {
    use Opcode::*;
    let dst = insn.dst.unwrap_or(0);
    let src = insn.src.as_slice();

    match insn.op {
        // No registers
        Nop | ReturnVoid | Goto | Goto16 | Goto32 => RegUse {
            def: None,
            reads: vec![],
            def_wide: false,
        },

        // def=None, reads=[dst] — value being returned/thrown/tested/used
        Return | ReturnObject | Throw | MonitorEnter | MonitorExit | FillArrayData
        | PackedSwitch | SparseSwitch | IfEqz | IfNez | IfLtz | IfGez | IfGtz | IfLez => RegUse {
            def: None,
            reads: vec![dst],
            def_wide: false,
        },

        ReturnWide => RegUse {
            def: None,
            reads: vec![dst],
            def_wide: false,
        },

        // def=None, reads=src — two-register branch tests
        IfEq | IfNe | IfLt | IfGe | IfGt | IfLe => RegUse {
            def: None,
            reads: src.to_vec(),
            def_wide: false,
        },

        // def=None, reads=[dst, src[0]] — iput: value(dst) + object(src)
        Iput | IputBoolean | IputByte | IputChar | IputShort | IputObject => RegUse {
            def: None,
            reads: {
                let mut r = vec![dst];
                r.extend_from_slice(src);
                r
            },
            def_wide: false,
        },
        IputWide => RegUse {
            def: None,
            reads: {
                let mut r = vec![dst];
                r.extend_from_slice(src);
                r
            },
            def_wide: false,
        },

        // def=None, reads=[dst] — sput: value(dst)
        Sput | SputWide | SputObject | SputBoolean | SputByte | SputChar | SputShort => RegUse {
            def: None,
            reads: vec![dst],
            def_wide: false,
        },

        // def=None, reads=[dst, src[0], src[1]] — aput: value(dst) + array + index
        Aput | AputObject | AputBoolean | AputByte | AputChar | AputShort => RegUse {
            def: None,
            reads: {
                let mut r = vec![dst];
                r.extend_from_slice(src);
                r
            },
            def_wide: false,
        },
        AputWide => RegUse {
            def: None,
            reads: {
                let mut r = vec![dst];
                r.extend_from_slice(src);
                r
            },
            def_wide: false,
        },

        // def=None, reads=src — invokes
        InvokeVirtual
        | InvokeSuper
        | InvokeDirect
        | InvokeStatic
        | InvokeInterface
        | InvokeVirtualRange
        | InvokeSuperRange
        | InvokeDirectRange
        | InvokeStaticRange
        | InvokeInterfaceRange
        | InvokePolymorphic
        | InvokePolymorphicRange
        | InvokeCustom
        | InvokeCustomRange
        | FilledNewArray
        | FilledNewArrayRange => RegUse {
            def: None,
            reads: src.to_vec(),
            def_wide: false,
        },

        // def=Some(dst), reads=[] — no source registers
        MoveResult | MoveResultObject | MoveException | Const4 | Const16 | Const | ConstHigh16
        | ConstString | ConstStringJumbo | ConstClass | NewInstance | Sget | SgetObject
        | SgetBoolean | SgetByte | SgetChar | SgetShort | ConstMethodHandle | ConstMethodType => {
            RegUse {
                def: Some(dst),
                reads: vec![],
                def_wide: false,
            }
        }

        MoveResultWide | ConstWide16 | ConstWide32 | ConstWide | ConstWideHigh16 | SgetWide => {
            RegUse {
                def: Some(dst),
                reads: vec![],
                def_wide: true,
            }
        }

        // def=Some(dst), reads=[src[0]] — moves, iget, unary, arraylen
        Move | MoveFrom16 | Move16 | MoveObject | MoveObjectFrom16 | MoveObject16 => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: false,
        },

        MoveWide | MoveWideFrom16 | MoveWide16 => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: true,
        },

        Iget | IgetObject | IgetBoolean | IgetByte | IgetChar | IgetShort => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: false,
        },
        IgetWide => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: true,
        },

        ArrayLength => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: false,
        },

        // Unary/conversion — F12x: def=dst, reads=[src[0]]
        NegInt | NotInt | NegFloat | IntToFloat | FloatToInt | IntToByte | IntToChar
        | IntToShort => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: false,
        },

        NegLong | NotLong => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: true,
        },

        NegDouble => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: true,
        },

        IntToLong | IntToDouble | FloatToLong | FloatToDouble => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: true,
        },

        LongToInt | LongToFloat | DoubleToInt | DoubleToFloat => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: false,
        },

        LongToDouble | DoubleToLong => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: true,
        },

        // def=Some(dst), reads=[dst] — CheckCast (in-place)
        CheckCast => RegUse {
            def: Some(dst),
            reads: vec![dst],
            def_wide: false,
        },

        // def=Some(dst), reads=[src[0], src[1]] — new-array, instance-of
        InstanceOf | NewArray => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: false,
        },

        // Aget — def=Some(dst), reads=[src[0], src[1]] (array, index)
        Aget | AgetObject | AgetBoolean | AgetByte | AgetChar | AgetShort => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: false,
        },
        AgetWide => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: true,
        },

        // 3-register arithmetic — F23x: def=dst, reads=[src[0], src[1]]
        AddInt | SubInt | MulInt | DivInt | RemInt | AndInt | OrInt | XorInt | ShlInt | ShrInt
        | UshrInt | AddFloat | SubFloat | MulFloat | DivFloat | RemFloat | CmplFloat
        | CmpgFloat => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: false,
        },

        AddLong | SubLong | MulLong | DivLong | RemLong | AndLong | OrLong | XorLong | ShlLong
        | ShrLong | UshrLong | AddDouble | SubDouble | MulDouble | DivDouble | RemDouble => {
            RegUse {
                def: Some(dst),
                reads: src.to_vec(),
                def_wide: true,
            }
        }

        CmplDouble | CmpgDouble | CmpLong => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: false, // result is int
        },

        // 2addr ops — F12x: def=dst, reads=[dst, src[0]]
        AddInt2Addr | SubInt2Addr | MulInt2Addr | DivInt2Addr | RemInt2Addr | AndInt2Addr
        | OrInt2Addr | XorInt2Addr | ShlInt2Addr | ShrInt2Addr | UshrInt2Addr | AddFloat2Addr
        | SubFloat2Addr | MulFloat2Addr | DivFloat2Addr | RemFloat2Addr => RegUse {
            def: Some(dst),
            reads: {
                let mut r = vec![dst];
                r.extend_from_slice(src);
                r
            },
            def_wide: false,
        },

        AddLong2Addr | SubLong2Addr | MulLong2Addr | DivLong2Addr | RemLong2Addr | AndLong2Addr
        | OrLong2Addr | XorLong2Addr | ShlLong2Addr | ShrLong2Addr | UshrLong2Addr
        | AddDouble2Addr | SubDouble2Addr | MulDouble2Addr | DivDouble2Addr | RemDouble2Addr => {
            RegUse {
                def: Some(dst),
                reads: {
                    let mut r = vec![dst];
                    r.extend_from_slice(src);
                    r
                },
                def_wide: true,
            }
        }

        // Lit16 ops — F22s: def=dst, reads=[src[0]]
        AddIntLit16 | RsubInt | MulIntLit16 | DivIntLit16 | RemIntLit16 | AndIntLit16
        | OrIntLit16 | XorIntLit16 => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: false,
        },

        // Lit8 ops — F22b: def=dst, reads=[src[0]]
        AddIntLit8 | RsubIntLit8 | MulIntLit8 | DivIntLit8 | RemIntLit8 | AndIntLit8
        | OrIntLit8 | XorIntLit8 | ShlIntLit8 | ShrIntLit8 | UshrIntLit8 => RegUse {
            def: Some(dst),
            reads: src.to_vec(),
            def_wide: false,
        },
    }
}

// ── SsaBody construction ────────────────────────────────────────────

impl SsaBody {
    /// Build SSA form from a CodeItem and its CFG.
    ///
    /// Drives `droidsaw_common::ssa::Builder` for the Braun name-resolution
    /// state machine (shared with `droidsaw-hermes`). Dex-side wraps the
    /// result in dex-flavored [`VarId`] / [`PhiNode`] types and runs its own
    /// trivial-phi removal afterwards — common owns the algorithm, not the
    /// bundle types.
    #[allow(clippy::arithmetic_side_effects, reason = "`first_param_reg + i` bounded by registers_size (u16 spec cap) via saturating_sub; `def_reg + 1` for wide-def pair where DEX spec requires def_reg+1 < registers_size on well-formed input, parser-validated.")]
    pub fn build(code: &CodeItem, cfg: &Cfg) -> Result<Self> {
        let mut builder: CommonBuilder<Cfg, u16> = CommonBuilder::new();

        // Pre-seed method parameters in the entry block. Parameters occupy
        // the last ins_size registers of the register file.
        let first_param_reg = code.registers_size.saturating_sub(code.ins_size);
        // PROOF: `code.ins_size: u16` widens to `usize` losslessly on every
        // target droidsaw supports (32-bit or 64-bit; u16 fits in usize).
        #[allow(clippy::as_conversions, reason = "PROOF: u16 → usize widening, lossless on all supported targets.")]
        let mut param_vars = Vec::with_capacity(code.ins_size as usize);
        for i in 0..code.ins_size {
            let reg = first_param_reg + i;
            let v = builder.new_var(reg)?;
            builder.write_variable(cfg.entry, reg, v);
            param_vars.push(VarId::from(v));
        }

        // Pass 1: walk blocks + instructions, driving the builder's
        // read/write at each use/def. Merge points get empty-args phis,
        // sealed in pass 2.
        let mut ssa_blocks = BTreeMap::new();

        for block in &cfg.blocks {
            let mut ssa_insns = Vec::new();

            for insn in &block.instructions {
                let reg_use = classify_reg_use(insn);

                let mut uses = Vec::with_capacity(reg_use.reads.len());
                for &read_reg in &reg_use.reads {
                    let v = builder.read_variable(block.id, read_reg, cfg)?;
                    uses.push(VarId::from(v));
                }

                let dst = if let Some(def_reg) = reg_use.def {
                    let v = builder.new_var(def_reg)?;
                    builder.write_variable(block.id, def_reg, v);
                    if reg_use.def_wide {
                        builder.write_variable(block.id, def_reg + 1, v);
                    }
                    Some(VarId::from(v))
                } else {
                    None
                };

                ssa_insns.push(SsaInsn {
                    insn: insn.clone(),
                    dst,
                    uses,
                });
            }

            ssa_blocks.insert(
                block.id,
                SsaBlock {
                    id: block.id,
                    phis: Vec::new(),
                    insns: ssa_insns,
                },
            );
        }

        // Pass 2: seal phis. Filling a phi at one block can create phis on
        // back-edges; common's seal loop iterates until stable (bounded).
        builder.seal_phis(cfg)?;

        // Pass 3: drain common's phis into dex-flavored PhiNode shape.
        for (&bid, ssa_block) in ssa_blocks.iter_mut() {
            let common_phis = builder.take_phis(bid);
            ssa_block.phis = common_phis
                .into_iter()
                .map(|p| PhiNode {
                    dst: VarId::from(p.dst),
                    operands: p
                        .args
                        .into_iter()
                        .map(|(b, v)| (b, VarId::from(v)))
                        .collect(),
                })
                .collect();
        }

        let var_counter = builder.var_count();
        let mut body = SsaBody {
            blocks: ssa_blocks,
            entry: cfg.entry,
            param_vars,
            var_counter,
        };
        body.remove_trivial_phis();
        droidsaw_common::diag::stage_dump("ssa", &body);
        Ok(body)
    }

    /// Remove trivial phi nodes where all non-self operands are the same value.
    ///
    /// Per round, the replacement map is transitively closed before
    /// application: chain `A → B → C` becomes `A → C, B → C` in a single
    /// rewrite pass, so downstream operands referencing A or B always
    /// land on the terminal value C in the same round. Without this,
    /// one-hop substitution leaves operands pointing at intermediate
    /// (now-deleted) phi vars, which the next round treats as distinct
    /// dangling identifiers — preserving non-minimal phis at downstream
    /// merge points whose operands transitively resolve to a single
    /// value. The chain-fixpoint discipline was surfaced by the
    /// common-side SSA differential fuzz oracle on a failing
    /// reducible-DAG case.
    ///
    /// Replacement cycles (mutual A → B → A) — caused by all-self-ref-
    /// only phi pairs that survive the per-round trivial check — are
    /// preserved as-is (left in the replacement map at one-hop).
    /// Cycles cannot have a "terminal" value, and the next round
    /// drops both phis from the phis map; subsequent operands pointing
    /// at them become dangling-but-distinct identifiers, which is
    /// alpha-equivalent to Braun's textbook "create fresh Undef per
    /// cycle entry" semantics.
    fn remove_trivial_phis(&mut self) {
        loop {
            let mut replacements: BTreeMap<VarId, VarId> = BTreeMap::new();

            for block in self.blocks.values() {
                for phi in &block.phis {
                    let mut same: Option<&VarId> = None;
                    let mut trivial = true;
                    for operand in phi.operands.values() {
                        if *operand == phi.dst {
                            continue; // self-reference
                        }
                        match same {
                            None => same = Some(operand),
                            Some(s) if *s == *operand => {}
                            Some(_) => {
                                trivial = false;
                                break;
                            }
                        }
                    }
                    if trivial {
                        if let Some(replacement) = same {
                            replacements.insert(phi.dst.clone(), replacement.clone());
                        }
                    }
                }
            }

            if replacements.is_empty() {
                break;
            }

            // Transitive-closure: for each (A, B) in replacements, if B
            // is itself replaced, follow the chain to its terminal C.
            // Cycle guard: if the chain revisits a node, leave the
            // replacement at the cycle-entry one-hop (next round's
            // batch drop handles it via dangling-identifier semantics).
            let keys: Vec<VarId> = replacements.keys().cloned().collect();
            for a in keys {
                let mut visited: BTreeSet<VarId> = BTreeSet::new();
                let mut cur = match replacements.get(&a) {
                    Some(v) => v.clone(),
                    None => continue,
                };
                visited.insert(a.clone());
                let mut terminal = cur.clone();
                while let Some(next) = replacements.get(&cur) {
                    if !visited.insert(cur.clone()) {
                        // Cycle detected — bail; leave `a` mapped to
                        // its current one-hop target.
                        terminal = a.clone(); // sentinel: skip rewrite
                        break;
                    }
                    cur = next.clone();
                    terminal = cur.clone();
                }
                if terminal != a {
                    replacements.insert(a, terminal);
                }
            }

            for block in self.blocks.values_mut() {
                block
                    .phis
                    .retain(|phi| !replacements.contains_key(&phi.dst));
                for phi in &mut block.phis {
                    for op in phi.operands.values_mut() {
                        if let Some(repl) = replacements.get(op) {
                            *op = repl.clone();
                        }
                    }
                }
                for insn in &mut block.insns {
                    for u in &mut insn.uses {
                        if let Some(repl) = replacements.get(u) {
                            *u = repl.clone();
                        }
                    }
                }
            }
        }
    }
}

// Historical note: the Braun name-resolution state machine (BraunBuilder,
// read_variable, write_variable, fresh_var, phi-fill loop) used to live
// here. It moved to `droidsaw_common::ssa::Builder` as part of the SSA
// promotion track. The
// deep single-pred chain regression test that lived here with it is
// covered by common's `ssa::tests::{isolated_single_pred_cycle_terminates,
// three_block_single_pred_cycle_terminates, linear_chain_no_phis}`.

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::{PoolIndex, RegList};
    use crate::ids::*;

    #[test]
    fn varid_display_valid_java_identifier() {
        let v = VarId::new(3, 7);
        let s = v.to_string();
        assert_eq!(s, "v3_7");
        // Must match Java identifier pattern
        assert!(s.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_' || c == '$'));
        assert!(s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$'));
    }

    #[test]
    fn varid_ordering() {
        let a = VarId::new(0, 0);
        let b = VarId::new(0, 1);
        let c = VarId::new(1, 0);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn varid_from_common_var() {
        let cv: CommonVar<u16> = CommonVar { reg: 5, ver: 12 };
        let v: VarId = cv.into();
        assert_eq!(v, VarId::new(5, 12));
    }

    #[test]
    fn classify_iget_defines_dst() {
        let insn = Instruction {
            addr: 0,
            op: Opcode::Iget,
            size: 2,
            dst: Some(0),
            src: RegList::one(1),
            literal: 0,
            target: None,
            pool_idx: Some(PoolIndex::Field(FieldIdx(0))),
        };
        let ru = classify_reg_use(&insn);
        assert_eq!(ru.def, Some(0));
        assert_eq!(ru.reads, vec![1]);
        assert!(!ru.def_wide);
    }

    #[test]
    fn classify_iput_no_def() {
        let insn = Instruction {
            addr: 0,
            op: Opcode::Iput,
            size: 2,
            dst: Some(1),         // value register
            src: RegList::one(0), // object register
            literal: 0,
            target: None,
            pool_idx: Some(PoolIndex::Field(FieldIdx(0))),
        };
        let ru = classify_reg_use(&insn);
        assert_eq!(ru.def, None);
        assert_eq!(ru.reads, vec![1, 0]); // value + object
    }

    #[test]
    fn classify_invoke_no_def_reads_src() {
        let insn = Instruction {
            addr: 0,
            op: Opcode::InvokeDirect,
            size: 3,
            dst: None,
            src: RegList::one(0),
            literal: 0,
            target: None,
            pool_idx: Some(PoolIndex::Method(MethodIdx(3))),
        };
        let ru = classify_reg_use(&insn);
        assert_eq!(ru.def, None);
        assert_eq!(ru.reads, vec![0]);
    }

    #[test]
    fn classify_return_reads_dst() {
        let insn = Instruction {
            addr: 0,
            op: Opcode::Return,
            size: 1,
            dst: Some(0),
            src: RegList::empty(),
            literal: 0,
            target: None,
            pool_idx: None,
        };
        let ru = classify_reg_use(&insn);
        assert_eq!(ru.def, None);
        assert_eq!(ru.reads, vec![0]);
    }

    #[test]
    fn classify_add_int_2addr() {
        let insn = Instruction {
            addr: 0,
            op: Opcode::AddInt2Addr,
            size: 1,
            dst: Some(0),
            src: RegList::one(1),
            literal: 0,
            target: None,
            pool_idx: None,
        };
        let ru = classify_reg_use(&insn);
        assert_eq!(ru.def, Some(0));
        assert_eq!(ru.reads, vec![0, 1]); // dst is also read
    }

    #[test]
    fn classify_move_result_object_defines() {
        let insn = Instruction {
            addr: 0,
            op: Opcode::MoveResultObject,
            size: 1,
            dst: Some(2),
            src: RegList::empty(),
            literal: 0,
            target: None,
            pool_idx: None,
        };
        let ru = classify_reg_use(&insn);
        assert_eq!(ru.def, Some(2));
        assert!(ru.reads.is_empty());
    }

    #[test]
    fn classify_nop_no_regs() {
        let insn = Instruction {
            addr: 0,
            op: Opcode::Nop,
            size: 1,
            dst: None,
            src: RegList::empty(),
            literal: 0,
            target: None,
            pool_idx: None,
        };
        let ru = classify_reg_use(&insn);
        assert_eq!(ru.def, None);
        assert!(ru.reads.is_empty());
    }

    #[test]
    fn classify_check_cast_reads_and_writes_dst() {
        let insn = Instruction {
            addr: 0,
            op: Opcode::CheckCast,
            size: 2,
            dst: Some(0),
            src: RegList::empty(),
            literal: 0,
            target: None,
            pool_idx: Some(PoolIndex::Type(TypeIdx(1))),
        };
        let ru = classify_reg_use(&insn);
        assert_eq!(ru.def, Some(0));
        assert_eq!(ru.reads, vec![0]);
    }
}
