//! Control flow graph construction from DEX bytecode.
#![allow(missing_docs, reason = "internal")]
#![cfg_attr(not(test), allow(clippy::as_conversions, reason = "PROOF (bulk allow, 12 sites): cfg.rs builds the control-flow graph from a parser-validated instruction stream. Casts cluster around (a) `u32 instruction-offset as usize` widening for slice indexing into the parser-validated instruction array, lossless on 64-bit; (b) `usize block-id as u32` narrowing for CFG-internal labelling, dominated by the CFG builder's per-method block count (bounded by instruction count, which is `< 2^32 / 2` by DEX `code_item.insns_size: u32` spec); (c) `i32 branch-offset as u32` reinterpret-cast for signed-relative-offset arithmetic, dominated by the decoder's per-instruction validation. Per-site PROOF refinement deferred."))]

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::decode::{CodeItem, Instruction, PayloadData};
use crate::error::Result;
use crate::ids::TypeIdx;
use crate::opcodes::Opcode;

/// Index into the CFG's block list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct BlockIdx(pub u32);

/// Type of edge between basic blocks.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum EdgeKind {
    FallThrough,
    Branch,
    SwitchCase(i32),
    SwitchDefault,
    ExceptionHandler(TypeIdx),
    ExceptionCatchAll,
}

/// An edge from one block to another.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Edge {
    pub target: BlockIdx,
    pub kind: EdgeKind,
}

/// A basic block: maximal sequence of instructions with single entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BasicBlock {
    pub id: BlockIdx,
    pub start_addr: u32,
    pub instructions: Vec<Instruction>,
    pub successors: Vec<Edge>,
    pub predecessors: BTreeSet<BlockIdx>,
}

/// Exception region mapping a try range to its handlers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExceptionRegion {
    pub start_addr: u32,
    pub end_addr: u32,
    pub handler_blocks: Vec<(EdgeKind, BlockIdx)>,
}

/// Control flow graph for a single method.
#[derive(Debug, serde::Serialize)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    pub entry: BlockIdx,
    pub exception_regions: Vec<ExceptionRegion>,
    pub addr_to_block: BTreeMap<u32, BlockIdx>,
}

impl Cfg {
    pub fn build(code: &CodeItem) -> Result<Self> {
        if code.instructions.is_empty() {
            let cfg = Cfg {
                blocks: Vec::new(),
                entry: BlockIdx(0),
                exception_regions: Vec::new(),
                addr_to_block: BTreeMap::new(),
            };
            droidsaw_common::diag::stage_dump("cfg", &cfg);
            return Ok(cfg);
        }

        let leaders = find_leaders(code);
        let (mut blocks, addr_to_block) = build_blocks(code, &leaders);
        add_edges(&mut blocks, &addr_to_block, code);
        add_exception_edges(&mut blocks, &addr_to_block, code);
        fill_predecessors(&mut blocks);
        let exception_regions = build_exception_regions(code, &addr_to_block);

        let cfg = Cfg {
            entry: BlockIdx(0),
            blocks,
            exception_regions,
            addr_to_block,
        };
        droidsaw_common::diag::stage_dump("cfg", &cfg);
        Ok(cfg)
    }

    #[allow(
        clippy::indexing_slicing,
        reason = "PROOF: BlockIdx values are minted only by Cfg::build (which produces idx.0 in 0..blocks.len()) and `successors`/`predecessors` lists which carry only minted indices. The debug_assert! catches contract violation in test/debug; release-mode trusts the structural invariant."
    )]
    pub fn block(&self, idx: BlockIdx) -> &BasicBlock {
        debug_assert!(
            (idx.0 as usize) < self.blocks.len(),
            "BlockIdx({}) out of range for Cfg with {} blocks",
            idx.0,
            self.blocks.len()
        );
        &self.blocks[idx.0 as usize]
    }

    pub fn block_at(&self, addr: u32) -> Option<BlockIdx> {
        // Find the block whose range contains addr
        self.addr_to_block
            .range(..=addr)
            .next_back()
            .map(|(_, &idx)| idx)
    }
}

/// Full CFG view including exception edges — used for SSA, taint analysis,
/// anything that needs to see all control flow.
#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: BlockIdx is minted only by Cfg::build / nodes() (yielding `0..blocks.len()`); successors / predecessors lists carry only minted indices. Trait callers receiving an invalid BlockIdx is a logic bug at the call site, not adversarial input."
)]
impl droidsaw_common::graph::Graph for Cfg {
    type Node = BlockIdx;

    fn entry(&self) -> BlockIdx {
        self.entry
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "PROOF: blocks.len() is bounded by DEX code_item insns_size: u32 — basic blocks are formed by partitioning the instruction stream, so block count ≤ insn count ≤ u32::MAX."
    )]
    fn nodes(&self) -> Vec<BlockIdx> {
        (0..self.blocks.len() as u32).map(BlockIdx).collect()
    }

    fn successors(&self, node: BlockIdx) -> Vec<BlockIdx> {
        self.blocks[node.0 as usize]
            .successors
            .iter()
            .map(|e| e.target)
            .collect()
    }

    fn predecessors(&self, node: BlockIdx) -> Vec<BlockIdx> {
        self.blocks[node.0 as usize]
            .predecessors
            .iter()
            .copied()
            .collect()
    }
}

// SSA name-resolution view for `droidsaw_common::ssa::Builder`. Exception
// edges are already folded into `Graph::predecessors` at CFG-construction
// time (see `add_exception_edges` + `fill_predecessors`), so the default
// empty `exc_predecessors` impl is correct — there is no second map to
// surface the way hermes does.
impl droidsaw_common::ssa::SsaCfg for Cfg {}

/// Normal-flow view of the CFG — exception edges are hidden.
///
/// This is what dominator and structure analyses want: exception edges create
/// "virtual" predecessors that don't participate in normal control flow
/// structuring (an exception handler is reachable from anywhere in its try
/// block, so including exception edges makes every handler's dominator the
/// try region, which breaks if/else recovery).
///
/// Wrap a `&Cfg` in `NormalFlow` before passing to `common::graph::dominators`.
pub struct NormalFlow<'a>(pub &'a Cfg);

#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: same invariant as Cfg's Graph impl — BlockIdx values originate from Cfg::build / nodes(); pred/succ lists are seeded only with minted indices."
)]
impl<'a> droidsaw_common::graph::Graph for NormalFlow<'a> {
    type Node = BlockIdx;

    fn entry(&self) -> BlockIdx {
        self.0.entry
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "PROOF: same as forward-Cfg's nodes() — blocks.len() bounded by DEX code_item insns_size: u32."
    )]
    fn nodes(&self) -> Vec<BlockIdx> {
        (0..self.0.blocks.len() as u32).map(BlockIdx).collect()
    }

    fn successors(&self, node: BlockIdx) -> Vec<BlockIdx> {
        self.0.blocks[node.0 as usize]
            .successors
            .iter()
            .filter(|e| {
                !matches!(
                    e.kind,
                    EdgeKind::ExceptionHandler(_) | EdgeKind::ExceptionCatchAll
                )
            })
            .map(|e| e.target)
            .collect()
    }

    fn predecessors(&self, node: BlockIdx) -> Vec<BlockIdx> {
        // Filter out predecessors whose edge to `node` is an exception edge
        let target = node;
        self.0.blocks[node.0 as usize]
            .predecessors
            .iter()
            .copied()
            .filter(|&p| {
                let p_block = &self.0.blocks[p.0 as usize];
                p_block.successors.iter().any(|e| {
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

// ORACLE-OPCODE-LOCKSTEP-BEGIN
// Canonical CF opcode names used by the production CF predicates below.
// build.rs parses this section and cross-checks it against cfg_oracle.rs.
// If a new CF opcode is added here, it MUST also appear in the oracle section.
//
// Unconditional branches: "Goto"  "Goto16"  "Goto32"
// Switch:                 "PackedSwitch"  "SparseSwitch"
// Conditional branches:   "IfEq"  "IfNe"  "IfLt"  "IfGe"  "IfGt"  "IfLe"
//                         "IfEqz"  "IfNez"  "IfLtz"  "IfGez"  "IfGtz"  "IfLez"
// Terminals:              "Throw"  "ReturnVoid"  "Return"  "ReturnWide"  "ReturnObject"
// ORACLE-OPCODE-LOCKSTEP-END

pub(crate) fn is_branch(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Goto
            | Opcode::Goto16
            | Opcode::Goto32
            | Opcode::IfEq
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
            | Opcode::SparseSwitch
    )
}

fn is_unconditional_branch(op: Opcode) -> bool {
    matches!(op, Opcode::Goto | Opcode::Goto16 | Opcode::Goto32)
}

fn is_terminal(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Throw
            | Opcode::ReturnVoid
            | Opcode::Return
            | Opcode::ReturnWide
            | Opcode::ReturnObject
    )
}

#[allow(clippy::arithmetic_side_effects, reason = "addr + size on parser-validated CodeItem; DEX spec caps insns_size to 0xFFFE units, so u32 sum cannot overflow on well-formed input. Parser rejects malformed sizes via bound_count.")]
fn find_leaders(code: &CodeItem) -> BTreeSet<u32> {
    let mut leaders = BTreeSet::new();
    leaders.insert(0);

    for insn in &code.instructions {
        let next_addr = insn.addr + u32::from(insn.size);

        if is_branch(insn.op) || is_terminal(insn.op) {
            leaders.insert(next_addr);
        }

        if let Some(target) = insn.target {
            if matches!(insn.op, Opcode::PackedSwitch | Opcode::SparseSwitch) {
                // Switch targets come from payloads
                if let Some(
                    PayloadData::PackedSwitch { targets, .. }
                    | PayloadData::SparseSwitch { targets, .. },
                ) = code.payloads.get(&target)
                {
                    for &t in targets {
                        leaders.insert(t);
                    }
                }
            } else if is_branch(insn.op) {
                leaders.insert(target);
            }
        }
    }

    // Exception handler entries
    for handler in &code.catch_handlers {
        for catch in &handler.catches {
            leaders.insert(catch.handler_addr);
        }
        if let Some(addr) = handler.catch_all_addr {
            leaders.insert(addr);
        }
    }

    leaders
}

#[allow(clippy::arithmetic_side_effects, reason = "`i + 1` on enumerate() index over leader_vec; leader_vec.len() ≤ insn count, which is parser-bounded.")]
#[allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: `i` is enumerate index over leader_vec; leader_vec.len() ≤ insn count ≤ u32::MAX by DEX file-format spec."
)]
fn build_blocks(
    code: &CodeItem,
    leaders: &BTreeSet<u32>,
) -> (Vec<BasicBlock>, BTreeMap<u32, BlockIdx>) {
    let leader_vec: Vec<u32> = leaders.iter().copied().collect();
    let mut addr_to_block = BTreeMap::new();
    let mut blocks = Vec::with_capacity(leader_vec.len());

    for (i, &leader_addr) in leader_vec.iter().enumerate() {
        let block_idx = BlockIdx(i as u32);
        addr_to_block.insert(leader_addr, block_idx);

        // SEMANTICS-DEFAULT-EMPTY: last block has no successor leader; u32::MAX
        // acts as an open-ended sentinel so the filter `insn.addr < next_leader`
        // admits all remaining instructions (no real address reaches u32::MAX).
        let next_leader = leader_vec.get(i + 1).copied().unwrap_or(u32::MAX);
        let insns: Vec<Instruction> = code
            .instructions
            .iter()
            .filter(|insn| insn.addr >= leader_addr && insn.addr < next_leader)
            .cloned()
            .collect();

        blocks.push(BasicBlock {
            id: block_idx,
            start_addr: leader_addr,
            instructions: insns,
            successors: Vec::new(),
            predecessors: BTreeSet::new(),
        });
    }

    (blocks, addr_to_block)
}

#[allow(clippy::arithmetic_side_effects, reason = "addr + size on parser-validated Instruction; first_key + j on SwitchPayload — first_key is i32 from spec-bounded payload, j is loop index over payload.targets which is parser-validated.")]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "PROOF: `j` is enumerate index over targets in a packed_switch payload; payload size is u16 by DEX spec §7.3.5, so j < 65536 ≤ i32::MAX. Narrowing exact, no wrap."
)]
fn add_edges(blocks: &mut [BasicBlock], addr_to_block: &BTreeMap<u32, BlockIdx>, code: &CodeItem) {
    // Collect edge info first, then apply (avoids borrow issues with index loop)
    let edge_info: Vec<Vec<Edge>> = blocks
        .iter()
        .map(|block| {
            let last = match block.instructions.last() {
                Some(insn) => insn,
                None => return Vec::new(),
            };
            let next_addr = last.addr + u32::from(last.size);
            let mut edges = Vec::new();

            if is_terminal(last.op) {
                return edges;
            }

            if is_unconditional_branch(last.op) {
                if let Some(target) = last.target {
                    if let Some(&target_idx) = addr_to_block.get(&target) {
                        edges.push(Edge {
                            target: target_idx,
                            kind: EdgeKind::Branch,
                        });
                    }
                }
                return edges;
            }

            match last.op {
                Opcode::PackedSwitch | Opcode::SparseSwitch => {
                    if let Some(&next_idx) = addr_to_block.get(&next_addr) {
                        edges.push(Edge {
                            target: next_idx,
                            kind: EdgeKind::SwitchDefault,
                        });
                    }
                    if let Some(target) = last.target {
                        if let Some(payload) = code.payloads.get(&target) {
                            match payload {
                                PayloadData::PackedSwitch { first_key, targets } => {
                                    for (j, &t) in targets.iter().enumerate() {
                                        if let Some(&t_idx) = addr_to_block.get(&t) {
                                            edges.push(Edge {
                                                target: t_idx,
                                                kind: EdgeKind::SwitchCase(*first_key + j as i32),
                                            });
                                        }
                                    }
                                }
                                PayloadData::SparseSwitch { keys, targets } => {
                                    for (&key, &t) in keys.iter().zip(targets.iter()) {
                                        if let Some(&t_idx) = addr_to_block.get(&t) {
                                            edges.push(Edge {
                                                target: t_idx,
                                                kind: EdgeKind::SwitchCase(key),
                                            });
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                op if is_branch(op) => {
                    if let Some(&next_idx) = addr_to_block.get(&next_addr) {
                        edges.push(Edge {
                            target: next_idx,
                            kind: EdgeKind::FallThrough,
                        });
                    }
                    if let Some(target) = last.target {
                        if let Some(&target_idx) = addr_to_block.get(&target) {
                            edges.push(Edge {
                                target: target_idx,
                                kind: EdgeKind::Branch,
                            });
                        }
                    }
                }
                _ => {
                    if let Some(&next_idx) = addr_to_block.get(&next_addr) {
                        edges.push(Edge {
                            target: next_idx,
                            kind: EdgeKind::FallThrough,
                        });
                    }
                }
            }
            edges
        })
        .collect();

    for (block, edges) in blocks.iter_mut().zip(edge_info) {
        block.successors = edges;
    }
}

#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: try_item.handler_idx is parsed by parser::parse_code_item which validates `handler_idx < code.catch_handlers.len()` at parse time (DEX spec §6 require + bound_count). Reaching here implies the parser accepted the input."
)]
#[allow(clippy::arithmetic_side_effects, reason = "try_start + insn_count on parser-validated TryItem (spec-capped to u16 insn_count); block_last.addr + block_last.size on parser-validated Instruction.")]
fn add_exception_edges(
    blocks: &mut [BasicBlock],
    addr_to_block: &BTreeMap<u32, BlockIdx>,
    code: &CodeItem,
) {
    for try_item in &code.tries {
        let try_start = try_item.start_addr;
        let try_end = try_start + u32::from(try_item.insn_count);
        let handler = &code.catch_handlers[try_item.handler_idx];

        // Find all blocks that overlap with this try region
        for block in blocks.iter_mut() {
            let Some(block_last) = block.instructions.last() else {
                continue;
            };
            let block_start = block.start_addr;
            let block_end = block_last.addr + u32::from(block_last.size);

            // Check overlap
            if block_start < try_end && block_end > try_start {
                for catch in &handler.catches {
                    if let Some(&handler_idx) = addr_to_block.get(&catch.handler_addr) {
                        block.successors.push(Edge {
                            target: handler_idx,
                            kind: EdgeKind::ExceptionHandler(catch.exception_type),
                        });
                    }
                }
                if let Some(catch_all_addr) = handler.catch_all_addr {
                    if let Some(&handler_idx) = addr_to_block.get(&catch_all_addr) {
                        block.successors.push(Edge {
                            target: handler_idx,
                            kind: EdgeKind::ExceptionCatchAll,
                        });
                    }
                }
            }
        }
    }
}

#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: edges are built from `b.successors[*].target` which are minted BlockIdx values (`< blocks.len()`). dst.0 is a minted index by construction."
)]
fn fill_predecessors(blocks: &mut [BasicBlock]) {
    let edges: Vec<(BlockIdx, BlockIdx)> = blocks
        .iter()
        .flat_map(|b| b.successors.iter().map(move |e| (b.id, e.target)))
        .collect();
    for (src, dst) in edges {
        blocks[dst.0 as usize].predecessors.insert(src);
    }
}

#[allow(
    clippy::indexing_slicing,
    reason = "PROOF: same invariant as add_exception_edges — try_item.handler_idx is parser-validated `< code.catch_handlers.len()`."
)]
#[allow(clippy::arithmetic_side_effects, reason = "try_start + insn_count on parser-validated TryItem (spec-capped to u16 insn_count).")]
fn build_exception_regions(
    code: &CodeItem,
    addr_to_block: &BTreeMap<u32, BlockIdx>,
) -> Vec<ExceptionRegion> {
    code.tries
        .iter()
        .map(|try_item| {
            let handler = &code.catch_handlers[try_item.handler_idx];
            let mut handler_blocks = Vec::new();

            for catch in &handler.catches {
                if let Some(&idx) = addr_to_block.get(&catch.handler_addr) {
                    handler_blocks.push((EdgeKind::ExceptionHandler(catch.exception_type), idx));
                }
            }
            if let Some(addr) = handler.catch_all_addr {
                if let Some(&idx) = addr_to_block.get(&addr) {
                    handler_blocks.push((EdgeKind::ExceptionCatchAll, idx));
                }
            }

            ExceptionRegion {
                start_addr: try_item.start_addr,
                end_addr: try_item.start_addr + u32::from(try_item.insn_count),
                handler_blocks,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::RegList;

    fn make_insn(addr: u32, op: Opcode, size: u8) -> Instruction {
        Instruction {
            addr,
            op,
            size,
            dst: None,
            src: RegList::empty(),
            literal: 0,
            target: None,
            pool_idx: None,
        }
    }

    #[test]
    fn linear_code_single_block() {
        let code = CodeItem {
            registers_size: 2,
            ins_size: 1,
            outs_size: 0,
            debug_info_off: 0,
            instructions: vec![
                make_insn(0, Opcode::Nop, 1),
                make_insn(1, Opcode::ReturnVoid, 1),
            ],
            tries: vec![],
            catch_handlers: vec![],
            payloads: BTreeMap::new(),
            invariant_violations: vec![],
        };
        let cfg = Cfg::build(&code).unwrap();
        // return-void creates a leader at addr 2, but there are no insns there
        // so we get 2 blocks: [nop] and [] (empty block after return)
        // The important thing: block 0 has no successors (terminal)
        assert!(!cfg.blocks[0].instructions.is_empty());
        let last_block_with_insns = cfg
            .blocks
            .iter()
            .find(|b| b.instructions.last().map(|i| i.op) == Some(Opcode::ReturnVoid));
        assert!(last_block_with_insns.is_some());
        assert!(last_block_with_insns.unwrap().successors.is_empty());
    }

    #[test]
    fn if_branch_three_blocks() {
        // if-eqz v0, +3  (addr 0, size 2, target 3)
        // return-void     (addr 2, size 1)
        // nop             (addr 3, size 1)  -- branch target
        // return-void     (addr 4, size 1)
        let code = CodeItem {
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            debug_info_off: 0,
            instructions: vec![
                {
                    let mut i = make_insn(0, Opcode::IfEqz, 2);
                    i.dst = Some(0);
                    i.target = Some(3);
                    i
                },
                make_insn(2, Opcode::ReturnVoid, 1),
                make_insn(3, Opcode::Nop, 1),
                make_insn(4, Opcode::ReturnVoid, 1),
            ],
            tries: vec![],
            catch_handlers: vec![],
            payloads: BTreeMap::new(),
            invariant_violations: vec![],
        };
        let cfg = Cfg::build(&code).unwrap();

        // Leaders: 0, 2 (fall-through of if), 3 (branch target), 5 (after last return)
        // Block 0: [if-eqz] → fall-through to block at 2, branch to block at 3
        let block0 = cfg.block(BlockIdx(0));
        assert_eq!(block0.instructions.len(), 1);
        assert_eq!(block0.successors.len(), 2);

        // Block at addr 2: [return-void] → no successors
        let block_2 = cfg.block(*cfg.addr_to_block.get(&2).unwrap());
        assert_eq!(block_2.instructions.len(), 1);
        assert_eq!(block_2.instructions[0].op, Opcode::ReturnVoid);
        assert!(block_2.successors.is_empty());

        // Block at addr 3: [nop, return-void] or just [nop] + block at 4
        let block_3 = cfg.block(*cfg.addr_to_block.get(&3).unwrap());
        assert!(!block_3.instructions.is_empty());
    }

    #[test]
    fn goto_creates_branch_edge() {
        // goto +2 (addr 0, size 1, target 2)
        // nop     (addr 1, size 1) — unreachable
        // return-void (addr 2, size 1) — target
        let code = CodeItem {
            registers_size: 0,
            ins_size: 0,
            outs_size: 0,
            debug_info_off: 0,
            instructions: vec![
                {
                    let mut i = make_insn(0, Opcode::Goto, 1);
                    i.target = Some(2);
                    i
                },
                make_insn(1, Opcode::Nop, 1),
                make_insn(2, Opcode::ReturnVoid, 1),
            ],
            tries: vec![],
            catch_handlers: vec![],
            payloads: BTreeMap::new(),
            invariant_violations: vec![],
        };
        let cfg = Cfg::build(&code).unwrap();

        let block0 = cfg.block(BlockIdx(0));
        assert_eq!(block0.successors.len(), 1);
        assert!(matches!(block0.successors[0].kind, EdgeKind::Branch));

        let target_block = cfg.block(block0.successors[0].target);
        assert_eq!(target_block.instructions[0].op, Opcode::ReturnVoid);
    }

    #[test]
    fn predecessor_consistency() {
        let code = CodeItem {
            registers_size: 1,
            ins_size: 0,
            outs_size: 0,
            debug_info_off: 0,
            instructions: vec![
                {
                    let mut i = make_insn(0, Opcode::IfEqz, 2);
                    i.dst = Some(0);
                    i.target = Some(3);
                    i
                },
                make_insn(2, Opcode::ReturnVoid, 1),
                make_insn(3, Opcode::ReturnVoid, 1),
            ],
            tries: vec![],
            catch_handlers: vec![],
            payloads: BTreeMap::new(),
            invariant_violations: vec![],
        };
        let cfg = Cfg::build(&code).unwrap();

        // Verify: for every successor edge A→B, B.predecessors contains A
        for block in &cfg.blocks {
            for edge in &block.successors {
                let target = cfg.block(edge.target);
                assert!(
                    target.predecessors.contains(&block.id),
                    "block {} → block {} but predecessor not recorded",
                    block.id.0,
                    edge.target.0
                );
            }
        }
    }
}
